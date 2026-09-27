use deslop_core::{
    DependencyEdge, DependencyEdgeKind, SourceSpan, Symbol, SymbolKind, Visibility,
};
use sha2::{Digest, Sha256};
use std::path::Path;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Expr, ExprCall, ExprMethodCall, ImplItem, ItemFn, ItemImpl, ItemStruct, ItemTrait};

pub struct RustAstExtractor<'a> {
    pub file_path: &'a Path,
    pub symbols: Vec<Symbol>,
    pub edges: Vec<DependencyEdge>,
    pub current_symbol_id: Option<String>,
}

impl<'a> RustAstExtractor<'a> {
    pub fn new(file_path: &'a Path) -> Self {
        Self {
            file_path,
            symbols: Vec::new(),
            edges: Vec::new(),
            current_symbol_id: None,
        }
    }

    fn calculate_ast_hash(tokens: &str) -> String {
        let mut hasher = Sha256::new();
        // Normalize whitespace
        let normalized = tokens.split_whitespace().collect::<Vec<_>>().join(" ");
        hasher.update(normalized.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

impl<'ast, 'a> Visit<'ast> for RustAstExtractor<'a> {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let fn_name = node.sig.ident.to_string();
        let span = node.span();
        let start = span.start();
        let end = span.end();
        let file_str = self.file_path.to_string_lossy();
        let symbol_id = format!("{}::{}", file_str, fn_name);

        let visibility = match &node.vis {
            syn::Visibility::Public(_) => Visibility::Public,
            syn::Visibility::Restricted(_) => Visibility::Internal,
            syn::Visibility::Inherited => Visibility::Private,
        };

        let loc = if end.line >= start.line {
            end.line - start.line + 1
        } else {
            1
        };

        // Rough cyclomatic complexity: count control flow branches
        let code_str = quote::quote!(#node).to_string();
        let cyclomatic = 1
            + code_str.matches(" if ").count()
            + code_str.matches(" match ").count()
            + code_str.matches(" for ").count()
            + code_str.matches(" while ").count()
            + code_str.matches(" && ").count()
            + code_str.matches(" || ").count();

        let ast_hash = Self::calculate_ast_hash(&quote::quote!(#node.block).to_string());

        let sig_str = quote::quote!(#node.sig).to_string();

        self.symbols.push(Symbol {
            id: symbol_id.clone(),
            name: fn_name,
            kind: SymbolKind::Function,
            file_path: self.file_path.to_path_buf(),
            span: SourceSpan::new(start.line, start.column, end.line, end.column),
            visibility,
            loc,
            cyclomatic_complexity: cyclomatic,
            doc: None,
            signature: sig_str,
            is_pure_hint: !code_str.contains("mut ") && !code_str.contains("unsafe"),
            ast_hash: Some(ast_hash),
        });

        let prev = self.current_symbol_id.take();
        self.current_symbol_id = Some(symbol_id);
        syn::visit::visit_item_fn(self, node);
        self.current_symbol_id = prev;
    }

    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        let name = node.ident.to_string();
        let span = node.span();
        let start = span.start();
        let end = span.end();
        let symbol_id = format!("{}::{}", self.file_path.to_string_lossy(), name);

        let visibility = match &node.vis {
            syn::Visibility::Public(_) => Visibility::Public,
            _ => Visibility::Private,
        };

        self.symbols.push(Symbol {
            id: symbol_id,
            name,
            kind: SymbolKind::Struct,
            file_path: self.file_path.to_path_buf(),
            span: SourceSpan::new(start.line, start.column, end.line, end.column),
            visibility,
            loc: if end.line >= start.line {
                end.line - start.line + 1
            } else {
                1
            },
            cyclomatic_complexity: 1,
            doc: None,
            signature: quote::quote!(#node).to_string(),
            is_pure_hint: true,
            ast_hash: None,
        });

        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item_trait(&mut self, node: &'ast ItemTrait) {
        let name = node.ident.to_string();
        let span = node.span();
        let start = span.start();
        let end = span.end();
        let symbol_id = format!("{}::{}", self.file_path.to_string_lossy(), name);

        let visibility = match &node.vis {
            syn::Visibility::Public(_) => Visibility::Public,
            _ => Visibility::Private,
        };

        self.symbols.push(Symbol {
            id: symbol_id,
            name,
            kind: SymbolKind::Trait,
            file_path: self.file_path.to_path_buf(),
            span: SourceSpan::new(start.line, start.column, end.line, end.column),
            visibility,
            loc: if end.line >= start.line {
                end.line - start.line + 1
            } else {
                1
            },
            cyclomatic_complexity: 1,
            doc: None,
            signature: quote::quote!(#node).to_string(),
            is_pure_hint: true,
            ast_hash: None,
        });

        syn::visit::visit_item_trait(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        // Track trait implementations
        if let Some((_, trait_path, _)) = &node.trait_ {
            let trait_name = quote::quote!(#trait_path).to_string().replace(" ", "");
            let self_type = quote::quote!(#node.self_ty).to_string().replace(" ", "");

            self.edges.push(DependencyEdge {
                from_symbol: format!("{}::{}", self.file_path.to_string_lossy(), self_type),
                to_symbol: trait_name,
                kind: DependencyEdgeKind::Implements,
                count: 1,
            });
        }

        // Visit methods inside impl
        for item in &node.items {
            if let ImplItem::Fn(m) = item {
                let m_name = m.sig.ident.to_string();
                let span = m.span();
                let start = span.start();
                let end = span.end();
                let self_type = quote::quote!(#node.self_ty).to_string().replace(" ", "");
                let symbol_id = format!(
                    "{}::{}::{}",
                    self.file_path.to_string_lossy(),
                    self_type,
                    m_name
                );

                let code_str = quote::quote!(#m).to_string();
                let cyclomatic = 1
                    + code_str.matches(" if ").count()
                    + code_str.matches(" match ").count()
                    + code_str.matches(" for ").count()
                    + code_str.matches(" while ").count();

                let ast_hash = Self::calculate_ast_hash(&quote::quote!(#m.block).to_string());

                self.symbols.push(Symbol {
                    id: symbol_id.clone(),
                    name: format!("{}::{}", self_type, m_name),
                    kind: SymbolKind::Method,
                    file_path: self.file_path.to_path_buf(),
                    span: SourceSpan::new(start.line, start.column, end.line, end.column),
                    visibility: match &m.vis {
                        syn::Visibility::Public(_) => Visibility::Public,
                        _ => Visibility::Private,
                    },
                    loc: if end.line >= start.line {
                        end.line - start.line + 1
                    } else {
                        1
                    },
                    cyclomatic_complexity: cyclomatic,
                    doc: None,
                    signature: quote::quote!(#m.sig).to_string(),
                    is_pure_hint: !code_str.contains("&mut ") && !code_str.contains("unsafe"),
                    ast_hash: Some(ast_hash),
                });

                let prev = self.current_symbol_id.take();
                self.current_symbol_id = Some(symbol_id);
                syn::visit::visit_impl_item_fn(self, m);
                self.current_symbol_id = prev;
            }
        }
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Some(caller) = &self.current_symbol_id {
            if let Expr::Path(path) = &*node.func {
                let callee_name = quote::quote!(#path).to_string().replace(" ", "");
                self.edges.push(DependencyEdge {
                    from_symbol: caller.clone(),
                    to_symbol: callee_name,
                    kind: DependencyEdgeKind::Calls,
                    count: 1,
                });
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if let Some(caller) = &self.current_symbol_id {
            let method_name = node.method.to_string();
            self.edges.push(DependencyEdge {
                from_symbol: caller.clone(),
                to_symbol: method_name,
                kind: DependencyEdgeKind::Calls,
                count: 1,
            });
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

pub fn parse_rust_file(
    path: &Path,
    content: &str,
) -> anyhow::Result<(Vec<Symbol>, Vec<DependencyEdge>)> {
    let syntax_tree: syn::File = syn::parse_file(content)?;
    let mut extractor = RustAstExtractor::new(path);
    extractor.visit_file(&syntax_tree);
    Ok((extractor.symbols, extractor.edges))
}
