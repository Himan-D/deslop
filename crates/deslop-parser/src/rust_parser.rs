use deslop_core::{
    DependencyEdge, DependencyEdgeKind, Import, ParsedFile, SourceSpan, Symbol, SymbolKind,
    Visibility,
};
use sha2::{Digest, Sha256};
use std::path::Path;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{
    Expr, ExprCall, ExprMethodCall, ExprPath, ExprStruct, ImplItem, ItemConst, ItemEnum, ItemFn,
    ItemImpl, ItemStatic, ItemStruct, ItemTrait, ItemType, TypePath,
};

pub struct RustAstExtractor<'a> {
    pub file_path: &'a Path,
    pub symbols: Vec<Symbol>,
    pub edges: Vec<DependencyEdge>,
    pub imports: Vec<Import>,
    pub current_symbol_id: Option<String>,
    current_impl_type: Option<String>,
    in_test_module: bool,
}

impl<'a> RustAstExtractor<'a> {
    pub fn new(file_path: &'a Path) -> Self {
        Self {
            file_path,
            symbols: Vec::new(),
            edges: Vec::new(),
            imports: Vec::new(),
            current_symbol_id: None,
            current_impl_type: None,
            in_test_module: false,
        }
    }

    fn calculate_ast_hash(tokens: &str) -> String {
        let mut hasher = Sha256::new();
        // Normalize whitespace
        let normalized = tokens.split_whitespace().collect::<Vec<_>>().join(" ");
        hasher.update(normalized.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    fn attribute_paths(attrs: &[syn::Attribute]) -> Vec<String> {
        attrs
            .iter()
            .map(|a| {
                let path = a
                    .path()
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::");
                // Keep `cfg` predicates (`#[cfg(test)]` -> `cfg(test)`).
                if path == "cfg" {
                    if let syn::Meta::List(list) = &a.meta {
                        let args: String = list.tokens.to_string().split_whitespace().collect();
                        return format!("cfg({})", args);
                    }
                }
                path
            })
            .collect()
    }

    fn push_plain_item(
        &mut self,
        name: &str,
        vis: &syn::Visibility,
        span: proc_macro2::Span,
        attrs: &[syn::Attribute],
        kind: SymbolKind,
    ) {
        let start = span.start();
        let end = span.end();
        let symbol_id = format!("{}::{}", self.file_path.to_string_lossy(), name);

        let visibility = match vis {
            syn::Visibility::Public(_) => Visibility::Public,
            _ => Visibility::Private,
        };

        self.symbols.push(Symbol {
            id: symbol_id,
            name: name.to_string(),
            kind,
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
            signature: name.to_string(),
            is_pure_hint: true,
            ast_hash: None,
            attributes: self.symbol_attributes(attrs),
            is_trait_impl: false,
        });
    }

    fn symbol_attributes(&self, attrs: &[syn::Attribute]) -> Vec<String> {
        let mut out = Self::attribute_paths(attrs);
        // Contents of `mod tests` / `#[cfg(test)]` modules are test code even
        // when the items themselves carry no test attribute.
        if self.in_test_module && !out.iter().any(|a| a == "cfg(test)") {
            out.push("cfg(test)".to_string());
        }
        out
    }

    fn emit_type_ref(&mut self, path: &syn::Path) {
        if path.segments.is_empty() {
            return;
        }
        if let Some(caller) = self.current_symbol_id.clone() {
            let dotted: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
            self.edges.push(DependencyEdge {
                from_symbol: caller,
                to_symbol: dotted.join("::"),
                kind: DependencyEdgeKind::ReferencesType,
                count: 1,
            });
        }
    }

    fn emit_generic_arg_edges(&mut self, caller: &str, args: &syn::PathArguments) {
        if let syn::PathArguments::AngleBracketed(bracketed) = args {
            for arg in &bracketed.args {
                if let syn::GenericArgument::Type(ty) = arg {
                    let mut type_names = Vec::new();
                    collect_type_names(ty, &mut type_names);
                    for type_name in type_names {
                        self.edges.push(DependencyEdge {
                            from_symbol: caller.to_string(),
                            to_symbol: type_name,
                            kind: DependencyEdgeKind::ReferencesType,
                            count: 1,
                        });
                    }
                }
            }
        }
    }
}

/// McCabe cyclomatic complexity from the AST: base 1 plus one per decision
/// point (`if`, `for`, `while`, `loop`, `?`, `&&`, `||`) and one per `match`
/// arm. String literals and comments never count. Nested named `fn` items are
/// skipped so each function is measured on its own body.
struct ComplexityCounter {
    complexity: usize,
}

impl ComplexityCounter {
    fn of_block(block: &syn::Block) -> usize {
        let mut counter = Self { complexity: 1 };
        counter.visit_block(block);
        counter.complexity
    }
}

impl<'ast> Visit<'ast> for ComplexityCounter {
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.complexity += 1;
        syn::visit::visit_expr_if(self, node);
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        self.complexity += node.arms.len().max(1);
        syn::visit::visit_expr_match(self, node);
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.complexity += 1;
        syn::visit::visit_expr_for_loop(self, node);
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        self.complexity += 1;
        syn::visit::visit_expr_while(self, node);
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.complexity += 1;
        syn::visit::visit_expr_loop(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if matches!(node.op, syn::BinOp::And(_) | syn::BinOp::Or(_)) {
            self.complexity += 1;
        }
        syn::visit::visit_expr_binary(self, node);
    }

    fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
        self.complexity += 1;
        syn::visit::visit_expr_try(self, node);
    }

    fn visit_item_fn(&mut self, _node: &'ast syn::ItemFn) {
        // Nested named functions get their own measurement; do not recurse.
    }
}

impl<'ast, 'a> Visit<'ast> for RustAstExtractor<'a> {
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        collect_use_tree(&node.tree, &mut Vec::new(), &mut self.imports);
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let is_test = node.ident == "tests"
            || Self::attribute_paths(&node.attrs)
                .iter()
                .any(|a| a == "cfg(test)");
        let prev = self.in_test_module;
        self.in_test_module = prev || is_test;
        syn::visit::visit_item_mod(self, node);
        self.in_test_module = prev;
    }

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

        let code_str = quote::quote!(#node).to_string();
        let cyclomatic = ComplexityCounter::of_block(&node.block);

        let fn_block = &node.block;
        let ast_hash = Self::calculate_ast_hash(&quote::quote!(#fn_block).to_string());

        // NOTE: `#node.sig` would interpolate the whole item plus a literal
        // `.sig`; bind the field first so only the signature is quoted.
        let fn_sig = &node.sig;
        let sig_str = quote::quote!(#fn_sig).to_string();

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
            attributes: self.symbol_attributes(&node.attrs),
            is_trait_impl: false,
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
            attributes: self.symbol_attributes(&node.attrs),
            is_trait_impl: false,
        });

        // Attribute field-type references to the struct itself.
        let struct_id = self.symbols.last().map(|s| s.id.clone());
        let prev = self.current_symbol_id.take();
        self.current_symbol_id = struct_id;
        syn::visit::visit_item_struct(self, node);
        self.current_symbol_id = prev;
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
            attributes: self.symbol_attributes(&node.attrs),
            is_trait_impl: false,
        });

        // Attribute signature-type references to the trait itself.
        let trait_id = self.symbols.last().map(|s| s.id.clone());
        let prev = self.current_symbol_id.take();
        self.current_symbol_id = trait_id;
        syn::visit::visit_item_trait(self, node);
        self.current_symbol_id = prev;
    }

    fn visit_item_enum(&mut self, node: &'ast ItemEnum) {
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
            id: symbol_id.clone(),
            name,
            kind: SymbolKind::Enum,
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
            attributes: self.symbol_attributes(&node.attrs),
            is_trait_impl: false,
        });

        let prev = self.current_symbol_id.take();
        self.current_symbol_id = Some(symbol_id);
        syn::visit::visit_item_enum(self, node);
        self.current_symbol_id = prev;
    }

    fn visit_item_const(&mut self, node: &'ast ItemConst) {
        self.push_plain_item(
            &node.ident.to_string(),
            &node.vis,
            node.span(),
            &node.attrs,
            SymbolKind::Constant,
        );
        let prev = self.current_symbol_id.take();
        self.current_symbol_id = self.symbols.last().map(|s| s.id.clone());
        syn::visit::visit_item_const(self, node);
        self.current_symbol_id = prev;
    }

    fn visit_item_static(&mut self, node: &'ast ItemStatic) {
        self.push_plain_item(
            &node.ident.to_string(),
            &node.vis,
            node.span(),
            &node.attrs,
            SymbolKind::Constant,
        );
        let prev = self.current_symbol_id.take();
        self.current_symbol_id = self.symbols.last().map(|s| s.id.clone());
        syn::visit::visit_item_static(self, node);
        self.current_symbol_id = prev;
    }

    fn visit_item_type(&mut self, node: &'ast ItemType) {
        self.push_plain_item(
            &node.ident.to_string(),
            &node.vis,
            node.span(),
            &node.attrs,
            SymbolKind::TypeAlias,
        );
        let prev = self.current_symbol_id.take();
        self.current_symbol_id = self.symbols.last().map(|s| s.id.clone());
        syn::visit::visit_item_type(self, node);
        self.current_symbol_id = prev;
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        let self_ty = &node.self_ty;
        let self_type = quote::quote!(#self_ty).to_string().replace(" ", "");
        let is_trait_impl = node.trait_.is_some();

        // Track trait implementations
        if let Some((_, trait_path, _)) = &node.trait_ {
            let trait_name = quote::quote!(#trait_path).to_string().replace(" ", "");

            self.edges.push(DependencyEdge {
                from_symbol: format!("{}::{}", self.file_path.to_string_lossy(), self_type),
                to_symbol: trait_name,
                kind: DependencyEdgeKind::Implements,
                count: 1,
            });
        }

        // Visit methods inside impl
        let prev_type = self.current_impl_type.replace(self_type.clone());
        for item in &node.items {
            if let ImplItem::Fn(m) = item {
                let m_name = m.sig.ident.to_string();
                let span = m.span();
                let start = span.start();
                let end = span.end();
                let symbol_id = format!(
                    "{}::{}::{}",
                    self.file_path.to_string_lossy(),
                    self_type,
                    m_name
                );

                let code_str = quote::quote!(#m).to_string();
                let cyclomatic = ComplexityCounter::of_block(&m.block);

                let m_block = &m.block;
                let ast_hash = Self::calculate_ast_hash(&quote::quote!(#m_block).to_string());
                let m_sig = &m.sig;

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
                    signature: quote::quote!(#m_sig).to_string(),
                    is_pure_hint: !code_str.contains("&mut ") && !code_str.contains("unsafe"),
                    ast_hash: Some(ast_hash),
                    attributes: self.symbol_attributes(&m.attrs),
                    is_trait_impl,
                });

                let prev = self.current_symbol_id.take();
                self.current_symbol_id = Some(symbol_id);
                syn::visit::visit_impl_item_fn(self, m);
                self.current_symbol_id = prev;
            }
        }
        self.current_impl_type = prev_type;
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
                // Generic type arguments are type uses too
                // (e.g. `from_str::<McpRequest>` references `McpRequest`).
                if let Some(seg) = path.path.segments.last() {
                    let caller_id = caller.clone();
                    self.emit_generic_arg_edges(&caller_id, &seg.arguments);
                }
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast ExprPath) {
        // Value-position paths reference types, enum variants, and constants
        // (`Status::Active`, `MAX`). Single lowercase idents are almost always
        // local variables, so only qualified or Uppercase paths emit edges;
        // anything unresolvable is dropped by the graph builder.
        if node.qself.is_none() && !node.path.segments.is_empty() {
            let first = node
                .path
                .segments
                .first()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            let is_candidate = node.path.segments.len() > 1
                || first
                    .chars()
                    .next()
                    .map(|c| c.is_uppercase())
                    .unwrap_or(false);
            if is_candidate {
                self.emit_type_ref(&node.path);
            }
        }
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_pat(&mut self, node: &'ast syn::Pat) {
        // Pattern paths reference types: `match x { Status::Active => .. }`,
        // `let Some(x) = ..`, `let Row { title } = ..`.
        match node {
            syn::Pat::Path(p) if p.qself.is_none() => self.emit_type_ref(&p.path),
            syn::Pat::TupleStruct(p) => self.emit_type_ref(&p.path),
            syn::Pat::Struct(p) => self.emit_type_ref(&p.path),
            _ => {}
        }
        syn::visit::visit_pat(self, node);
    }

    fn visit_type_path(&mut self, node: &'ast TypePath) {
        // Type-position references: signatures, annotations, field types,
        // generic arguments (`Vec<Symbol>` links `Symbol` via recursion).
        if let Some(caller) = &self.current_symbol_id {
            if node.qself.is_none() {
                if let Some(seg) = node.path.segments.last() {
                    self.edges.push(DependencyEdge {
                        from_symbol: caller.clone(),
                        to_symbol: seg.ident.to_string(),
                        kind: DependencyEdgeKind::ReferencesType,
                        count: 1,
                    });
                }
            }
        }
        syn::visit::visit_type_path(self, node);
    }

    fn visit_expr_struct(&mut self, node: &'ast ExprStruct) {
        if let Some(caller) = &self.current_symbol_id {
            let mut path_str = node
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect::<Vec<_>>()
                .join("::");
            if path_str == "Self" {
                if let Some(ty) = &self.current_impl_type {
                    path_str = ty.clone();
                }
            }
            if !path_str.is_empty() {
                self.edges.push(DependencyEdge {
                    from_symbol: caller.clone(),
                    to_symbol: path_str,
                    kind: DependencyEdgeKind::Instantiates,
                    count: 1,
                });
            }
        }
        syn::visit::visit_expr_struct(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if let Some(caller) = &self.current_symbol_id {
            let method_name = node.method.to_string();
            // Qualify `self.foo()` with the enclosing impl type so the graph
            // resolver can match `Type::foo` instead of guessing by bare name.
            let is_self_receiver =
                matches!(&*node.receiver, Expr::Path(p) if p.path.is_ident("self"));
            let callee = match (&self.current_impl_type, is_self_receiver) {
                (Some(ty), true) => format!("{}::{}", ty, method_name),
                _ => method_name,
            };
            let caller_id = caller.clone();
            self.edges.push(DependencyEdge {
                from_symbol: caller_id.clone(),
                to_symbol: callee,
                kind: DependencyEdgeKind::Calls,
                count: 1,
            });
            // Turbofish on method calls (`into_iter::<McpRequest>()`).
            if let Some(turbofish) = &node.turbofish {
                let mut type_names = Vec::new();
                for arg in &turbofish.args {
                    if let syn::GenericArgument::Type(ty) = arg {
                        collect_type_names(ty, &mut type_names);
                    }
                }
                for type_name in type_names {
                    self.edges.push(DependencyEdge {
                        from_symbol: caller_id.clone(),
                        to_symbol: type_name,
                        kind: DependencyEdgeKind::ReferencesType,
                        count: 1,
                    });
                }
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        // Macro bodies are opaque token streams that `syn::visit` never
        // descends into, so calls like `vec![build(x)]` or
        // `assert_eq!(f(a), b)` would be missed entirely. Scan the tokens for
        // `path(...)` call shapes instead. Literals are token-typed, so string
        // contents can never produce false calls.
        if let Some(caller) = self.current_symbol_id.clone() {
            let mut calls = Vec::new();
            collect_macro_calls(node.tokens.clone().into_iter(), &mut calls);
            for callee in calls {
                self.edges.push(DependencyEdge {
                    from_symbol: caller.clone(),
                    to_symbol: callee,
                    kind: DependencyEdgeKind::Calls,
                    count: 1,
                });
            }
        }
    }
}

/// Extracts `a::b(...)` call shapes from a macro token stream, recursing into
/// nested groups so `assert_eq!(f(vec![g(x)]), y)` yields `f` and `g`.
fn collect_macro_calls(
    tokens: impl Iterator<Item = proc_macro2::TokenTree>,
    calls: &mut Vec<String>,
) {
    use proc_macro2::{Delimiter, TokenTree};
    let tokens: Vec<TokenTree> = tokens.collect();
    let mut i = 0;
    while i < tokens.len() {
        match &tokens[i] {
            TokenTree::Group(group) => {
                collect_macro_calls(group.stream().into_iter(), calls);
                i += 1;
            }
            TokenTree::Ident(ident) => {
                let mut path = vec![ident.to_string()];
                let mut j = i + 1;
                while j + 2 < tokens.len() {
                    match (&tokens[j], &tokens[j + 1], &tokens[j + 2]) {
                        (
                            TokenTree::Punct(colon1),
                            TokenTree::Punct(colon2),
                            TokenTree::Ident(next),
                        ) if colon1.as_char() == ':'
                            && colon2.as_char() == ':'
                            && colon1.spacing() == proc_macro2::Spacing::Joint =>
                        {
                            path.push(next.to_string());
                            j += 3;
                        }
                        _ => break,
                    }
                }
                if j < tokens.len() {
                    if let TokenTree::Group(group) = &tokens[j] {
                        if group.delimiter() == Delimiter::Parenthesis {
                            calls.push(path.join("::"));
                        }
                    }
                }
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
}

/// Collects concrete type names from a type, recursing into nested generics
/// (`Vec<Symbol>` yields `Vec` and `Symbol`). Single self-recursive function
/// so the call graph stays acyclic.
fn collect_type_names(ty: &syn::Type, names: &mut Vec<String>) {
    match ty {
        syn::Type::Path(type_path) => {
            if let Some(seg) = type_path.path.segments.last() {
                names.push(seg.ident.to_string());
                if let syn::PathArguments::AngleBracketed(bracketed) = &seg.arguments {
                    for arg in &bracketed.args {
                        if let syn::GenericArgument::Type(inner) = arg {
                            collect_type_names(inner, names);
                        }
                    }
                }
            }
        }
        syn::Type::Reference(type_ref) => collect_type_names(&type_ref.elem, names),
        syn::Type::Ptr(type_ptr) => collect_type_names(&type_ptr.elem, names),
        syn::Type::Slice(type_slice) => collect_type_names(&type_slice.elem, names),
        syn::Type::Array(type_array) => collect_type_names(&type_array.elem, names),
        syn::Type::Tuple(type_tuple) => {
            for elem in &type_tuple.elems {
                collect_type_names(elem, names);
            }
        }
        _ => {}
    }
}

/// Flattens a `use` tree into (local name, full path) bindings.
fn collect_use_tree(tree: &syn::UseTree, prefix: &mut Vec<String>, out: &mut Vec<Import>) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_tree(&path.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            // `use foo::{self}` binds `foo` itself, not the name `self`.
            if name.ident == "self" {
                if let Some(last) = prefix.last() {
                    out.push(Import {
                        local: last.clone(),
                        path: prefix.join("::"),
                        is_glob: false,
                    });
                }
                return;
            }
            let mut full = prefix.clone();
            full.push(name.ident.to_string());
            out.push(Import {
                local: name.ident.to_string(),
                path: full.join("::"),
                is_glob: false,
            });
        }
        syn::UseTree::Rename(rename) => {
            let mut full = prefix.clone();
            full.push(rename.ident.to_string());
            out.push(Import {
                local: rename.rename.to_string(),
                path: full.join("::"),
                is_glob: false,
            });
        }
        syn::UseTree::Glob(_) => {
            out.push(Import {
                local: String::new(),
                path: prefix.join("::"),
                is_glob: true,
            });
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_use_tree(item, prefix, out);
            }
        }
    }
}

pub fn parse_rust_file(path: &Path, content: &str) -> anyhow::Result<ParsedFile> {
    let syntax_tree: syn::File = syn::parse_file(content)?;
    let mut extractor = RustAstExtractor::new(path);
    extractor.visit_file(&syntax_tree);
    Ok(ParsedFile {
        symbols: extractor.symbols,
        edges: extractor.edges,
        imports: extractor.imports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> (Vec<Symbol>, Vec<DependencyEdge>) {
        let parsed = parse_rust_file(Path::new("test.rs"), content).expect("parse failed");
        (parsed.symbols, parsed.edges)
    }

    fn complexity_of(symbols: &[Symbol], name: &str) -> usize {
        symbols
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("symbol {} not found", name))
            .cyclomatic_complexity
    }

    #[test]
    fn complexity_counts_match_arms_not_substrings() {
        let (symbols, _) = parse(
            r#"
            fn classify(x: u8) -> &'static str {
                let decoy = " if match for while && || ";
                match x {
                    0 => "zero",
                    1 => "one",
                    _ => decoy,
                }
            }
            "#,
        );
        // 1 base + 3 arms; the string literal contributes nothing.
        assert_eq!(complexity_of(&symbols, "classify"), 4);
    }

    #[test]
    fn complexity_counts_branches_operators_and_try() {
        let (symbols, _) = parse(
            r#"
            fn check(a: bool, b: bool, c: bool) -> anyhow::Result<bool> {
                let x = fallible()?;
                if a && b || c {
                    for _ in 0..x {
                        while !ready() {
                            break;
                        }
                    }
                }
                Ok(true)
            }
            "#,
        );
        // 1 + ?(1) + if(1) + &&(1) + ||(1) + for(1) + while(1) = 7
        assert_eq!(complexity_of(&symbols, "check"), 7);
    }

    #[test]
    fn complexity_ignores_nested_named_functions() {
        let (symbols, _) = parse(
            r#"
            fn outer(x: bool) -> bool {
                fn inner(y: bool) -> bool {
                    if y { true } else { false }
                }
                if x { inner(x) } else { false }
            }
            "#,
        );
        assert_eq!(complexity_of(&symbols, "outer"), 2);
        assert_eq!(complexity_of(&symbols, "inner"), 2);
    }

    #[test]
    fn signature_excludes_body_and_hash_covers_body_only() {
        let (symbols, _) = parse(
            r#"
            fn first(x: i32) -> i32 {
                x + 1
            }
            fn second(y: i32) -> i32 {
                x + 1
            }
            "#,
        );
        // Both bodies are token-identical (`x + 1`); only the names and
        // parameter idents differ, and those live outside the hashed block.
        let first = symbols.iter().find(|s| s.name == "first").unwrap();
        assert!(!first.signature.contains('{'), "sig: {}", first.signature);
        assert!(
            first.signature.contains("-> i32"),
            "sig: {}",
            first.signature
        );
        let second = symbols.iter().find(|s| s.name == "second").unwrap();
        assert_eq!(first.ast_hash, second.ast_hash);
    }

    #[test]
    fn test_attribute_is_captured() {
        let (symbols, _) = parse(
            r#"
            #[test]
            fn test_parse_works() {
                assert!(true);
            }
            "#,
        );
        let sym = symbols
            .iter()
            .find(|s| s.name == "test_parse_works")
            .unwrap();
        assert!(sym.attributes.iter().any(|a| a == "test"));
        assert!(sym.is_test_entrypoint());
    }

    #[test]
    fn trait_impl_methods_are_flagged() {
        let (symbols, _) = parse(
            r#"
            struct Foo;
            impl Foo {
                fn inherent(&self) {}
            }
            impl Default for Foo {
                fn default() -> Self {
                    Foo
                }
            }
            "#,
        );
        let inherent = symbols.iter().find(|s| s.name == "Foo::inherent").unwrap();
        let default = symbols.iter().find(|s| s.name == "Foo::default").unwrap();
        assert!(!inherent.is_trait_impl);
        assert!(default.is_trait_impl);
    }

    #[test]
    fn self_method_calls_are_type_qualified() {
        let (symbols, edges) = parse(
            r#"
            struct Engine;
            impl Engine {
                fn analyze(&self) {
                    self.helper();
                }
                fn helper(&self) {}
            }
            "#,
        );
        assert!(symbols.iter().any(|s| s.name == "Engine::helper"));
        let call = edges
            .iter()
            .find(|e| e.kind == DependencyEdgeKind::Calls)
            .expect("expected a Calls edge");
        assert_eq!(call.to_symbol, "Engine::helper");
    }

    #[test]
    fn struct_literal_emits_instantiates_edge() {
        let (_symbols, edges) = parse(
            r#"
            struct Row {
                title: String,
            }
            fn make() -> Row {
                Row { title: String::new() }
            }
            "#,
        );
        let inst = edges
            .iter()
            .find(|e| e.kind == DependencyEdgeKind::Instantiates)
            .expect("expected an Instantiates edge");
        assert_eq!(inst.to_symbol, "Row");
    }

    #[test]
    fn macro_bodies_yield_call_edges() {
        let (_symbols, edges) = parse(
            r#"
            fn build(x: i32) -> i32 { x }
            fn leaf(y: i32) -> i32 { y }
            fn run() {
                let items = vec![build(1), leaf(2)];
                assert_eq!(build(3), leaf(3));
                let decoy = "not_a_call( ";
            }
            "#,
        );
        let calls: Vec<&str> = edges
            .iter()
            .filter(|e| e.kind == DependencyEdgeKind::Calls && e.from_symbol.ends_with("::run"))
            .map(|e| e.to_symbol.as_str())
            .collect();
        assert!(calls.contains(&"build"), "calls: {:?}", calls);
        assert!(calls.contains(&"leaf"), "calls: {:?}", calls);
        assert!(!calls.iter().any(|c| c.contains("not_a_call")));
    }

    #[test]
    fn method_turbofish_emits_reference_edges() {
        let (_symbols, edges) = parse(
            r#"
            struct Req;
            fn run(raw: &str) {
                let mut it = serde_json::Deserializer::from_str(raw).into_iter::<Req>();
                let _ = it.next();
            }
            "#,
        );
        let refs: Vec<&str> = edges
            .iter()
            .filter(|e| e.kind == DependencyEdgeKind::ReferencesType)
            .map(|e| e.to_symbol.as_str())
            .collect();
        assert!(refs.contains(&"Req"), "refs: {:?}", refs);
    }

    #[test]
    fn test_module_contents_are_marked_test_code() {
        let (symbols, _) = parse(
            r#"
            fn helper() {}
            #[cfg(test)]
            mod tests {
                fn scaffold() {}
                #[test]
                fn it_works() {
                    scaffold();
                }
            }
            "#,
        );
        let helper = symbols.iter().find(|s| s.name == "helper").unwrap();
        let scaffold = symbols.iter().find(|s| s.name == "scaffold").unwrap();
        let test_fn = symbols.iter().find(|s| s.name == "it_works").unwrap();
        assert!(!helper.is_test_code());
        assert!(scaffold.is_test_code());
        assert!(!scaffold.is_test_entrypoint());
        assert!(test_fn.is_test_entrypoint());
    }

    #[test]
    fn enum_const_static_alias_symbols_are_emitted() {
        let (symbols, _) = parse(
            r#"
            pub enum Status { Active, Idle }
            pub const MAX: usize = 8;
            static SINGLETON: &str = "x";
            pub type UserId = u64;
            "#,
        );
        let kind_of = |name: &str| {
            symbols
                .iter()
                .find(|s| s.name == name)
                .unwrap_or_else(|| panic!("symbol {} not found", name))
                .kind
        };
        assert_eq!(kind_of("Status"), deslop_core::SymbolKind::Enum);
        assert_eq!(kind_of("MAX"), deslop_core::SymbolKind::Constant);
        assert_eq!(kind_of("SINGLETON"), deslop_core::SymbolKind::Constant);
        assert_eq!(kind_of("UserId"), deslop_core::SymbolKind::TypeAlias);
        assert_eq!(
            symbols
                .iter()
                .find(|s| s.name == "Status")
                .unwrap()
                .visibility,
            deslop_core::Visibility::Public
        );
        assert_eq!(
            symbols
                .iter()
                .find(|s| s.name == "SINGLETON")
                .unwrap()
                .visibility,
            deslop_core::Visibility::Private
        );
    }

    #[test]
    fn value_and_pattern_paths_emit_type_references() {
        let (symbols, edges) = parse(
            r#"
            enum Status { Active, Idle }
            struct Row { title: String }
            const MAX: usize = 8;
            fn run(s: Status, row: Row) -> usize {
                let other = Status::Idle;
                let limit = MAX;
                let lowercase_skipped = other;
                match s {
                    Status::Active => MAX,
                    _ => 0,
                }
            }
            fn destructure(row: Row) -> String {
                let Row { title } = row;
                title
            }
            "#,
        );
        assert!(symbols.iter().any(|s| s.name == "Status"));
        let refs_from = |caller: &str| -> Vec<String> {
            edges
                .iter()
                .filter(|e| {
                    e.kind == DependencyEdgeKind::ReferencesType
                        && e.from_symbol.ends_with(&format!("::{}", caller))
                })
                .map(|e| e.to_symbol.clone())
                .collect()
        };
        let run_refs = refs_from("run");
        assert!(
            run_refs.contains(&"Status::Idle".to_string()),
            "{:?}",
            run_refs
        );
        assert!(run_refs.contains(&"MAX".to_string()), "{:?}", run_refs);
        assert!(
            run_refs.contains(&"Status::Active".to_string()),
            "{:?}",
            run_refs
        );
        // Signature and annotation types link too.
        assert!(run_refs.contains(&"Status".to_string()), "{:?}", run_refs);
        assert!(run_refs.contains(&"Row".to_string()), "{:?}", run_refs);
        assert!(run_refs.contains(&"usize".to_string()), "{:?}", run_refs);
        // Lowercase locals are not references.
        assert!(!run_refs
            .iter()
            .any(|r| r == "other" || r == "s" || r == "row"));
        // Struct patterns reference the struct.
        let destructure_refs = refs_from("destructure");
        assert!(
            destructure_refs.contains(&"Row".to_string()),
            "{:?}",
            destructure_refs
        );
    }

    #[test]
    fn struct_field_types_attribute_to_the_struct() {
        let (_symbols, edges) = parse(
            r#"
            struct Inner;
            struct Outer {
                one: Inner,
                many: Vec<Inner>,
            }
            "#,
        );
        let from_outer: Vec<&str> = edges
            .iter()
            .filter(|e| {
                e.kind == DependencyEdgeKind::ReferencesType && e.from_symbol.ends_with("::Outer")
            })
            .map(|e| e.to_symbol.as_str())
            .collect();
        assert!(from_outer.contains(&"Inner"), "{:?}", from_outer);
    }

    #[test]
    fn use_trees_flatten_to_import_bindings() {
        let parsed = parse_rust_file(
            Path::new("test.rs"),
            r#"
            use deslop_core::{Symbol, SymbolKind};
            use payments::Store as PStore;
            use helpers::*;
            use std::io::{self, BufRead};
            fn run() {}
            "#,
        )
        .expect("parse failed");
        let binding = |local: &str| {
            parsed
                .imports
                .iter()
                .find(|i| i.local == local)
                .unwrap_or_else(|| panic!("import {} not found: {:?}", local, parsed.imports))
                .path
                .clone()
        };
        assert_eq!(binding("Symbol"), "deslop_core::Symbol");
        assert_eq!(binding("SymbolKind"), "deslop_core::SymbolKind");
        assert_eq!(binding("PStore"), "payments::Store");
        assert_eq!(binding("BufRead"), "std::io::BufRead");
        assert_eq!(binding("io"), "std::io");
        let glob = parsed
            .imports
            .iter()
            .find(|i| i.is_glob)
            .expect("glob import");
        assert_eq!(glob.path, "helpers");
    }

    #[test]
    fn turbofish_type_args_emit_reference_edges() {
        let (_symbols, edges) = parse(
            r#"
            struct McpRequest;
            fn handle(line: &str) {
                let req: McpRequest = serde_json::from_str::<McpRequest>(line).unwrap();
            }
            "#,
        );
        let refs: Vec<&str> = edges
            .iter()
            .filter(|e| e.kind == DependencyEdgeKind::ReferencesType)
            .map(|e| e.to_symbol.as_str())
            .collect();
        assert!(refs.contains(&"McpRequest"), "refs: {:?}", refs);
    }
}
