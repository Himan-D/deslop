use deslop_core::{DependencyEdgeKind, Language, SymbolKind, Visibility};
use deslop_parser::{FileParser, UniversalParser};
use std::path::Path;

#[test]
fn typescript_arrow_function_exports_visibility_and_calls() {
    let parser = UniversalParser::new(Language::TypeScript);
    let src = r#"
export const addDays = (date: Date, amount: number): Date => { return date; };
const helper = (x: number) => x + 1;
"#;
    let parsed = parser.parse(Path::new("dates.ts"), src);

    let add_days = parsed
        .symbols
        .iter()
        .find(|s| s.name == "addDays")
        .expect("addDays symbol should be extracted");
    assert_eq!(add_days.kind, SymbolKind::Function);
    assert_eq!(add_days.visibility, Visibility::Public);

    let helper = parsed
        .symbols
        .iter()
        .find(|s| s.name == "helper")
        .expect("helper symbol should be extracted");
    assert_eq!(helper.kind, SymbolKind::Function);
    assert_eq!(helper.visibility, Visibility::Private);

    let src_with_call = r#"
export const addDays = (date: Date, amount: number): Date => {
    helper(amount);
    return date;
};
const helper = (x: number) => x + 1;
"#;
    let parsed_with_call = parser.parse(Path::new("dates.ts"), src_with_call);
    assert!(
        parsed_with_call.edges.iter().any(|e| {
            e.kind == DependencyEdgeKind::Calls
                && e.from_symbol.ends_with("addDays")
                && e.to_symbol == "helper"
        }),
        "expected Calls edge from addDays to helper, got: {:?}",
        parsed_with_call.edges
    );
}

#[test]
fn typescript_tsx_types_enums_and_es_imports() {
    let parser = UniversalParser::new(Language::TypeScript);
    let src = r#"
import { format as fmt, parse } from './date';
import * as utils from './utils';
import React from 'react';

export interface Props { id: string }
export type UserId = string;
export enum Role { Admin, User }
export const Card = ({ id }: Props) => <div>{id}</div>;
"#;
    let parsed = parser.parse(Path::new("card.tsx"), src);

    let props = parsed
        .symbols
        .iter()
        .find(|s| s.name == "Props")
        .expect("Props interface should be extracted");
    assert_eq!(props.kind, SymbolKind::Interface);
    assert_eq!(props.visibility, Visibility::Public);

    let user_id = parsed
        .symbols
        .iter()
        .find(|s| s.name == "UserId")
        .expect("UserId type alias should be extracted");
    assert_eq!(user_id.kind, SymbolKind::TypeAlias);
    assert_eq!(user_id.visibility, Visibility::Public);

    let role = parsed
        .symbols
        .iter()
        .find(|s| s.name == "Role")
        .expect("Role enum should be extracted");
    assert_eq!(role.kind, SymbolKind::Enum);
    assert_eq!(role.visibility, Visibility::Public);

    let card = parsed
        .symbols
        .iter()
        .find(|s| s.name == "Card")
        .expect("Card TSX arrow component should be extracted");
    assert_eq!(card.kind, SymbolKind::Function);
    assert_eq!(card.visibility, Visibility::Public);

    let fmt = parsed
        .imports
        .iter()
        .find(|i| i.local == "fmt")
        .expect("fmt import should be extracted");
    assert!(!fmt.is_glob);

    assert!(
        parsed.imports.iter().any(|i| i.local == "parse" && !i.is_glob),
        "parse import should be extracted: {:?}",
        parsed.imports
    );

    let utils = parsed
        .imports
        .iter()
        .find(|i| i.local == "utils")
        .expect("utils namespace import should be extracted");
    assert!(utils.is_glob);

    assert!(
        parsed.imports.iter().any(|i| i.local == "React" && !i.is_glob),
        "React default import should be extracted: {:?}",
        parsed.imports
    );
}

#[test]
fn python_decorated_definitions_and_imports() {
    let parser = UniversalParser::new(Language::Python);
    let src = "from pkg.sub import alpha, beta as b\nimport os\n\n@dataclass\nclass User:\n    def greet(self): pass\n";
    let parsed = parser.parse(Path::new("user.py"), src);

    let user = parsed
        .symbols
        .iter()
        .find(|s| s.name == "User")
        .expect("User class should be extracted");
    assert_eq!(user.kind, SymbolKind::Class);
    assert!(
        user.attributes.iter().any(|a| a.contains("dataclass")),
        "User should have dataclass in attributes, got: {:?}",
        user.attributes
    );

    let greet = parsed
        .symbols
        .iter()
        .find(|s| s.name == "User::greet")
        .expect("User::greet method should be extracted");
    assert_eq!(greet.kind, SymbolKind::Method);

    for local in ["alpha", "b", "os"] {
        assert!(
            parsed.imports.iter().any(|i| i.local == local),
            "expected Python import `{local}`, got: {:?}",
            parsed.imports
        );
    }
}

#[test]
fn go_structs_interfaces_methods_and_imports() {
    let parser = UniversalParser::new(Language::Go);
    let src = r#"
package main

import (
    "fmt"
    alias "net/http"
)

type Store struct {}
type Reader interface { Read() }
func (s *Store) Get(id string) string { return fmt.Sprint(id) }
"#;
    let parsed = parser.parse(Path::new("store.go"), src);

    let store = parsed
        .symbols
        .iter()
        .find(|s| s.name == "Store")
        .expect("Store struct should be extracted");
    assert_eq!(store.kind, SymbolKind::Struct);

    let reader = parsed
        .symbols
        .iter()
        .find(|s| s.name == "Reader")
        .expect("Reader interface should be extracted");
    assert_eq!(reader.kind, SymbolKind::Interface);

    let get = parsed
        .symbols
        .iter()
        .find(|s| s.name == "Store::Get")
        .expect("Store::Get method should be extracted");
    assert_eq!(get.kind, SymbolKind::Method);

    for local in ["fmt", "alias"] {
        assert!(
            parsed.imports.iter().any(|i| i.local == local),
            "expected Go import `{local}`, got: {:?}",
            parsed.imports
        );
    }

    assert!(
        parsed.edges.iter().any(|e| {
            e.kind == DependencyEdgeKind::Calls
                && e.from_symbol.ends_with("Store::Get")
                && e.to_symbol == "fmt::Sprint"
        }),
        "expected Calls edge from Store::Get to fmt::Sprint, got: {:?}",
        parsed.edges
    );
}

#[test]
fn typescript_this_method_call_emits_self_qualifier() {
    let parser = UniversalParser::new(Language::TypeScript);
    let src = r#"
class Service {
    run() {
        this.helper();
    }
    helper() {}
}
"#;
    let parsed = parser.parse(Path::new("service.ts"), src);
    assert!(
        parsed.edges.iter().any(|e| {
            e.kind == DependencyEdgeKind::Calls
                && e.from_symbol.ends_with("Service::run")
                && e.to_symbol == "Self::helper"
        }),
        "expected Calls edge from Service::run to Self::helper, got: {:?}",
        parsed.edges
    );
}

#[test]
fn python_self_method_call_emits_self_qualifier() {
    let parser = UniversalParser::new(Language::Python);
    let src = r#"
class Service:
    def run(self):
        self.helper()

    def helper(self):
        pass
"#;
    let parsed = parser.parse(Path::new("service.py"), src);
    assert!(
        parsed.edges.iter().any(|e| {
            e.kind == DependencyEdgeKind::Calls
                && e.from_symbol.ends_with("Service::run")
                && e.to_symbol == "Self::helper"
        }),
        "expected Calls edge from Service::run to Self::helper, got: {:?}",
        parsed.edges
    );
}
