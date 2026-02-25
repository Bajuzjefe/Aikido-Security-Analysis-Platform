//! Aiken stdlib function semantics model (Phase 4).
//!
//! Models the behavior of key stdlib functions so detectors can reason
//! about what a function call actually does rather than just its name.

use std::collections::HashMap;

/// Semantic information about a stdlib function.
#[derive(Debug, Clone)]
pub struct FunctionSemantics {
    /// Full function name (e.g., "assets.quantity_of").
    pub name: String,
    /// What this function does.
    pub behavior: FunctionBehavior,
    /// Whether this function is safe for multi-asset comparison.
    pub safe_for_multi_asset: bool,
    /// Whether this function validates all assets or just one.
    pub validates_all_assets: bool,
    /// Whether this is an existence check (vs. value retrieval).
    pub is_existence_check: bool,
}

/// What a stdlib function does semantically.
#[derive(Debug, Clone, PartialEq)]
pub enum FunctionBehavior {
    /// Extracts a single value from a collection (e.g., quantity_of).
    SingleExtraction,
    /// Checks all items in a collection (e.g., assets.match).
    CollectionCheck,
    /// Checks for key existence (e.g., dict.has_key).
    ExistenceCheck,
    /// Retrieves a value by key (e.g., dict.get).
    ValueRetrieval,
    /// Iterates over all items (e.g., list.map, list.foldl).
    FullIteration,
    /// Checks a single condition (e.g., list.has).
    SingleCheck,
    /// Counts items (e.g., list.length).
    Counting,
    /// Input lookup by reference (e.g., transaction.find_input).
    InputLookup,
    /// Other behavior.
    Other,
}

/// Build the stdlib semantics model.
pub fn build_stdlib_model() -> HashMap<String, FunctionSemantics> {
    let mut model = HashMap::new();

    // Value operations
    model.insert(
        "assets.quantity_of".to_string(),
        FunctionSemantics {
            name: "assets.quantity_of".to_string(),
            behavior: FunctionBehavior::SingleExtraction,
            safe_for_multi_asset: false,
            validates_all_assets: false,
            is_existence_check: false,
        },
    );
    model.insert(
        "assets.match".to_string(),
        FunctionSemantics {
            name: "assets.match".to_string(),
            behavior: FunctionBehavior::CollectionCheck,
            safe_for_multi_asset: true, // when used with ==
            validates_all_assets: true,
            is_existence_check: false,
        },
    );
    model.insert(
        "value.lovelace_of".to_string(),
        FunctionSemantics {
            name: "value.lovelace_of".to_string(),
            behavior: FunctionBehavior::SingleExtraction,
            safe_for_multi_asset: false,
            validates_all_assets: false,
            is_existence_check: false,
        },
    );
    model.insert(
        "assets.tokens".to_string(),
        FunctionSemantics {
            name: "assets.tokens".to_string(),
            behavior: FunctionBehavior::FullIteration,
            safe_for_multi_asset: true,
            validates_all_assets: true,
            is_existence_check: false,
        },
    );
    model.insert(
        "assets.policies".to_string(),
        FunctionSemantics {
            name: "assets.policies".to_string(),
            behavior: FunctionBehavior::FullIteration,
            safe_for_multi_asset: true,
            validates_all_assets: true,
            is_existence_check: false,
        },
    );
    model.insert(
        "value.to_pairs".to_string(),
        FunctionSemantics {
            name: "value.to_pairs".to_string(),
            behavior: FunctionBehavior::FullIteration,
            safe_for_multi_asset: true,
            validates_all_assets: true,
            is_existence_check: false,
        },
    );
    model.insert(
        "value.flatten_with".to_string(),
        FunctionSemantics {
            name: "value.flatten_with".to_string(),
            behavior: FunctionBehavior::FullIteration,
            safe_for_multi_asset: true,
            validates_all_assets: true,
            is_existence_check: false,
        },
    );

    // Dict/Map operations
    model.insert(
        "dict.has_key".to_string(),
        FunctionSemantics {
            name: "dict.has_key".to_string(),
            behavior: FunctionBehavior::ExistenceCheck,
            safe_for_multi_asset: false,
            validates_all_assets: false,
            is_existence_check: true,
        },
    );
    model.insert(
        "dict.get".to_string(),
        FunctionSemantics {
            name: "dict.get".to_string(),
            behavior: FunctionBehavior::ValueRetrieval,
            safe_for_multi_asset: false,
            validates_all_assets: false,
            is_existence_check: false,
        },
    );
    model.insert(
        "pairs.has_key".to_string(),
        FunctionSemantics {
            name: "pairs.has_key".to_string(),
            behavior: FunctionBehavior::ExistenceCheck,
            safe_for_multi_asset: false,
            validates_all_assets: false,
            is_existence_check: true,
        },
    );
    model.insert(
        "pairs.get_first".to_string(),
        FunctionSemantics {
            name: "pairs.get_first".to_string(),
            behavior: FunctionBehavior::ValueRetrieval,
            safe_for_multi_asset: false,
            validates_all_assets: false,
            is_existence_check: false,
        },
    );

    // List operations
    model.insert(
        "list.has".to_string(),
        FunctionSemantics {
            name: "list.has".to_string(),
            behavior: FunctionBehavior::SingleCheck,
            safe_for_multi_asset: false,
            validates_all_assets: false,
            is_existence_check: true,
        },
    );
    model.insert(
        "list.any".to_string(),
        FunctionSemantics {
            name: "list.any".to_string(),
            behavior: FunctionBehavior::SingleCheck,
            safe_for_multi_asset: false,
            validates_all_assets: false,
            is_existence_check: true,
        },
    );
    model.insert(
        "list.length".to_string(),
        FunctionSemantics {
            name: "list.length".to_string(),
            behavior: FunctionBehavior::Counting,
            safe_for_multi_asset: false,
            validates_all_assets: false,
            is_existence_check: false,
        },
    );
    model.insert(
        "list.filter".to_string(),
        FunctionSemantics {
            name: "list.filter".to_string(),
            behavior: FunctionBehavior::FullIteration,
            safe_for_multi_asset: false,
            validates_all_assets: false,
            is_existence_check: false,
        },
    );
    model.insert(
        "list.foldl".to_string(),
        FunctionSemantics {
            name: "list.foldl".to_string(),
            behavior: FunctionBehavior::FullIteration,
            safe_for_multi_asset: false,
            validates_all_assets: false,
            is_existence_check: false,
        },
    );

    // Transaction operations
    model.insert(
        "transaction.find_input".to_string(),
        FunctionSemantics {
            name: "transaction.find_input".to_string(),
            behavior: FunctionBehavior::InputLookup,
            safe_for_multi_asset: false,
            validates_all_assets: false,
            is_existence_check: false,
        },
    );

    model
}

/// Check if a set of function calls includes safe multi-asset handling.
pub fn has_safe_multi_asset_handling(function_calls: &std::collections::HashSet<String>) -> bool {
    let model = build_stdlib_model();
    function_calls.iter().any(|call| {
        model
            .get(call)
            .or_else(|| {
                // Try partial match for qualified calls like "value.lovelace_of"
                model
                    .iter()
                    .find(|(k, _)| call.contains(k.as_str()))
                    .map(|(_, v)| v)
            })
            .is_some_and(|sem| sem.validates_all_assets)
    })
}

/// Check if function calls only use existence checks (no value retrieval).
pub fn only_uses_existence_checks(function_calls: &std::collections::HashSet<String>) -> bool {
    let model = build_stdlib_model();
    function_calls.iter().all(|call| {
        model
            .get(call)
            .or_else(|| {
                model
                    .iter()
                    .find(|(k, _)| call.contains(k.as_str()))
                    .map(|(_, v)| v)
            })
            .is_none_or(|sem| sem.is_existence_check || sem.behavior == FunctionBehavior::Other)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_model() {
        let model = build_stdlib_model();
        assert!(model.contains_key("assets.quantity_of"));
        assert!(model.contains_key("dict.has_key"));
        assert!(model.contains_key("list.has"));
    }

    #[test]
    fn test_safe_multi_asset() {
        let mut calls = std::collections::HashSet::new();
        calls.insert("assets.match".to_string());
        assert!(has_safe_multi_asset_handling(&calls));
    }

    #[test]
    fn test_unsafe_single_extraction() {
        let mut calls = std::collections::HashSet::new();
        calls.insert("assets.quantity_of".to_string());
        assert!(!has_safe_multi_asset_handling(&calls));
    }

    #[test]
    fn test_existence_checks_only() {
        let mut calls = std::collections::HashSet::new();
        calls.insert("dict.has_key".to_string());
        assert!(only_uses_existence_checks(&calls));
    }
}
