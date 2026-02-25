//! Fuzz target for detector engine (#101).
//! Feeds arbitrary bytes into detector analysis to find panics/crashes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;

use aikido_core::ast_walker::{
    ConstructorInfo, DataTypeInfo, FieldInfo, HandlerInfo, ModuleInfo, ModuleKind, ParamInfo,
    ValidatorInfo,
};
use aikido_core::body_analysis::{BodySignals, WhenBranchInfo};
use aikido_core::detector::run_detectors;

/// Build a ModuleInfo from fuzz bytes in a structured way.
fn module_from_bytes(data: &[u8]) -> Option<Vec<ModuleInfo>> {
    if data.len() < 10 {
        return None;
    }

    let num_modules = (data[0] % 3) as usize + 1;
    let num_validators = (data[1] % 3) as usize;
    let num_handlers = (data[2] % 4) as usize + 1;
    let uses_own_ref = data[3] % 2 == 0;
    let has_division = data[4] % 2 == 0;
    let kind = if data[5] % 2 == 0 {
        ModuleKind::Validator
    } else {
        ModuleKind::Lib
    };

    let handler_name = match data[6] % 4 {
        0 => "spend",
        1 => "mint",
        2 => "withdraw",
        _ => "else",
    };

    let mut tx_accesses = HashSet::new();
    if data[7] & 1 != 0 {
        tx_accesses.insert("outputs".to_string());
    }
    if data[7] & 2 != 0 {
        tx_accesses.insert("inputs".to_string());
    }
    if data[7] & 4 != 0 {
        tx_accesses.insert("extra_signatories".to_string());
    }
    if data[7] & 8 != 0 {
        tx_accesses.insert("validity_range".to_string());
    }
    if data[7] & 16 != 0 {
        tx_accesses.insert("reference_inputs".to_string());
    }
    if data[7] & 32 != 0 {
        tx_accesses.insert("mint".to_string());
    }

    let mut function_calls = HashSet::new();
    if data[8] & 1 != 0 {
        function_calls.insert("list.has".to_string());
    }
    if data[8] & 2 != 0 {
        function_calls.insert("list.any".to_string());
    }
    if data[8] & 4 != 0 {
        function_calls.insert("interval.is_entirely_before".to_string());
    }

    let datum_type = if data[9] % 3 == 0 {
        "Option<MyDatum>".to_string()
    } else if data[9] % 3 == 1 {
        "MyDatum".to_string()
    } else {
        "Data".to_string()
    };

    let when_branches = if data.len() > 10 {
        let n = (data[10] % 4) as usize;
        (0..n)
            .map(|i| {
                let byte = data.get(11 + i).copied().unwrap_or(0);
                WhenBranchInfo {
                    pattern_text: format!("Branch{i}"),
                    is_catchall: byte & 1 != 0,
                    body_is_literal_true: byte & 2 != 0,
                    body_is_error: byte & 4 != 0,
                }
            })
            .collect()
    } else {
        vec![]
    };

    let bytearray_lengths: Vec<usize> = data
        .get(15..20)
        .unwrap_or(&[])
        .iter()
        .map(|&b| b as usize)
        .collect();

    let modules = (0..num_modules)
        .map(|mi| {
            let validators = (0..num_validators)
                .map(|vi| {
                    let handlers = (0..num_handlers)
                        .map(|_| HandlerInfo {
                            name: handler_name.to_string(),
                            params: vec![
                                ParamInfo {
                                    name: "datum".to_string(),
                                    type_name: datum_type.clone(),
                                },
                                ParamInfo {
                                    name: "redeemer".to_string(),
                                    type_name: "MyRedeemer".to_string(),
                                },
                                ParamInfo {
                                    name: "own_ref".to_string(),
                                    type_name: "OutputReference".to_string(),
                                },
                                ParamInfo {
                                    name: "tx".to_string(),
                                    type_name: "Transaction".to_string(),
                                },
                            ],
                            return_type: "Bool".to_string(),
                            body_signals: BodySignals {
                                tx_field_accesses: tx_accesses.clone(),
                                uses_own_ref,
                                function_calls: function_calls.clone(),
                                var_references: HashSet::new(),
                                when_branches: when_branches.clone(),
                                has_division,
                                bytearray_literal_lengths: bytearray_lengths.clone(),
                                ..BodySignals::default()
                            },
                            location: Some((0, 100)),
                        })
                        .collect();

                    ValidatorInfo {
                        name: format!("v{vi}"),
                        params: vec![],
                        handlers,
                        summary: None,
                    }
                })
                .collect();

            ModuleInfo {
                name: format!("test/mod{mi}"),
                path: format!("validators/mod{mi}.ak"),
                kind: kind.clone(),
                validators,
                data_types: vec![DataTypeInfo {
                    name: "MyDatum".to_string(),
                    public: true,
                    constructors: vec![ConstructorInfo {
                        name: "MyDatum".to_string(),
                        fields: vec![FieldInfo {
                            label: Some("owner".to_string()),
                            type_name: "ByteArray".to_string(),
                        }],
                    }],
                }],
                functions: vec![],
                constants: vec![],
                type_aliases: vec![],
                test_count: 0,
                source_code: None,
                test_function_names: vec![],
            }
        })
        .collect();

    Some(modules)
}

fuzz_target!(|data: &[u8]| {
    if let Some(modules) = module_from_bytes(data) {
        let _ = run_detectors(&modules);
    }
});
