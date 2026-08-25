//! A serializable projection of a decoded [`ContractSpec`], for `extract`.
//!
//! The tool already decodes a build's full `contractspecv0` interface, but
//! until now the only thing a caller could do with it was compare two of them.
//! [`ExtractedSpec`] exposes that decoded interface directly, so a developer can
//! inspect what a WASM actually declares, and a pipeline can store a build's
//! interface as an artifact, without reaching for separate Stellar tooling.
//!
//! The `stellar_xdr` types are not `serde`-serializable in the feature set this
//! crate enables, so this module defines a plain projection of them rather than
//! leaking XDR internals into the output. That is also what makes the shape a
//! documented contract rather than an implementation detail.
//!
//! # Output shape
//!
//! ```json
//! {
//!   "spec_schema_version": 1,
//!   "tool_version": "0.1.0",
//!   "source": "./target/wasm32-unknown-unknown/release/contract.wasm",
//!   "interface_hash": "<64 hex chars>",
//!   "env_meta": {
//!     "interface_version": 90194313216,
//!     "protocol_version": 21,
//!     "pre_release_version": 0
//!   },
//!   "functions":   [ { "name": …, "doc": …, "inputs": [ … ], "outputs": [ … ] } ],
//!   "structs":     [ { "name": …, "doc": …, "lib": …, "fields": [ … ] } ],
//!   "enums":       [ { "name": …, "doc": …, "lib": …, "cases": [ … ] } ],
//!   "unions":      [ { "name": …, "doc": …, "lib": …, "cases": [ … ] } ],
//!   "error_enums": [ { "name": …, "doc": …, "lib": …, "cases": [ … ] } ]
//! }
//! ```
//!
//! Every collection is sorted by name, so two extractions of the same build are
//! byte-identical regardless of the order the XDR entries happened to be laid
//! out in. `env_meta` is `null` when the WASM carries no `contractenvmetav0`
//! section.
//!
//! Types are emitted structurally under a `kind` tag rather than as display
//! strings, so a consumer can distinguish a user-defined type named `u32` from
//! the primitive — see [`SpecType`].

use serde::{Deserialize, Serialize};
use stellar_xdr::curr::{
    ScSpecFunctionInputV0, ScSpecTypeDef, ScSpecUdtEnumCaseV0, ScSpecUdtErrorEnumCaseV0,
    ScSpecUdtStructFieldV0, ScSpecUdtUnionCaseV0,
};

use crate::interface_hash::InterfaceHash;
use crate::parser::{ContractEnvMeta, SorobanMetadata};
use crate::spec::ContractSpec;

/// Version of the `extract` output shape.
///
/// Bumped when a change would break a consumer that reads the current shape.
/// Adding a field is not such a change.
pub const SPEC_SCHEMA_VERSION: u32 = 1;

/// A contract's decoded interface, ready to serialize.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedSpec {
    pub spec_schema_version: u32,
    pub tool_version: String,
    /// Where the build came from: a file path or a contract ID.
    pub source: String,
    /// The build's interface hash, the same value the comparison report shows.
    pub interface_hash: String,
    /// Decoded `contractenvmetav0`, or `null` when the section is absent.
    pub env_meta: Option<EnvMetaJson>,
    pub functions: Vec<FunctionJson>,
    pub structs: Vec<StructJson>,
    pub enums: Vec<EnumJson>,
    pub unions: Vec<UnionJson>,
    pub error_enums: Vec<ErrorEnumJson>,
}

impl ExtractedSpec {
    /// Build the extraction result for one decoded build.
    pub fn new(source: impl Into<String>, metadata: &SorobanMetadata, spec: &ContractSpec) -> Self {
        // Sorting every collection by name is what makes two extractions of the
        // same build byte-identical: the spec maps have no inherent order.
        let mut functions: Vec<FunctionJson> = spec
            .functions
            .iter()
            .map(|(name, f)| FunctionJson {
                name: name.clone(),
                doc: f.doc.to_string(),
                inputs: f.inputs.iter().map(ParamJson::from).collect(),
                outputs: f.outputs.iter().map(SpecType::from).collect(),
            })
            .collect();
        functions.sort_by(|a, b| a.name.cmp(&b.name));

        let mut structs: Vec<StructJson> = spec
            .structs
            .iter()
            .map(|(name, s)| StructJson {
                name: name.clone(),
                doc: s.doc.to_string(),
                lib: s.lib.to_string(),
                fields: s.fields.iter().map(FieldJson::from).collect(),
            })
            .collect();
        structs.sort_by(|a, b| a.name.cmp(&b.name));

        let mut enums: Vec<EnumJson> = spec
            .enums
            .iter()
            .map(|(name, e)| EnumJson {
                name: name.clone(),
                doc: e.doc.to_string(),
                lib: e.lib.to_string(),
                cases: e.cases.iter().map(EnumCaseJson::from).collect(),
            })
            .collect();
        enums.sort_by(|a, b| a.name.cmp(&b.name));

        let mut unions: Vec<UnionJson> = spec
            .unions
            .iter()
            .map(|(name, u)| UnionJson {
                name: name.clone(),
                doc: u.doc.to_string(),
                lib: u.lib.to_string(),
                cases: u.cases.iter().map(UnionCaseJson::from).collect(),
            })
            .collect();
        unions.sort_by(|a, b| a.name.cmp(&b.name));

        let mut error_enums: Vec<ErrorEnumJson> = spec
            .error_enums
            .iter()
            .map(|(name, e)| ErrorEnumJson {
                name: name.clone(),
                doc: e.doc.to_string(),
                lib: e.lib.to_string(),
                cases: e.cases.iter().map(ErrorEnumCaseJson::from).collect(),
            })
            .collect();
        error_enums.sort_by(|a, b| a.name.cmp(&b.name));

        Self {
            spec_schema_version: SPEC_SCHEMA_VERSION,
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            source: source.into(),
            interface_hash: InterfaceHash::of_spec(spec).to_hex(),
            env_meta: metadata.env_meta.as_ref().map(EnvMetaJson::from),
            functions,
            structs,
            enums,
            unions,
            error_enums,
        }
    }
}

impl ExtractedSpec {
    /// Convert an [`ExtractedSpec`] back into a [`ContractSpec`] for diffing.
    pub fn to_contract_spec(&self) -> Result<ContractSpec, anyhow::Error> {
        let mut spec = ContractSpec::default();

        for s in &self.structs {
            let fields: Result<Vec<_>, anyhow::Error> = s
                .fields
                .iter()
                .map(|f| {
                    Ok(stellar_xdr::curr::ScSpecUdtStructFieldV0 {
                        doc: f
                            .doc
                            .as_str()
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("doc error"))?,
                        name: f
                            .name
                            .as_str()
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("name error"))?,
                        type_: (&f.type_).try_into()?,
                    })
                })
                .collect();
            let xdr_struct = stellar_xdr::curr::ScSpecUdtStructV0 {
                doc: s
                    .doc
                    .as_str()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("doc error"))?,
                lib: s
                    .lib
                    .as_str()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("lib error"))?,
                name: s
                    .name
                    .as_str()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("name error"))?,
                fields: fields?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Too many fields"))?,
            };
            spec.structs.insert(s.name.clone(), xdr_struct);
        }

        for e in &self.enums {
            let cases: Result<Vec<_>, anyhow::Error> = e
                .cases
                .iter()
                .map(|c| {
                    Ok(stellar_xdr::curr::ScSpecUdtEnumCaseV0 {
                        doc: c
                            .doc
                            .as_str()
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("doc error"))?,
                        name: c
                            .name
                            .as_str()
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("name error"))?,
                        value: c.value,
                    })
                })
                .collect();
            let xdr_enum = stellar_xdr::curr::ScSpecUdtEnumV0 {
                doc: e
                    .doc
                    .as_str()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("doc error"))?,
                lib: e
                    .lib
                    .as_str()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("lib error"))?,
                name: e
                    .name
                    .as_str()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("name error"))?,
                cases: cases?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Too many cases"))?,
            };
            spec.enums.insert(e.name.clone(), xdr_enum);
        }

        for u in &self.unions {
            let cases: Result<Vec<_>, anyhow::Error> = u
                .cases
                .iter()
                .map(|c| match c {
                    UnionCaseJson::Void { name, doc } => {
                        Ok(stellar_xdr::curr::ScSpecUdtUnionCaseV0::VoidV0(
                            stellar_xdr::curr::ScSpecUdtUnionCaseVoidV0 {
                                doc: doc
                                    .as_str()
                                    .try_into()
                                    .map_err(|_| anyhow::anyhow!("doc error"))?,
                                name: name
                                    .as_str()
                                    .try_into()
                                    .map_err(|_| anyhow::anyhow!("name error"))?,
                            },
                        ))
                    }
                    UnionCaseJson::Tuple { name, doc, types } => {
                        let parsed_types: Result<Vec<_>, anyhow::Error> =
                            types.iter().map(|t| t.try_into()).collect();
                        Ok(stellar_xdr::curr::ScSpecUdtUnionCaseV0::TupleV0(
                            stellar_xdr::curr::ScSpecUdtUnionCaseTupleV0 {
                                doc: doc
                                    .as_str()
                                    .try_into()
                                    .map_err(|_| anyhow::anyhow!("doc error"))?,
                                name: name
                                    .as_str()
                                    .try_into()
                                    .map_err(|_| anyhow::anyhow!("name error"))?,
                                type_: parsed_types?
                                    .try_into()
                                    .map_err(|_| anyhow::anyhow!("Too many types"))?,
                            },
                        ))
                    }
                })
                .collect();
            let xdr_union = stellar_xdr::curr::ScSpecUdtUnionV0 {
                doc: u
                    .doc
                    .as_str()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("doc error"))?,
                lib: u
                    .lib
                    .as_str()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("lib error"))?,
                name: u
                    .name
                    .as_str()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("name error"))?,
                cases: cases?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Too many cases"))?,
            };
            spec.unions.insert(u.name.clone(), xdr_union);
        }

        for err in &self.error_enums {
            let cases: Result<Vec<_>, anyhow::Error> = err
                .cases
                .iter()
                .map(|c| {
                    Ok(stellar_xdr::curr::ScSpecUdtErrorEnumCaseV0 {
                        doc: c
                            .doc
                            .as_str()
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("doc error"))?,
                        name: c
                            .name
                            .as_str()
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("name error"))?,
                        value: c.value,
                    })
                })
                .collect();
            let xdr_error = stellar_xdr::curr::ScSpecUdtErrorEnumV0 {
                doc: err
                    .doc
                    .as_str()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("doc error"))?,
                lib: err
                    .lib
                    .as_str()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("lib error"))?,
                name: err
                    .name
                    .as_str()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("name error"))?,
                cases: cases?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Too many cases"))?,
            };
            spec.error_enums.insert(err.name.clone(), xdr_error);
        }

        for func in &self.functions {
            let inputs: Result<Vec<_>, anyhow::Error> = func
                .inputs
                .iter()
                .map(|i| {
                    Ok(stellar_xdr::curr::ScSpecFunctionInputV0 {
                        doc: i
                            .doc
                            .as_str()
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("doc error"))?,
                        name: i
                            .name
                            .as_str()
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("name error"))?,
                        type_: (&i.type_).try_into()?,
                    })
                })
                .collect();
            let outputs: Result<Vec<_>, anyhow::Error> =
                func.outputs.iter().map(|o| o.try_into()).collect();
            let xdr_func = stellar_xdr::curr::ScSpecFunctionV0 {
                doc: func
                    .doc
                    .as_str()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("doc error"))?,
                name: func
                    .name
                    .as_str()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("name error"))?,
                inputs: inputs?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Too many inputs"))?,
                outputs: outputs?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Too many outputs"))?,
            };
            spec.functions.insert(func.name.clone(), xdr_func);
        }

        Ok(spec)
    }
}

/// Decoded `contractenvmetav0`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvMetaJson {
    /// The packed 64-bit interface version, when present.
    pub interface_version: Option<u64>,
    /// High 32 bits of the interface version.
    pub protocol_version: Option<u32>,
    /// Low 32 bits of the interface version.
    pub pre_release_version: Option<u32>,
}

impl From<&ContractEnvMeta> for EnvMetaJson {
    fn from(meta: &ContractEnvMeta) -> Self {
        Self {
            interface_version: meta.interface_version(),
            protocol_version: meta.protocol_version(),
            pre_release_version: meta.pre_release_version(),
        }
    }
}

/// A contract function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionJson {
    pub name: String,
    pub doc: String,
    /// Parameters in declaration order — Soroban invokes positionally.
    pub inputs: Vec<ParamJson>,
    pub outputs: Vec<SpecType>,
}

/// A function parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamJson {
    pub name: String,
    pub doc: String,
    #[serde(rename = "type")]
    pub type_: SpecType,
}

impl From<&ScSpecFunctionInputV0> for ParamJson {
    fn from(input: &ScSpecFunctionInputV0) -> Self {
        Self {
            name: input.name.to_string(),
            doc: input.doc.to_string(),
            type_: SpecType::from(&input.type_),
        }
    }
}

/// A user-defined struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructJson {
    pub name: String,
    pub doc: String,
    pub lib: String,
    /// Fields in declaration order — structs serialize positionally.
    pub fields: Vec<FieldJson>,
}

/// A struct field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldJson {
    pub name: String,
    pub doc: String,
    #[serde(rename = "type")]
    pub type_: SpecType,
}

impl From<&ScSpecUdtStructFieldV0> for FieldJson {
    fn from(field: &ScSpecUdtStructFieldV0) -> Self {
        Self {
            name: field.name.to_string(),
            doc: field.doc.to_string(),
            type_: SpecType::from(&field.type_),
        }
    }
}

/// A user-defined C-like enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumJson {
    pub name: String,
    pub doc: String,
    pub lib: String,
    pub cases: Vec<EnumCaseJson>,
}

/// An enum case and its explicit integer value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumCaseJson {
    pub name: String,
    pub doc: String,
    pub value: u32,
}

impl From<&ScSpecUdtEnumCaseV0> for EnumCaseJson {
    fn from(case: &ScSpecUdtEnumCaseV0) -> Self {
        Self {
            name: case.name.to_string(),
            doc: case.doc.to_string(),
            value: case.value,
        }
    }
}

/// A user-defined union (a tagged enum carrying data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnionJson {
    pub name: String,
    pub doc: String,
    pub lib: String,
    /// Cases in declaration order — unions serialize by positional discriminant.
    pub cases: Vec<UnionCaseJson>,
}

/// A union case: either payload-free, or carrying a tuple of types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UnionCaseJson {
    Void {
        name: String,
        doc: String,
    },
    Tuple {
        name: String,
        doc: String,
        types: Vec<SpecType>,
    },
}

impl From<&ScSpecUdtUnionCaseV0> for UnionCaseJson {
    fn from(case: &ScSpecUdtUnionCaseV0) -> Self {
        match case {
            ScSpecUdtUnionCaseV0::VoidV0(v) => UnionCaseJson::Void {
                name: v.name.to_string(),
                doc: v.doc.to_string(),
            },
            ScSpecUdtUnionCaseV0::TupleV0(t) => UnionCaseJson::Tuple {
                name: t.name.to_string(),
                doc: t.doc.to_string(),
                types: t.type_.iter().map(SpecType::from).collect(),
            },
        }
    }
}

/// A user-defined error enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorEnumJson {
    pub name: String,
    pub doc: String,
    pub lib: String,
    pub cases: Vec<ErrorEnumCaseJson>,
}

/// An error enum case and its error code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorEnumCaseJson {
    pub name: String,
    pub doc: String,
    pub value: u32,
}

impl From<&ScSpecUdtErrorEnumCaseV0> for ErrorEnumCaseJson {
    fn from(case: &ScSpecUdtErrorEnumCaseV0) -> Self {
        Self {
            name: case.name.to_string(),
            doc: case.doc.to_string(),
            value: case.value,
        }
    }
}

/// A type, encoded structurally under a `kind` tag.
///
/// Emitted this way rather than as a display string because display strings are
/// ambiguous: a user-defined type named `u32` renders identically to the
/// primitive `u32`. Consumers that only want something readable can use the
/// `display` field the CLI is happy to reconstruct via
/// [`crate::mapper::type_to_string`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpecType {
    Val,
    Bool,
    Void,
    Error,
    U32,
    I32,
    U64,
    I64,
    Timepoint,
    Duration,
    U128,
    I128,
    U256,
    I256,
    Bytes,
    String,
    Symbol,
    Address,
    Option {
        value: Box<SpecType>,
    },
    Result {
        ok: Box<SpecType>,
        error: Box<SpecType>,
    },
    Vec {
        element: Box<SpecType>,
    },
    Map {
        key: Box<SpecType>,
        value: Box<SpecType>,
    },
    Tuple {
        values: Vec<SpecType>,
    },
    BytesN {
        n: u32,
    },
    Udt {
        name: String,
    },
}

impl From<&ScSpecTypeDef> for SpecType {
    fn from(type_def: &ScSpecTypeDef) -> Self {
        match type_def {
            ScSpecTypeDef::Val => SpecType::Val,
            ScSpecTypeDef::Bool => SpecType::Bool,
            ScSpecTypeDef::Void => SpecType::Void,
            ScSpecTypeDef::Error => SpecType::Error,
            ScSpecTypeDef::U32 => SpecType::U32,
            ScSpecTypeDef::I32 => SpecType::I32,
            ScSpecTypeDef::U64 => SpecType::U64,
            ScSpecTypeDef::I64 => SpecType::I64,
            ScSpecTypeDef::Timepoint => SpecType::Timepoint,
            ScSpecTypeDef::Duration => SpecType::Duration,
            ScSpecTypeDef::U128 => SpecType::U128,
            ScSpecTypeDef::I128 => SpecType::I128,
            ScSpecTypeDef::U256 => SpecType::U256,
            ScSpecTypeDef::I256 => SpecType::I256,
            ScSpecTypeDef::Bytes => SpecType::Bytes,
            ScSpecTypeDef::String => SpecType::String,
            ScSpecTypeDef::Symbol => SpecType::Symbol,
            ScSpecTypeDef::Address => SpecType::Address,
            ScSpecTypeDef::Option(inner) => SpecType::Option {
                value: Box::new(SpecType::from(&*inner.value_type)),
            },
            ScSpecTypeDef::Result(inner) => SpecType::Result {
                ok: Box::new(SpecType::from(&*inner.ok_type)),
                error: Box::new(SpecType::from(&*inner.error_type)),
            },
            ScSpecTypeDef::Vec(inner) => SpecType::Vec {
                element: Box::new(SpecType::from(&*inner.element_type)),
            },
            ScSpecTypeDef::Map(inner) => SpecType::Map {
                key: Box::new(SpecType::from(&*inner.key_type)),
                value: Box::new(SpecType::from(&*inner.value_type)),
            },
            ScSpecTypeDef::Tuple(inner) => SpecType::Tuple {
                values: inner.value_types.iter().map(SpecType::from).collect(),
            },
            ScSpecTypeDef::BytesN(inner) => SpecType::BytesN { n: inner.n },
            ScSpecTypeDef::Udt(inner) => SpecType::Udt {
                name: inner.name.to_string(),
            },
        }
    }
}

impl TryFrom<&SpecType> for ScSpecTypeDef {
    type Error = anyhow::Error;

    fn try_from(type_def: &SpecType) -> Result<Self, anyhow::Error> {
        match type_def {
            SpecType::Val => Ok(ScSpecTypeDef::Val),
            SpecType::Bool => Ok(ScSpecTypeDef::Bool),
            SpecType::Void => Ok(ScSpecTypeDef::Void),
            SpecType::Error => Ok(ScSpecTypeDef::Error),
            SpecType::U32 => Ok(ScSpecTypeDef::U32),
            SpecType::I32 => Ok(ScSpecTypeDef::I32),
            SpecType::U64 => Ok(ScSpecTypeDef::U64),
            SpecType::I64 => Ok(ScSpecTypeDef::I64),
            SpecType::Timepoint => Ok(ScSpecTypeDef::Timepoint),
            SpecType::Duration => Ok(ScSpecTypeDef::Duration),
            SpecType::U128 => Ok(ScSpecTypeDef::U128),
            SpecType::I128 => Ok(ScSpecTypeDef::I128),
            SpecType::U256 => Ok(ScSpecTypeDef::U256),
            SpecType::I256 => Ok(ScSpecTypeDef::I256),
            SpecType::Bytes => Ok(ScSpecTypeDef::Bytes),
            SpecType::String => Ok(ScSpecTypeDef::String),
            SpecType::Symbol => Ok(ScSpecTypeDef::Symbol),
            SpecType::Address => Ok(ScSpecTypeDef::Address),
            SpecType::Option { value } => Ok(ScSpecTypeDef::Option(Box::new(
                stellar_xdr::curr::ScSpecTypeOption {
                    value_type: Box::new(ScSpecTypeDef::try_from(value.as_ref())?),
                },
            ))),
            SpecType::Result { ok, error } => Ok(ScSpecTypeDef::Result(Box::new(
                stellar_xdr::curr::ScSpecTypeResult {
                    ok_type: Box::new(ScSpecTypeDef::try_from(ok.as_ref())?),
                    error_type: Box::new(ScSpecTypeDef::try_from(error.as_ref())?),
                },
            ))),
            SpecType::Vec { element } => Ok(ScSpecTypeDef::Vec(Box::new(
                stellar_xdr::curr::ScSpecTypeVec {
                    element_type: Box::new(ScSpecTypeDef::try_from(element.as_ref())?),
                },
            ))),
            SpecType::Map { key, value } => Ok(ScSpecTypeDef::Map(Box::new(
                stellar_xdr::curr::ScSpecTypeMap {
                    key_type: Box::new(ScSpecTypeDef::try_from(key.as_ref())?),
                    value_type: Box::new(ScSpecTypeDef::try_from(value.as_ref())?),
                },
            ))),
            SpecType::Tuple { values } => {
                let parsed_types: Result<Vec<_>, _> =
                    values.iter().map(ScSpecTypeDef::try_from).collect();
                Ok(ScSpecTypeDef::Tuple(Box::new(
                    stellar_xdr::curr::ScSpecTypeTuple {
                        value_types: parsed_types?
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("Tuple too large"))?,
                    },
                )))
            }
            SpecType::BytesN { n } => {
                Ok(ScSpecTypeDef::BytesN(stellar_xdr::curr::ScSpecTypeBytesN {
                    n: *n,
                }))
            }
            SpecType::Udt { name } => Ok(ScSpecTypeDef::Udt(stellar_xdr::curr::ScSpecTypeUdt {
                name: name.as_str().try_into()?,
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        ScSpecEntry, ScSpecFunctionV0, ScSpecTypeOption, ScSpecTypeUdt, ScSpecUdtStructV0, StringM,
        VecM,
    };

    fn metadata() -> SorobanMetadata {
        SorobanMetadata::default()
    }

    fn extracted(entries: &[ScSpecEntry]) -> ExtractedSpec {
        let spec = ContractSpec::from_entries(entries);
        ExtractedSpec::new("test", &metadata(), &spec)
    }

    #[test]
    fn output_is_sorted_by_name_regardless_of_entry_order() {
        let make = |name: &str| {
            ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
                doc: StringM::default(),
                name: name.try_into().unwrap(),
                inputs: VecM::default(),
                outputs: VecM::default(),
            })
        };

        let forward = extracted(&[make("zeta"), make("alpha"), make("mid")]);
        let reversed = extracted(&[make("mid"), make("alpha"), make("zeta")]);

        let names: Vec<&str> = forward.functions.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "mid", "zeta"]);

        assert_eq!(
            serde_json::to_string(&forward).unwrap(),
            serde_json::to_string(&reversed).unwrap(),
            "extraction must be byte-identical regardless of entry order"
        );
    }

    #[test]
    fn carries_the_interface_hash() {
        let spec = ContractSpec::from_entries(&[]);
        let extracted = ExtractedSpec::new("test", &metadata(), &spec);
        assert_eq!(extracted.interface_hash, spec.interface_hash().to_hex());
        assert_eq!(extracted.interface_hash.len(), 64);
    }

    #[test]
    fn types_are_tagged_structurally() {
        let json = serde_json::to_value(SpecType::from(&ScSpecTypeDef::U32)).unwrap();
        assert_eq!(json, serde_json::json!({ "kind": "u32" }));

        let nested = ScSpecTypeDef::Option(Box::new(ScSpecTypeOption {
            value_type: Box::new(ScSpecTypeDef::Address),
        }));
        assert_eq!(
            serde_json::to_value(SpecType::from(&nested)).unwrap(),
            serde_json::json!({ "kind": "option", "value": { "kind": "address" } })
        );
    }

    #[test]
    fn a_udt_named_like_a_primitive_is_distinguishable() {
        let udt = ScSpecTypeDef::Udt(ScSpecTypeUdt {
            name: "u32".try_into().unwrap(),
        });
        assert_eq!(
            serde_json::to_value(SpecType::from(&udt)).unwrap(),
            serde_json::json!({ "kind": "udt", "name": "u32" })
        );
        assert_ne!(
            serde_json::to_value(SpecType::from(&udt)).unwrap(),
            serde_json::to_value(SpecType::from(&ScSpecTypeDef::U32)).unwrap()
        );
    }

    #[test]
    fn the_shape_round_trips() {
        let entry = ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
            doc: "A record.".try_into().unwrap(),
            lib: StringM::default(),
            name: "Data".try_into().unwrap(),
            fields: VecM::default(),
        });
        let original = extracted(&[entry]);

        let json = serde_json::to_string(&original).unwrap();
        let restored: ExtractedSpec = serde_json::from_str(&json).unwrap();

        assert_eq!(serde_json::to_string(&restored).unwrap(), json);
        assert_eq!(restored.structs[0].name, "Data");
        assert_eq!(restored.structs[0].doc, "A record.");
    }

    #[test]
    fn env_meta_is_null_when_absent() {
        let value = serde_json::to_value(extracted(&[])).unwrap();
        assert_eq!(value["env_meta"], serde_json::Value::Null);
        assert_eq!(value["spec_schema_version"], SPEC_SCHEMA_VERSION);
    }
}
