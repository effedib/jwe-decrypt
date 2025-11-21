use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct JweHeader {
    pub alg: String,
    pub enc: String,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
    /*
    // --- Optional Fields ---
    /// (Compression Algorithm): standard value: "DEF" (DEFLATE)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip: Option<String>,
    /// (JWK Set URL) URL which points to a JWK key set
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,
    /// (JSON Web Key) public key which is addressed by the JWE
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Value>,
    /// (Key ID): A key identifier to help the receiver to select
    /// the correct key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// (X.509 URL): URL which points to a X.509 Certificate Chain
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
    /// (X.509 Certificate Chain): the X.509 Certificate Chain ifself
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    /// (X.509 Certificate SHA-1 Thumbprint): thumbprint SHA-1
    /// (Base64URL-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    /// (X.509 Certificate SHA-256 Thumbprint): thumbprint SHA-256
    /// (Base64URL-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5t#S256")]
    pub x5t_s256: Option<String>,
    /// (Type)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// (Content Type)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,
    /// (Critical): An array of header names that must be
    /// understood and processed by the receiver.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,

    /// (Agreement PartyUInfo) Information about the
    /// U part for algorithms based on ECDH-ES
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apu: Option<String>,
    /// (Agreement PartyVInfo) Information on Part V
    /// for ECDH-ES-based algorithms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apv: Option<String>,
    /// (PBES2 Salt Input)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p2s: Option<String>,
    /// (PBES2 Count)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p2c: Option<String>,
    */
}
