use base64::{
    Engine as _, alphabet,
    engine::{self, general_purpose},
};
use std::sync::OnceLock;
use std::{fmt, string};

use crate::jwe::JweToken;

#[derive(Debug, PartialEq, Eq)]
pub enum JweParseError {
    MissingParts(),
    TooManyParts(),
    InvalidBase64(base64::DecodeError),
    InvalidUtf8Error(string::FromUtf8Error),
}

impl fmt::Display for JweParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message = match self {
            JweParseError::MissingParts() => "Missing JWE section".to_string(),
            JweParseError::TooManyParts() => "Unespected section".to_string(),
            JweParseError::InvalidBase64(e) => format!("Base64 decoding failed: {}", e),
            JweParseError::InvalidUtf8Error(e) => format!("Invalid UTF-8 string: {}", e),
        };
        write!(f, "{}", message)
    }
}

impl From<base64::DecodeError> for JweParseError {
    fn from(e: base64::DecodeError) -> Self {
        JweParseError::InvalidBase64(e)
    }
}

impl From<string::FromUtf8Error> for JweParseError {
    fn from(e: string::FromUtf8Error) -> Self {
        JweParseError::InvalidUtf8Error(e)
    }
}

static BASE64_ENGINE: OnceLock<engine::GeneralPurpose> = OnceLock::new();

#[inline]
fn get_base64() -> &'static engine::GeneralPurpose {
    BASE64_ENGINE
        .get_or_init(|| engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD))
}

fn parse_base64_string(string_to_parse: &str) -> Result<String, JweParseError> {
    let bytes = get_base64().decode(string_to_parse)?;
    let string = String::from_utf8(bytes)?;
    Ok(string)
}

pub fn split_jwe(token: &str) -> Result<[&str; 5], JweParseError> {
    let parts = token
        .split(".")
        .collect::<Vec<&str>>()
        .try_into()
        .map_err(|vec: Vec<&str>| {
            if vec.len() < 5 {
                JweParseError::MissingParts()
            } else {
                JweParseError::TooManyParts()
            }
        });
    parts
}

pub fn parse_jwe(token: &str) -> Result<JweToken, JweParseError> {
    let [b64_header, b64_key, b64_iv, b64_cipher, b64_tag] = split_jwe(token)?;

    let decode = |s: &str| get_base64().decode(s);

    let aad = b64_header.as_bytes().to_vec();
    let header = parse_base64_string(b64_header)?;
    let key_encrypted = decode(b64_key)?;
    let iv = decode(b64_iv)?;
    let ciphertext = decode(b64_cipher)?;
    let tag = decode(b64_tag)?;

    Ok(JweToken::new(
        header,
        aad,
        key_encrypted,
        iv,
        ciphertext,
        tag,
    ))
}
