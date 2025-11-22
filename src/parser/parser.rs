use base64::{
    Engine as _, alphabet,
    engine::{self, general_purpose},
};
use std::sync::OnceLock;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum Base64Error {
    #[error("Base64 decoding failed")]
    DecodeBase64(#[from] base64::DecodeError),
    #[error("Invalid UTF-8 string")]
    DecodeString(#[from] std::string::FromUtf8Error),
}

#[derive(Debug, PartialEq, Eq)]
pub enum JweParseError {
    MissingParts,
    TooManyParts,
}

static BASE64_ENGINE: OnceLock<engine::GeneralPurpose> = OnceLock::new();

#[inline]
pub fn get_base64() -> &'static engine::GeneralPurpose {
    BASE64_ENGINE
        .get_or_init(|| engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD))
}

pub fn parse_base64_string(string_to_parse: &str) -> Result<String, Base64Error> {
    let bytes = get_base64().decode(string_to_parse)?;
    let string = String::from_utf8(bytes)?;
    Ok(string)
}

pub fn parse_jwe_input_string(token: &str) -> Result<[&str; 5], JweParseError> {
    let parts: Vec<&str> = token.split(".").collect();
    parts.try_into().map_err(|vec: Vec<&str>| {
        if vec.len() < 5 {
            JweParseError::MissingParts
        } else {
            JweParseError::TooManyParts
        }
    })
}
