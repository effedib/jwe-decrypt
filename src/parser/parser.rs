use base64::{
    Engine as _, alphabet,
    engine::{self, general_purpose},
};
use std::sync::OnceLock;

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

pub fn parse_base64_string(s: &str) -> String {
    let s = get_base64().decode(s).expect("error decoding base64");
    let s = str::from_utf8(&s).expect("error decoding string");
    s.to_string()
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
