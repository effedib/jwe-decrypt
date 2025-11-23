mod jwe;
mod parser;

use clap::{Arg, Command};
use std::{
    fs,
    io::{self, Read},
};

use crate::jwe::{AlgorithmFactory, JweHeader};
use crate::parser::parse_jwe;

fn main() {
    let matches = Command::new("jwtinfo")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Shows information about a JWT (Json Web Token)")
        .args([
            Arg::new("token")
                .index(1)
                .allow_hyphen_values(true)
                .required(true)
                .help("the JWT/JWE as a string (use \"-\" to read from stdin)"),
            Arg::new("key")
                .index(2)
                .required(true)
                .help("the path to the private key for the cek decryption"),
        ])
        .get_matches();

    let mut token = matches.get_one::<String>("token").unwrap().clone();
    let mut buffer = String::new();

    if token == "-" {
        io::stdin().read_to_string(&mut buffer).unwrap();
        token = (*buffer.trim()).to_string();
    }

    let original_key_path = matches.get_one::<String>("key").unwrap().clone();
    let original_key = fs::read(original_key_path.as_str()).unwrap();

    let jwe_token = parse_jwe(token.as_str()).unwrap();

    let jwe_header: JweHeader =
        serde_json::from_str(&jwe_token.header).expect("not serialized error");

    let key_decryptor = AlgorithmFactory::get_key_decryptor(jwe_header.alg.as_str()).unwrap();
    let key_decrypted = key_decryptor
        .decrypt_cek(&original_key, &jwe_token.key_encrypted)
        .unwrap();

    let content_decryptor =
        AlgorithmFactory::get_content_decryptor(jwe_header.enc.as_str()).unwrap();

    let cipher = jwe_token
        .decrypt_content(&*content_decryptor, &key_decrypted)
        .unwrap();

    let payload_string = String::from_utf8(cipher).expect("payload is not valid UTF-8");

    println!("{}", payload_string);
}
