mod jwe;

use rsa::Oaep;
use rsa::RsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use sha2::Sha256;
use std::sync::OnceLock;

use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInPlace, KeyInit},
};

use base64::{
    Engine as _, alphabet,
    engine::{self, general_purpose},
};

use crate::jwe::JweHeader;

static BASE64_ENGINE: OnceLock<engine::GeneralPurpose> = OnceLock::new();

#[inline]
fn get_base64() -> &'static engine::GeneralPurpose {
    BASE64_ENGINE
        .get_or_init(|| engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD))
}

fn parse_base64_string(s: &str) -> String {
    let s = get_base64().decode(s).expect("error decoding base64");
    let s = str::from_utf8(&s).expect("error decoding string");
    s.to_string()
}

fn main() {
    let token = "eyJhbGciOiAiUlNBLU9BRVAtMjU2IiwgImVuYyI6ICJBMjU2R0NNIiwgInR5cCI6ICJKV0UifQ.e2ioQVm4Q7Pqhg2R8GdizJ3JpWJH4BV37UlJXvU_8mMXBUZMpx51-zv2loeHRMKR5KwRpn7yYfihngQSZKLYNiSrz6Hpyom4Ko-gOyC1qKJ9Asybo068ITPmxqcd4bGPldHa8WoLg9IP_lU_xbqA0H6qdWUQu5ODNn3j37ZhS9tqBV_tTChVUtSRxVxDz34KzfYsglYIQl25zMypD7kl4B-yhfprvem5hdCIayhGU2GoR8pmb3p-BG3ijdfZeNwDvzJPGoSymTF7fI1gM-4pwmWyiuqv3ejbqvf-RGTi6GEkGNLO6CaNV810UlOn84yG6C6fxJMBut2XoTIkf5bOeg.q16Q-_YmNq0hKdPv.dDVe4F9xFnV6dWDUL-_LMA-zTgoCiqHE1mHEdMyIPCplhBVQVQ.wo_iBS3dHtURjXjqfDpSbA";
    let mut parts = token.split(".");
    let header_b64 = parts.next().expect("expected header not found");
    let header = parse_base64_string(header_b64);
    println!("{}", header);
    let h: JweHeader = serde_json::from_str(&header).expect("not serialized error");
    println!("{}\t{}", h.alg, h.enc);
    let aad = header_b64.as_bytes();
    let cek = parts.next().unwrap();
    let key_encrypted = get_base64()
        .decode(cek)
        .expect("error converting key from base64");
    let k = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCj0bD8nk/R4983
/AunjXRChKd+KvUxESNb6KVkpwmrFHSX/vnlfmzFkEkY37nFzbF/HY1137RgRmw+
7jbDR3uzIqLnr4W1U6EW71qYC5SvQNFeq0tSQK2IzaYbbowTHqTbZqRNt7kJuHid
v2LCEhZyDPRsdsdzR5Bl/F35J4SpboiCOn52wigrQAki7CgJOeboQECxIJ7GPXYC
d5ZFwa2xTx89l4ctG15t+75k43iotKeraIUqMu1CTvOAZtITo1KW7f9FyPPFpz/p
hjNeQqr/OqCSRllyy3+djGbGqFf6WsFmJGmkypThAq6phA4DeIGY6OEEVGctM/jK
QDEB90RrAgMBAAECggEAEI8THU3hUp1+hDmxcePOAyVGiu3LsASD9vfatARgaU8d
g/mth+GSHBw8D0waCqEClo9Fq8sLgAnOSkQo++8/VTmkjtfCo7QK3fceyKyvAFIE
d9XHvM413FSxPCed+BbKYjULWaG/Dfj8FDHyyRwr8aZWlJojCgeLVIvAcf1pHvkY
GOzgZplfTML2gQ0DKhYCTEbhlceA6eXxiT19gcugUcJyaLhdRb0dZaVqIKE+/iTJ
2W+YiUv4yaUlA+ro8TWOYDKBNuZpEzO01+uYW2L5b//GPM9pBttzpkVX3HwyGZOe
Qos7b4IZK9F/y8TRpHDqrDXvnL2vFKHtvTymoiqI7QKBgQDmnvlEmwwMleguQVID
GX1AQu8tpQlPv6D+quaHNFDd1u0+zNg8d5ZJvL02SK1Bpo9RtSN9M8Y4e7nIUrKb
ETZ6qMatEwIkMzirXKGPdNE94272Bnalg1xGvZNNNJtKK96pXaCNPqFWSvfanimH
yIdwrsOqPgvIZExvaLt2Z+r7FQKBgQC12Mh8/AvTMnsHzgwjE+bCMC2zZWUXq+Yf
/6FWgri+fJ7jxtYhh4mO7xUm+cjTvDBFvfKQofx6vyB+tL/y6dP7b0nfY7IUPSIB
LMlshAvu9HKGEAIZ/CFGroIqo38q6iVOCFdrru1gmK7PvpT/LWAMaFqWuMkK5k//
WyCHZ6shfwKBgE+fhYp1SaSywRXvQYSGcWMVeQS2XU+mZsxmbu8xVdYx1XmAOgwu
cboFqwIp93+aJRNdyeH5VS+9L/iE7NtzBu80hFvPG0cqVB99/N3NxExs0KuqsZ4V
i291Fn1qc08ZdGffRoZdoFBt08MsJkSWLITwIegOQf0u++DfNRH9cPi9AoGBAK1A
L6tcW0vJMYw7FDcrU9Q5IKFlfg4yeVqNK0KH4smhY6QxoXtqbXVfdXCf1GVeS0N2
+C4yFqE/jQ8K2EHv40YPPnt1uYkswUQLTpBzsgbkoGP3xnjJTU7RHjTPdm4FjKsu
qVNv4rsAXLSSp9QCgBryJTSqMuiOizMHuBMpgtKzAoGBAI53Eo30rDcD/qmPuG70
pGPi3dAGy34/11igst0bmgWkwTC5sTyDAC98QgltCNdSvjVPqtsIE9rEPuYyYJdZ
lMPGF7y1ZKnS9qMgyfn/ru8PPk6yqP+jOVW0RshBGjm6q72Kzdk3UsgxiV7XQeOX
WHF8NVIYRmjWdMX9srDtqL/K
-----END PRIVATE KEY-----";
    let priv_key = RsaPrivateKey::from_pkcs8_pem(k).unwrap();
    let padding = Oaep::new::<Sha256>();
    let dec_key = priv_key.decrypt(padding, &key_encrypted).expect("error");

    let iv_b64 = parts.next().expect("missing iv");
    let ciphertext_b64 = parts.next().expect("missing ciphertext");
    let tag_b64 = parts.next().expect("missing tag");

    let iv = get_base64().decode(iv_b64).expect("failed to decode iv");
    let ciphertext = get_base64()
        .decode(ciphertext_b64)
        .expect("failed to decode ciphertext");
    let tag_bytes = get_base64().decode(tag_b64).expect("failed to decode tag");

    let cipher = Aes256Gcm::new_from_slice(&dec_key)
        .expect("Invalid key length -- this should not happen as the CEK is 32 bytes");

    let nonce = iv
        .as_slice()
        .try_into()
        .expect("Invalid nonce length (must be 12 bytes for AES-GCM)");

    let tag = tag_bytes
        .as_slice()
        .try_into()
        .expect("Invalid tag length (must be 16 bytes for AES-GCM)");

    let mut buffer = ciphertext.to_vec();
    cipher
        .decrypt_in_place_detached(nonce, aad, &mut buffer, tag)
        .expect("DECRYPTION FAILED: authentication tag mismatch");

    let payload_string = String::from_utf8(buffer).expect("payload is not valid UTF-8");

    println!("{}", payload_string);
}
