use argon2::{self, Config, ThreadMode, Variant};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as enc64, Engine as _};
use ed25519_dalek::*;
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid KeyPair")]
    InvalidKeyPair,
    #[error("Invalid Public Key")]
    InvalidPublicKey,
    #[error(transparent)]
    DecodeError(#[from] base64::DecodeError),
}

//magic number for the ALPN protocol that allows for less roundtrip during tls negociation
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

//Derive a password using argon2id
//  using parameters slighly greater than the minimum recommended by OSWAP https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
// - 32 mb of memory
// - an iteration count of 2
// - parallelism count of 2
// - the login is used as a salt
pub fn derive_pass_phrase(login: String, pass_phrase: String) -> [u8; 32] {
    let password = pass_phrase.as_bytes();
    let salt = hash(login.as_bytes());

    let config = Config::<'_> {
        mem_cost: 32768,
        time_cost: 2,
        variant: Variant::Argon2id,
        lanes: 2,
        thread_mode: ThreadMode::Parallel,
        ..Default::default()
    };

    let hashed = argon2::hash_encoded(password, &salt, &config).unwrap();
    let matches = argon2::verify_encoded(&hashed, password).unwrap();
    assert!(matches);
    hash(hashed.as_bytes())
}

pub fn hash(bytes: &[u8]) -> [u8; 32] {
    blake3::hash(bytes).as_bytes().to_owned()
}

pub fn base64_encode(data: &[u8]) -> String {
    enc64.encode(data)
}

pub fn base64_decode(data: &[u8]) -> Result<Vec<u8>, Error> {
    enc64.decode(data).map_err(Error::from)
}

pub fn create_random_key_pair() -> Keypair {
    let mut csprng = OsRng {};
    let mut random: [u8; 32] = [0; 32];

    csprng.fill_bytes(&mut random);

    create_ed25519_key_pair(&random)
}

pub fn create_ed25519_key_pair(random: &[u8; 32]) -> Keypair {
    let sk: SecretKey = SecretKey::from_bytes(random).unwrap();
    let pk: PublicKey = (&sk).into();
    Keypair {
        public: pk,
        secret: sk,
    }
}

pub fn import_ed25519_keypair(keypair: [u8; 64]) -> Result<Keypair, Error> {
    Keypair::from_bytes(&keypair).map_err(|_| Error::InvalidKeyPair)
}

pub fn export_ed25519_keypair(keypair: &Keypair) -> [u8; 64] {
    keypair.to_bytes()
}

pub fn import_ed25519_public_key(public_key: [u8; 32]) -> Result<PublicKey, Error> {
    PublicKey::from_bytes(&public_key).map_err(|_| Error::InvalidPublicKey)
}

pub fn export_ed25519_public_key(public_key: &PublicKey) -> [u8; 32] {
    public_key.to_bytes()
}

pub fn sign(keypair: &Keypair, message: &[u8]) -> Signature {
    keypair.sign(message)
}

pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<(), Error> {
    public_key
        .verify(message, signature)
        .map_err(|_| Error::InvalidSignature)
}

pub fn generate_self_signed_certificate() -> (rustls::Certificate, rustls::PrivateKey) {
    let mut param = rcgen::CertificateParams::new(vec!["".into()]);
    param.alg = &rcgen::PKCS_ED25519;

    let cert = rcgen::Certificate::from_params(param).unwrap();

    let key = cert.serialize_private_key_der();
    let secret_key = rustls::PrivateKey(key);

    let cert = cert.serialize_der().unwrap();
    let pub_key = rustls::Certificate(cert);

    (pub_key, secret_key)
}

//Provides human readable smaller hash
//
//usefull to remember an item and search it later
//NOT UNIQUE do not use as a primary key!!
#[allow(clippy::needless_range_loop)]
pub fn humanized_hash(hash: &[u8; 32], length: usize) -> String {
    let consonnant = [
        "B", "C", "D", "F", "G", "H", "J", "K", "L", "M", "N", "P", "Q", "R", "S", "T", "V", "W",
        "X", "Z",
    ];
    let vowel = ["A", "E", "I", "O", "U", "Y"];
    let mut v: Vec<&str> = vec![];

    let mut use_vowel = false;
    let mut arr: &[&str];
    for pos in 0..length {
        if use_vowel {
            arr = &vowel;
            use_vowel = false;
        } else {
            arr = &consonnant;
            use_vowel = true;
        }
        let id = hash[pos] as usize;
        v.push(arr[id % arr.len()]);
    }
    let mut final_number = 0;
    for i in 0..3 {
        final_number += hash[length + i] as usize;
    }

    let fnum = final_number.to_string();

    v.push("-");
    v.push(fnum.as_str());
    v.concat()
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn control_derive_pass_phrase() {
        let login = "test".to_string();
        let pass_phrase = "testphrase".to_string();

        let hashed = derive_pass_phrase(login, pass_phrase);

        assert_eq!(
            base64_encode(&hashed),
            "8iNQii9JMas_nWInYjOhDEClqeYBNrQG2T5KH9Y0oPM"
        );
    }

    #[test]
    fn control_hash() {
        assert_eq!(
            base64_encode(&hash(b"bytes")),
            "3xmx8QX_kpGRzknQu_3FtO3CpxpA9QLclVNZ6zNkniQ"
        );
    }

    #[test]
    fn control_ed25519() {
        let rd = hash(b"not random");
        let keypair = create_ed25519_key_pair(&rd);

        let exp_kp = export_ed25519_keypair(&keypair);

        assert_eq!(
            base64_encode(keypair.public.as_bytes()),
            "VLqfMPIS3mN_KTHRQ5tvfbJKojiw3z1jqcv0oWn-1Y4"
        );

        assert_eq!(
            base64_encode(keypair.secret.as_bytes()),
            "RkG04WSsJLl3i6STKCBmU-sB2xqREK0VCM-qnjoq8Ik"
        );

        let msg = b"message to sign";
        let signature = sign(&keypair, msg);

        let keypair = import_ed25519_keypair(exp_kp).unwrap();

        let exp_pub = export_ed25519_public_key(&keypair.public);
        let imp_pub = import_ed25519_public_key(exp_pub).unwrap();

        verify(&imp_pub, msg, &signature).unwrap();
    }

    #[test]
    fn control_humanized_hash() {
        let bytes: [u8; 32] = hash(b"not random");

        assert_eq!("NYBOBU-340", humanized_hash(&bytes, 6));
        assert_eq!("NYBOBUV-443", humanized_hash(&bytes, 7));
        assert_eq!("NYBOBUVYZ-450", humanized_hash(&bytes, 9));
    }
}
