use argon2::{self, Config, ThreadMode, Variant};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as enc64, Engine as _};

use ed25519_dalek::{SignatureError, Signer, Verifier};
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    InvalidKeyType(u8),

    #[error("{0}")]
    InvalidSignature(String),

    #[error(transparent)]
    SignatureError(#[from] SignatureError),

    #[error(transparent)]
    DecodeError(#[from] base64::DecodeError),
}

//magic number for the ALPN protocol that allows for less roundtrip during tls negociation
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

///Derive a password using argon2id
///  using parameters slighly greater than the minimum recommended by OSWAP https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
/// - 20480 mb of memory
/// - an iteration count of 2
/// - parallelism count of 2
/// - the login is used as a salt
pub fn derive_pass_phrase(login: String, pass_phrase: String) -> [u8; 32] {
    let password = pass_phrase.as_bytes();
    let salt = hash(login.as_bytes());

    let config = Config::<'_> {
        mem_cost: 20480,
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

pub trait KeyPair {
    fn new() -> Self;
    fn create_from(random: &[u8; 32]) -> Self;
    fn import(keypair: &[u8]) -> Result<Box<Self>, Error>;
    fn export(&self) -> Vec<u8>;
    fn export_public(&self) -> Vec<u8>;
    fn sign(&self, message: &[u8]) -> Vec<u8>;
}

const KEY_TYPE_ED_2519: u8 = 1;

pub struct Ed2519KeyPair {
    keypair: ed25519_dalek::Keypair,
}
impl KeyPair for Ed2519KeyPair {
    fn new() -> Self {
        let mut random: [u8; 32] = [0; 32];

        OsRng.fill_bytes(&mut random);

        Ed2519KeyPair::create_from(&random)
    }

    fn create_from(random: &[u8; 32]) -> Self {
        let sk: ed25519_dalek::SecretKey = ed25519_dalek::SecretKey::from_bytes(random).unwrap();
        let pk: ed25519_dalek::PublicKey = (&sk).into();
        Ed2519KeyPair {
            keypair: ed25519_dalek::Keypair {
                public: pk,
                secret: sk,
            },
        }
    }

    fn import(keypair: &[u8]) -> Result<Box<Self>, Error> {
        if keypair[0] != KEY_TYPE_ED_2519 {
            return Err(Error::InvalidKeyType(KEY_TYPE_ED_2519));
        }
        let keypair = ed25519_dalek::Keypair::from_bytes(&keypair[1..])?;
        Ok(Box::new(Ed2519KeyPair { keypair }))
    }

    fn export(&self) -> Vec<u8> {
        let mut export = vec![KEY_TYPE_ED_2519];
        let keyp = self.keypair.to_bytes();
        export.append(&mut keyp.to_vec());
        export
    }

    fn export_public(&self) -> Vec<u8> {
        let mut export = vec![KEY_TYPE_ED_2519];
        let keyp = self.keypair.public.to_bytes();
        export.append(&mut keyp.to_vec());
        export
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.keypair.sign(message).to_bytes().into()
    }
}

pub trait PublicKey {
    fn import(public_key: &[u8]) -> Result<Box<Self>, Error>;
    fn export(&self) -> Vec<u8>;
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error>;
}

pub struct Ed2519PublicKey {
    public_key: ed25519_dalek::PublicKey,
}
impl PublicKey for Ed2519PublicKey {
    fn import(public_key: &[u8]) -> Result<Box<Self>, Error> {
        if public_key[0] != KEY_TYPE_ED_2519 {
            return Err(Error::InvalidKeyType(KEY_TYPE_ED_2519));
        }
        let public_key = ed25519_dalek::PublicKey::from_bytes(&public_key[1..])?;
        Ok(Box::new(Self { public_key }))
    }

    fn export(&self) -> Vec<u8> {
        let mut export = vec![KEY_TYPE_ED_2519];
        let keyp = self.public_key.to_bytes();
        export.append(&mut keyp.to_vec());
        export
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        let sig = ed25519_dalek::Signature::from_bytes(signature)
            .map_err(|e| Error::InvalidSignature(e.to_string()))?;
        self.public_key.verify(data, &sig)?;
        Ok(())
    }
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
            "KER9-vDQvEeLBD5EAnPo52l8XEiuEO5vuaZDXOpQId0"
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
        let keypair = Ed2519KeyPair::create_from(&rd);

        let exp_kp = keypair.export();

        assert_eq!(
            base64_encode(keypair.keypair.public.as_bytes()),
            "VLqfMPIS3mN_KTHRQ5tvfbJKojiw3z1jqcv0oWn-1Y4"
        );

        assert_eq!(
            base64_encode(keypair.keypair.secret.as_bytes()),
            "RkG04WSsJLl3i6STKCBmU-sB2xqREK0VCM-qnjoq8Ik"
        );

        let msg = b"message to sign";
        let signature = keypair.sign(&msg.to_vec());

        let keypair = Ed2519KeyPair::import(&exp_kp).unwrap();

        let exp_pub = keypair.export_public();
        let imp_pub = Ed2519PublicKey::import(&exp_pub).unwrap();

        imp_pub.verify(msg, &signature).unwrap();
    }
}
