use argon2::{self, Config, Variant, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as enc64, Engine as _};

use ed25519_dalek::{SignatureError, Signer, Verifier};
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    InvalidKeyType(u8),

    #[error("{0}")]
    InvalidKeyLenght(String),

    #[error("{0}")]
    InvalidSignature(String),

    #[error(transparent)]
    SignatureError(#[from] SignatureError),

    #[error(transparent)]
    DecodeError(#[from] base64::DecodeError),
}

//magic number for the ALPN protocol that allows for less roundtrip during tls negociation
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

///20,067
/// Derive a password using argon2id
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
        version: Version::Version13,
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

pub trait SigningKey {
    fn new() -> Self;
    fn create_from(random: [u8; 32]) -> Self;
    fn import(keypair: &[u8]) -> Result<Box<Self>, Error>;
    fn export(&self) -> Vec<u8>;
    fn export_public(&self) -> Vec<u8>;
    fn sign(&self, message: &[u8]) -> Vec<u8>;
}

const KEY_TYPE_ED_2519: u8 = 1;

pub struct Ed2519SigningKey {
    signing_key: ed25519_dalek::SigningKey,
}
impl SigningKey for Ed2519SigningKey {
    fn new() -> Self {
        let mut random: [u8; 32] = [0; 32];

        OsRng.fill_bytes(&mut random);

        Ed2519SigningKey::create_from(random)
    }

    fn create_from(random: [u8; 32]) -> Self {
        let sk: ed25519_dalek::SecretKey = random;
        Ed2519SigningKey {
            signing_key: ed25519_dalek::SigningKey::from(&sk),
        }
    }

    fn import(keypair: &[u8]) -> Result<Box<Self>, Error> {
        if keypair[0] != KEY_TYPE_ED_2519 {
            return Err(Error::InvalidKeyType(KEY_TYPE_ED_2519));
        }
        if keypair.len() != 33 {
            return Err(Error::InvalidKeyLenght(format!(
                "key lenght must be 33,  value: {} ",
                keypair.len()
            )));
        }

        let ke: [u8; 32] = keypair[1..33].try_into().unwrap();
        let keypair = ed25519_dalek::SigningKey::from(ke);

        Ok(Box::new(Ed2519SigningKey {
            signing_key: keypair,
        }))
    }

    fn export(&self) -> Vec<u8> {
        let mut export = vec![KEY_TYPE_ED_2519];
        let keyp = self.signing_key.to_bytes();
        export.extend(keyp);
        export
    }

    fn export_public(&self) -> Vec<u8> {
        let mut export = vec![KEY_TYPE_ED_2519];
        let keyp = self.signing_key.verifying_key().to_bytes();
        export.extend(keyp);
        export
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing_key.sign(message).to_bytes().into()
    }
}

pub trait PublicKey {
    fn import(public_key: &[u8]) -> Result<Box<Self>, Error>;
    fn export(&self) -> Vec<u8>;
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error>;
}

pub struct Ed2519PublicKey {
    public_key: ed25519_dalek::VerifyingKey,
}
impl PublicKey for Ed2519PublicKey {
    fn import(public_key: &[u8]) -> Result<Box<Self>, Error> {
        if public_key[0] != KEY_TYPE_ED_2519 {
            return Err(Error::InvalidKeyType(KEY_TYPE_ED_2519));
        }
        if public_key.len() != 33 {
            return Err(Error::InvalidKeyLenght(format!(
                "key lenght must be 33,  value: {} ",
                public_key.len()
            )));
        }

        let ke: [u8; 32] = public_key[1..33].try_into().unwrap();

        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&ke)?;
        Ok(Box::new(Self { public_key }))
    }

    fn export(&self) -> Vec<u8> {
        let mut export = vec![KEY_TYPE_ED_2519];
        let keyp = self.public_key.to_bytes();
        export.extend(keyp);
        export
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        if signature.len() != 64 {
            return Err(Error::InvalidKeyLenght(format!(
                "signatue lenght must be 64,  value: {} ",
                signature.len()
            )));
        }
        let sign: [u8; 64] = signature.try_into().unwrap();

        let sig = ed25519_dalek::Signature::from_bytes(&sign);
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
        let signing_key = Ed2519SigningKey::create_from(rd);

        let exp_kp = signing_key.export();

        assert_eq!(
            base64_encode(signing_key.signing_key.as_bytes()),
            "RkG04WSsJLl3i6STKCBmU-sB2xqREK0VCM-qnjoq8Ik"
        );

        assert_eq!(
            base64_encode(&signing_key.export_public()[0..]),
            "AVS6nzDyEt5jfykx0UObb32ySqI4sN89Y6nL9KFp_tWO"
        );

        let msg = b"message to sign";
        let signature = signing_key.sign(&msg.to_vec());

        let keypair = Ed2519SigningKey::import(&exp_kp).unwrap();

        let exp_pub = keypair.export_public();
        let imp_pub = Ed2519PublicKey::import(&exp_pub).unwrap();

        imp_pub.verify(msg, &signature).unwrap();
    }
}
