use argon2::{self, Config, ThreadMode, Variant};
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
}

//magic number for the ALPN protocol that allows for less roundtrip during tls negociation
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

pub fn derive_pass_phrase(login: String, pass_phrase: String) -> [u8; 32] {
    let password = pass_phrase.as_bytes();
    let salt = hash(login.as_bytes());

    let config = Config::<'_> {
        mem_cost: 8192,
        time_cost: 3,
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
//do not use as a primary key!!
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
        assert_eq!(hex::encode(hashed).len(), 64);

        assert_eq!(
            hex::encode(hashed),
            "2c186859ce3e3e70684c9c9be14f9c64fc7634666dd60c990bbefb487441965b"
        );
    }

    #[test]
    fn control_hash() {
        assert_eq!(
            hex::encode(hash(b"bytes")),
            "df19b1f105ff929191ce49d0bbfdc5b4edc2a71a40f502dc955359eb33649e24"
        );
    }

    #[test]
    fn control_ed25519() {
        let rd = hash(b"not random");
        let keypair = create_ed25519_key_pair(&rd);

        let exp_kp = export_ed25519_keypair(&keypair);
        println!("{}", hex::encode(&exp_kp));

        assert_eq!(
            hex::encode(&exp_kp),
            "4641b4e164ac24b9778ba49328206653eb01db1a9110ad1508cfaa9e3a2af08954ba9f30f212de637f2931d1439b6f7db24aa238b0df3d63a9cbf4a169fed58e"
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
        let bytes: [u8; 32] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];

        assert_eq!("BEDOGYJ-24", humanized_hash(&bytes, 7));
        assert_eq!("BEDOGYJEL-30", humanized_hash(&bytes, 9));
    }
}
