use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

use crate::date_utils::now;
use argon2::{self, Config, Variant, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as enc64, Engine as _};
use ed25519_dalek::{SignatureError, Signer, Verifier};
use rand::{rngs::OsRng, RngCore};
use rcgen::{CertificateParams, KeyPair, SanType};
use serde::{Deserialize, Serialize};
use sysinfo::System;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    InvalidKeyType(u8),

    #[error("{0}")]
    InvalidKeyLenght(String),

    #[error("{0}")]
    InvalidSignature(String),

    #[error(transparent)]
    Signature(#[from] SignatureError),

    #[error(transparent)]
    Decode(#[from] base64::DecodeError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("Invalid Base64 encoded Uid")]
    Uid(),

    #[error("Invalid Base64 encoded MeetingToken")]
    MeetingToken(),
}

///
/// when exporting a key the first byte is a flag indicating the public key algorithm used
/// currenlty useless but might become usefull in the future to implement new key algorithms
///
const KEY_TYPE_ED_2519: u8 = 1;

///
/// import a existing signing key, using the first byte flag to detect the signature scheme
///
///
#[cfg(test)]
pub fn import_signing_key(keypair: &[u8]) -> Result<impl SigningKey, Error> {
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

    Ok(Ed25519SigningKey {
        signing_key: keypair,
    })
}

///
/// import a existing verifying key, using the first byte flag to detect the signature scheme
///
pub fn import_verifying_key(veriying_key: &[u8]) -> Result<Box<dyn VerifyingKey>, Error> {
    if veriying_key[0] != KEY_TYPE_ED_2519 {
        return Err(Error::InvalidKeyType(KEY_TYPE_ED_2519));
    }
    if veriying_key.len() != 33 {
        return Err(Error::InvalidKeyLenght(format!(
            "key lenght must be 33,  value: {} ",
            veriying_key.len()
        )));
    }

    let ke: [u8; 32] = veriying_key[1..33].try_into().unwrap();

    let veriying_key = ed25519_dalek::VerifyingKey::from_bytes(&ke)?;
    Ok(Box::new(Ed2519VerifyingKey { veriying_key }))
}

///
/// Signing key using Ed25519 signature scheme
///
pub struct Ed25519SigningKey {
    signing_key: ed25519_dalek::SigningKey,
}

impl Ed25519SigningKey {
    ///
    /// new key using a random number
    ///
    #[cfg(test)]
    pub fn new() -> Self {
        let random: [u8; 32] = random32();
        Ed25519SigningKey::create_from(&random)
    }

    ///
    /// creates a signing key using a provided random number
    /// usefull to create a predictable key from a key derivation function
    ///
    pub fn create_from(random: &[u8; 32]) -> Self {
        let sk: &ed25519_dalek::SecretKey = random;
        Ed25519SigningKey {
            signing_key: ed25519_dalek::SigningKey::from(sk),
        }
    }
}

///
/// Defines the necessary functions to sign  data  
///
pub trait SigningKey {
    ///
    /// Export the signing key, adding a flag to detect the encryption scheme
    ///
    fn export(&self) -> Vec<u8>;

    ///
    /// Exports the verifying key, adding a a flag to detect the encryption scheme
    ///
    fn export_verifying_key(&self) -> Vec<u8>;

    ///
    /// Provides a copy of the verifying key
    ///
    fn verifying_key(&self) -> impl VerifyingKey;

    ///
    /// Sign a message, returning the signature
    /// passed message should be small, like a hash of the real message
    ///
    fn sign(&self, message: &[u8]) -> Vec<u8>;
}

impl SigningKey for Ed25519SigningKey {
    fn export(&self) -> Vec<u8> {
        let mut export = vec![KEY_TYPE_ED_2519];
        let keyp = self.signing_key.to_bytes();
        export.extend(keyp);
        export
    }

    fn export_verifying_key(&self) -> Vec<u8> {
        let mut export = vec![KEY_TYPE_ED_2519];
        let keyp = self.signing_key.verifying_key().to_bytes();
        export.extend(keyp);
        export
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing_key.sign(message).to_bytes().into()
    }

    fn verifying_key(&self) -> impl VerifyingKey {
        Ed2519VerifyingKey {
            veriying_key: self.signing_key.verifying_key(),
        }
    }
}

///
/// Defines the necessary function to verify data  
///
pub trait VerifyingKey {
    ///
    /// Export the verifying key, adding a flag to detect the encryption scheme
    ///
    //  fn export(&self) -> Vec<u8>;

    ///
    /// verify the signature against the provided message
    ///
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error>;
}

///
/// verification key using Ed25519 signature scheme
///
pub struct Ed2519VerifyingKey {
    pub veriying_key: ed25519_dalek::VerifyingKey,
}
impl VerifyingKey for Ed2519VerifyingKey {
    // fn export(&self) -> Vec<u8> {
    //     let mut export = vec![KEY_TYPE_ED_2519];
    //     let keyp = self.veriying_key.to_bytes();
    //     export.extend(keyp);
    //     export
    // }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        if signature.len() != 64 {
            return Err(Error::InvalidKeyLenght(format!(
                "signatue lenght must be 64,  value: {} ",
                signature.len()
            )));
        }
        let sign: [u8; 64] = signature.try_into().unwrap();

        let sig = ed25519_dalek::Signature::from_bytes(&sign);
        self.veriying_key.verify(data, &sig)?;
        Ok(())
    }
}
///
/// generates a self signed certificate
///
pub fn generate_x509_certificate(name: &str) -> rcgen::CertifiedKey {
    let mut params: CertificateParams = Default::default();

    params.subject_alt_names = vec![SanType::DnsName(name.try_into().unwrap())];
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    // let cert: rcgen::CertifiedKey = rcgen::generate_simple_self_signed(vec![name]).unwrap();
    rcgen::CertifiedKey { cert, key_pair }
}

///
/// The quick connection initiate connection with a domain name used during TLS negociations to avoid man in the middle attack.
/// As we are using p2p and self signed certificates, we don't have a domain name to connect to we have to generate one.
///
/// This name is transmitted in clear text over the network as part of the QUIC handshake.
/// If the name is too weird (like a base64 encoded value), it could be easy to detect that the connection is a Discret connection, and not a standard HTTP3 one.
/// So we try to be a little bit sneaky by creating a plausible domain names.
///
/// This functiion is public because it is used by the discret_beacon projet
///
pub fn random_domain_name() -> String {
    let min_value = 5;
    let max_value = 8;
    let divider = max_value - min_value;
    let offset: usize = OsRng.next_u32().try_into().unwrap();
    let num = offset % divider;

    let alphabet = [
        'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
        'v', 'w', 'x', 'z',
    ];
    let vowels = ['a', 'e', 'i', 'o', 'u', 'y'];
    let extension = [
        ".com", ".org", ".net", ".us", ".co", ".biz", ".info", ".fr", ".uk", ".me", ".cn", ".de",
        ".ly", ".in", ".eu", ".ca", ".coop", ".asia", ".cat", ".pro", ".ac", ".ad", ".ae", ".af",
        ".ai", ".am",
    ];
    let size = num + min_value;
    let mut domain = String::new();

    let mut vowel = OsRng.next_u32() % 2 == 1;
    for _ in 0..size {
        let mut index: usize = OsRng.next_u32().try_into().unwrap();
        if vowel {
            index %= vowels.len();
            domain.push(vowels[index]);
            vowel = false;
        } else {
            index %= alphabet.len();
            domain.push(alphabet[index]);
            vowel = true;
        }
    }
    let mut index: usize = OsRng.next_u32().try_into().unwrap();
    index %= extension.len();
    domain.push_str(extension[index]);

    domain
}

pub fn random32() -> [u8; 32] {
    let mut random: [u8; 32] = [0; 32];

    OsRng.fill_bytes(&mut random);
    random
}

pub const MEETING_TOKEN_SIZE: usize = 7;
pub type MeetingToken = [u8; MEETING_TOKEN_SIZE];
///
/// Use Diffie Hellman to create an id to be used to announce yourself on the network to the other peers.
/// The id is way too small to be secured, but it is big enougth to have a low collision rate
/// this will allow peer to recognize themselves on the network
/// The authentication is performed using a signature
///
/// The connection protocol is
///     generate a self signed certificate
///     for each allowed peer generate the diffie hellman id an put it in an array
///     sign the cerificate and the array with the public_key used to insert data
///     broadcast this data
///     in one single packet you can announce yoursef to other peers
///     upeon retrieval
///         peer will check if there is an id corresponding
///         this is will allow to retrieve the peer verifying key
///         verify authenticity
///         start connection
///         
pub struct MeetingSecret {
    secret: StaticSecret,
}
impl MeetingSecret {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }

    pub fn token(&self, their_public: &PublicKey) -> MeetingToken {
        //if both public key are the same, it is the same user and hash the private key instead of using diffie hellman
        let hash = if their_public.eq(&self.public_key()) {
            hash(self.secret.as_bytes())
        } else {
            let df = self.secret.diffie_hellman(their_public);
            hash(df.as_bytes())
        };
        let mut token: MeetingToken = [0; MEETING_TOKEN_SIZE];
        token.copy_from_slice(&hash[0..MEETING_TOKEN_SIZE]);
        token
    }

    /// derive a token from a string context and a secret
    /// provided by the Blake3 hash function  
    ///
    pub fn derive_token(context: &str, key_material: &[u8]) -> MeetingToken {
        let hash = blake3::derive_key(context, key_material);
        let mut token: MeetingToken = [0; MEETING_TOKEN_SIZE];
        token.copy_from_slice(&hash[0..MEETING_TOKEN_SIZE]);
        token
    }

    pub fn decode_token(base64: &str) -> Result<MeetingToken, Error> {
        let r = base64_decode(base64.as_bytes()).map_err(|_| Error::MeetingToken())?;
        let mut token: MeetingToken = [0; MEETING_TOKEN_SIZE];
        if r.len() < MEETING_TOKEN_SIZE {
            return Err(Error::MeetingToken());
        }
        token.copy_from_slice(&r[0..MEETING_TOKEN_SIZE]);

        Ok(token)
    }
}

///
/// Derive a password using argon2id
///  using parameters slighly greater than the minimum recommended by OSWAP <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
/// - 20480 KB of memory
/// - an iteration count of 2
/// - parallelism count of 2
/// - the login is used as a salt
///
pub fn derive_pass_phrase(login: &str, pass_phrase: &str) -> [u8; 32] {
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

///
/// hash a byte array using the Blake3 hash function
///
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

///
/// derive a ket from a string context and a secret
/// provided by the Blake3 hash function  
///
pub fn derive_key(context: &str, key_material: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, key_material)
}

///
/// encode bytes into a base 64 String
///
pub fn base64_encode(data: &[u8]) -> String {
    enc64.encode(data)
}

///
/// decode a base 64 String into bytes
///
pub fn base64_decode(data: &[u8]) -> Result<Vec<u8>, Error> {
    enc64.decode(data).map_err(Error::from)
}

pub const UID_SIZE: usize = 16;
pub type Uid = [u8; UID_SIZE];
const DEFAULT_UID: Uid = [0; UID_SIZE];
///
/// generate a 16 byte uid with the time on the first 6 bytes to improve index locality
///
///
pub fn new_uid() -> Uid {
    const TIME_BYTES: usize = 6;
    let time = now();
    let time = &time.to_be_bytes()[TIME_BYTES..];

    let mut uid = DEFAULT_UID;
    let (one, two) = uid.split_at_mut(time.len());

    one.copy_from_slice(time);
    OsRng.fill_bytes(two);

    uid
}

/// derive a ket from a string context and a secret
/// provided by the Blake3 hash function  
///
pub fn derive_uid(context: &str, key_material: &[u8]) -> Uid {
    let hash = blake3::derive_key(context, key_material);
    let mut uid = default_uid();
    uid.copy_from_slice(&hash[0..UID_SIZE]);
    uid
}

pub fn default_uid() -> Uid {
    DEFAULT_UID
}

pub fn uid_decode(base64: &str) -> Result<Uid, Error> {
    let s = base64_decode(base64.as_bytes())?;
    let uid: Uid = s.try_into().map_err(|_| Error::Uid())?;
    Ok(uid)
}

pub fn uid_encode(uid: &Uid) -> String {
    base64_encode(uid)
}

pub fn uid_from(v: Vec<u8>) -> Result<Uid, Error> {
    let uid: Uid = v.try_into().map_err(|_| Error::Uid())?;
    Ok(uid)
}

///
/// try to get a unique identifier from the underlying hardware
/// returns a unique identifier and  the machine name.
///
/// This is only used to identifies devices you own, not devices of other peers
///
/// if the platform is not supported by sysinfo,
/// creates a file named discret_fingerprint.bin and stores a random number
///
#[derive(Serialize, Deserialize, Clone)]
pub struct HardwareFingerprint {
    pub id: Uid,
    pub name: String,
}
impl HardwareFingerprint {
    pub fn get(file_path: &PathBuf) -> Result<Self, Error> {
        let id = if file_path.is_file() {
            let mut file = File::open(file_path)?;
            let mut uid = default_uid();
            file.read(&mut uid)?;
            uid
        } else {
            let uid = new_uid();
            let mut file = File::create(file_path)?;
            file.write_all(&uid)?;
            uid
        };

        let mut name = "Unknown Device".to_string();
        if sysinfo::IS_SUPPORTED_SYSTEM {
            let host = System::host_name().unwrap_or_default();
            //let system = System::name().unwrap_or_default();
            //let networks = Networks::new_with_refreshed_list();
            let osname = System::long_os_version().unwrap_or_default();
            name = format!("{osname}, {host}");
        };

        Ok(Self { id, name })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    #[test]
    fn control_derive_pass_phrase() {
        let login = "test";
        let pass_phrase = "testphrase";

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
        let signing_key = Ed25519SigningKey::create_from(&rd);

        let exp_kp = signing_key.export();

        assert_eq!(
            base64_encode(signing_key.signing_key.as_bytes()),
            "RkG04WSsJLl3i6STKCBmU-sB2xqREK0VCM-qnjoq8Ik"
        );

        assert_eq!(
            base64_encode(&signing_key.export_verifying_key()[0..]),
            "AVS6nzDyEt5jfykx0UObb32ySqI4sN89Y6nL9KFp_tWO"
        );

        let msg = b"message to sign";
        let signature = signing_key.sign(&msg.to_vec());

        let keypair = import_signing_key(&exp_kp).unwrap();

        let exp_pub = keypair.export_verifying_key();
        let imp_pub = import_verifying_key(&exp_pub).unwrap();

        imp_pub.verify(msg, &signature).unwrap();
    }

    #[test]
    pub fn meeting_secret() {
        let peer1 = MeetingSecret::new(random32());
        let peer1_public = peer1.public_key();
        let peer1_public = bincode::serialize(&peer1_public.as_bytes()).unwrap();

        let peer2 = MeetingSecret::new(random32());
        let peer2_public = peer2.public_key();
        let peer2_public = bincode::serialize(&peer2_public).unwrap();

        let peer1_public: PublicKey = bincode::deserialize(&peer1_public).unwrap();
        let peer2_public: PublicKey = bincode::deserialize(&peer2_public).unwrap();

        let id1 = peer2.token(&peer1_public);
        let id2 = peer1.token(&peer2_public);
        assert_eq!(id1, id2);
    }

    #[test]
    pub fn hardware_fingerprint() {
        let path: PathBuf = "test_data/hardware_fingerprint.bin".into();
        let _ = fs::remove_file(&path);

        let id1 = HardwareFingerprint::get(&path).unwrap();
        let id2 = HardwareFingerprint::get(&path).unwrap();
        assert_eq!(id1.id, id2.id);
    }

    #[test]
    pub fn random_domain() {
        for _ in 0..50 {
            // println!("{}", random_domain_name());
            assert!(random_domain_name().len() <= 14);
        }
    }
}
