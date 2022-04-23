use crate::errors::VaultError;
use argon2::{self, Config};
use ed25519_dalek::*;
use rand::{rngs::OsRng, RngCore};

pub fn derive_pass_phrase(pass_phrase: String) -> [u8; 32] {
    let password = pass_phrase.as_bytes();
    let salt = b"Static salt, we whant deterministic result";
    let config = Config::default();
    let hashed = argon2::hash_encoded(password, salt, &config).unwrap();
    let matches = argon2::verify_encoded(&hashed, password).unwrap();
    assert!(matches);
    hash(hashed.as_bytes())
}

pub fn hash(bytes: &[u8]) -> [u8; 32] {
    blake3::hash(bytes).as_bytes().to_owned()
}

#[allow(dead_code)]
pub fn create_random_key_pair() -> Keypair {
    let mut csprng = OsRng {};
    let mut random: [u8; 32] = [0; 32];

    csprng.fill_bytes(&mut random);

    create_key_pair(&random)
}

#[allow(dead_code)]
pub fn create_key_pair(random: &[u8; 32]) -> Keypair {
    let sk: SecretKey = SecretKey::from_bytes(random).unwrap();
    let pk: PublicKey = (&sk).into();
    Keypair {
        public: pk,
        secret: sk,
    }
}

#[allow(dead_code)]
pub fn import_keypair(keypair: [u8; 64]) -> Result<Keypair, VaultError> {
    match Keypair::from_bytes(&keypair) {
        Ok(val) => Ok(val),
        Err(_) => Err(VaultError::InvalidKeyPair),
    }
}

#[allow(dead_code)]
pub fn export_keypair(keypair: &Keypair) -> [u8; 64] {
    keypair.to_bytes()
}

#[allow(dead_code)]
pub fn import_public_key(public_key: [u8; 32]) -> Result<PublicKey, VaultError> {
    match PublicKey::from_bytes(&public_key) {
        Ok(val) => Ok(val),
        Err(_) => Err(VaultError::InvalidPublicKey),
    }
}

#[allow(dead_code)]
pub fn export_public_key(public_key: &PublicKey) -> [u8; 32] {
    public_key.to_bytes()
}

#[allow(dead_code)]
pub fn sign(keypair: &Keypair, message: &[u8]) -> Signature {
    let signature = keypair.sign(message);
    signature
}

#[allow(dead_code)]
pub fn verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: Signature,
) -> Result<(), VaultError> {
    match public_key.verify(&message, &signature) {
        Ok(_) => Ok(()),
        Err(_) => Err(VaultError::InvalidSignature),
    }
}

#[allow(dead_code)]
//Provides human readable smaller hash
//do not use as a primary key!!
//length:7 provides only about 25 000 000 000 different combinations
//no bound checking length should be small
pub fn reduce_hash_for_humans(hash: &[u8; 32], length: usize) -> String {
    let consonnant = [
        "B", "C", "D", "F", "G", "H", "J", "K", "L", "M", "N", "P", "Q", "R", "S", "T", "V", "W",
        "X", "Z",
    ];
    let vowel = ["A", "E", "I", "O", "U", "Y"];
    //, "AE", "AO", "AI", "AU", "AY", "EA", "EI", "EU", "IA", "IO", "OI", "OU", "UA", "UI",
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
    fn derive_pass_phrase_test() {
        let pass_phrase = "testphrase".to_string();
        let hashed = derive_pass_phrase(pass_phrase);
        assert_eq!(hex::encode(hashed).len(), 64);
        assert_eq!(
            hex::encode(hashed),
            "f553b655b9515fc0f126b74bf485bb38c53954ba38fcaac16217554267a36646"
        );
    }

    #[test]
    fn reduce_hash_for_humans_test() {
        let bytes: [u8; 32] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];

        assert_eq!("BEDOGYJ-24", reduce_hash_for_humans(&bytes, 7));
        assert_eq!("BEDOGYJEL-30", reduce_hash_for_humans(&bytes, 9));
    }
}
