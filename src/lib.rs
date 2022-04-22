use argon2::{self, Config};

mod database;
mod errors;
type Hash = [u8; 32];

pub fn create(pass_phrase: String) -> Result<Database, errors::VaultError> {
    let secret = derive_pass_phrase(pass_phrase);
    Ok(start_database(secret))
}

pub fn open(pass_phrase: String) -> Result<Database, errors::VaultError> {
    let secret = derive_pass_phrase(pass_phrase);

    Ok(start_database(secret))
}

pub struct Database {
    pub database_key: String,
    pub database_file: String,
}

fn start_database(secret: [u8; 32]) -> Database {
    let database_key = vec!["x'".to_string(), hex::encode(&secret), "'".to_string()].concat();
    let database_file = hex::encode(hash(&secret));
    Database {
        database_key,
        database_file,
    }
}

fn derive_pass_phrase(pass_phrase: String) -> Hash {
    let password = pass_phrase.as_bytes();
    let salt = b"Static salt, we whant deterministic result";
    let config = Config::default();
    let hashed = argon2::hash_encoded(password, salt, &config).unwrap();
    let matches = argon2::verify_encoded(&hashed, password).unwrap();
    assert!(matches);
    hash(hashed.as_bytes())
}

fn hash(bytes: &[u8]) -> Hash {
    blake3::hash(bytes).as_bytes().to_owned()
}

//pub fn close(key: String) {}

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
    fn start_database_test() {
        let pass_phrase = "testphrase".to_string();

        let secret = derive_pass_phrase(pass_phrase);
        let db = start_database(secret);
        assert_eq!(
            db.database_key,
            "x'f553b655b9515fc0f126b74bf485bb38c53954ba38fcaac16217554267a36646'"
        );
        assert_eq!(
            db.database_file,
            "36057f6d2846d773a3d95138a1bd908d9a656c27d3031e571628509f54a4e7a8"
        );
    }
}
