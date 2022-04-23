mod cryptography;
mod database;
mod errors;
use cryptography::*;
use database::Database;

pub fn create(pass_phrase: String) -> Result<Database, errors::VaultError> {
    let secret = derive_pass_phrase(pass_phrase);
    Ok(start_database(secret))
}

pub fn open(pass_phrase: String) -> Result<Database, errors::VaultError> {
    let secret = derive_pass_phrase(pass_phrase);
    Ok(start_database(secret))
}

fn start_database(secret: [u8; 32]) -> Database {
    Database::new("./", secret)
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
}
