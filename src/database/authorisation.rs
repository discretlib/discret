use std::{collections::HashMap, fmt};

pub type Result<T> = std::result::Result<T, Error>;
use thiserror::Error;
#[derive(Error, Debug)]
pub enum Error {
    #[error("Authorisation '{0}' allready exists")]
    AuthorisationExists(String),

    #[error("Rights allreday exits for entity '{0}'")]
    RightsExists(String),

    #[error("User is allready disabled at a later date")]
    UserAllreadyDisabled(),

    #[error("credential validity date is set before an existing credential validity")]
    InvalidCredentialDate(),
}

#[derive(Default)]
pub struct Room {
    pub parent: Vec<u8>,
    authorisations: HashMap<String, Authorisation>,
}

impl Room {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn add_auth(&mut self, name: &str, auth: Authorisation) -> Result<()> {
        if self.authorisations.get(name).is_some() {
            return Err(Error::AuthorisationExists(name.to_string()));
        }
        self.authorisations.insert(name.to_string(), auth);
        Ok(())
    }

    pub fn get_auth(&self, name: &str) -> Option<&Authorisation> {
        self.authorisations.get(name)
    }

    pub fn is_user_valid_at(&self, user: &Vec<u8>, date: i64) -> bool {
        for entry in &self.authorisations {
            let auth = entry.1;
            if auth.is_user_valid_at(user, date) {
                return true;
            }
        }
        false
    }

    pub fn can(&self, user: &Vec<u8>, entity: &str, date: i64, right: &RightType) -> bool {
        for entry in &self.authorisations {
            let auth = entry.1;
            if auth.is_user_valid_at(user, date) && auth.can(entity, date, right) {
                return true;
            }
        }
        false
    }
}

#[derive(Default)]
pub struct Authorisation {
    users: HashMap<Vec<u8>, Option<i64>>,
    credential: Vec<Credential>,
}
impl Authorisation {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
    pub fn set_credential(&mut self, cred: Credential) -> Result<()> {
        let date = cred.valid_from;
        if let Some(last) = self.credential.last() {
            if last.valid_from >= date {
                return Err(Error::InvalidCredentialDate());
            }
        }
        self.credential.push(cred);
        Ok(())
    }

    pub fn get_credential_at(&self, date: i64) -> Option<&Credential> {
        self.credential
            .iter()
            .rev()
            .find(|&cred| cred.valid_from <= date)
    }

    pub fn is_user_valid_at(&self, user: &Vec<u8>, date: i64) -> bool {
        if let Some(val) = self.users.get(user) {
            if let Some(validity) = val {
                *validity >= date
            } else {
                true
            }
        } else {
            false
        }
    }

    pub fn disable_user_starting_at(&mut self, user: &Vec<u8>, date: i64) -> Result<()> {
        if let Some(u) = self.users.get(user) {
            if let Some(old) = u {
                if *old > date {
                    return Err(Error::UserAllreadyDisabled());
                }
            }
            self.users.insert(user.clone(), Some(date));
        }
        Ok(())
    }

    pub fn enable_user(&mut self, user: &Vec<u8>) {
        self.users.insert(user.clone(), None);
    }

    pub fn can(&self, entity: &str, date: i64, right: &RightType) -> bool {
        for cred in self.credential.iter().rev() {
            if cred.valid_from <= date {
                match right {
                    RightType::MutateRoom => return cred.mutate_room,
                    RightType::MutateRoomUsers => return cred.mutate_room_users,
                    RightType::Insert | RightType::DeleteAll | RightType::MutateAll => {}
                }

                if let Some(cred) = cred.credentials.get(entity) {
                    match right {
                        RightType::Insert => return cred.insert,
                        RightType::DeleteAll => return cred.delete_all,
                        RightType::MutateAll => return cred.mutate_all,
                        RightType::MutateRoom | RightType::MutateRoomUsers => {}
                    }
                }
            }
        }
        false
    }
}

#[derive(Default)]
pub struct Credential {
    pub valid_from: i64,
    pub mutate_room: bool,
    pub mutate_room_users: bool,
    pub credentials: HashMap<String, EntityRight>,
}
impl Credential {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
    pub fn add_entity_rights(&mut self, name: &str, entity_right: EntityRight) -> Result<()> {
        if self.credentials.get(name).is_some() {
            return Err(Error::AuthorisationExists(name.to_string()));
        }
        self.credentials.insert(name.to_string(), entity_right);
        Ok(())
    }
}

pub struct EntityRight {
    pub insert: bool,
    pub delete_all: bool,
    pub mutate_all: bool,
}

#[derive(Debug)]
pub enum RightType {
    Insert,
    DeleteAll,
    MutateAll,
    MutateRoom,
    MutateRoomUsers,
}
impl fmt::Display for RightType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(test)]
mod tests {

    use crate::cryptography::{now, random_secret};

    use super::*;

    pub const USER1: &'static str = "cAH9ZO7FMgNhdaEpVLQbmQMb8gI-92d-b6wtTQbSLsw";
    pub const USER2: &'static str = "Vd5TCzm0QfQVWpsq47IIC6nKNIkCBw9PHnfJ4eX3HL4";
    pub const USER3: &'static str = "eNDCXC4jToBqPz5-pcobB7tQPlIMexYp-wUk9v2gIlY";

    #[test]
    fn test_mutate_room() {
        let user1 = random_secret().to_vec();

        let mut room = Room::new();
        let mut auth = Authorisation::new();
        auth.enable_user(&user1);
        let mut cred1 = Credential::new();
        cred1.valid_from = 1000;
        cred1.mutate_room = true;
        cred1.mutate_room_users = true;

        auth.set_credential(cred1).unwrap();

        let mut cred2 = Credential::new();
        cred2.valid_from = 1000;

        auth.set_credential(cred2).expect_err(
            "Cannot insert a new credential with a from_date lower or equal to the last one",
        );

        let mut cred2 = Credential::new();
        cred2.valid_from = 2000;
        cred2.mutate_room = false;
        cred2.mutate_room_users = false;

        auth.set_credential(cred2).unwrap();

        assert!(!auth.can("", 10, &RightType::MutateRoom));
        assert!(!auth.can("", 10, &RightType::MutateRoomUsers));
        assert!(auth.can("", 1000, &RightType::MutateRoom));
        assert!(auth.can("", 1000, &RightType::MutateRoomUsers));
        assert!(auth.can("", 1500, &RightType::MutateRoom));
        assert!(auth.can("", 1500, &RightType::MutateRoomUsers));
        assert!(!auth.can("", 2000, &RightType::MutateRoom));
        assert!(!auth.can("", 2000, &RightType::MutateRoomUsers));
        assert!(!auth.can("", now(), &RightType::MutateRoom));
        assert!(!auth.can("", now(), &RightType::MutateRoomUsers));

        assert!(auth.is_user_valid_at(&user1, 1500));

        auth.disable_user_starting_at(&user1, 1500).unwrap();
        auth.disable_user_starting_at(&user1, 1000)
            .expect_err("cannot set a user validity date to a lower value than the current one");
        assert!(auth.is_user_valid_at(&user1, 1400));
        assert!(!auth.is_user_valid_at(&user1, 1501));

        room.add_auth("admin", auth).unwrap();
        room.add_auth("admin", Authorisation::new())
            .expect_err("cannot insert twice");

        assert!(!room.can(&user1, "", 10, &RightType::MutateRoom));
        assert!(room.can(&user1, "", 1400, &RightType::MutateRoom));
        assert!(!room.can(&user1, "", 1501, &RightType::MutateRoom));
    }

    #[test]
    fn test_entity_right() {
        let user1 = random_secret().to_vec();

        let mut room = Room::new();
        let mut auth = Authorisation::new();
        auth.enable_user(&user1);
        let mut cred1 = Credential::new();
        cred1.valid_from = 1000;
        cred1
            .add_entity_rights(
                "Person",
                EntityRight {
                    insert: true,
                    delete_all: true,
                    mutate_all: true,
                },
            )
            .unwrap();
        cred1
            .add_entity_rights(
                "Pet",
                EntityRight {
                    insert: false,
                    delete_all: false,
                    mutate_all: false,
                },
            )
            .unwrap();

        cred1
            .add_entity_rights(
                "Pet",
                EntityRight {
                    insert: false,
                    delete_all: false,
                    mutate_all: false,
                },
            )
            .expect_err("cannot insert twice");

        auth.set_credential(cred1).unwrap();
        room.add_auth("user", auth).unwrap();

        assert!(!room.can(&user1, "Person", 0, &RightType::DeleteAll));
        assert!(!room.can(&user1, "Person", 0, &RightType::Insert));
        assert!(!room.can(&user1, "Person", 0, &RightType::MutateAll));

        assert!(room.can(&user1, "Person", 1000, &RightType::DeleteAll));
        assert!(room.can(&user1, "Person", 1000, &RightType::Insert));
        assert!(room.can(&user1, "Person", 1000, &RightType::MutateAll));

        assert!(!room.can(&user1, "Pet", 1000, &RightType::DeleteAll));
        assert!(!room.can(&user1, "Pet", 1000, &RightType::Insert));
        assert!(!room.can(&user1, "Pet", 1000, &RightType::MutateAll));

        let user2 = random_secret().to_vec();
        assert!(!room.can(&user2, "Person", 1000, &RightType::DeleteAll));
        assert!(!room.can(&user2, "Person", 1000, &RightType::Insert));
        assert!(!room.can(&user2, "Person", 1000, &RightType::MutateAll));
    }
}
