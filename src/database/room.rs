use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use crate::security::{base64_decode, uid_decode, Uid};

use super::{
    system_entities::{self, AUTH_RIGHTS_FIELD, AUTH_USER_FIELD, ID_FIELD, MODIFICATION_DATE_FIELD},
    Error, Result,
};

///
/// Room is the root of the authorisation model
///
/// Every entity instance are linked to one or more Rooms that defines who can access and modify the data.
/// During peer to peer synchronisation, Rooms are used to determine which data will be synchronized with whom.
///
/// Room is comprised of a number of authorisation group, each group defines different access rights.
/// Users can belong to several authorisation group
///
///
#[derive(Default, Clone, Debug)]
pub struct Room {
    pub id: Uid,
    pub mdate: i64,
    pub admins: HashMap<Vec<u8>, Vec<User>>,
    pub user_admins: HashMap<Vec<u8>, Vec<User>>,
    pub authorisations: HashMap<Uid, Authorisation>,
}

impl Room {
    pub fn add_auth(&mut self, auth: Authorisation) -> Result<()> {
        if self.authorisations.get(&auth.id).is_some() {
            return Err(Error::AuthorisationExists());
        }
        self.authorisations.insert(auth.id.clone(), auth);
        Ok(())
    }

    pub fn get_auth(&self, id: &Uid) -> Option<&Authorisation> {
        self.authorisations.get(id)
    }

    pub fn get_auth_mut(&mut self, id: &Uid) -> Option<&mut Authorisation> {
        self.authorisations.get_mut(id)
    }

    pub fn add_admin_user(&mut self, user: User) -> Result<()> {
        let entry = self.admins.entry(user.verifying_key.clone()).or_default();

        if let Some(last_user) = entry.last() {
            if last_user.date > user.date {
                return Err(Error::InvalidUserDate());
            }
        }
        entry.push(user);
        Ok(())
    }

    pub fn is_admin(&self, user: &Vec<u8>, date: i64) -> bool {
        if let Some(val) = self.admins.get(user) {
            let user_opt = val.iter().rev().find(|&user| user.date <= date);
            match user_opt {
                Some(user) => user.enabled,
                None => false,
            }
        } else {
            false
        }
    }

    pub fn add_user_admin_user(&mut self, user: User) -> Result<()> {
        let entry = self
            .user_admins
            .entry(user.verifying_key.clone())
            .or_default();

        if let Some(last_user) = entry.last() {
            if last_user.date > user.date {
                return Err(Error::InvalidUserDate());
            }
        }
        entry.push(user);
        Ok(())
    }

    pub fn is_user_admin(&self, user: &Vec<u8>, date: i64) -> bool {
        if let Some(val) = self.user_admins.get(user) {
            let user_opt = val.iter().rev().find(|&user| user.date <= date);
            match user_opt {
                Some(user) => user.enabled,
                None => false,
            }
        } else {
            false
        }
    }

    pub fn is_user_valid_at(&self, verifying_key: &Vec<u8>, date: i64) -> bool {
        if let Some(users) = self.admins.get(verifying_key) {
            println!("have");
            let user_opt = users.iter().rev().find(|&user| user.date <= date);
            if let Some(user) = user_opt {
                if user.enabled {
                    return true;
                }
            }
        }

        if let Some(users) = self.user_admins.get(verifying_key) {
            let user_opt = users.iter().rev().find(|&user| user.date <= date);
            if let Some(user) = user_opt {
                if user.enabled {
                    return true;
                }
            }
        }

        for entry in &self.authorisations {
            let auth = entry.1;
            if auth.is_user_valid_at(verifying_key, date) {
                return true;
            }
        }
        false
    }

    pub fn has_user(&self, user: &Vec<u8>) -> bool {
        for entry in &self.authorisations {
            let auth = entry.1;
            if auth.has_user(user) {
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

    pub fn users(&self) -> HashSet<Vec<u8>> {
        let mut user_set = HashSet::new();
        for users in &self.admins {
            for user in users.1 {
                user_set.insert(user.verifying_key.clone());
            }
        }
        for users in &self.user_admins {
            for user in users.1 {
                user_set.insert(user.verifying_key.clone());
            }
        }
        for entry in &self.authorisations {
            entry.1.get_users(&mut user_set);
        }
        user_set
    }
}

///
/// Authorisation for a room,
/// mdate: used to allow name change at the database level
/// users: list of allowed user. each user can have several entries allowing to enable disable user. To maintain history consistency users definitions are never deleted
/// rights: list of per-entity access rights.
///
#[derive(Default, Clone, Debug)]
pub struct Authorisation {
    pub id: Uid,
    pub mdate: i64,
    pub users: HashMap<Vec<u8>, Vec<User>>,
    pub rights: HashMap<String, Vec<EntityRight>>,
}

impl Authorisation {
    pub fn add_right(&mut self, right: EntityRight) -> Result<()> {
        let entry = self.rights.entry(right.entity.clone()).or_default();

        let date = right.valid_from;
        if let Some(last) = entry.last() {
            if last.valid_from > date {
                return Err(Error::InvalidRightDate());
            }
        }
        entry.push(right);
        Ok(())
    }

    pub fn get_right_at(&self, entity: &str, date: i64) -> Option<&EntityRight> {
        match self.rights.get(entity) {
            Some(entries) => entries.iter().rev().find(|&cred| cred.valid_from <= date),
            None => None,
        }
    }

    pub fn has_user(&self, user: &Vec<u8>) -> bool {
        self.users.get(user).is_some()
    }

    pub fn add_user(&mut self, user: User) -> Result<()> {
        let entry = self.users.entry(user.verifying_key.clone()).or_default();
        if let Some(last_user) = entry.last() {
            if last_user.date > user.date {
                return Err(Error::InvalidUserDate());
            }
        }
        entry.push(user);
        Ok(())
    }

    pub fn is_user_valid_at(&self, user: &Vec<u8>, date: i64) -> bool {
        if let Some(val) = self.users.get(user) {
            let user_opt = val.iter().rev().find(|&user| user.date <= date);
            match user_opt {
                Some(user) => user.enabled,
                None => false,
            }
        } else {
            false
        }
    }

    pub fn can(&self, entity: &str, date: i64, right: &RightType) -> bool {
        match self.get_right_at(entity, date) {
            Some(entity_right) => match right {
                RightType::MutateSelf => entity_right.mutate_self,
                RightType::MutateAll => entity_right.mutate_all,
            },
            None => false,
        }
    }

    pub fn get_users(&self, user_set: &mut HashSet<Vec<u8>>) {
        for entry in &self.users {
            for user in entry.1 {
                user_set.insert(user.verifying_key.clone());
            }
        }
    }
}

///
/// user definition used by the authorisation model. can be enabled or disabled
/// date stores the begining of validity of the user
///
#[derive(Default, Clone, Debug)]
pub struct User {
    pub verifying_key: Vec<u8>,
    pub date: i64,
    pub enabled: bool,
}

///
/// Entity Rights definition for an entity. Cannot be mutated to preserve history consistency
///
/// entity: name of the entity
///
/// mutate_self:
///  - true: can create/mutate/delete your own entity
///  - false: read only, cannot create or mutate entity
///
/// mutate_all:
///  - true: can mutate/delete any entity of the specified type
///  - false: can only mutate its own entity
#[derive(Default, Clone, Debug)]
pub struct EntityRight {
    valid_from: i64,
    entity: String,
    mutate_self: bool,
    mutate_all: bool,
}
impl EntityRight {
    pub fn new(valid_from: i64, entity: String, mutate_self: bool, mutate_all: bool) -> Self {
        // mutate_all:true cannot have mutate_self:false
        // overide the mutate_self value in that case
        let mut mutate_self = mutate_self;
        if mutate_all {
            mutate_self = true;
        }
        Self {
            valid_from,
            entity,
            mutate_self,
            mutate_all,
        }
    }
}

///
/// Helper enum that define every rights
///
#[derive(Debug)]
pub enum RightType {
    MutateSelf,
    MutateAll,
}
impl fmt::Display for RightType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub fn load_auth_from_json(value: &serde_json::Value) -> Result<Authorisation> {
    let auth_map = value.as_object().unwrap();
    let id = uid_decode(auth_map.get(ID_FIELD).unwrap().as_str().unwrap())?;

    let mdate = auth_map
        .get(MODIFICATION_DATE_FIELD)
        .unwrap()
        .as_i64()
        .unwrap();
    let mut authorisation = Authorisation {
        id,
        mdate,
        users: HashMap::new(),
        rights: HashMap::new(),
    };

    let user_array = auth_map.get(AUTH_USER_FIELD).unwrap().as_array().unwrap();
    for user_value in user_array {
        let user = load_user_from_json(user_value)?;
        authorisation.add_user(user)?;
    }

    let right_array = auth_map.get(AUTH_RIGHTS_FIELD).unwrap().as_array().unwrap();
    for right_value in right_array {
        let right_map = right_value.as_object().unwrap();
        let valid_from = right_map.get("mdate").unwrap().as_i64().unwrap();

        let entity = right_map
            .get("entity")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let mutate_self = right_map.get("mutate_self").unwrap().as_bool().unwrap();
        let mutate_all = right_map.get("mutate_all").unwrap().as_bool().unwrap();
        let right = EntityRight {
            valid_from,
            entity,
            mutate_self,
            mutate_all,
        };
        authorisation.add_right(right)?;
    }

    Ok(authorisation)
}

pub fn load_user_from_json(user_value: &serde_json::Value) -> Result<User> {
    let user_map = user_value.as_object().unwrap();
    let date = user_map
        .get(MODIFICATION_DATE_FIELD)
        .unwrap()
        .as_i64()
        .unwrap();
    let enabled = user_map.get("enabled").unwrap().as_bool().unwrap();
    let verifying_key = base64_decode(
        user_map
            .get("verifying_key")
            .unwrap()
            .as_str()
            .unwrap()
            .as_bytes(),
    )?;
    let user = User {
        verifying_key,
        date,
        enabled,
    };
    Ok(user)
}

pub fn user_from_json(json: &str, date: i64) -> Result<User> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    let map = value
        .as_object()
        .ok_or(Error::InvalidJsonObject("User".to_string()))?;

    let verifying_key = map
        .get(system_entities::USER_VERIFYING_KEY_SHORT)
        .ok_or(Error::MissingJsonField("User.verifying_key".to_string()))?;
    let verifying_key = verifying_key
        .as_str()
        .ok_or(Error::MissingJsonField("User.verifying_key".to_string()))?;
    let verifying_key = base64_decode(verifying_key.as_bytes())?;

    let enabled = match map.get(system_entities::USER_ENABLED_SHORT) {
        Some(value) => value.as_bool().unwrap_or(true),
        None => true,
    };

    Ok(User {
        verifying_key,
        date,
        enabled,
    })
}

pub fn entity_right_from_json(valid_from: i64, json: &str) -> Result<EntityRight> {
    let value: serde_json::Value = serde_json::from_str(json)?;

    let map = value
        .as_object()
        .ok_or(Error::InvalidJsonObject("EntityRight".to_string()))?;

    let entity = map
        .get(system_entities::RIGHT_ENTITY_SHORT)
        .ok_or(Error::MissingJsonField("EntityRight.entity".to_string()))?;
    let entity = entity
        .as_str()
        .ok_or(Error::MissingJsonField("EntityRight.entity".to_string()))?;

    let mutate_self =
        map.get(system_entities::RIGHT_MUTATE_SELF_SHORT)
            .ok_or(Error::MissingJsonField(
                "EntityRight.mutate_self".to_string(),
            ))?;
    let mutate_self = mutate_self.as_bool().ok_or(Error::MissingJsonField(
        "EntityRight.mutate_self".to_string(),
    ))?;

    let mutate_all =
        map.get(system_entities::RIGHT_MUTATE_ALL_SHORT)
            .ok_or(Error::MissingJsonField(
                "EntityRight.mutate_self".to_string(),
            ))?;
    let mutate_all = mutate_all.as_bool().ok_or(Error::MissingJsonField(
        "EntityRight.mutate_self".to_string(),
    ))?;

    Ok(EntityRight::new(
        valid_from,
        entity.to_string(),
        mutate_self,
        mutate_all,
    ))
}
