use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use tokio::sync::{mpsc, oneshot::Sender};

use crate::cryptography::{base64_decode, base64_encode, now, Ed25519SigningKey, SigningKey};

use super::{
    configuration::{self, AUTH_CRED_FIELD, AUTH_USER_FIELD, ROOM_ENT},
    mutation_query::{InsertEntity, MutationQuery},
    sqlite_database::{BufferedDatabaseWriter, WriteMessage, Writeable},
    Error, Result,
};

#[derive(Default, Clone)]
pub struct Room {
    id: Vec<u8>,
    pub parent: HashSet<Vec<u8>>,
    pub authorisations: HashMap<Vec<u8>, Authorisation>,
}

impl Room {
    pub fn add_auth(&mut self, id: Vec<u8>, auth: Authorisation) -> Result<()> {
        if self.authorisations.get(&id).is_some() {
            return Err(Error::AuthorisationExists());
        }
        self.authorisations.insert(id, auth);
        Ok(())
    }

    pub fn get_auth(&self, id: &Vec<u8>) -> Option<&Authorisation> {
        self.authorisations.get(id)
    }

    pub fn get_auth_mut(&mut self, id: &Vec<u8>) -> Option<&mut Authorisation> {
        self.authorisations.get_mut(id)
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
}

#[derive(Default, Clone)]
pub struct Authorisation {
    users: HashMap<Vec<u8>, Option<i64>>,
    credential: Vec<Credential>,
}

impl Authorisation {
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

    pub fn has_user(&self, user: &Vec<u8>) -> bool {
        if let Some(_) = self.users.get(user) {
            true
        } else {
            false
        }
    }

    pub fn set_user(&mut self, user: Vec<u8>, date: Option<i64>) -> Result<()> {
        match date {
            Some(date) => {
                self.disable_user_starting_at(user, date)?;
            }
            None => {
                self.enable_user(user);
            }
        }
        Ok(())
    }

    pub fn disable_user_starting_at(&mut self, user: Vec<u8>, date: i64) -> Result<()> {
        if let Some(u) = self.users.get(&user) {
            if let Some(old) = u {
                if *old > date {
                    return Err(Error::UserAlreadyDisabled());
                }
            }
        }
        self.users.insert(user, Some(date));
        Ok(())
    }

    pub fn enable_user(&mut self, user: Vec<u8>) {
        self.users.insert(user, None);
    }

    pub fn can(&self, entity: &str, date: i64, right: &RightType) -> bool {
        for cred in self.credential.iter().rev() {
            if cred.valid_from <= date {
                match right {
                    RightType::MutateRoom => return cred.mutate_room,
                    RightType::MutateRoomUsers => return cred.mutate_room_users,
                    RightType::Insert | RightType::DeleteAll | RightType::MutateAll => {}
                }

                if let Some(cred) = cred.entity_rights.get(entity) {
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

#[derive(Default, Clone)]
pub struct Credential {
    pub id: Vec<u8>,
    pub valid_from: i64,
    pub mutate_room: bool,
    pub mutate_room_users: bool,
    pub entity_rights: HashMap<String, EntityRight>,
}
impl Credential {
    pub fn add_entity_rights(&mut self, name: &str, entity_right: EntityRight) -> Result<()> {
        if self.entity_rights.get(name).is_some() {
            return Err(Error::RightsExists(name.to_string()));
        }
        self.entity_rights.insert(name.to_string(), entity_right);
        Ok(())
    }
}

#[derive(Default, Clone)]
pub struct EntityRight {
    pub entity: String,
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

pub enum AuthorisationMessage {
    MutationQuery(
        MutationQuery,
        BufferedDatabaseWriter,
        Sender<super::Result<MutationQuery>>,
    ),
    RoomMutationQuery(Result<()>, RoomMutationQuery),
}
pub struct RoomMutationQuery {
    mutation_query: MutationQuery,
    reply: Sender<super::Result<MutationQuery>>,
}
impl Writeable for RoomMutationQuery {
    fn write(&self, conn: &rusqlite::Connection) -> std::result::Result<(), rusqlite::Error> {
        self.mutation_query.write(conn)
    }
}

#[derive(Clone)]
pub struct AuthorisationService {
    sender: mpsc::Sender<AuthorisationMessage>,
}
impl AuthorisationService {
    pub fn start(signing_key: Ed25519SigningKey) -> Self {
        let (sender, mut receiver) = mpsc::channel::<AuthorisationMessage>(100);
        let mut auth = RoomAuthorisations {
            signing_key,
            rooms: HashMap::new(),
        };
        let self_sender = sender.clone();
        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                match msg {
                    AuthorisationMessage::MutationQuery(
                        mut mutation_query,
                        database_writer,
                        reply,
                    ) => {
                        let need_room_insert = match auth.validate_mutation(&mut mutation_query) {
                            Ok(has_room) => has_room,
                            Err(e) => {
                                let _ = reply.send(Err(e));
                                continue;
                            }
                        };
                        if need_room_insert {
                            let query = WriteMessage::RoomMutationQuery(
                                RoomMutationQuery {
                                    mutation_query,
                                    reply,
                                },
                                self_sender.clone(),
                            );
                            let _ = database_writer.send(query).await;
                        } else {
                            let query = WriteMessage::MutationQuery(mutation_query, reply);
                            let _ = database_writer.send(query).await;
                        }
                    }
                    AuthorisationMessage::RoomMutationQuery(result, query) => match result {
                        Ok(_) => {
                            //Create and update rooms
                            // auth.mutate_rooms(&query.mutation_query);
                            //
                            let _ = query.reply.send(Ok(query.mutation_query));
                        }
                        Err(e) => {
                            let _ = query.reply.send(Err(e));
                        }
                    },
                }
            }
        });

        Self { sender }
    }

    ///
    /// send message without waiting for the query to finish
    ///
    pub async fn send(&self, msg: AuthorisationMessage) -> Result<()> {
        self.sender
            .send(msg)
            .await
            .map_err(|e| Error::ChannelSend(e.to_string()))
    }

    ///
    /// send message without waiting for the query to finish
    ///
    pub fn send_blocking(&self, msg: AuthorisationMessage) -> Result<()> {
        self.sender
            .blocking_send(msg)
            .map_err(|e| Error::ChannelSend(e.to_string()))
    }
}

struct RoomAuthorisations {
    signing_key: Ed25519SigningKey,
    rooms: HashMap<Vec<u8>, Room>,
}
impl RoomAuthorisations {
    pub fn validate_mutation(&mut self, mutation_query: &mut MutationQuery) -> Result<bool> {
        //  println!("Hello");
        mutation_query.sign_all(&self.signing_key)?;
        let mut has_room_mutation = false;
        for insert_entity in &mutation_query.insert_entities {
            if self.validate_insert_entity(insert_entity)? {
                has_room_mutation = true;
            }
        }
        Ok(has_room_mutation)
    }

    pub fn validate_insert_entity(&self, insert_entity: &InsertEntity) -> Result<bool> {
        let to_insert = &insert_entity.node_insert;
        let mut has_room_mutation = false;
        if let Some(node) = &to_insert.node {
            match to_insert.entity.as_str() {
                configuration::ROOM_ENT => {
                    self.validate_room_mutation(insert_entity)?;
                    has_room_mutation = true;
                }
                configuration::AUTHORISATION_ENT
                | configuration::CREDENTIAL_ENT
                | configuration::ENTITY_RIGHT_ENT
                | configuration::USER_AUTH_ENT => {
                    return Err(Error::InvalidAuthorisationMutation(
                        to_insert.entity.clone(),
                    ))
                }
                _ => {
                    match &to_insert.old_node {
                        Some(old_node) => {
                            let same_user = old_node._verifying_key.eq(&node._verifying_key);
                            for room_id in &to_insert.rooms {
                                if let Some(room) = self.rooms.get(room_id) {
                                    let can = if same_user {
                                        room.can(
                                            &node._verifying_key,
                                            &to_insert.entity,
                                            node.mdate,
                                            &RightType::Insert,
                                        )
                                    } else {
                                        room.can(
                                            &node._verifying_key,
                                            &to_insert.entity,
                                            node.mdate,
                                            &RightType::MutateAll,
                                        )
                                    };
                                    if !can {
                                        return Err(Error::AuthorisationRejected(
                                            to_insert.entity.clone(),
                                            base64_encode(&room_id),
                                        ));
                                    }
                                } else {
                                    return Err(Error::UnknownRoom(base64_encode(room_id)));
                                }
                            }

                            //
                            // add author edge
                            //
                        }
                        None => {
                            for room_id in &to_insert.rooms {
                                if let Some(room) = self.rooms.get(room_id) {
                                    let can = room.can(
                                        &node._verifying_key,
                                        &to_insert.entity,
                                        node.mdate,
                                        &RightType::Insert,
                                    );
                                    if !can {
                                        return Err(Error::AuthorisationRejected(
                                            to_insert.entity.clone(),
                                            base64_encode(&room_id),
                                        ));
                                    }
                                } else {
                                    return Err(Error::UnknownRoom(base64_encode(room_id)));
                                }
                            }
                        }
                    }

                    for entry in &insert_entity.sub_nodes {
                        for insert_entity in entry.1 {
                            if self.validate_insert_entity(insert_entity)? {
                                has_room_mutation = true;
                            }
                        }
                    }
                }
            }
        }

        Ok(has_room_mutation)
    }

    pub fn validate_room_mutation(&self, insert_entity: &InsertEntity) -> Result<()> {
        let node_insert = &insert_entity.node_insert;

        if !insert_entity.edge_deletions.is_empty() {
            return Err(Error::CannotRemove(
                "authorisations".to_string(),
                ROOM_ENT.to_string(),
            ));
        }

        let new_node = match &node_insert.node {
            Some(node) => node,
            None => return Ok(()),
        };

        let mut room = match &node_insert.old_node {
            Some(old_node) => {
                if let Some(room) = self.rooms.get(&old_node.id) {
                    if !room.can(
                        &new_node._verifying_key,
                        "",
                        new_node.mdate,
                        &RightType::MutateRoom,
                    ) {
                        return Err(Error::AuthorisationRejected(
                            node_insert.entity.clone(),
                            base64_encode(&old_node.id),
                        ));
                    }

                    room.clone()
                } else {
                    return Err(Error::UnknownRoom(base64_encode(&old_node.id)));
                }
            }
            None => {
                for room_id in &node_insert.rooms {
                    if let Some(room) = self.rooms.get(room_id) {
                        if !room.can(
                            &new_node._verifying_key,
                            ROOM_ENT,
                            new_node.mdate,
                            &RightType::Insert,
                        ) {
                            return Err(Error::AuthorisationRejected(
                                node_insert.entity.clone(),
                                base64_encode(&room_id),
                            ));
                        }
                    } else {
                        return Err(Error::UnknownRoom(base64_encode(room_id)));
                    }
                }

                let mut room = Room::default();
                room.id = node_insert.id.clone();
                room.parent.extend(node_insert.rooms.clone());
                room
            }
        };

        let mut need_room_mutation = false;
        let mut need_user_mutation = false;

        for authorisation in &insert_entity.sub_nodes {
            for auth in authorisation.1 {
                let rigigt = self.validate_authorisation_mutation(&mut room, auth)?;
                if rigigt.0 {
                    need_room_mutation = true;
                }
                if rigigt.1 {
                    need_user_mutation = true;
                }
            }
        }

        //check if user can mutate the room after inserti
        let verifying_key = self.signing_key.export_verifying_key();
        if need_room_mutation {
            if !room.can(&verifying_key, "", now(), &RightType::MutateRoom) {
                return Err(Error::AuthorisationRejected(
                    node_insert.entity.clone(),
                    base64_encode(&room.id),
                ));
            }
        }

        if need_user_mutation {
            if !room.can(&verifying_key, "", now(), &RightType::MutateRoomUsers) {
                return Err(Error::AuthorisationRejected(
                    node_insert.entity.clone(),
                    base64_encode(&room.id),
                ));
            }
        }
        Ok(())
    }

    fn validate_authorisation_mutation(
        &self,
        room: &mut Room,
        insert_entity: &InsertEntity,
    ) -> Result<(bool, bool)> {
        if !insert_entity.edge_deletions.is_empty() {
            return Err(Error::CannotRemove(
                "authorisations".to_string(),
                ROOM_ENT.to_string(),
            ));
        }
        let room_user = &room.clone();
        let node_insert = &insert_entity.node_insert;

        //verify that the passed authentication belongs to the room
        let authorisation = match &node_insert.node {
            Some(_) => match room.get_auth_mut(&node_insert.id) {
                Some(au) => au,
                None => match node_insert.old_node {
                    Some(_) => return Err(Error::NotBelongsTo()),
                    None => {
                        let authorisation = Authorisation::default();
                        room.add_auth(node_insert.id.clone(), authorisation)?;
                        room.get_auth_mut(&node_insert.id).unwrap()
                    }
                },
            },
            None => match room.get_auth_mut(&node_insert.id) {
                Some(au) => au,
                None => return Err(Error::NotBelongsTo()),
            },
        };

        let mut need_user_mutation = false;
        let mut need_room_mutation = false;

        for entry in &insert_entity.sub_nodes {
            match entry.0.as_str() {
                AUTH_CRED_FIELD => {
                    need_room_mutation = true;
                    //cred exists check validity
                    //
                    for insert_entity in entry.1 {
                        if !insert_entity.edge_deletions.is_empty() {
                            return Err(Error::CannotRemove(
                                "Credential".to_string(),
                                ROOM_ENT.to_string(),
                            ));
                        }
                        let node_insert = &insert_entity.node_insert;
                        if authorisation.credential.is_empty() {
                            if node_insert.node.is_none() || node_insert.old_node.is_some() {
                                return Err(Error::NotBelongsTo());
                            }
                            if let Some(node) = &node_insert.node {
                                if let Some(json) = &node._json {
                                    let mut credential = Credential::default();
                                    credential_from(json, &mut credential)?;
                                }
                            }
                        } else {
                            let last_auth = authorisation.credential.last().unwrap();
                            if !last_auth.id.eq(&node_insert.id) {
                                return Err(Error::NotBelongsTo());
                            }
                            match &node_insert.node {
                                Some(node) => {
                                    if let Some(json) = &node._json {
                                        let mut credential = last_auth.clone();
                                        credential_from(json, &mut credential)?;
                                    }
                                }
                                None => {
                                    // let mut credential = last_auth.clone();
                                }
                            }
                        }
                    }
                }
                AUTH_USER_FIELD => {
                    need_user_mutation = true;
                    for insert_entity in entry.1 {
                        self.validate_user(insert_entity, room_user, authorisation)?;
                    }
                }
                _ => unreachable!(),
            }
        }

        // room.
        Ok((need_room_mutation, need_user_mutation))
    }

    fn validate_user(
        &self,
        insert_entity: &InsertEntity,
        room_user: &Room,
        authorisation: &mut Authorisation,
    ) -> Result<()> {
        let node_insert = &insert_entity.node_insert;
        if let Some(node) = &node_insert.node {
            if let Some(json) = &node._json {
                let user = user_from(json)?;
                if let Some(u) = user.0 {
                    if room_user.has_user(&u) {
                        authorisation.set_user(u, user.1)?;
                    } else if room_user.parent.is_empty() {
                        authorisation.set_user(u, user.1)?;
                    } else {
                        let mut found = false;
                        for parent_id in &room_user.parent {
                            if let Some(parent) = self.rooms.get(parent_id) {
                                if parent.has_user(&u) {
                                    authorisation.set_user(u.clone(), user.1)?;
                                    found = true;
                                }
                            }
                        }
                        if !found {
                            return Err(Error::UserNotInParentRoom(
                                base64_encode(&u),
                                base64_encode(&room_user.id),
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn user_from(json: &String) -> Result<(Option<Vec<u8>>, Option<i64>)> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    if let Some(map) = value.as_object() {
        if let Some(user) = map.get("user") {
            if let Some(base64) = user.as_str() {
                let user = base64_decode(base64.as_bytes())?;
                let valid = match map.get("valid_before") {
                    Some(value) => match value.as_i64() {
                        Some(v) => Some(v),
                        None => None,
                    },
                    None => None,
                };
                return Ok((Some(user), valid));
            }
        }
    }
    Ok((None, None))
}

fn credential_from(json: &String, credential: &mut Credential) -> Result<()> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    if let Some(map) = value.as_object() {
        if let Some(valid_from) = map.get("valid_from") {
            if let Some(valid_from) = valid_from.as_i64() {
                credential.valid_from = valid_from;
            }
        }
        if let Some(mutate_room) = map.get("mutate_room") {
            if let Some(mutate_room) = mutate_room.as_bool() {
                credential.mutate_room = mutate_room;
            }
        }

        if let Some(mutate_room_users) = map.get("mutate_room_users") {
            if let Some(mutate_room_users) = mutate_room_users.as_bool() {
                credential.mutate_room_users = mutate_room_users;
            }
        }
    }
    Ok(())
}

fn entity_right_from(json: &String) -> Result<EntityRight> {
    let mut entity_right = EntityRight::default();

    let value: serde_json::Value = serde_json::from_str(json)?;
    if let Some(map) = value.as_object() {
        if let Some(entity) = map.get("entity") {
            if let Some(entity) = entity.as_str() {
                entity_right.entity = entity.to_string();
            }
        }
        if let Some(insert) = map.get("insert") {
            if let Some(insert) = insert.as_bool() {
                entity_right.insert = insert;
            }
        }

        if let Some(mutate_all) = map.get("mutate_all") {
            if let Some(mutate_all) = mutate_all.as_bool() {
                entity_right.mutate_all = mutate_all;
            }
        }

        if let Some(delete_all) = map.get("delete_all") {
            if let Some(delete_all) = delete_all.as_bool() {
                entity_right.delete_all = delete_all;
            }
        }
    }
    Ok(entity_right)
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

        let mut room = Room::default();
        let mut auth = Authorisation::default();
        auth.enable_user(user1.clone());
        let mut cred1 = Credential::default();
        cred1.valid_from = 1000;
        cred1.mutate_room = true;
        cred1.mutate_room_users = true;

        auth.set_credential(cred1).unwrap();

        let mut cred2 = Credential::default();
        cred2.valid_from = 1000;

        auth.set_credential(cred2).expect_err(
            "Cannot insert a new credential with a from_date lower or equal to the last one",
        );

        let mut cred2 = Credential::default();
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

        auth.disable_user_starting_at(user1.clone(), 1500).unwrap();
        auth.disable_user_starting_at(user1.clone(), 1000)
            .expect_err("cannot set a user validity date to a lower value than the current one");
        assert!(auth.is_user_valid_at(&user1, 1400));
        assert!(!auth.is_user_valid_at(&user1, 1501));

        let authorisation_id = random_secret().to_vec();
        room.add_auth(authorisation_id.clone(), auth).unwrap();
        room.add_auth(authorisation_id, Authorisation::default())
            .expect_err("cannot insert twice");

        assert!(!room.can(&user1, "", 10, &RightType::MutateRoom));
        assert!(room.can(&user1, "", 1400, &RightType::MutateRoom));
        assert!(!room.can(&user1, "", 1501, &RightType::MutateRoom));
    }

    #[test]
    fn test_entity_right() {
        let user1 = random_secret().to_vec();

        let mut room = Room::default();
        let mut auth = Authorisation::default();
        auth.enable_user(user1.clone());
        let mut cred1 = Credential::default();
        cred1.valid_from = 1000;
        cred1
            .add_entity_rights(
                "Person",
                EntityRight {
                    entity: "Person".to_string(),
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
                    entity: "Pet".to_string(),
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
                    entity: "Pet".to_string(),
                    insert: false,
                    delete_all: false,
                    mutate_all: false,
                },
            )
            .expect_err("cannot insert twice");

        auth.set_credential(cred1).unwrap();
        let authorisation_id = random_secret().to_vec();
        room.add_auth(authorisation_id, auth).unwrap();

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
