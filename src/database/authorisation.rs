use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use tokio::sync::{mpsc, oneshot::Sender};

use crate::{
    cryptography::{base64_decode, base64_encode, now, Ed25519SigningKey, SigningKey},
    database::configuration::{ID_FIELD, MODIFICATION_DATE_FIELD, ROOMS_FIELD},
};

use super::{
    configuration::{self, AUTH_CRED_FIELD, AUTH_USER_FIELD, ROOM_ENT},
    deletion::DeletionQuery,
    mutation_query::{InsertEntity, MutationQuery},
    sqlite_database::{BufferedDatabaseWriter, WriteMessage, Writeable},
    Error, Result,
};

#[derive(Default, Clone, Debug)]
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

#[derive(Default, Clone, Debug)]
pub struct User {
    pub verifying_key: Vec<u8>,
    pub date: i64,
    pub enabled: bool,
}

#[derive(Default, Clone, Debug)]
pub struct Authorisation {
    id: Vec<u8>,
    users: HashMap<Vec<u8>, Vec<User>>,
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

    pub fn has_user(&self, user: &Vec<u8>) -> bool {
        if let Some(_) = self.users.get(user) {
            true
        } else {
            false
        }
    }

    pub fn set_user(&mut self, user: User) -> Result<()> {
        let entry = self
            .users
            .entry(user.verifying_key.clone())
            .or_insert(Vec::new());

        if let Some(last_user) = entry.last() {
            if last_user.date >= user.date {
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
        for cred in self.credential.iter().rev() {
            if cred.valid_from <= date {
                match right {
                    RightType::MutateRoom => return cred.mutate_room,
                    RightType::MutateRoomUsers => return cred.mutate_room_users,
                    RightType::MutateSelf | RightType::DeleteAll | RightType::MutateAll => {}
                }

                if let Some(cred) = cred.rights.get(entity) {
                    match right {
                        RightType::MutateSelf => return cred.mutate_self,
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

#[derive(Default, Clone, Debug)]
pub struct Credential {
    pub valid_from: i64,
    pub mutate_room: bool,
    pub mutate_room_users: bool,
    pub rights: HashMap<String, EntityRight>,
}
impl Credential {
    pub fn add_entity_rights(&mut self, name: &str, entity_right: EntityRight) -> Result<()> {
        if self.rights.get(name).is_some() {
            return Err(Error::RightsExists(name.to_string()));
        }
        self.rights.insert(name.to_string(), entity_right);
        Ok(())
    }
}

#[derive(Default, Clone, Debug)]
pub struct EntityRight {
    pub entity: String,
    pub mutate_self: bool,
    pub delete_all: bool,
    pub mutate_all: bool,
}

#[derive(Debug)]
pub enum RightType {
    MutateSelf,
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
    DeletionQuery(
        DeletionQuery,
        BufferedDatabaseWriter,
        Sender<super::Result<DeletionQuery>>,
    ),
    Load(String, Sender<super::Result<()>>),
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
    pub fn start(mut auth: RoomAuthorisations) -> Self {
        let (sender, mut receiver) = mpsc::channel::<AuthorisationMessage>(100);

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
                            Ok(rooms) => {
                                if rooms.is_empty() {
                                    false
                                } else {
                                    true
                                }
                            }
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
                    AuthorisationMessage::RoomMutationQuery(result, mut query) => match result {
                        Ok(_) => {
                            match auth.validate_mutation(&mut query.mutation_query) {
                                Ok(rooms) => {
                                    for room in rooms {
                                        auth.add_room(room);
                                    }
                                    let _ = query.reply.send(Ok(query.mutation_query));
                                }
                                Err(e) => {
                                    let _ = query.reply.send(Err(e));
                                }
                            };
                        }
                        Err(e) => {
                            let _ = query.reply.send(Err(e));
                        }
                    },

                    AuthorisationMessage::Load(rooms, reply) => {
                        let res = auth.load(&rooms);
                        let _ = reply.send(res);
                    }

                    AuthorisationMessage::DeletionQuery(deletion_query, database_writer, reply) => {
                        match auth.validate_deletion(&deletion_query) {
                            Ok(_) => {
                                let query = WriteMessage::DeletionQuery(deletion_query, reply);
                                let _ = database_writer.send(query).await;
                            }
                            Err(e) => {
                                let _ = reply.send(Err(e));
                            }
                        }
                    }
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

pub struct RoomAuthorisations {
    pub signing_key: Ed25519SigningKey,
    pub rooms: HashMap<Vec<u8>, Room>,
}
impl RoomAuthorisations {
    pub fn add_room(&mut self, room: Room) {
        self.rooms.insert(room.id.clone(), room);
    }

    pub fn validate_deletion(&self, deletion_query: &DeletionQuery) -> Result<()> {
        let _verifying_key = self.signing_key.export_verifying_key();
        for node in &deletion_query.nodes {
            match node.name.as_str() {
                configuration::ROOM_ENT
                | configuration::AUTHORISATION_ENT
                | configuration::CREDENTIAL_ENT
                | configuration::ENTITY_RIGHT_ENT
                | configuration::USER_AUTH_ENT => return Err(Error::DeleteNotAllowed()),
                _ => {
                    for room_id in &node.rooms {
                        match self.rooms.get(room_id) {
                            Some(room) => {
                                let can = if node.verifying_key.eq(&_verifying_key) {
                                    room.can(
                                        &_verifying_key,
                                        &node.name,
                                        now(),
                                        &RightType::MutateSelf,
                                    )
                                } else {
                                    room.can(
                                        &_verifying_key,
                                        &node.name,
                                        now(),
                                        &RightType::DeleteAll,
                                    )
                                };
                                if !can {
                                    return Err(Error::AuthorisationRejected(
                                        node.name.clone(),
                                        base64_encode(&room_id),
                                    ));
                                }
                            }
                            None => return Err(Error::UnknownRoom(base64_encode(room_id))),
                        }
                    }
                }
            }
        }
        for edge in &deletion_query.edges {
            match edge.source_entity.as_str() {
                configuration::ROOM_ENT
                | configuration::AUTHORISATION_ENT
                | configuration::CREDENTIAL_ENT
                | configuration::ENTITY_RIGHT_ENT
                | configuration::USER_AUTH_ENT => return Err(Error::DeleteNotAllowed()),
                _ => {
                    for room_id in &edge.rooms {
                        match self.rooms.get(room_id) {
                            Some(room) => {
                                let can = if edge.verifying_key.eq(&_verifying_key) {
                                    room.can(
                                        &_verifying_key,
                                        &edge.source_entity,
                                        now(),
                                        &RightType::MutateSelf,
                                    )
                                } else {
                                    room.can(
                                        &_verifying_key,
                                        &edge.source_entity,
                                        now(),
                                        &RightType::DeleteAll,
                                    )
                                };
                                if !can {
                                    return Err(Error::AuthorisationRejected(
                                        edge.source_entity.clone(),
                                        base64_encode(&room_id),
                                    ));
                                }
                            }
                            None => return Err(Error::UnknownRoom(base64_encode(room_id))),
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn validate_mutation(&mut self, mutation_query: &mut MutationQuery) -> Result<Vec<Room>> {
        mutation_query.sign_all(&self.signing_key)?;

        let verifying_key = self.signing_key.export_verifying_key();
        let mut rooms = Vec::new();
        for insert_entity in &mut mutation_query.insert_entities {
            let mut rooms_ent = self.validate_insert_entity(insert_entity, &verifying_key)?;
            rooms.append(&mut rooms_ent);
        }
        Ok(rooms)
    }

    pub fn validate_insert_entity(
        &self,
        insert_entity: &mut InsertEntity,
        verifying_key: &Vec<u8>,
    ) -> Result<Vec<Room>> {
        let to_insert = &insert_entity.node_insert;
        let mut rooms = Vec::new();

        match to_insert.entity.as_str() {
            configuration::ROOM_ENT => {
                let room = self.validate_room_mutation(insert_entity, verifying_key)?;
                if let Some(room) = room {
                    rooms.push(room);
                }
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
                if let Some(node) = &to_insert.node {
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
                                            &RightType::MutateSelf,
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
                                //    println!("{}  {}", base64_encode(&room_id), to_insert.entity);
                                if let Some(room) = self.rooms.get(room_id) {
                                    let can = room.can(
                                        &node._verifying_key,
                                        &to_insert.entity,
                                        node.mdate,
                                        &RightType::MutateSelf,
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

                    for entry in &mut insert_entity.sub_nodes {
                        for insert_entity in entry.1 {
                            let mut room_ent =
                                self.validate_insert_entity(insert_entity, verifying_key)?;
                            rooms.append(&mut room_ent);
                        }
                    }
                }
            }
        }

        Ok(rooms)
    }

    pub fn validate_room_mutation(
        &self,
        insert_entity: &mut InsertEntity,
        verifying_key: &Vec<u8>,
    ) -> Result<Option<Room>> {
        let node_insert = &insert_entity.node_insert;

        if !insert_entity.edge_deletions.is_empty() {
            return Err(Error::CannotRemove(
                "authorisations".to_string(),
                ROOM_ENT.to_string(),
            ));
        }

        let mut room = match &node_insert.old_node {
            Some(old_node) => {
                if let Some(room) = self.rooms.get(&old_node.id) {
                    if !room.can(verifying_key, "", now(), &RightType::MutateRoom) {
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
                if node_insert.node.is_none() {
                    //no history, no node to insert, it is a reference
                    return Ok(None);
                }
                for room_id in &node_insert.rooms {
                    if let Some(room) = self.rooms.get(room_id) {
                        if !room.can(&verifying_key, ROOM_ENT, now(), &RightType::MutateSelf) {
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

        for authorisation in &mut insert_entity.sub_nodes {
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

        //println!("{:#?}", room);
        //check if user can mutate the room after inserti
        if need_room_mutation {
            //   println!("need_room_mutation {}", need_room_mutation);
            if !room.can(&verifying_key, "", now(), &RightType::MutateRoom) {
                return Err(Error::AuthorisationRejected(
                    node_insert.entity.clone(),
                    base64_encode(&room.id),
                ));
            }
        }

        if need_user_mutation {
            //     println!("need_user_mutation {}", need_user_mutation);
            if !room.can(&verifying_key, "", now(), &RightType::MutateRoomUsers) {
                return Err(Error::AuthorisationRejected(
                    node_insert.entity.clone(),
                    base64_encode(&room.id),
                ));
            }
        }
        Ok(Some(room))
    }

    fn validate_authorisation_mutation(
        &self,
        room: &mut Room,
        insert_entity: &mut InsertEntity,
    ) -> Result<(bool, bool)> {
        if !insert_entity.edge_deletions.is_empty() {
            return Err(Error::CannotRemove(
                "_Authorisation".to_string(),
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

                    for insert_entity in entry.1 {
                        if !insert_entity.edge_deletions.is_empty() {
                            return Err(Error::CannotRemove(
                                "_Credential".to_string(),
                                ROOM_ENT.to_string(),
                            ));
                        }
                        let node_insert = &insert_entity.node_insert;

                        if node_insert.node.is_none() || node_insert.old_node.is_some() {
                            return Err(Error::UpdateNotAllowed());
                        }
                        if let Some(node) = &node_insert.node {
                            if let Some(json) = &node._json {
                                let mut credential = Credential::default();
                                credential.valid_from = node.mdate;
                                credential_from(json, &mut credential)?;
                                self.validate_entity_rigths(insert_entity, &mut credential)?;
                                authorisation.set_credential(credential)?;
                            }
                        }
                    }
                }
                AUTH_USER_FIELD => {
                    need_user_mutation = true;
                    for insert_entity in entry.1 {
                        if !insert_entity.edge_deletions.is_empty() {
                            return Err(Error::CannotRemove(
                                "_UserAuth".to_string(),
                                ROOM_ENT.to_string(),
                            ));
                        }
                        if insert_entity.node_insert.node.is_none()
                            || insert_entity.node_insert.old_node.is_some()
                        {
                            return Err(Error::UpdateNotAllowed());
                        }
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
                let user = user_from(json, node.mdate)?;
                if let Some(u) = user {
                    if room_user.has_user(&u.verifying_key) || room_user.parent.is_empty() {
                        authorisation.set_user(u)?;
                    } else {
                        let mut found = false;
                        for parent_id in &room_user.parent {
                            if let Some(parent) = self.rooms.get(parent_id) {
                                if parent.has_user(&u.verifying_key) {
                                    authorisation.set_user(u.clone())?;
                                    found = true;
                                    break;
                                }
                            }
                        }
                        if !found {
                            return Err(Error::UserNotInParentRoom(
                                base64_encode(&u.verifying_key),
                                base64_encode(&room_user.id),
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_entity_rigths(
        &self,
        insert_entity: &InsertEntity,
        credential: &mut Credential,
    ) -> Result<()> {
        for entry in &insert_entity.sub_nodes {
            if !insert_entity.edge_deletions.is_empty() {
                return Err(Error::CannotRemove(
                    "_EntityRight".to_string(),
                    ROOM_ENT.to_string(),
                ));
            }
            for insert_entity in entry.1 {
                let node_insert = &insert_entity.node_insert;
                if node_insert.node.is_none() || node_insert.old_node.is_some() {
                    return Err(Error::UpdateNotAllowed());
                }
                if let Some(node) = &node_insert.node {
                    if let Some(json) = &node._json {
                        let cred = entity_right_from(json)?;
                        if !cred.entity.is_empty() {
                            credential.rights.insert(cred.entity.clone(), cred);
                        } else {
                            return Err(Error::EntityRightMissingName());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub const LOAD_QUERY: &'static str = "
        query LOAD_ROOMS{
            _Room{
                id
                _rooms{ id }
                authorisations{
                    id
                    credentials(order_by(mdate desc)){
                        mdate
                        mutate_room
                        mutate_room_users
                        rights{
                            entity
                            mutate_self
                            mutate_all
                            delete_all
                        }
                    }
                    users(order_by(mdate desc)){
                        mdate
                        verifying_key
                        enabled
                    }
                }
            }
        }
    ";

    pub fn load(&mut self, result: &str) -> Result<()> {
        let object: serde_json::Value = serde_json::from_str(result)?;
        let rooms = object
            .as_object()
            .unwrap()
            .get(ROOM_ENT)
            .unwrap()
            .as_array()
            .unwrap();
        for room_value in rooms {
            let room_map = room_value.as_object().unwrap();

            let id = base64_decode(room_map.get(ID_FIELD).unwrap().as_str().unwrap().as_bytes())?;

            let mut parent = HashSet::new();
            let parent_array = room_map.get(ROOMS_FIELD).unwrap().as_array().unwrap();
            for parent_value in parent_array {
                let parent_map = parent_value.as_object().unwrap();
                let parent_id = base64_decode(
                    parent_map
                        .get(ID_FIELD)
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .as_bytes(),
                )?;
                parent.insert(parent_id);
            }

            let mut authorisations = HashMap::new();
            let auth_array = room_map.get("authorisations").unwrap().as_array().unwrap();
            for auth_value in auth_array {
                let auth = load_authorisation(auth_value)?;
                authorisations.insert(auth.id.clone(), auth);
            }

            let room = Room {
                id,
                parent,
                authorisations,
            };
            self.add_room(room);
        }

        // println!("{}", serde_json::to_string_pretty(&object)?);
        Ok(())
    }
}

fn load_authorisation(value: &serde_json::Value) -> Result<Authorisation> {
    let auth_map = value.as_object().unwrap();
    let id = base64_decode(auth_map.get(ID_FIELD).unwrap().as_str().unwrap().as_bytes())?;

    let mut authorisation = Authorisation {
        id,
        users: HashMap::new(),
        credential: Vec::new(),
    };

    let user_array = auth_map.get(AUTH_USER_FIELD).unwrap().as_array().unwrap();
    for user_value in user_array {
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

        authorisation.set_user(user)?;
    }

    let cred_array = auth_map.get(AUTH_CRED_FIELD).unwrap().as_array().unwrap();
    for cred_value in cred_array {
        let cred_map = cred_value.as_object().unwrap();
        let valid_from = cred_map
            .get(MODIFICATION_DATE_FIELD)
            .unwrap()
            .as_i64()
            .unwrap();

        let mutate_room = cred_map.get("mutate_room").unwrap().as_bool().unwrap();
        let mutate_room_users = cred_map
            .get("mutate_room_users")
            .unwrap()
            .as_bool()
            .unwrap();

        let mut rights = HashMap::new();
        let rights_array = cred_map.get("rights").unwrap().as_array().unwrap();
        for right_value in rights_array {
            let right_map = right_value.as_object().unwrap();
            let entity = right_map
                .get("entity")
                .unwrap()
                .as_str()
                .unwrap()
                .to_string();
            let mutate_self = right_map.get("mutate_self").unwrap().as_bool().unwrap();
            let mutate_all = right_map.get("mutate_all").unwrap().as_bool().unwrap();
            let delete_all = right_map.get("delete_all").unwrap().as_bool().unwrap();
            let right = EntityRight {
                entity,
                mutate_self,
                delete_all,
                mutate_all,
            };
            rights.insert(right.entity.clone(), right);
        }

        let credential = Credential {
            valid_from,
            mutate_room,
            mutate_room_users,
            rights,
        };
        authorisation.set_credential(credential)?;
    }

    Ok(authorisation)
}

fn user_from(json: &String, date: i64) -> Result<Option<User>> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    if let Some(map) = value.as_object() {
        if let Some(verifying_key) = map.get(configuration::USER_VERIFYING_KEY_SHORT) {
            if let Some(base64) = verifying_key.as_str() {
                let verifying_key = base64_decode(base64.as_bytes())?;
                let enabled = match map.get(configuration::USER_ENABLED_SHORT) {
                    Some(value) => match value.as_bool() {
                        Some(v) => v,
                        None => true,
                    },
                    None => true,
                };
                let user = User {
                    verifying_key,
                    date,
                    enabled,
                };

                return Ok(Some(user));
            }
        }
    }
    Ok(None)
}

fn credential_from(json: &String, credential: &mut Credential) -> Result<()> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    if let Some(map) = value.as_object() {
        if let Some(mutate_room) = map.get(configuration::CRED_MUTATE_ROOM_SHORT) {
            if let Some(mutate_room) = mutate_room.as_bool() {
                credential.mutate_room = mutate_room;
            }
        }

        if let Some(mutate_room_users) = map.get(configuration::CRED_MUTATE_ROOM_USERS_SHORT) {
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
        if let Some(entity) = map.get(configuration::RIGHT_ENTITY_SHORT) {
            if let Some(entity) = entity.as_str() {
                entity_right.entity = entity.to_string();
            }
        }
        if let Some(mutate_self) = map.get(configuration::RIGHT_MUTATE_SELF_SHORT) {
            if let Some(mutate_self) = mutate_self.as_bool() {
                entity_right.mutate_self = mutate_self;
            }
        }

        if let Some(mutate_all) = map.get(configuration::RIGHT_MUTATE_SHORT) {
            if let Some(mutate_all) = mutate_all.as_bool() {
                entity_right.mutate_all = mutate_all;
            }
        }

        if let Some(delete_all) = map.get(configuration::RIGHT_DELETE_SHORT) {
            if let Some(delete_all) = delete_all.as_bool() {
                entity_right.delete_all = delete_all;
            }
        }
    }
    Ok(entity_right)
}
