use std::{collections::HashMap, fmt};

use rusqlite::Connection;
use tokio::sync::{mpsc, oneshot::Sender};

use crate::{
    cryptography::{base64_decode, base64_encode, Ed25519SigningKey, SigningKey},
    database::configuration::{
        AUTH_RIGHTS_FIELD_SHORT, AUTH_USER_FIELD_SHORT, ID_FIELD, MODIFICATION_DATE_FIELD,
        ROOM_AUTHORISATION_FIELD_SHORT, ROOM_ENT_SHORT, USER_ENABLED_SHORT,
        USER_VERIFYING_KEY_SHORT,
    },
    date_utils::now,
};

use super::{
    configuration::{
        self, AUTHORISATION_ENT_SHORT, AUTH_RIGHTS_FIELD, AUTH_USER_FIELD, ENTITY_RIGHT_ENT_SHORT,
        RIGHT_DELETE_SHORT, RIGHT_ENTITY_SHORT, RIGHT_MUTATE_SELF_SHORT, RIGHT_MUTATE_SHORT,
        ROOM_ADMIN_FIELD, ROOM_ADMIN_FIELD_SHORT, ROOM_AUTHORISATION_FIELD, ROOM_ENT,
        ROOM_ID_FIELD, ROOM_USER_ADMIN_FIELD, ROOM_USER_ADMIN_FIELD_SHORT, USER_AUTH_ENT_SHORT,
    },
    daily_log::DailyMutations,
    deletion::DeletionQuery,
    edge::{Edge, EdgeDeletionEntry},
    mutation_query::{InsertEntity, MutationQuery},
    node::{Node, NodeDeletionEntry},
    sqlite_database::{BufferedDatabaseWriter, WriteMessage, Writeable},
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
    id: Vec<u8>,
    pub mdate: i64,
    pub parent: Option<Vec<u8>>,
    pub admins: HashMap<Vec<u8>, Vec<User>>,
    pub user_admins: HashMap<Vec<u8>, Vec<User>>,
    pub authorisations: HashMap<Vec<u8>, Authorisation>,
}

impl Room {
    pub fn add_auth(&mut self, auth: Authorisation) -> Result<()> {
        if self.authorisations.get(&auth.id).is_some() {
            return Err(Error::AuthorisationExists());
        }
        self.authorisations.insert(auth.id.clone(), auth);
        Ok(())
    }

    pub fn get_auth(&self, id: &Vec<u8>) -> Option<&Authorisation> {
        self.authorisations.get(id)
    }

    pub fn get_auth_mut(&mut self, id: &Vec<u8>) -> Option<&mut Authorisation> {
        self.authorisations.get_mut(id)
    }

    pub fn add_admin_user(&mut self, user: User) -> Result<()> {
        let entry = self.admins.entry(user.verifying_key.clone()).or_default();

        if let Some(last_user) = entry.last() {
            if last_user.date >= user.date {
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
            if last_user.date >= user.date {
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

///
/// Authorisation for a room,
/// mdate: used to allow name change at the database level
/// users: list of allowed user. each user can have several entries allowing to enable disable user. To maintain history consistency users definitions are never deleted
/// rights: list of per-entity access rights.
///
#[derive(Default, Clone, Debug)]
pub struct Authorisation {
    id: Vec<u8>,
    mdate: i64,
    users: HashMap<Vec<u8>, Vec<User>>,
    rights: HashMap<String, Vec<EntityRight>>,
}

impl Authorisation {
    pub fn add_right(&mut self, right: EntityRight) -> Result<()> {
        let entry = self.rights.entry(right.entity.clone()).or_default();

        let date = right.valid_from;
        if let Some(last) = entry.last() {
            if last.valid_from >= date {
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
        match self.get_right_at(entity, date) {
            Some(entity_right) => match right {
                RightType::MutateSelf => entity_right.mutate_self,
                RightType::DeleteAll => entity_right.delete_all,
                RightType::MutateAll => entity_right.mutate_all,
            },
            None => false,
        }
    }
}

///
/// user definition used by the authorisation model. can be enabled or disabled
/// date stores the begining of validity of the user
///
#[derive(Default, Clone, Debug)]
pub struct User {
    pub id: Vec<u8>,
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
///  - true: can create and mutate your own entity
///  - false: read only, cannot create or mutate entity
///
/// delete_all:
///  - true: can delete any entity of the specified type
///  - false: can only delete its own entity
///
/// mutate_all:
///  - true: can mutate any entity of the specified type
///  - false: can only mutate its own entity
#[derive(Default, Clone, Debug)]
pub struct EntityRight {
    pub id: Vec<u8>,
    pub valid_from: i64,
    pub entity: String,
    pub mutate_self: bool,
    pub delete_all: bool,
    pub mutate_all: bool,
}

///
/// Helper enum that define every rights
///
#[derive(Debug)]
pub enum RightType {
    MutateSelf,
    DeleteAll,
    MutateAll,
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
    RoomAdd(RoomNode, mpsc::Sender<super::Result<()>>),
}

pub struct RoomMutationQuery {
    mutation_query: MutationQuery,
    reply: Sender<super::Result<MutationQuery>>,
}
impl Writeable for RoomMutationQuery {
    fn write(&mut self, conn: &rusqlite::Connection) -> std::result::Result<(), rusqlite::Error> {
        self.mutation_query.write(conn)
    }
}
impl RoomMutationQuery {
    pub fn update_daily_logs(&self, daily_log: &mut DailyMutations) {
        self.mutation_query.update_daily_logs(daily_log);
    }
}

#[derive(Clone)]
pub struct AuthorisationService {
    sender: mpsc::Sender<AuthorisationMessage>,
    room_mutation_sender: mpsc::Sender<AuthorisationMessage>,
}
impl AuthorisationService {
    pub fn start(mut auth: RoomAuthorisations) -> Self {
        let (sender, mut receiver) = mpsc::channel::<AuthorisationMessage>(100);

        //special channel to receive RoomMutationQuery from the database writer
        //separated to avoid potentail deadlock when inserting a lot of room at teh same time
        let (room_mutation_sender, mut room_mutation_receiver) =
            mpsc::channel::<AuthorisationMessage>(100);

        let self_sender = room_mutation_sender.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = receiver.recv() =>{
                        match msg {
                            Some(msg) => {
                                Self::process_message(msg, &mut auth,&self_sender).await;
                            },
                            None => break,
                        }
                    }
                    msg = room_mutation_receiver.recv() =>{
                        match msg {
                            Some(msg) => {
                                Self::process_message(msg, &mut auth,&self_sender).await;
                            },
                            None => break,
                        }
                    }
                }
            }
        });

        Self {
            sender,
            room_mutation_sender,
        }
    }

    pub async fn process_message(
        msg: AuthorisationMessage,
        auth: &mut RoomAuthorisations,
        self_sender: &mpsc::Sender<AuthorisationMessage>,
    ) {
        match msg {
            AuthorisationMessage::MutationQuery(mut mutation_query, database_writer, reply) => {
                let need_room_insert = match auth.validate_mutation(&mut mutation_query) {
                    Ok(rooms) => !rooms.is_empty(),
                    Err(e) => {
                        let _ = reply.send(Err(e));
                        return;
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
                let res = auth.load_json(&rooms);
                let _ = reply.send(res);
            }

            AuthorisationMessage::DeletionQuery(mut deletion_query, database_writer, reply) => {
                match auth.validate_deletion(&mut deletion_query) {
                    Ok(_) => {
                        let query = WriteMessage::DeletionQuery(deletion_query, reply);
                        let _ = database_writer.send(query).await;
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e));
                    }
                }
            }
            AuthorisationMessage::RoomAdd(room_node, reply) => {
                match auth.validate_room_node(&room_node) {
                    Ok(insert) => {
                        let _ = match insert {
                            true => todo!(),
                            false => {
                                let _ = reply.send(Ok(()));
                            }
                        };
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e));
                    }
                }
            }
        }
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

    pub fn validate_deletion(&self, deletion_query: &mut DeletionQuery) -> Result<()> {
        let now = now();
        let verifying_key = self.signing_key.export_verifying_key();
        for node in &deletion_query.nodes {
            match node.name.as_str() {
                configuration::ROOM_ENT
                | configuration::AUTHORISATION_ENT
                | configuration::ENTITY_RIGHT_ENT
                | configuration::USER_AUTH_ENT => return Err(Error::DeleteNotAllowed()),
                _ => {
                    if let Some(room_id) = &node.node.room_id {
                        match self.rooms.get(room_id) {
                            Some(room) => {
                                let can = if node.node._verifying_key.eq(&verifying_key) {
                                    room.can(
                                        &verifying_key,
                                        &node.name,
                                        node.date,
                                        &RightType::MutateSelf,
                                    )
                                } else {
                                    room.can(&verifying_key, &node.name, now, &RightType::DeleteAll)
                                };
                                if !can {
                                    return Err(Error::AuthorisationRejected(
                                        node.name.clone(),
                                        base64_encode(room_id),
                                    ));
                                }
                                let log_entry = NodeDeletionEntry::build(
                                    room.id.clone(),
                                    &node.node,
                                    now,
                                    verifying_key.clone(),
                                    &self.signing_key,
                                );
                                deletion_query.node_log.push(log_entry);
                            }
                            None => return Err(Error::UnknownRoom(base64_encode(room_id))),
                        }
                    }
                }
            }
        }
        for edge in &deletion_query.edges {
            match edge.edge.src_entity.as_str() {
                configuration::ROOM_ENT
                | configuration::AUTHORISATION_ENT
                | configuration::ENTITY_RIGHT_ENT
                | configuration::USER_AUTH_ENT => return Err(Error::DeleteNotAllowed()),
                _ => {
                    if let Some(room_id) = &edge.room_id {
                        match self.rooms.get(room_id) {
                            Some(room) => {
                                let can = if edge.edge.verifying_key.eq(&verifying_key) {
                                    room.can(
                                        &verifying_key,
                                        &edge.src_name,
                                        edge.date,
                                        &RightType::MutateSelf,
                                    )
                                } else {
                                    room.can(
                                        &verifying_key,
                                        &edge.src_name,
                                        now,
                                        &RightType::DeleteAll,
                                    )
                                };
                                if !can {
                                    return Err(Error::AuthorisationRejected(
                                        edge.edge.src_entity.clone(),
                                        base64_encode(room_id),
                                    ));
                                }
                                let log_entry = EdgeDeletionEntry::build(
                                    room.id.clone(),
                                    &edge.edge,
                                    now,
                                    verifying_key.clone(),
                                    &self.signing_key,
                                );
                                deletion_query.edge_log.push(log_entry);
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
        for insert_entity in &mut mutation_query.mutate_entities {
            let mut rooms_ent = self.validate_entity_mutation(insert_entity, &verifying_key)?;

            rooms.append(&mut rooms_ent);
        }
        Ok(rooms)
    }

    pub fn validate_entity_mutation(
        &self,
        entity_to_mutate: &mut InsertEntity,
        verifying_key: &Vec<u8>,
    ) -> Result<Vec<Room>> {
        let to_insert = &entity_to_mutate.node_to_mutate;
        let mut rooms = Vec::new();
        let now = now();
        match to_insert.entity.as_str() {
            configuration::ROOM_ENT => {
                let room = self.validate_room_mutation(entity_to_mutate, verifying_key)?;
                if let Some(room) = room {
                    rooms.push(room);
                }
            }
            configuration::AUTHORISATION_ENT
            | configuration::ENTITY_RIGHT_ENT
            | configuration::USER_AUTH_ENT => {
                return Err(Error::InvalidAuthorisationMutation(
                    to_insert.entity.clone(),
                ))
            }
            _ => {
                match &to_insert.old_node {
                    Some(old_node) => {
                        let same_user = old_node._verifying_key.eq(verifying_key);
                        if let Some(room_id) = &to_insert.room_id {
                            if let Some(room) = self.rooms.get(room_id) {
                                let can = if same_user {
                                    room.can(
                                        verifying_key,
                                        &to_insert.entity,
                                        to_insert.date,
                                        &RightType::MutateSelf,
                                    )
                                } else {
                                    room.can(
                                        verifying_key,
                                        &to_insert.entity,
                                        to_insert.date,
                                        &RightType::MutateAll,
                                    )
                                };
                                if !can {
                                    return Err(Error::AuthorisationRejected(
                                        to_insert.entity.clone(),
                                        base64_encode(room_id),
                                    ));
                                }
                                for edge_deletion in &entity_to_mutate.edge_deletions {
                                    let log = EdgeDeletionEntry::build(
                                        room.id.clone(),
                                        edge_deletion,
                                        now,
                                        verifying_key.clone(),
                                        &self.signing_key,
                                    );
                                    entity_to_mutate.edge_deletions_log.push(log);
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
                        if let Some(room_id) = &to_insert.room_id {
                            //    println!("{}  {}", base64_encode(&room_id), to_insert.entity);
                            if let Some(room) = self.rooms.get(room_id) {
                                let can = room.can(
                                    verifying_key,
                                    &to_insert.entity,
                                    to_insert.date,
                                    &RightType::MutateSelf,
                                );
                                if !can {
                                    return Err(Error::AuthorisationRejected(
                                        to_insert.entity.clone(),
                                        base64_encode(room_id),
                                    ));
                                }
                                for edge_deletion in &entity_to_mutate.edge_deletions {
                                    let log = EdgeDeletionEntry::build(
                                        room.id.clone(),
                                        edge_deletion,
                                        now,
                                        verifying_key.clone(),
                                        &self.signing_key,
                                    );
                                    entity_to_mutate.edge_deletions_log.push(log);
                                }
                            } else {
                                return Err(Error::UnknownRoom(base64_encode(room_id)));
                            }
                        }
                    }
                }

                for entry in &mut entity_to_mutate.sub_nodes {
                    for insert_entity in entry.1 {
                        let mut room_ent =
                            self.validate_entity_mutation(insert_entity, verifying_key)?;
                        rooms.append(&mut room_ent);
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
        let node_insert = &insert_entity.node_to_mutate;

        if !insert_entity.edge_deletions.is_empty() {
            return Err(Error::CannotRemove(
                "authorisations".to_string(),
                ROOM_ENT.to_string(),
            ));
        }

        let mut room = match &node_insert.old_node {
            Some(old_node) => {
                if let Some(room) = self.rooms.get(&old_node.id) {
                    if !room.is_admin(verifying_key, node_insert.date) {
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
                if let Some(room_id) = &node_insert.room_id {
                    if let Some(room) = self.rooms.get(room_id) {
                        if !room.can(
                            verifying_key,
                            ROOM_ENT,
                            node_insert.date,
                            &RightType::MutateSelf,
                        ) {
                            return Err(Error::AuthorisationRejected(
                                node_insert.entity.clone(),
                                base64_encode(room_id),
                            ));
                        }
                    } else {
                        return Err(Error::UnknownRoom(base64_encode(room_id)));
                    }
                }

                let room = Room {
                    id: node_insert.id.clone(),
                    parent: node_insert.room_id.clone(),
                    ..Default::default()
                };
                room
            }
        };

        let mut need_room_mutation = false;
        let mut need_user_mutation = false;

        for entry in &mut insert_entity.sub_nodes {
            match entry.0.as_str() {
                ROOM_ADMIN_FIELD => {
                    need_room_mutation = true;
                    for insert_entity in entry.1 {
                        if !insert_entity.edge_deletions.is_empty() {
                            return Err(Error::CannotRemove(
                                "_UserAuth".to_string(),
                                ROOM_ENT.to_string(),
                            ));
                        }
                        if insert_entity.node_to_mutate.node.is_none()
                            || insert_entity.node_to_mutate.old_node.is_some()
                        {
                            return Err(Error::UpdateNotAllowed());
                        }

                        let node_insert = &insert_entity.node_to_mutate;
                        if let Some(node) = &node_insert.node {
                            if let Some(json) = &node._json {
                                let user = user_from_json(&node.id, json, node.mdate)?;
                                if let Some(u) = user {
                                    room.add_admin_user(u)?;
                                }
                            }
                        }
                    }
                }
                ROOM_USER_ADMIN_FIELD => {
                    need_room_mutation = true;
                    for insert_entity in entry.1 {
                        if !insert_entity.edge_deletions.is_empty() {
                            return Err(Error::CannotRemove(
                                "_UserAuth".to_string(),
                                ROOM_ENT.to_string(),
                            ));
                        }
                        if insert_entity.node_to_mutate.node.is_none()
                            || insert_entity.node_to_mutate.old_node.is_some()
                        {
                            return Err(Error::UpdateNotAllowed());
                        }

                        let node_insert = &insert_entity.node_to_mutate;
                        if let Some(node) = &node_insert.node {
                            if let Some(json) = &node._json {
                                let user = user_from_json(&node.id, json, node.mdate)?;
                                if let Some(u) = user {
                                    room.add_user_admin_user(u)?;
                                }
                            }
                        }
                    }
                }
                ROOM_AUTHORISATION_FIELD => {
                    for auth in entry.1 {
                        let rigigt = self.validate_authorisation_mutation(&mut room, auth)?;
                        if rigigt.0 {
                            need_room_mutation = true;
                        }
                        if rigigt.1 {
                            need_user_mutation = true;
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
        //check if user can mutate the room
        if need_room_mutation {
            //   println!("need_room_mutation {}", need_room_mutation);
            if !room.is_admin(verifying_key, now()) {
                return Err(Error::AuthorisationRejected(
                    node_insert.entity.clone(),
                    base64_encode(&room.id),
                ));
            }
        }

        if need_user_mutation {
            //     println!("need_user_mutation {}", need_user_mutation);
            if !room.is_user_admin(verifying_key, now()) {
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
        let node_insert = &insert_entity.node_to_mutate;

        //verify that the passed authentication belongs to the room
        let authorisation = match &node_insert.node {
            Some(_) => match room.get_auth_mut(&node_insert.id) {
                Some(au) => au,
                None => match node_insert.old_node {
                    Some(_) => return Err(Error::NotBelongsTo()),
                    None => {
                        let authorisation = Authorisation {
                            id: node_insert.id.clone(),
                            mdate: node_insert.date,
                            ..Default::default()
                        };

                        room.add_auth(authorisation)?;
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
                AUTH_RIGHTS_FIELD => {
                    need_room_mutation = true;

                    for insert_entity in entry.1 {
                        if !insert_entity.edge_deletions.is_empty() {
                            return Err(Error::CannotRemove(
                                "_Rights".to_string(),
                                ROOM_ENT.to_string(),
                            ));
                        }
                        let node_insert = &insert_entity.node_to_mutate;

                        if node_insert.node.is_none() || node_insert.old_node.is_some() {
                            return Err(Error::UpdateNotAllowed());
                        }
                        if let Some(node) = &node_insert.node {
                            if let Some(json) = &node._json {
                                let mut right = EntityRight {
                                    id: node.id.clone(),
                                    valid_from: node.mdate,
                                    ..Default::default()
                                };
                                entity_right_from_json(&mut right, json)?;

                                authorisation.add_right(right)?;
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
                        if insert_entity.node_to_mutate.node.is_none()
                            || insert_entity.node_to_mutate.old_node.is_some()
                        {
                            return Err(Error::UpdateNotAllowed());
                        }
                        self.validate_user(insert_entity, room_user, authorisation)?;
                    }
                }
                _ => unreachable!(),
            }
        }

        Ok((need_room_mutation, need_user_mutation))
    }

    fn validate_user(
        &self,
        insert_entity: &InsertEntity,
        room_user: &Room,
        authorisation: &mut Authorisation,
    ) -> Result<()> {
        let node_insert = &insert_entity.node_to_mutate;
        if let Some(node) = &node_insert.node {
            if let Some(json) = &node._json {
                let user = user_from_json(&node.id, json, node.mdate)?;
                if let Some(u) = user {
                    if room_user.has_user(&u.verifying_key) || room_user.parent.is_none() {
                        authorisation.add_user(u)?;
                    } else {
                        let mut found = false;
                        for parent_id in &room_user.parent {
                            if let Some(parent) = self.rooms.get(parent_id) {
                                if parent.has_user(&u.verifying_key) {
                                    authorisation.add_user(u.clone())?;
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

    pub const LOAD_QUERY: &'static str = "
        query LOAD_ROOMS{
            _Room{
                id
                mdate
                room_id
                admin (order_by(mdate desc)) {
                    id
                    mdate
                    verifying_key
                    enabled
                }
                user_admin (order_by(mdate desc)) {
                    id
                    mdate
                    verifying_key
                    enabled
                }
                authorisations{
                    id
                    mdate
                    rights(order_by(mdate desc)){
                        id
                        mdate
                        entity
                        mutate_self
                        mutate_all
                        delete_all
                    }
                    users(order_by(mdate desc)){
                        id
                        mdate
                        verifying_key
                        enabled
                    }
                }
            }
        }
    ";

    pub fn load_json(&mut self, result: &str) -> Result<()> {
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
            let mdate = room_map
                .get(MODIFICATION_DATE_FIELD)
                .unwrap()
                .as_i64()
                .unwrap();

            let parent_str = room_map.get(ROOM_ID_FIELD).unwrap().as_str();
            let parent = match parent_str {
                Some(str) => Some(base64_decode(str.as_bytes())?),
                None => None,
            };

            let mut authorisations = HashMap::new();
            let auth_array = room_map
                .get(ROOM_AUTHORISATION_FIELD)
                .unwrap()
                .as_array()
                .unwrap();
            for auth_value in auth_array {
                let auth = load_auth_from_json(auth_value)?;
                authorisations.insert(auth.id.clone(), auth);
            }

            let mut room = Room {
                id,
                mdate,
                parent,
                authorisations,
                admins: HashMap::new(),
                user_admins: HashMap::new(),
            };

            let admin_array = room_map.get(ROOM_ADMIN_FIELD).unwrap().as_array().unwrap();
            for value in admin_array {
                let user = load_user_from_json(value)?;
                room.add_admin_user(user)?;
            }

            let user_admin_array = room_map
                .get(ROOM_USER_ADMIN_FIELD)
                .unwrap()
                .as_array()
                .unwrap();
            for value in user_admin_array {
                let user = load_user_from_json(value)?;
                room.add_user_admin_user(user)?;
            }

            self.add_room(room);
        }

        // println!("{}", serde_json::to_string_pretty(&object)?);
        Ok(())
    }

    pub fn validate_room_node(&self, room_node: &RoomNode) -> Result<bool> {
        let insert = match self.rooms.get(&room_node.node.id) {
            Some(room) => validate_existing_room_node(room, room_node)?,
            None => true,
        };

        Ok(insert)
    }
}

// validate the room node against the existing one
// returns true if the node has changes to be inserted
fn validate_existing_room_node(room: &Room, room_node: &RoomNode) -> Result<bool> {
    let mut need_update = false;

    for auth in &room.authorisations {
        let id = auth.0;
        if !room_node.auth_edges.iter().any(|e| e.dest.eq(id)) {
            return Err(Error::CannotRemove(
                "Authorisation".to_string(),
                "Room".to_string(),
            ));
        }
    }

    //process known nodes first

    for auth_node in &room_node.auth_nodes {
        auth_node.node.verify()?;
        let signer = &auth_node.node._verifying_key;
        let date = auth_node.node.mdate;
        if !room.is_admin(signer, date) {
            return Err(Error::AuthorisationRejected(
                "Authorisation".to_string(),
                base64_encode(&room.id),
            ));
        }

        let id = &auth_node.node.id;
        let authorisation = room.authorisations.get(id);
        match authorisation {
            Some(_authorisation) => todo!(),
            None => {
                need_update = true;
                let _signer = &auth_node.node._verifying_key;
                let _date = auth_node.node.mdate;
            }
        }
    }

    Ok(need_update)
}

fn parse_room_node(room_node: &RoomNode) -> Result<Room> {
    let mut room = Room {
        id: room_node.node.id.clone(),
        mdate: room_node.node.mdate,
        parent: room_node.node.room_id.clone(),
        ..Default::default()
    };

    for auth in &room_node.auth_nodes {
        let mut authorisation = Authorisation {
            id: auth.node.id.clone(),
            mdate: auth.node.mdate,
            ..Default::default()
        };
        for right_node in &auth.right_nodes {
            let entity_right = parse_entity_right_node(right_node)?;
            authorisation.add_right(entity_right)?;
        }

        for user_node in &auth.user_nodes {
            let user = parse_user_node(user_node)?;
            authorisation.add_user(user)?;
        }
        room.add_auth(authorisation)?;
    }

    Ok(room)
}

fn parse_user_node(user_node: &UserAuthNode) -> Result<User> {
    let user_json: serde_json::Value = match &user_node.node._json {
        Some(json) => serde_json::from_str(json)?,
        None => return Err(Error::InvalidNode("Invalid UserAuth node".to_string())),
    };

    if !user_json.is_object() {
        return Err(Error::InvalidNode("Invalid UserAuth node".to_string()));
    }
    let user_map = user_json.as_object().unwrap();
    let verifying_key = match user_map.get(USER_VERIFYING_KEY_SHORT) {
        Some(v) => match v.as_str() {
            Some(v) => base64_decode(v.as_bytes())?,
            None => return Err(Error::InvalidNode("Invalid EntityRight node".to_string())),
        },
        None => return Err(Error::InvalidNode("Invalid EntityRight node".to_string())),
    };

    let enabled = match user_map.get(USER_ENABLED_SHORT) {
        Some(v) => match v.as_bool() {
            Some(v) => v,
            None => return Err(Error::InvalidNode("Invalid EntityRight node".to_string())),
        },
        None => return Err(Error::InvalidNode("Invalid EntityRight node".to_string())),
    };

    let date = user_node.node.mdate;

    let user = User {
        id: user_node.node.id.clone(),
        verifying_key,
        date,
        enabled,
    };

    Ok(user)
}

fn parse_entity_right_node(entity_right_node: &EntityRightNode) -> Result<EntityRight> {
    let right_json: serde_json::Value = match &entity_right_node.node._json {
        Some(json) => serde_json::from_str(json)?,
        None => return Err(Error::InvalidNode("Invalid EntityRight node".to_string())),
    };

    if !right_json.is_object() {
        return Err(Error::InvalidNode("Invalid EntityRight node".to_string()));
    }
    let right_map = right_json.as_object().unwrap();

    let entity = match right_map.get(RIGHT_ENTITY_SHORT) {
        Some(v) => match v.as_str() {
            Some(v) => v.to_string(),
            None => return Err(Error::InvalidNode("Invalid EntityRight node".to_string())),
        },
        None => return Err(Error::InvalidNode("Invalid EntityRight node".to_string())),
    };

    let mutate_self = match right_map.get(RIGHT_MUTATE_SELF_SHORT) {
        Some(v) => match v.as_bool() {
            Some(v) => v,
            None => return Err(Error::InvalidNode("Invalid EntityRight node".to_string())),
        },
        None => return Err(Error::InvalidNode("Invalid EntityRight node".to_string())),
    };

    let delete_all = match right_map.get(RIGHT_MUTATE_SHORT) {
        Some(v) => match v.as_bool() {
            Some(v) => v,
            None => return Err(Error::InvalidNode("Invalid EntityRight node".to_string())),
        },
        None => return Err(Error::InvalidNode("Invalid EntityRight node".to_string())),
    };

    let mutate_all = match right_map.get(RIGHT_DELETE_SHORT) {
        Some(v) => match v.as_bool() {
            Some(v) => v,
            None => return Err(Error::InvalidNode("Invalid EntityRight node".to_string())),
        },
        None => return Err(Error::InvalidNode("Invalid EntityRight node".to_string())),
    };

    let entity_right = EntityRight {
        id: entity_right_node.node.id.clone(),
        valid_from: entity_right_node.node.mdate,
        entity,
        mutate_self,
        delete_all,
        mutate_all,
    };
    Ok(entity_right)
}

fn load_auth_from_json(value: &serde_json::Value) -> Result<Authorisation> {
    let auth_map = value.as_object().unwrap();
    let id = base64_decode(auth_map.get(ID_FIELD).unwrap().as_str().unwrap().as_bytes())?;
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
        let id = base64_decode(
            right_map
                .get(ID_FIELD)
                .unwrap()
                .as_str()
                .unwrap()
                .as_bytes(),
        )?;
        let valid_from = right_map.get("mdate").unwrap().as_i64().unwrap();

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
            id,
            valid_from,
            entity,
            mutate_self,
            delete_all,
            mutate_all,
        };
        authorisation.add_right(right)?;
    }

    Ok(authorisation)
}

fn load_user_from_json(user_value: &serde_json::Value) -> Result<User> {
    let user_map = user_value.as_object().unwrap();
    let id = base64_decode(user_map.get(ID_FIELD).unwrap().as_str().unwrap().as_bytes())?;
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
        id,
        verifying_key,
        date,
        enabled,
    };
    Ok(user)
}

fn user_from_json(id: &Vec<u8>, json: &str, date: i64) -> Result<Option<User>> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    if let Some(map) = value.as_object() {
        if let Some(verifying_key) = map.get(configuration::USER_VERIFYING_KEY_SHORT) {
            if let Some(base64) = verifying_key.as_str() {
                let verifying_key = base64_decode(base64.as_bytes())?;
                let enabled = match map.get(configuration::USER_ENABLED_SHORT) {
                    Some(value) => value.as_bool().unwrap_or(true),
                    None => true,
                };
                let user = User {
                    id: id.clone(),
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

fn entity_right_from_json(entity_right: &mut EntityRight, json: &str) -> Result<()> {
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
    Ok(())
}

//
// The following code handle the room Database representation and manipulations used during synchronisation
//

///
/// room database definition that is used for data synchronisation
///
#[derive(Debug)]
pub struct RoomNode {
    pub node: Node,

    pub admin_edges: Vec<Edge>,
    pub admin_nodes: Vec<UserAuthNode>,

    pub user_admin_edges: Vec<Edge>,
    pub user_admin_nodes: Vec<UserAuthNode>,

    pub auth_edges: Vec<Edge>,
    pub auth_nodes: Vec<AuthorisationNode>,
}
impl RoomNode {
    pub fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        self.node.write(conn, false, &None, &None)?;

        for a in &self.auth_edges {
            a.write(conn)?;
        }
        for a in &mut self.auth_nodes {
            a.write(conn)?;
        }
        Ok(())
    }

    pub fn read(
        conn: &Connection,
        id: &Vec<u8>,
    ) -> std::result::Result<Option<Self>, rusqlite::Error> {
        let node = Node::get(id, ROOM_ENT_SHORT, conn)?;
        if node.is_none() {
            return Ok(None);
        }
        let node = *node.unwrap();
        let mut admin_edges = Edge::get_edges(id, ROOM_ADMIN_FIELD_SHORT, conn)?;
        //user insertion order is mandatory
        admin_edges.sort_by(|a, b| b.cdate.cmp(&a.cdate));

        let mut admin_nodes = Vec::new();
        for edge in &admin_edges {
            let user_opt = UserAuthNode::read(conn, &edge.dest)?;
            if let Some(user) = user_opt {
                admin_nodes.push(user);
            }
        }

        let mut user_admin_edges = Edge::get_edges(id, ROOM_USER_ADMIN_FIELD_SHORT, conn)?;
        //user insertion order is mandatory
        user_admin_edges.sort_by(|a, b| b.cdate.cmp(&a.cdate));

        let mut user_admin_nodes = Vec::new();
        for edge in &user_admin_edges {
            let user_opt = UserAuthNode::read(conn, &edge.dest)?;
            if let Some(user) = user_opt {
                user_admin_nodes.push(user);
            }
        }

        let auth_edges = Edge::get_edges(id, ROOM_AUTHORISATION_FIELD_SHORT, conn)?;
        let mut auth_nodes = Vec::new();
        for edge in &auth_edges {
            let auth_opt = AuthorisationNode::read(conn, &edge.dest)?;
            if let Some(auth) = auth_opt {
                auth_nodes.push(auth);
            }
        }

        Ok(Some(Self {
            node,
            admin_edges,
            admin_nodes,
            user_admin_edges,
            user_admin_nodes,
            auth_edges,
            auth_nodes,
        }))
    }
}

///
/// authorisation database definition that is used for data synchronisation
///
#[derive(Debug)]
pub struct AuthorisationNode {
    pub node: Node,
    pub right_edges: Vec<Edge>,
    pub right_nodes: Vec<EntityRightNode>,
    pub user_edges: Vec<Edge>,
    pub user_nodes: Vec<UserAuthNode>,
}
impl AuthorisationNode {
    pub fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        self.node.write(conn, false, &None, &None)?;
        for c in &self.right_edges {
            c.write(conn)?;
        }
        for c in &mut self.right_nodes {
            c.write(conn)?;
        }
        for u in &self.user_edges {
            u.write(conn)?;
        }
        for u in &mut self.user_nodes {
            u.write(conn)?;
        }
        Ok(())
    }

    pub fn read(
        conn: &Connection,
        id: &Vec<u8>,
    ) -> std::result::Result<Option<Self>, rusqlite::Error> {
        let node = Node::get(id, AUTHORISATION_ENT_SHORT, conn)?;
        if node.is_none() {
            return Ok(None);
        }
        let node = *node.unwrap();

        let mut right_edges = Edge::get_edges(id, AUTH_RIGHTS_FIELD_SHORT, conn)?;
        //rights insertion must respect must be done in the right order
        right_edges.sort_by(|a, b| b.cdate.cmp(&a.cdate));

        let mut right_nodes = Vec::new();
        for edge in &right_edges {
            let right_opt = EntityRightNode::read(conn, &edge.dest)?;
            if let Some(cred) = right_opt {
                right_nodes.push(cred);
            }
        }

        let mut user_edges = Edge::get_edges(id, AUTH_USER_FIELD_SHORT, conn)?;
        //user insertion order is mandatory
        user_edges.sort_by(|a, b| b.cdate.cmp(&a.cdate));

        let mut user_nodes = Vec::new();
        for edge in &user_edges {
            let user_opt = UserAuthNode::read(conn, &edge.dest)?;
            if let Some(user) = user_opt {
                user_nodes.push(user);
            }
        }

        Ok(Some(Self {
            node,
            right_edges,
            right_nodes,
            user_edges,
            user_nodes,
        }))
    }
}

///
/// User database definition that is used for data synchronisation
///
#[derive(Debug)]
pub struct UserAuthNode {
    pub node: Node,
}
impl UserAuthNode {
    pub fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        self.node.write(conn, false, &None, &None)?;
        Ok(())
    }
    pub fn read(
        conn: &Connection,
        id: &Vec<u8>,
    ) -> std::result::Result<Option<Self>, rusqlite::Error> {
        let node = Node::get(id, USER_AUTH_ENT_SHORT, conn)?;
        if node.is_none() {
            return Ok(None);
        }
        let node = *node.unwrap();
        Ok(Some(Self { node }))
    }
}

#[derive(Debug)]
pub struct EntityRightNode {
    pub node: Node,
}
impl EntityRightNode {
    pub fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        self.node.write(conn, false, &None, &None)?;
        Ok(())
    }
    pub fn read(
        conn: &Connection,
        id: &Vec<u8>,
    ) -> std::result::Result<Option<Self>, rusqlite::Error> {
        let node = Node::get(id, ENTITY_RIGHT_ENT_SHORT, conn)?;
        if node.is_none() {
            return Ok(None);
        }
        let node = *node.unwrap();
        Ok(Some(Self { node }))
    }
}
