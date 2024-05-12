use std::collections::{HashMap, HashSet};

use tokio::sync::{mpsc, oneshot::Sender};

use crate::{
    cryptography::{base64_decode, base64_encode, Ed25519SigningKey, SigningKey},
    date_utils::now,
    event_service::{EventService, EventServiceMessage},
    synchronisation::{
        authorisation_node::{
            parse_room_node, prepare_new_room, prepare_room_with_history, RoomNode,
        },
        node_full::FullNode,
    },
};

use super::{
    configuration::{
        self, AUTH_RIGHTS_FIELD, AUTH_USER_FIELD, ID_FIELD, MODIFICATION_DATE_FIELD,
        ROOM_ADMIN_FIELD, ROOM_AUTHORISATION_FIELD, ROOM_ENT, ROOM_ID_FIELD, ROOM_USER_ADMIN_FIELD,
    },
    daily_log::{DailyMutations, RoomDefinitionLog},
    deletion::DeletionQuery,
    edge::EdgeDeletionEntry,
    mutation_query::{InsertEntity, MutationQuery},
    node::NodeDeletionEntry,
    room::*,
    sqlite_database::{BufferedDatabaseWriter, WriteMessage, Writeable},
    Error, Result,
};

pub enum AuthorisationMessage {
    Load(String, Sender<super::Result<()>>),
    Deletion(DeletionQuery, Sender<super::Result<DeletionQuery>>),
    Mutation(MutationQuery, Sender<super::Result<MutationQuery>>),
    RoomMutationWrite(Result<()>, RoomMutationWriteQuery),
    RoomNodeAdd(Option<RoomNode>, RoomNode, Sender<super::Result<()>>),
    RoomNodeWrite(Result<()>, RoomNodeWriteQuery),
    RoomForUser(Vec<u8>, i64, Sender<HashSet<Vec<u8>>>),
    AddFullNode(Vec<FullNode>, Vec<Vec<u8>>, Sender<Result<Vec<Vec<u8>>>>),
}

pub struct RoomMutationWriteQuery {
    room_list: HashSet<Vec<u8>>,
    mutation_query: MutationQuery,
    reply: Sender<super::Result<MutationQuery>>,
}
impl Writeable for RoomMutationWriteQuery {
    fn write(&mut self, conn: &rusqlite::Connection) -> std::result::Result<(), rusqlite::Error> {
        self.mutation_query.write(conn)?;
        for room_id in &self.room_list {
            RoomDefinitionLog::add(room_id, self.mutation_query.date, conn)?;
        }
        Ok(())
    }
}
impl RoomMutationWriteQuery {
    pub fn update_daily_logs(&self, daily_log: &mut DailyMutations) {
        for insert in &self.mutation_query.mutate_entities {
            if !self.room_list.contains(&insert.node_to_mutate.id) {
                insert.update_daily_logs(daily_log);
            }
        }
    }
}

pub struct RoomNodeWriteQuery {
    room: RoomNode,
    reply: Sender<super::Result<()>>,
}
impl Writeable for RoomNodeWriteQuery {
    fn write(&mut self, conn: &rusqlite::Connection) -> std::result::Result<(), rusqlite::Error> {
        self.room.write(conn)?;
        if let Some(id) = &self.room.node.room_id {
            RoomDefinitionLog::add(id, self.room.last_modified, conn)?;
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct AuthorisationService {
    sender: mpsc::Sender<AuthorisationMessage>,
}
impl AuthorisationService {
    pub fn start(
        mut auth: RoomAuthorisations,
        database_writer: BufferedDatabaseWriter,
        event_service: EventService,
    ) -> Self {
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
                                Self::process_message(msg, &mut auth, &database_writer,&event_service, &self_sender).await;
                            },
                            None => break,
                        }
                    }
                    msg = room_mutation_receiver.recv() =>{
                        match msg {
                            Some(msg) => {
                                Self::process_message(msg, &mut auth,&database_writer,&event_service, &self_sender).await;
                            },
                            None => break,
                        }
                    }
                }
            }
        });

        Self { sender }
    }

    pub async fn process_message(
        msg: AuthorisationMessage,
        auth: &mut RoomAuthorisations,
        database_writer: &BufferedDatabaseWriter,
        event_service: &EventService,
        self_sender: &mpsc::Sender<AuthorisationMessage>,
    ) {
        match msg {
            AuthorisationMessage::Load(rooms, reply) => {
                let res = auth.load_json(&rooms);
                let _ = reply.send(res);
            }

            AuthorisationMessage::Deletion(mut deletion_query, reply) => {
                match auth.validate_deletion(&mut deletion_query) {
                    Ok(_) => {
                        let query = WriteMessage::Deletion(deletion_query, reply);
                        let _ = database_writer.send(query).await;
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e));
                    }
                }
            }

            AuthorisationMessage::Mutation(mut mutation_query, reply) => {
                match auth.validate_mutation(&mut mutation_query) {
                    Ok(rooms) => match rooms.is_empty() {
                        true => {
                            let query = WriteMessage::Mutation(mutation_query, reply);
                            let _ = database_writer.send(query).await;
                        }
                        false => {
                            let mut room_list: HashSet<Vec<u8>> = HashSet::new();
                            for room in rooms {
                                room_list.insert(room.id);
                            }
                            let query = WriteMessage::RoomMutation(
                                RoomMutationWriteQuery {
                                    room_list,
                                    mutation_query,
                                    reply,
                                },
                                self_sender.clone(),
                            );

                            let _ = database_writer.send(query).await;
                        }
                    },
                    Err(e) => {
                        let _ = reply.send(Err(e));
                        return;
                    }
                };
            }

            AuthorisationMessage::RoomMutationWrite(result, mut query) => match result {
                Ok(_) => {
                    match auth.validate_mutation(&mut query.mutation_query) {
                        Ok(rooms) => {
                            for room in rooms {
                                auth.add_room(room.clone());
                                event_service
                                    .notify(EventServiceMessage::RoomModified(room))
                                    .await;
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

            AuthorisationMessage::RoomNodeAdd(old_room_node, mut room_node, reply) => {
                match auth.prepare_room_node(old_room_node, &mut room_node) {
                    Ok(insert) => {
                        let _ = match insert {
                            true => {
                                let query = WriteMessage::RoomNode(
                                    RoomNodeWriteQuery {
                                        room: room_node,
                                        reply,
                                    },
                                    self_sender.clone(),
                                );
                                let _ = database_writer.send(query).await;
                            }
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
            AuthorisationMessage::RoomNodeWrite(res, query) => match res {
                Ok(_) => {
                    match parse_room_node(&query.room) {
                        Ok(room) => {
                            auth.add_room(room.clone());
                            event_service
                                .notify(EventServiceMessage::RoomModified(room))
                                .await;
                            let _ = query.reply.send(Ok(()));
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
            AuthorisationMessage::RoomForUser(verifying_key, date, reply) => {
                let rooms = auth.get_rooms_for_user(&verifying_key, date);
                let _ = reply.send(rooms);
            }

            AuthorisationMessage::AddFullNode(valid_nodes, mut invalid_node, reply) => {
                let mut write_nodes = Vec::new();

                for node in valid_nodes {
                    match auth.validate_full_node(&node) {
                        true => write_nodes.push(node),
                        false => invalid_node.push(node.node.id),
                    }
                }
                let query = WriteMessage::FullNode(write_nodes, invalid_node, reply);

                let _ = database_writer.send(query).await;
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
                                    room.can(&verifying_key, &node.name, now, &RightType::MutateAll)
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

        for node in &mut deletion_query.updated_nodes {
            node.sign(&self.signing_key)?;
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
                                        &RightType::MutateAll,
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
                    }
                    None => {
                        if let Some(room_id) = &to_insert.room_id {
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
                                let user = user_from_json(json, node.mdate)?;
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
                                let user = user_from_json(json, node.mdate)?;
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
                let user = user_from_json(json, node.mdate)?;
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

    pub fn get_rooms_for_user(&self, verifying_key: &Vec<u8>, date: i64) -> HashSet<Vec<u8>> {
        let mut result = HashSet::new();
        for room in &self.rooms {
            if room.1.is_user_valid_at(&verifying_key, date) {
                result.insert(room.0.clone());
            }
        }
        result
    }

    pub const LOAD_QUERY: &'static str = "
        query LOAD_ROOMS{
            _Room{
                id
                mdate
                room_id
                admin (order_by(mdate desc)) {
                    mdate
                    verifying_key
                    enabled
                }
                user_admin (order_by(mdate desc)) {
                    mdate
                    verifying_key
                    enabled
                }
                authorisations{
                    id
                    mdate
                    rights(order_by(mdate desc)){
                        mdate
                        entity
                        mutate_self
                        mutate_all
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

    pub fn prepare_room_node(
        &self,
        old_room_node: Option<RoomNode>,
        room_node: &mut RoomNode,
    ) -> Result<bool> {
        room_node.check_consistency()?;

        let insert = match self.rooms.get(&room_node.node.id) {
            Some(room) => match old_room_node {
                Some(old) => prepare_room_with_history(room, &old, room_node)?,
                None => {
                    return Err(Error::InvalidNode(
                        "the room exists should have an existing old_room_node".to_string(),
                    ))
                }
            },

            None => {
                prepare_new_room(room_node)?;
                true
            }
        };
        Ok(insert)
    }

    pub fn validate_full_node(&self, node: &FullNode) -> bool {
        if node.node.verify().is_err() {
            return false;
        }
        let required_right = match &node.old_verifying_key {
            Some(old_key) => match old_key.eq(&node.node._verifying_key) {
                true => RightType::MutateSelf,
                false => RightType::MutateAll,
            },
            None => RightType::MutateSelf,
        };
        let room_id = &node.node.room_id;
        if room_id.is_none() {
            return false;
        }
        let room_id = room_id.clone().unwrap();

        let room = self.rooms.get(&room_id);
        if room.is_none() {
            return false;
        }
        let room = room.unwrap();

        if node.entity_name.is_none() {
            return false;
        }
        let entity_name = &node.entity_name.clone().unwrap();
        if !room.can(
            &node.node._verifying_key,
            entity_name,
            node.node.mdate,
            &required_right,
        ) {
            return false;
        }

        for edge in &node.edges {
            if edge.verify().is_err() {
                return false;
            }
            let required_right = match &node.old_verifying_key {
                Some(old_key) => match old_key.eq(&edge.verifying_key) {
                    true => RightType::MutateSelf,
                    false => RightType::MutateAll,
                },
                None => RightType::MutateSelf,
            };
            if !room.can(
                &edge.verifying_key,
                entity_name,
                edge.cdate,
                &required_right,
            ) {
                return false;
            }
        }

        true
    }
}
