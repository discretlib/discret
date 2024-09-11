use std::collections::{HashMap, HashSet};

use tokio::sync::{mpsc, oneshot::Sender};

use crate::{
    date_utils::now,
    event_service::{EventService, EventServiceMessage},
    security::{
        base64_encode, derive_uid, uid_decode, uid_encode, Ed25519SigningKey, SigningKey, Uid,
    },
};

use super::{
    daily_log::{DailyMutations, RoomChangelog},
    deletion::DeletionQuery,
    edge::{Edge, EdgeDeletionEntry},
    mutation_query::{InsertEntity, MutationQuery},
    node::{NodeDeletionEntry, NodeToInsert},
    room::*,
    room_node::{prepare_new_room, prepare_room_with_history, RoomNode},
    sqlite_database::{BufferedDatabaseWriter, WriteMessage, Writeable},
    system_entities::{
        self, AUTH_RIGHTS_FIELD, AUTH_USER_ADMIN_FIELD, AUTH_USER_FIELD, ID_FIELD,
        MODIFICATION_DATE_FIELD, ROOM_ADMIN_FIELD, ROOM_AUTHORISATION_FIELD, ROOM_ENT,
    },
    Error, Result,
};

pub enum AuthorisationMessage {
    Sign(Vec<u8>, Sender<(Vec<u8>, Vec<u8>)>),
    Load(String, Sender<super::Result<()>>),
    Deletion(DeletionQuery, Sender<super::Result<DeletionQuery>>),
    Mutation(MutationQuery, Sender<super::Result<MutationQuery>>),
    MutationStream(MutationQuery, mpsc::Sender<super::Result<MutationQuery>>),
    RoomMutationWrite(Result<()>, RoomMutationWriteQuery),
    RoomMutationStreamWrite(Result<()>, RoomMutationStreamWriteQuery),
    RoomNodeAdd(Option<RoomNode>, Box<RoomNode>, Sender<super::Result<()>>),
    RoomNodeWrite(Result<()>, RoomNodeWriteQuery),
    RoomsForPeer(Vec<u8>, i64, Sender<HashSet<Uid>>),
    AddNodes(Vec<NodeToInsert>, Vec<Uid>, Sender<Result<Vec<Uid>>>),
    AddEdges(Uid, Vec<(Edge, String)>, Vec<Uid>, Sender<Result<Vec<Uid>>>),
    DeleteEdges(
        Vec<(EdgeDeletionEntry, Option<Vec<u8>>)>,
        Sender<Result<()>>,
    ),
    DeleteNodes(
        HashMap<Uid, (NodeDeletionEntry, Option<Vec<u8>>)>,
        Sender<Result<()>>,
    ),
    UserForRoom(Uid, Sender<Result<HashSet<Vec<u8>>>>),
    // ValidatePeerNodesRequest(Uid, Vec<Vec<u8>>, Sender<Result<Vec<Vec<u8>>>>),
}

pub struct RoomMutationWriteQuery {
    room_list: HashSet<Uid>,
    mutation_query: MutationQuery,
    reply: Sender<super::Result<MutationQuery>>,
}
impl Writeable for RoomMutationWriteQuery {
    fn write(&mut self, conn: &rusqlite::Connection) -> std::result::Result<(), rusqlite::Error> {
        self.mutation_query.write(conn)?;
        for room_id in &self.room_list {
            RoomChangelog::log_room_definition(room_id, self.mutation_query.date, conn)?;
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

pub struct RoomMutationStreamWriteQuery {
    room_list: HashSet<Uid>,
    mutation_query: MutationQuery,
    reply: mpsc::Sender<super::Result<MutationQuery>>,
}
impl Writeable for RoomMutationStreamWriteQuery {
    fn write(&mut self, conn: &rusqlite::Connection) -> std::result::Result<(), rusqlite::Error> {
        self.mutation_query.write(conn)?;
        for room_id in &self.room_list {
            RoomChangelog::log_room_definition(room_id, self.mutation_query.date, conn)?;
        }
        Ok(())
    }
}
impl RoomMutationStreamWriteQuery {
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

        RoomChangelog::log_room_definition(&self.room.node.id, self.room.last_modified, conn)?;

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
        //separated to avoid potentail deadlock when inserting a lot of room at the same time
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

            AuthorisationMessage::Sign(data, reply) => {
                let verifying = auth.signing_key.export_verifying_key();
                let signature = auth.signing_key.sign(&data);
                let _ = reply.send((verifying, signature));
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
                            let mut room_list: HashSet<Uid> = HashSet::new();
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
                    }
                };
            }

            AuthorisationMessage::MutationStream(mut mutation_query, reply) => {
                match auth.validate_mutation(&mut mutation_query) {
                    Ok(rooms) => match rooms.is_empty() {
                        true => {
                            let query = WriteMessage::MutationStream(mutation_query, reply);
                            let _ = database_writer.send(query).await;
                        }
                        false => {
                            let mut room_list: HashSet<Uid> = HashSet::new();
                            for room in rooms {
                                room_list.insert(room.id);
                            }
                            let query = WriteMessage::RoomMutationStream(
                                RoomMutationStreamWriteQuery {
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
                        let _ = reply.send(Err(e)).await;
                    }
                }
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

            AuthorisationMessage::RoomMutationStreamWrite(result, mut query) => match result {
                Ok(_) => {
                    match auth.validate_mutation(&mut query.mutation_query) {
                        Ok(rooms) => {
                            for room in rooms {
                                auth.add_room(room.clone());
                                event_service
                                    .notify(EventServiceMessage::RoomModified(room))
                                    .await;
                            }
                            let _ = query.reply.send(Ok(query.mutation_query)).await;
                        }
                        Err(e) => {
                            let _ = query.reply.send(Err(e)).await;
                        }
                    };
                }
                Err(e) => {
                    let _ = query.reply.send(Err(e)).await;
                }
            },

            AuthorisationMessage::RoomNodeAdd(old_room_node, mut room_node, reply) => {
                match auth.prepare_room_node(old_room_node, &mut room_node) {
                    Ok(insert) => {
                        match insert {
                            true => {
                                let query = WriteMessage::RoomNode(
                                    RoomNodeWriteQuery {
                                        room: *room_node,
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
                    match query.room.parse() {
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
            AuthorisationMessage::RoomsForPeer(verifying_key, date, reply) => {
                let rooms = auth.rooms_for_peer(&verifying_key, date);
                let _ = reply.send(rooms);
            }

            AuthorisationMessage::AddNodes(valid_nodes, mut invalid_node, reply) => {
                let mut write_nodes = Vec::new();

                for node in valid_nodes {
                    match auth.validate_node(&node) {
                        true => write_nodes.push(node),
                        false => invalid_node.push(node.id),
                    }
                }
                let query = WriteMessage::Nodes(write_nodes, invalid_node, reply);

                let _ = database_writer.send(query).await;
            }

            AuthorisationMessage::AddEdges(room_id, edges, mut invalid, reply) => {
                let room = auth.rooms.get(&room_id);
                if room.is_none() {
                    let _ = reply.send(Err(Error::UnknownRoom(base64_encode(&room_id))));
                    return;
                }
                let room = room.unwrap();

                let mut valid_edges = Vec::new();
                for (edge, entity_name) in edges {
                    if room.can(
                        &edge.verifying_key,
                        &entity_name,
                        edge.cdate,
                        &RightType::MutateSelf,
                    ) {
                        valid_edges.push(edge);
                    } else {
                        invalid.push(edge.src);
                    }
                }

                let query = WriteMessage::Edges(valid_edges, invalid, reply);

                let _ = database_writer.send(query).await;
            }

            AuthorisationMessage::DeleteEdges(edges, reply) => {
                let filtered_edges = auth.validate_edge_deletions(edges);
                if filtered_edges.is_empty() {
                    let _ = reply.send(Ok(()));
                } else {
                    let _ = database_writer
                        .send(WriteMessage::DeleteEdges(filtered_edges, reply))
                        .await;
                }
            }
            AuthorisationMessage::DeleteNodes(nodes, reply) => {
                let filtered_nodes = auth.validate_node_deletions(nodes);
                if filtered_nodes.is_empty() {
                    let _ = reply.send(Ok(()));
                } else {
                    let _ = database_writer
                        .send(WriteMessage::DeleteNodes(filtered_nodes, reply))
                        .await;
                }
            }

            AuthorisationMessage::UserForRoom(room_id, reply) => {
                let _ = reply.send(auth.user_for_room(room_id));
            } // AuthorisationMessage::ValidatePeerNodesRequest(room_id, keys, reply) => {
              //     let _ = reply.send(auth.validate_peer_nodes_request(room_id, keys));
              // }
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
    pub rooms: HashMap<Uid, Room>,
    pub max_node_size: u64,
}
impl RoomAuthorisations {
    pub fn add_room(&mut self, room: Room) {
        self.rooms.insert(room.id, room);
    }

    pub fn validate_deletion(&self, deletion_query: &mut DeletionQuery) -> Result<()> {
        let now = now();
        let verifying_key = self.signing_key.export_verifying_key();
        for node in &deletion_query.nodes {
            match node.name.as_str() {
                system_entities::ROOM_ENT
                | system_entities::AUTHORISATION_ENT
                | system_entities::ENTITY_RIGHT_ENT
                | system_entities::USER_AUTH_ENT => return Err(Error::DeleteNotAllowed()),
                _ => {
                    if let Some(room_id) = &node.node.room_id {
                        match self.rooms.get(room_id) {
                            Some(room) => {
                                let can = if node.node.verifying_key.eq(&verifying_key) {
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
                                    room.id,
                                    &node.node,
                                    now,
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
                system_entities::ROOM_ENT
                | system_entities::AUTHORISATION_ENT
                | system_entities::ENTITY_RIGHT_ENT
                | system_entities::USER_AUTH_ENT => return Err(Error::DeleteNotAllowed()),
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
                                    room.id,
                                    &edge.edge,
                                    now,
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
            system_entities::ROOM_ENT => {
                let room = self.validate_room_mutation(entity_to_mutate, verifying_key)?;
                if let Some(room) = room {
                    rooms.push(room);
                }
            }
            system_entities::AUTHORISATION_ENT
            | system_entities::ENTITY_RIGHT_ENT
            | system_entities::USER_AUTH_ENT => {
                return Err(Error::InvalidAuthorisationMutation(
                    to_insert.entity.clone(),
                ))
            }
            _ => {
                if to_insert.node.is_none() {
                    //this is a reference, not mutation occurs
                    return Ok(rooms);
                } else {
                    let node = to_insert.node.as_ref().unwrap();
                    let size = bincode::serialized_size(node)?;
                    if size > self.max_node_size {
                        return Err(Error::NodeTooBig(size, self.max_node_size));
                    }
                }
                match &to_insert.old_node {
                    Some(old_node) => {
                        let same_user = old_node.verifying_key.eq(verifying_key);
                        if let Some(room_id) = &to_insert.room_id {
                            if let Some(room) = self.rooms.get(room_id) {
                                if let Some(old_room_id) = &old_node.room_id {
                                    if !old_room_id.eq(room_id) {
                                        if let Some(old_room) = self.rooms.get(room_id) {
                                            let can = if same_user {
                                                old_room.can(
                                                    verifying_key,
                                                    &to_insert.entity,
                                                    to_insert.date,
                                                    &RightType::MutateSelf,
                                                )
                                            } else {
                                                old_room.can(
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
                                        } else {
                                            return Err(Error::UnknownRoom(base64_encode(room_id)));
                                        }
                                    }
                                }

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
                                        room.id,
                                        edge_deletion,
                                        now,
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
                                        room.id,
                                        edge_deletion,
                                        now,
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

    // create the system room associated the user
    // this rooms only leaves in memory and is never written
    // an entry is put in the room log to ensure proper data synchronisation
    pub async fn create_system_room(
        &mut self,
        room_id: Uid,
        database_writer: &BufferedDatabaseWriter,
    ) -> Result<()> {
        let mut room = Room {
            id: room_id,
            mdate: 0,
            admins: HashMap::new(),

            authorisations: HashMap::new(),
        };

        let mut auth = Authorisation {
            id: derive_uid("auth", &room_id),
            mdate: 0,
            users: HashMap::new(),
            rights: HashMap::new(),
            user_admins: HashMap::new(),
        };
        let vkey = self.signing_key.export_verifying_key();
        auth.add_user(User {
            verifying_key: vkey,
            date: 0,
            enabled: true,
        })?;

        auth.add_right(EntityRight::new(0, "*".to_string(), true, false))?;

        room.authorisations.insert(auth.id, auth);

        let change_log = RoomChangelog { room_id, mdate: 0 };
        database_writer.write(Box::new(change_log)).await?;
        self.add_room(room);
        Ok(())
    }

    pub fn validate_room_mutation(
        &self,
        insert_entity: &mut InsertEntity,
        verifying_key: &Vec<u8>,
    ) -> Result<Option<Room>> {
        let node_insert = &insert_entity.node_to_mutate;

        if !insert_entity.edge_deletions.is_empty() {
            return Err(Error::CannotRemove(
                "sys.Authorisations".to_string(),
                ROOM_ENT.to_string(),
            ));
        }

        let mut room = match &node_insert.old_node {
            Some(old_node) => {
                let room = self
                    .rooms
                    .get(&old_node.id)
                    .ok_or(Error::UnknownRoom(base64_encode(&old_node.id)))?;

                if !room.is_admin(verifying_key, node_insert.date) {
                    return Err(Error::AuthorisationRejected(
                        node_insert.entity.clone(),
                        base64_encode(&old_node.id),
                    ));
                }
                room.clone()
            }
            None => {
                if node_insert.node.is_none() {
                    //no history, no node to insert, it is a reference
                    return Ok(None);
                }
                if node_insert.room_id.is_some() {
                    return Err(Error::ForbiddenRoomId("sys.Room".to_string()));
                }

                Room {
                    id: node_insert.id,
                    ..Default::default()
                }
            }
        };

        let mut need_room_admin = false;

        for entry in &mut insert_entity.sub_nodes {
            match entry.0.as_str() {
                ROOM_ADMIN_FIELD => {
                    need_room_admin = true;
                    for insert_entity in entry.1 {
                        if !insert_entity.edge_deletions.is_empty() {
                            return Err(Error::CannotRemove(
                                "sys.UserAuth".to_string(),
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
                            if node_insert.room_id.is_some() {
                                return Err(Error::ForbiddenRoomId("sys.UserAuth".to_string()));
                            }
                            if let Some(json) = &node._json {
                                let user = user_from_json(json, node.mdate)?;
                                room.add_admin_user(user)?;
                            }
                        }
                    }
                }

                ROOM_AUTHORISATION_FIELD => {
                    for auth in entry.1 {
                        let need_mut =
                            self.validate_authorisation_mutation(&mut room, auth, verifying_key)?;
                        if need_mut {
                            need_room_admin = true;
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
        //check if user can mutate the room
        if need_room_admin && !room.is_admin(verifying_key, insert_entity.node_to_mutate.date) {
            return Err(Error::AuthorisationRejected(
                node_insert.entity.clone(),
                base64_encode(&room.id),
            ));
        }

        Ok(Some(room))
    }

    fn validate_authorisation_mutation(
        &self,
        room: &mut Room,
        insert_entity: &mut InsertEntity,
        verifying_key: &Vec<u8>,
    ) -> Result<bool> {
        if !insert_entity.edge_deletions.is_empty() {
            return Err(Error::CannotRemove(
                "sys.Authorisation".to_string(),
                ROOM_ENT.to_string(),
            ));
        }

        let node_insert = &insert_entity.node_to_mutate;
        if node_insert.room_id.is_some() {
            return Err(Error::ForbiddenRoomId("sys.Authorisation".to_string()));
        }
        //verify that the passed authorisation belongs to the room
        let authorisation = match &node_insert.node {
            Some(_) => match room.get_auth_mut(&node_insert.id) {
                Some(au) => au,
                None => match node_insert.old_node {
                    Some(_) => return Err(Error::NotBelongsTo()),
                    None => {
                        let authorisation = Authorisation {
                            id: node_insert.id,
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

        let mut need_user_admin = false;
        let mut need_room_admin = false;

        for entry in &insert_entity.sub_nodes {
            match entry.0.as_str() {
                AUTH_RIGHTS_FIELD => {
                    need_room_admin = true;

                    for insert_entity in entry.1 {
                        if !insert_entity.edge_deletions.is_empty() {
                            return Err(Error::CannotRemove(
                                "sys.UserAuth".to_string(),
                                ROOM_ENT.to_string(),
                            ));
                        }
                        let node_insert = &insert_entity.node_to_mutate;

                        if node_insert.node.is_none() || node_insert.old_node.is_some() {
                            return Err(Error::UpdateNotAllowed());
                        }
                        if node_insert.room_id.is_some() {
                            return Err(Error::ForbiddenRoomId("sys.UserAuth".to_string()));
                        }
                        if let Some(node) = &node_insert.node {
                            if let Some(json) = &node._json {
                                let right = entity_right_from_json(node.mdate, json)?;
                                authorisation.add_right(right)?;
                            }
                        }
                    }
                }
                AUTH_USER_FIELD => {
                    need_user_admin = true;
                    for insert_entity in entry.1 {
                        if !insert_entity.edge_deletions.is_empty() {
                            return Err(Error::CannotRemove(
                                "sys.UserAuth".to_string(),
                                ROOM_ENT.to_string(),
                            ));
                        }
                        if insert_entity.node_to_mutate.node.is_none()
                            || insert_entity.node_to_mutate.old_node.is_some()
                        {
                            return Err(Error::UpdateNotAllowed());
                        }
                        let node_insert = &insert_entity.node_to_mutate;
                        if node_insert.room_id.is_some() {
                            return Err(Error::ForbiddenRoomId("sys.UserAuth".to_string()));
                        }
                        if let Some(node) = &node_insert.node {
                            if let Some(json) = &node._json {
                                let user = user_from_json(json, node.mdate)?;
                                authorisation.add_user(user)?;
                            }
                        }
                    }
                }
                AUTH_USER_ADMIN_FIELD => {
                    need_room_admin = true;
                    for insert_entity in entry.1 {
                        if !insert_entity.edge_deletions.is_empty() {
                            return Err(Error::CannotRemove(
                                "sys.UserAuth".to_string(),
                                ROOM_ENT.to_string(),
                            ));
                        }
                        if insert_entity.node_to_mutate.node.is_none()
                            || insert_entity.node_to_mutate.old_node.is_some()
                        {
                            return Err(Error::UpdateNotAllowed());
                        }

                        let node_insert = &insert_entity.node_to_mutate;
                        if node_insert.room_id.is_some() {
                            return Err(Error::ForbiddenRoomId("sys.UserAuth".to_string()));
                        }
                        if let Some(node) = &node_insert.node {
                            if let Some(json) = &node._json {
                                let user = user_from_json(json, node.mdate)?;
                                authorisation.add_user_admin(user)?;
                            }
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
        if need_user_admin
            && !authorisation.can_admin_users(verifying_key, insert_entity.node_to_mutate.date)
        {
            need_room_admin = true;
        }

        Ok(need_room_admin)
    }

    pub fn rooms_for_peer(&self, verifying_key: &Vec<u8>, date: i64) -> HashSet<Uid> {
        let mut result = HashSet::new();
        for room in &self.rooms {
            if room.1.is_user_valid_at(verifying_key, date) {
                result.insert(*room.0);
            }
        }
        result
    }

    pub fn user_for_room(&self, room_id: Uid) -> Result<HashSet<Vec<u8>>> {
        let room = self
            .rooms
            .get(&room_id)
            .ok_or(Error::UnknownRoom(uid_encode(&room_id)))?;
        Ok(room.users())
    }

    // pub fn validate_peer_nodes_request(
    //     &self,
    //     room_id: Uid,
    //     keys: Vec<Vec<u8>>,
    // ) -> Result<Vec<Vec<u8>>> {
    //     let room = self
    //         .rooms
    //         .get(&room_id)
    //         .ok_or(Error::UnknownRoom(uid_encode(&room_id)))?;

    //     for key in &keys {
    //         if !room.has_user(key) {
    //             return Err(Error::InvalidUser(uid_encode(&room_id)));
    //         }
    //     }
    //     Ok(keys)
    // }

    pub const LOAD_QUERY: &'static str = "
        query LOAD_ROOMS{
            sys.Room {
                id
                mdate
                room_id
                admin (order_by(mdate desc)) {
                    mdate
                    verif_key
                    enabled
                }
               
                authorisations(nullable(rights, users, user_admin)){
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
                        verif_key
                        enabled
                    }
                    user_admin (order_by(mdate desc)) {
                        mdate
                        verif_key
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

            let id = uid_decode(room_map.get(ID_FIELD).unwrap().as_str().unwrap())?;
            let mdate = room_map
                .get(MODIFICATION_DATE_FIELD)
                .unwrap()
                .as_i64()
                .unwrap();

            let mut authorisations = HashMap::new();
            let auth_array = room_map
                .get(ROOM_AUTHORISATION_FIELD)
                .unwrap()
                .as_array()
                .unwrap();
            for auth_value in auth_array {
                let auth = load_auth_from_json(auth_value)?;
                authorisations.insert(auth.id, auth);
            }

            let mut room = Room {
                id,
                mdate,
                authorisations,
                admins: HashMap::new(),
            };

            let admin_array = room_map.get(ROOM_ADMIN_FIELD).unwrap().as_array().unwrap();
            for value in admin_array {
                let user = load_user_from_json(value)?;
                room.add_admin_user(user)?;
            }

            self.add_room(room);
        }

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

    pub fn validate_node(&self, node_to_insert: &NodeToInsert) -> bool {
        let node = match &node_to_insert.node {
            Some(n) => n,
            None => return false,
        };

        match bincode::serialized_size(node) {
            Ok(size) => {
                if size > self.max_node_size {
                    return false;
                }
            }
            Err(_) => return false,
        }

        let required_right = match &node_to_insert.old_verifying_key {
            Some(old_key) => match old_key.eq(&node.verifying_key) {
                true => RightType::MutateSelf,
                false => RightType::MutateAll,
            },
            None => RightType::MutateSelf,
        };
        let room_id = &node.room_id;
        if room_id.is_none() {
            return false; //during synchronisation only non empty rooms make sense
        }
        let room_id = room_id.unwrap();

        if let Some(old_room_id) = &node_to_insert.old_room_id {
            if !old_room_id.eq(&room_id) {
                let room = self.rooms.get(old_room_id);
                if room.is_none() {
                    return false;
                }
                let room = room.unwrap();
                if node_to_insert.entity_name.is_none() {
                    return false;
                }
                let entity_name = &node_to_insert.entity_name.clone().unwrap();
                if !room.can(
                    &node.verifying_key,
                    entity_name,
                    node.mdate,
                    &required_right,
                ) {
                    return false;
                }
            }
        }

        let room = self.rooms.get(&room_id);
        if room.is_none() {
            return false;
        }
        let room = room.unwrap();

        if node_to_insert.entity_name.is_none() {
            return false;
        }
        let entity_name = &node_to_insert.entity_name.clone().unwrap();
        if !room.can(
            &node.verifying_key,
            entity_name,
            node.mdate,
            &required_right,
        ) {
            return false;
        }

        // for edge in &node_to_insert.edges {
        //     let required_right = match &node_to_insert.old_verifying_key {
        //         Some(old_key) => match old_key.eq(&edge.verifying_key) {
        //             true => RightType::MutateSelf,
        //             false => RightType::MutateAll,
        //         },
        //         None => RightType::MutateSelf,
        //     };
        //     if !room.can(
        //         &edge.verifying_key,
        //         entity_name,
        //         edge.cdate,
        //         &required_right,
        //     ) {
        //         return false;
        //     }
        // }

        true
    }

    ///
    /// best effort edge validation
    ///
    pub fn validate_edge_deletions(
        &self,
        edges: Vec<(EdgeDeletionEntry, Option<Vec<u8>>)>,
    ) -> Vec<EdgeDeletionEntry> {
        let mut result = Vec::new();
        for entry in edges {
            let deletion = entry.0;
            if deletion.entity_name.is_none() {
                continue;
            };
            let entity_name = &deletion.entity_name.clone().unwrap();

            let room = &deletion.room_id;
            let room = self.rooms.get(room);
            if room.is_none() {
                continue;
            }
            let room = room.unwrap();
            let del_author = &deletion.verifying_key;
            let edge_author = entry.1;
            let valid = match edge_author {
                Some(author) => match author.eq(del_author) {
                    true => room.can(
                        del_author,
                        entity_name,
                        deletion.deletion_date,
                        &RightType::MutateSelf,
                    ),
                    false => room.can(
                        del_author,
                        entity_name,
                        deletion.deletion_date,
                        &RightType::MutateAll,
                    ),
                },
                None => room.can(
                    del_author,
                    entity_name,
                    deletion.deletion_date,
                    &RightType::MutateSelf,
                ),
            };
            if valid {
                result.push(deletion);
            }
        }
        result
    }

    ///
    /// best effort node deletion validation
    ///
    fn validate_node_deletions(
        &self,
        nodes: HashMap<Uid, (NodeDeletionEntry, Option<Vec<u8>>)>,
    ) -> Vec<NodeDeletionEntry> {
        let mut result = Vec::new();
        for entry in nodes {
            let entry = entry.1;
            let deletion = entry.0;
            if deletion.entity_name.is_none() {
                continue;
            };
            let entity_name = &deletion.entity_name.clone().unwrap();

            let room = &deletion.room_id;
            let room = self.rooms.get(room);
            if room.is_none() {
                continue;
            }
            let room = room.unwrap();
            let del_author = &deletion.verifying_key;
            let edge_author = entry.1;
            let valid = match edge_author {
                Some(author) => match author.eq(del_author) {
                    true => room.can(
                        del_author,
                        entity_name,
                        deletion.deletion_date,
                        &RightType::MutateSelf,
                    ),
                    false => room.can(
                        del_author,
                        entity_name,
                        deletion.deletion_date,
                        &RightType::MutateAll,
                    ),
                },
                None => room.can(
                    del_author,
                    entity_name,
                    deletion.deletion_date,
                    &RightType::MutateSelf,
                ),
            };
            if valid {
                result.push(deletion);
            }
        }
        result
    }
}
