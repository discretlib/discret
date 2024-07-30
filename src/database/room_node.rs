use std::cmp::max;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::security::{base64_decode, Uid};

use crate::database::{
    edge::Edge,
    node::Node,
    room::{Authorisation, EntityRight, Room, User},
    system_entities::{
        AUTHORISATION_ENT_SHORT, AUTH_RIGHTS_FIELD_SHORT, AUTH_USER_ADMIN_FIELD_SHORT,
        AUTH_USER_FIELD_SHORT, ENTITY_RIGHT_ENT_SHORT, RIGHT_ENTITY_SHORT, RIGHT_MUTATE_ALL_SHORT,
        RIGHT_MUTATE_SELF_SHORT, ROOM_ADMIN_FIELD_SHORT, ROOM_AUTHORISATION_FIELD_SHORT,
        ROOM_ENT_SHORT, USER_AUTH_ENT_SHORT, USER_ENABLED_SHORT, USER_VERIFYING_KEY_SHORT,
    },
    Error, Result,
};

///
/// room database definition that is used for data synchronisation
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomNode {
    pub node: Node,
    pub last_modified: i64,
    pub admin_edges: Vec<Edge>,
    pub admin_nodes: Vec<UserNode>,
    pub auth_edges: Vec<Edge>,
    pub auth_nodes: Vec<AuthorisationNode>,
}
impl RoomNode {
    ///
    /// validate signature and basic data consistency
    ///
    pub fn check_consistency(&self) -> Result<()> {
        //check admin consistency
        if self.admin_edges.len() != self.admin_nodes.len() {
            return Err(Error::InvalidNode(
                "RoomNode admin edge and node have different size".to_string(),
            ));
        }
        for admin_edge in &self.admin_edges {
            if !admin_edge.src.eq(&self.node.id) {
                return Err(Error::InvalidNode(
                    "Invalid RoomNode admin edge src".to_string(),
                ));
            }
            let user_node = self
                .admin_nodes
                .iter()
                .find(|user| user.node.id.eq(&admin_edge.dest));

            if user_node.is_none() {
                return Err(Error::InvalidNode(
                    "RoomNode has an invalid admin egde".to_string(),
                ));
            }
        }

        //check authorisation consistency
        if self.auth_edges.len() != self.auth_nodes.len() {
            return Err(Error::InvalidNode(
                "RoomNode authorisation edge and node have different size".to_string(),
            ));
        }
        for auth_edge in &self.auth_edges {
            if !auth_edge.src.eq(&self.node.id) {
                return Err(Error::InvalidNode(
                    "Invalid RoomNode authorisation edge src".to_string(),
                ));
            }
            let auth_node = self
                .auth_nodes
                .iter()
                .find(|auth| auth.node.id.eq(&auth_edge.dest));

            match auth_node {
                Some(auth) => auth.check_consistency()?,
                None => {
                    return Err(Error::InvalidNode(
                        "RoomNode has an invalid authorisation egde".to_string(),
                    ))
                }
            }
        }

        Ok(())
    }

    ///
    /// write in the database
    ///
    /// it is assumed that duplication check has allready been performed
    ///
    pub fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        self.node.write(conn, false, &None, &None)?;

        for a in &self.admin_edges {
            a.write(conn)?;
        }

        for a in &mut self.admin_nodes {
            a.write(conn)?;
        }

        for a in &self.auth_edges {
            a.write(conn)?;
        }

        for a in &mut self.auth_nodes {
            a.write(conn)?;
        }
        Ok(())
    }

    pub fn read(conn: &Connection, id: &Uid) -> std::result::Result<Option<Self>, rusqlite::Error> {
        let node = Node::get_with_entity(id, ROOM_ENT_SHORT, conn)?;
        if node.is_none() {
            return Ok(None);
        }
        let node = *node.unwrap();

        let mut last_modified = node.mdate;

        let mut admin_edges = Edge::get_edges(id, ROOM_ADMIN_FIELD_SHORT, conn)?;
        //user insertion order is mandatory
        admin_edges.sort_by(|a, b| b.cdate.cmp(&a.cdate));

        let mut admin_nodes = Vec::new();
        for edge in &admin_edges {
            let user_opt = UserNode::read(conn, &edge.dest)?;
            if let Some(user) = user_opt {
                last_modified = max(last_modified, user.node.mdate);
                admin_nodes.push(user);
            }
        }

        let auth_edges = Edge::get_edges(id, ROOM_AUTHORISATION_FIELD_SHORT, conn)?;
        let mut auth_nodes = Vec::new();
        for edge in &auth_edges {
            let auth_opt = AuthorisationNode::read(conn, &edge.dest)?;
            if let Some(auth) = auth_opt {
                last_modified = max(last_modified, auth.last_modified);
                auth_nodes.push(auth);
            }
        }

        Ok(Some(Self {
            node,
            last_modified,
            admin_edges,
            admin_nodes,
            auth_edges,
            auth_nodes,
        }))
    }

    ///
    /// Parse RoomNode into a Room
    ///
    pub fn parse(&self) -> Result<Room> {
        let mut room = Room {
            id: self.node.id,
            mdate: self.node.mdate,
            ..Default::default()
        };

        for user in &self.admin_nodes {
            let user = user.parse()?;
            room.add_admin_user(user)?;
        }

        for auth in &self.auth_nodes {
            let authorisation = auth.parse()?;
            room.add_auth(authorisation)?;
        }

        Ok(room)
    }
}

///
/// authorisation database definition that is used for data synchronisation
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorisationNode {
    pub node: Node,
    pub last_modified: i64,
    pub right_edges: Vec<Edge>,
    pub right_nodes: Vec<EntityRightNode>,
    pub user_edges: Vec<Edge>,
    pub user_nodes: Vec<UserNode>,
    pub user_admin_edges: Vec<Edge>,
    pub user_admin_nodes: Vec<UserNode>,
    pub need_update: bool,
}
impl AuthorisationNode {
    ///
    /// validate basic data consistency
    ///
    pub fn check_consistency(&self) -> Result<()> {
        //check right consistency
        if self.right_edges.len() != self.right_nodes.len() {
            return Err(Error::InvalidNode(
                "AuthorisationNode Rights edges and nodes have different size".to_string(),
            ));
        }
        for right_edge in &self.right_edges {
            if !right_edge.src.eq(&self.node.id) {
                return Err(Error::InvalidNode(
                    "Invalid AuthorisationNode Right edge source".to_string(),
                ));
            }
            let right_node = self
                .right_nodes
                .iter()
                .find(|right| right.node.id.eq(&right_edge.dest));

            if right_node.is_none() {
                return Err(Error::InvalidNode(
                    "AuthorisationNode has an invalid Right egde".to_string(),
                ));
            }
        }

        //check user consistency
        if self.user_edges.len() != self.user_nodes.len() {
            return Err(Error::InvalidNode(
                "AuthorisationNode user edges and nodes have different size".to_string(),
            ));
        }
        for user_edge in &self.user_edges {
            if !user_edge.src.eq(&self.node.id) {
                return Err(Error::InvalidNode(
                    "Invalid AuthorisationNode user edge source".to_string(),
                ));
            }
            let user_node = self
                .user_nodes
                .iter()
                .find(|user| user.node.id.eq(&user_edge.dest));

            if user_node.is_none() {
                return Err(Error::InvalidNode(
                    "AuthorisationNode has an invalid user egde".to_string(),
                ));
            }
        }

        //check right consistency
        if self.user_admin_edges.len() != self.user_admin_nodes.len() {
            return Err(Error::InvalidNode(
                "AuthorisationNode Rights edges and nodes have different size".to_string(),
            ));
        }
        for user_admin_edge in &self.user_admin_edges {
            if !user_admin_edge.src.eq(&self.node.id) {
                return Err(Error::InvalidNode(
                    "Invalid AuthorisationNode Right edge source".to_string(),
                ));
            }
            let user_admin_node = self
                .user_admin_nodes
                .iter()
                .find(|right| right.node.id.eq(&user_admin_edge.dest));

            if user_admin_node.is_none() {
                return Err(Error::InvalidNode(
                    "AuthorisationNode has an invalid Right egde".to_string(),
                ));
            }
        }

        Ok(())
    }
    pub fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        if self.need_update {
            self.node.write(conn, false, &None, &None)?;
        }
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

        for a in &self.user_admin_edges {
            a.write(conn)?;
        }

        for a in &mut self.user_admin_nodes {
            a.write(conn)?;
        }

        Ok(())
    }

    pub fn read(conn: &Connection, id: &Uid) -> std::result::Result<Option<Self>, rusqlite::Error> {
        let node = Node::get_with_entity(id, AUTHORISATION_ENT_SHORT, conn)?;
        if node.is_none() {
            return Ok(None);
        }
        let node = *node.unwrap();
        let mut last_modified = node.mdate;
        let mut right_edges = Edge::get_edges(id, AUTH_RIGHTS_FIELD_SHORT, conn)?;
        //rights insertion must respect must be done in the right order
        right_edges.sort_by(|a, b| b.cdate.cmp(&a.cdate));

        let mut right_nodes = Vec::new();
        for edge in &right_edges {
            let right_opt = EntityRightNode::read(conn, &edge.dest)?;
            if let Some(cred) = right_opt {
                last_modified = max(last_modified, cred.node.mdate);
                right_nodes.push(cred);
            }
        }

        let mut user_edges = Edge::get_edges(id, AUTH_USER_FIELD_SHORT, conn)?;
        //user insertion order is mandatory
        user_edges.sort_by(|a, b| b.cdate.cmp(&a.cdate));

        let mut user_nodes = Vec::new();
        for edge in &user_edges {
            let user_opt = UserNode::read(conn, &edge.dest)?;
            if let Some(user) = user_opt {
                last_modified = max(last_modified, user.node.mdate);
                user_nodes.push(user);
            }
        }

        let mut user_admin_edges = Edge::get_edges(id, AUTH_USER_ADMIN_FIELD_SHORT, conn)?;
        //user insertion order is mandatory
        user_admin_edges.sort_by(|a, b| b.cdate.cmp(&a.cdate));

        let mut user_admin_nodes = Vec::new();
        for edge in &user_admin_edges {
            let user_opt = UserNode::read(conn, &edge.dest)?;
            if let Some(user) = user_opt {
                last_modified = max(last_modified, user.node.mdate);
                user_admin_nodes.push(user);
            }
        }

        Ok(Some(Self {
            node,
            last_modified,
            right_edges,
            right_nodes,
            user_edges,
            user_nodes,
            user_admin_edges,
            user_admin_nodes,
            need_update: true,
        }))
    }

    pub fn parse(&self) -> Result<Authorisation> {
        let mut authorisation = Authorisation {
            id: self.node.id,
            mdate: self.node.mdate,
            ..Default::default()
        };
        for right_node in &self.right_nodes {
            let entity_right = right_node.parse()?;
            authorisation.add_right(entity_right)?;
        }

        for user_node in &self.user_nodes {
            let user = user_node.parse()?;
            authorisation.add_user(user)?;
        }

        for user in &self.user_admin_nodes {
            let user = user.parse()?;
            authorisation.add_user_admin(user)?;
        }
        Ok(authorisation)
    }
}

///
/// User database definition that is used for data synchronisation
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserNode {
    pub node: Node,
}
impl UserNode {
    pub fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        if self.node._local_id.is_none() {
            self.node.write(conn, false, &None, &None)?;
        }
        Ok(())
    }

    pub fn read(conn: &Connection, id: &Uid) -> std::result::Result<Option<Self>, rusqlite::Error> {
        let node = Node::get_with_entity(id, USER_AUTH_ENT_SHORT, conn)?;
        if node.is_none() {
            return Ok(None);
        }
        let node = *node.unwrap();
        Ok(Some(Self { node }))
    }

    fn parse(&self) -> Result<User> {
        let json = &self.node._json.as_ref().ok_or(Error::InvalidNode(
            "Invalid UserNode: empty Json".to_string(),
        ))?;

        let user_json: serde_json::Value = serde_json::from_str(json)?;
        let user_map = user_json.as_object().ok_or(Error::InvalidNode(
            "Invalid UserNode node: invalid object".to_string(),
        ))?;

        let verifying_key = user_map
            .get(USER_VERIFYING_KEY_SHORT)
            .ok_or(Error::InvalidNode(
                "Invalid UserNode node: missing 'verifying_key'".to_string(),
            ))?;
        let verifying_key = verifying_key.as_str().ok_or(Error::InvalidNode(
            "Invalid UserNode node: 'verifying_key' is not a String".to_string(),
        ))?;
        let verifying_key = base64_decode(verifying_key.as_bytes())?;

        let enabled = match user_map.get(USER_ENABLED_SHORT) {
            Some(v) => v.as_bool().ok_or(Error::InvalidNode(
                "Invalid UserNode node: 'enabled' is not a boolean".to_string(),
            ))?,
            None => true,
        };

        let date = self.node.mdate;

        let user = User {
            verifying_key,
            date,
            enabled,
        };

        Ok(user)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRightNode {
    pub node: Node,
}
impl EntityRightNode {
    pub fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        if self.node._local_id.is_none() {
            self.node.write(conn, false, &None, &None)?;
        }
        Ok(())
    }

    pub fn read(conn: &Connection, id: &Uid) -> std::result::Result<Option<Self>, rusqlite::Error> {
        let node = Node::get_with_entity(id, ENTITY_RIGHT_ENT_SHORT, conn)?;
        if node.is_none() {
            return Ok(None);
        }
        let node = *node.unwrap();
        Ok(Some(Self { node }))
    }

    pub fn parse(&self) -> Result<EntityRight> {
        let json = self.node._json.as_ref().ok_or(Error::InvalidNode(
            "Invalid EntityRight node: empty json".to_string(),
        ))?;

        let right_json: serde_json::Value = serde_json::from_str(json)?;

        let right_map = right_json.as_object().ok_or(Error::InvalidNode(
            "Invalid EntityRight node: invalid Json Object".to_string(),
        ))?;

        let entity = right_map.get(RIGHT_ENTITY_SHORT).ok_or(Error::InvalidNode(
            "Invalid EntityRight node: no Entity field".to_string(),
        ))?;
        let entity = entity
            .as_str()
            .ok_or(Error::InvalidNode(
                "Invalid EntityRight node: Entity is not a string".to_string(),
            ))?
            .to_string();

        let mutate_self = right_map
            .get(RIGHT_MUTATE_SELF_SHORT)
            .ok_or(Error::InvalidNode(
                "Invalid EntityRight node: no mutate_self field".to_string(),
            ))?;
        let mutate_self = mutate_self.as_bool().ok_or(Error::InvalidNode(
            "Invalid EntityRight node: mutate_self is not a boolean ".to_string(),
        ))?;

        let mutate_all = right_map
            .get(RIGHT_MUTATE_ALL_SHORT)
            .ok_or(Error::InvalidNode(
                "Invalid EntityRight node: no mutate_all field".to_string(),
            ))?;
        let mutate_all = mutate_all.as_bool().ok_or(Error::InvalidNode(
            "Invalid EntityRight node: mutate_all is not a boolean ".to_string(),
        ))?;

        let entity_right = EntityRight::new(self.node.mdate, entity, mutate_self, mutate_all);

        Ok(entity_right)
    }
}

///
/// validate the room node against the existing one
/// returns true if the node has changes to be inserted in the database
///
pub fn prepare_room_with_history(
    room: &Room,
    old_room_node: &RoomNode,
    room_node: &mut RoomNode,
) -> Result<bool> {
    let mut need_update = false;
    let mut room = room.clone();
    room_node.node._local_id = old_room_node.node._local_id;

    //ensure that existing admin edges exists in the room_node
    for old_edge in &old_room_node.admin_edges {
        let admin_edge = &room_node.admin_edges.iter().find(|edge| edge.eq(old_edge));
        if admin_edge.is_none() {
            room_node.admin_edges.push(old_edge.clone());
        }
    }
    room_node.admin_edges.sort_by(|a, b| a.cdate.cmp(&b.cdate));

    for old_user in &old_room_node.admin_nodes {
        let admin_node = room_node
            .admin_nodes
            .iter_mut()
            .find(|user| user.node.id.eq(&old_user.node.id));

        match admin_node {
            Some(user) => match user.node.eq(&old_user.node) {
                true => user.node._local_id = old_user.node._local_id,
                false => {
                    return Err(Error::InvalidNode(
                        "Invalid RoomNode, Administrator nodes cannot be mutated ".to_string(),
                    ))
                }
            },
            None => {
                room_node.admin_nodes.push(old_user.clone());
            }
        }
    }
    room_node
        .admin_nodes
        .sort_by(|a, b| a.node.mdate.cmp(&b.node.mdate));

    //
    // Find new admins and add them to the cloned room
    // the cloned room will be then used to validate every other room update
    //
    for new_admin in &room_node.admin_nodes {
        let admin_node = old_room_node
            .admin_nodes
            .iter()
            .find(|user| user.node.id.eq(&new_admin.node.id));
        if admin_node.is_none() {
            match room.is_admin(&new_admin.node.verifying_key, new_admin.node.mdate) {
                true => {
                    let user = new_admin.parse()?;
                    room.add_admin_user(user)?;
                    need_update = true;
                }
                false => {
                    return Err(Error::InvalidNode(
                        "RoomNode Administrator is not authorised".to_string(),
                    ))
                }
            }
        }
    }

    //check authorisation
    for old_edge in &old_room_node.auth_edges {
        let auth_edge = &room_node.auth_edges.iter().find(|edge| edge.eq(old_edge));
        if auth_edge.is_none() {
            room_node.auth_edges.push(old_edge.clone());
        }
    }

    for old_auth in &old_room_node.auth_nodes {
        let auth_node = room_node
            .auth_nodes
            .iter_mut()
            .find(|auth| auth.node.id.eq(&old_auth.node.id));

        match auth_node {
            Some(new_auth) => {
                match old_auth.node.mdate < new_auth.node.mdate {
                    true => {
                        new_auth.node._local_id = old_auth.node._local_id;
                        if !room.is_admin(&new_auth.node.verifying_key, new_auth.node.mdate) {
                            return Err(Error::InvalidNode(
                                "RoomNode Authorisation mutation not authorised".to_string(),
                            ));
                        }
                        need_update = true;
                        prepare_auth_with_history(&room, old_auth, new_auth)?;
                    }
                    false => {
                        new_auth.node = old_auth.node.clone();
                        new_auth.need_update = false;
                        if prepare_auth_with_history(&room, old_auth, new_auth)? {
                            need_update = true;
                        }
                    }
                };
            }
            None => {
                room_node.auth_nodes.push(old_auth.clone());
            }
        }
    }

    //handle new authorisations
    for new_auth in &room_node.auth_nodes {
        let old_auth = old_room_node
            .auth_nodes
            .iter()
            .find(|auth| auth.node.id.eq(&new_auth.node.id));
        if old_auth.is_none() {
            match room.is_admin(&new_auth.node.verifying_key, new_auth.node.mdate) {
                true => {
                    prepare_new_auth(&room, new_auth)?;
                    need_update = true;
                }
                false => {
                    return Err(Error::InvalidNode(
                        "RoomNode new Authorisation mutation not authorised".to_string(),
                    ))
                }
            }
        }
    }

    room_node.parse()?;

    Ok(need_update)
}

///
/// validate the new room by checking its rights and parsing it to validate json
///
pub fn prepare_new_room(room_node: &RoomNode) -> Result<()> {
    let room = room_node.parse()?;

    //verify rights
    for admin in &room_node.admin_nodes {
        if !room.is_admin(&admin.node.verifying_key, admin.node.mdate) {
            return Err(Error::InvalidNode(
                "New RoomNode Administrator not authorised".to_string(),
            ));
        }
    }

    for auth in &room_node.auth_nodes {
        match room.is_admin(&auth.node.verifying_key, auth.node.mdate) {
            true => {
                for user in &auth.user_nodes {
                    if !room.is_admin(&user.node.verifying_key, user.node.mdate) {
                        return Err(Error::InvalidNode(
                            "New RoomNode Authorisation User not authorised".to_string(),
                        ));
                    }
                }
                for right in &auth.right_nodes {
                    if !room.is_admin(&right.node.verifying_key, right.node.mdate) {
                        return Err(Error::InvalidNode(
                            "New RoomNode Authorisation Right not authorised".to_string(),
                        ));
                    }
                }

                for user_admin in &auth.user_admin_nodes {
                    if !room.is_admin(&user_admin.node.verifying_key, user_admin.node.mdate) {
                        return Err(Error::InvalidNode(
                            "New RoomNode User Administrator not authorised".to_string(),
                        ));
                    }
                }
            }
            false => {
                return Err(Error::InvalidNode(
                    "New RoomNode Authorisation not authorised".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn prepare_auth_with_history(
    room: &Room,
    old_auth: &AuthorisationNode,
    new_auth: &mut AuthorisationNode,
) -> Result<bool> {
    let mut need_update = false;

    //clone the existing auth to add new admins and check the reast of the authorisations
    let mut authorisation = room
        .authorisations
        .get(&old_auth.node.id)
        .expect("the old auth is extracted from the passed room")
        .clone();

    //ensure that existing user_admin edges exists in the auth_node
    for old_edge in &old_auth.user_admin_edges {
        let user_admin_edge = &new_auth
            .user_admin_edges
            .iter()
            .find(|edge| edge.eq(old_edge));
        if user_admin_edge.is_none() {
            new_auth.user_admin_edges.push(old_edge.clone());
        }
    }
    new_auth
        .user_admin_edges
        .sort_by(|a, b| a.cdate.cmp(&b.cdate));

    for old_user in &old_auth.user_admin_nodes {
        let user_admin_node = new_auth
            .user_admin_nodes
            .iter_mut()
            .find(|user| user.node.id.eq(&old_user.node.id));

        match user_admin_node {
            Some(user) => match user.node.eq(&old_user.node) {
                true => user.node._local_id = old_user.node._local_id,
                false => {
                    return Err(Error::InvalidNode(
                        "Invalid RoomNode, User Administrator nodes cannot be mutated ".to_string(),
                    ))
                }
            },
            None => {
                new_auth.user_admin_nodes.push(old_user.clone());
            }
        }
    }
    new_auth
        .user_admin_nodes
        .sort_by(|a, b| a.node.mdate.cmp(&b.node.mdate));

    //
    //
    // Find new admins and add them to the cloned room
    // the cloned room will be then used to validate every other room update
    //
    for new_user_admin in &new_auth.user_admin_nodes {
        let user_admin_node = old_auth
            .user_admin_nodes
            .iter()
            .find(|user| user.node.id.eq(&new_user_admin.node.id));
        if user_admin_node.is_none() {
            match room.is_admin(
                &new_user_admin.node.verifying_key,
                new_user_admin.node.mdate,
            ) {
                true => {
                    let user = new_user_admin.parse()?;
                    authorisation.add_user_admin(user)?;
                    need_update = true;
                }
                false => {
                    return Err(Error::InvalidNode(
                        "RoomNode User Administrator is not authorised".to_string(),
                    ))
                }
            }
        }
    }

    //ensure that existing user edges and nodes are included in the new Authorisation
    for old_edge in &old_auth.user_edges {
        let user_edge = &new_auth.user_edges.iter().find(|edge| edge.eq(old_edge));
        if user_edge.is_none() {
            new_auth.user_edges.push(old_edge.clone());
        }
    }
    new_auth.user_edges.sort_by(|a, b| a.cdate.cmp(&b.cdate));

    for old_user in &old_auth.user_nodes {
        let user_node = new_auth
            .user_nodes
            .iter_mut()
            .find(|user| user.node.id.eq(&old_user.node.id));

        match user_node {
            Some(user) => match user.node.eq(&old_user.node) {
                true => user.node._local_id = old_user.node._local_id,
                false => {
                    return Err(Error::InvalidNode(
                        "Invalid RoomNode, User Authorisation nodes cannot be mutated ".to_string(),
                    ))
                }
            },
            None => {
                new_auth.user_nodes.push(old_user.clone());
            }
        }
    }
    new_auth
        .user_nodes
        .sort_by(|a, b| a.node.mdate.cmp(&b.node.mdate));

    //
    // verify new users
    //
    for new_user in &new_auth.user_nodes {
        let user_node = old_auth
            .user_nodes
            .iter()
            .find(|user| user.node.id.eq(&new_user.node.id));

        if user_node.is_none() {
            match authorisation.can_admin_users(&new_user.node.verifying_key, new_user.node.mdate) {
                true => {
                    need_update = true;
                }
                false => match room.is_admin(&new_user.node.verifying_key, new_user.node.mdate) {
                    true => {
                        need_update = true;
                    }
                    false => {
                        return Err(Error::InvalidNode(
                            "RoomNode Authorisation new User not authorised".to_string(),
                        ))
                    }
                },
            }
        }
    }

    //ensure that existing Right edges and nodes are included in the new Authorisation
    for old_edge in &old_auth.right_edges {
        let right_edge = &new_auth.right_edges.iter().find(|edge| edge.eq(old_edge));
        if right_edge.is_none() {
            new_auth.right_edges.push(old_edge.clone());
        }
    }
    new_auth.right_edges.sort_by(|a, b| a.cdate.cmp(&b.cdate));

    for old_right in &old_auth.right_nodes {
        let right_node = new_auth
            .right_nodes
            .iter_mut()
            .find(|user| user.node.id.eq(&old_right.node.id));

        match right_node {
            Some(right) => match right.node.eq(&old_right.node) {
                true => right.node._local_id = old_right.node._local_id,
                false => {
                    return Err(Error::InvalidNode(
                        "Invalid RoomNode Authorisation, Right nodes cannot be mutated "
                            .to_string(),
                    ))
                }
            },
            None => {
                new_auth.right_nodes.push(old_right.clone());
            }
        }
    }
    new_auth
        .right_nodes
        .sort_by(|a, b| a.node.mdate.cmp(&b.node.mdate));

    //
    // verify new right
    //
    for new_right in &new_auth.right_nodes {
        let right_node = old_auth
            .right_nodes
            .iter()
            .find(|user| user.node.id.eq(&new_right.node.id));

        if right_node.is_none() {
            match room.is_admin(&new_right.node.verifying_key, new_right.node.mdate) {
                true => {
                    need_update = true;
                }
                false => {
                    return Err(Error::InvalidNode(
                        "RoomNode Authorisation new Right is not authorised".to_string(),
                    ))
                }
            }
        }
    }
    Ok(need_update)
}

fn prepare_new_auth(room: &Room, new_auth: &AuthorisationNode) -> Result<()> {
    let authorisation = new_auth.parse()?;
    for new_user in &new_auth.user_nodes {
        if !authorisation.can_admin_users(&new_user.node.verifying_key, new_user.node.mdate) {
            return Err(Error::InvalidNode(
                "RoomNode Authorisation new user is not authorised".to_string(),
            ));
        }
    }
    for new_right in &new_auth.right_nodes {
        if !room.is_admin(&new_right.node.verifying_key, new_right.node.mdate) {
            return Err(Error::InvalidNode(
                "RoomNode Authorisation new Right is not authorised".to_string(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use crate::{
        configuration::Configuration,
        database::{
            graph_database::GraphDatabaseService,
            query_language::parameter::{Parameters, ParametersAdd},
            room::RightType,
            system_entities::ROOM_AUTHORISATION_FIELD,
        },
        date_utils::now,
        event_service::EventService,
        log_service::LogService,
        security::{base64_encode, new_uid, random32, Ed25519SigningKey},
    };

    use super::*;
    use std::{fs, path::PathBuf};
    const DATA_PATH: &str = "test_data/database/authorisation_synch_test/";
    fn init_database_path() {
        let path: PathBuf = DATA_PATH.into();
        fs::create_dir_all(&path).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn export_room_from_database() {
        init_database_path();
        let data_model = "{
            Person{ 
                name:String, 
                parents:[Person]
            }
        }   
        ";

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let (app, verifying_key, _) = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
            LogService::start(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(&verifying_key);

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        let room = app
            .mutate_raw(
                r#"mutate mut {
                    sys.Room{
                        admin: [{
                            verif_key:$user_id
                        }]
                        
                        authorisations:[{
                            name:"admin"
                            rights:[{
                                entity:"Person"
                                mutate_self:true
                                mutate_all:true
                            }]
                            users: [{
                                verif_key:$user_id
                            }]

                            user_admin: [{
                                verif_key:$user_id
                            }]
                        }]
                    }

                }"#,
                Some(param),
            )
            .await
            .unwrap();

        let room_insert = &room.mutate_entities[0];

        let node: RoomNode = app
            .get_room_node(room_insert.node_to_mutate.id)
            .await
            .unwrap()
            .unwrap();

        node.check_consistency().unwrap();
        assert_eq!(1, node.admin_edges.len());
        assert_eq!(1, node.admin_edges.len());

        assert_eq!(1, node.auth_edges.len());
        assert_eq!(1, node.auth_nodes.len());

        let auth_node = &node.auth_nodes[0];
        assert_eq!("{\"32\":\"admin\"}", auth_node.node._json.clone().unwrap());
        assert_eq!(1, auth_node.right_edges.len());
        assert_eq!(1, auth_node.right_nodes.len());

        let right_node = &auth_node.right_nodes[0];
        assert_eq!(
            "{\"32\":\"Person\",\"33\":true,\"34\":true}",
            right_node.node._json.clone().unwrap()
        );
        assert_eq!(1, auth_node.user_edges.len());
        assert_eq!(1, auth_node.user_nodes.len());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn parse_room_node_test() {
        init_database_path();
        let data_model = "
        {
            Person{ 
                name:String, 
                parents:[Person]
            }   
        }";

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let (app, verifying_key, _) = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
            LogService::start(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(&verifying_key);

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        let room = app
            .mutate_raw(
                r#"mutate mut {
                    sys.Room{
                        admin: [{
                            verif_key:$user_id
                        }]

                        authorisations:[{
                            name:"admin"
                            rights:[{
                                entity:"Person"
                                mutate_self:true
                                mutate_all:true
                            }]
                        }]
                    }

                }"#,
                Some(param),
            )
            .await
            .unwrap();

        let room_insert = &room.mutate_entities[0];

        let node = app
            .get_room_node(room_insert.node_to_mutate.id)
            .await
            .unwrap()
            .unwrap();
        let room = node.parse().unwrap();
        assert!(room.can(&verifying_key, "Person", now(), &RightType::MutateAll));
        assert!(!room.can(&verifying_key, "Persons", now(), &RightType::MutateAll));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reinsert_room_node() {
        init_database_path();
        let data_model = "
        {
            Person{ 
                name:String, 
                parents:[Person]
            }
        }";

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let (app, verifying_key, _) = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
            LogService::start(),
        )
        .await
        .unwrap();

        let user_id = base64_encode(&verifying_key);

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        let room = app
            .mutate_raw(
                r#"mutate mut {
                    sys.Room {
                        admin: [{
                            verif_key:$user_id
                        }]
                        authorisations:[{
                            name:"admin"
                        }]
                    }
                }"#,
                Some(param),
            )
            .await
            .unwrap();

        let room_insert = &room.mutate_entities[0];
        let room_id = base64_encode(&room_insert.node_to_mutate.id);
        let node = app
            .get_room_node(room_insert.node_to_mutate.id)
            .await
            .unwrap()
            .unwrap();

        app.add_room_node(node.clone()).await.unwrap();

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();
        param.add("room_id", room_id.clone()).unwrap();
        app.mutate_raw(
            r#"mutate mut {
                sys.Room{
                    id:$room_id
                    authorisations:[{
                        name:"new"
                        rights:[{
                            entity:"Person"
                            mutate_self:true
                            mutate_all:true
                        }]
                        users: [{
                            verif_key:$user_id
                        }]
                    }]
                }

            }"#,
            Some(param),
        )
        .await
        .unwrap();

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        app.mutate_raw(
            r#"mutate mut {
            Person{
                room_id: $room_id
                name:"someone"
            }

        }"#,
            Some(param),
        )
        .await
        .unwrap();

        //add the old rooom definition, the new defition will not be replaced
        app.add_room_node(node.clone()).await.unwrap();

        //we are still able to insert data
        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        app.mutate_raw(
            r#"mutate  {
            Person{
                room_id: $room_id
                name:"someone 2"
            }

        }"#,
            Some(param),
        )
        .await
        .unwrap();

        let result = app
            .query(
                "query d {
            Person(order_by(name desc)){
                name
            }

        }",
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            result,
            "{\n\"Person\":[{\"name\":\"someone 2\"},{\"name\":\"someone\"}]\n}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn transfert_room() {
        init_database_path();
        let data_model = "
        {
            Person{ 
                name:String, 
                parents:[Person]
            }   
        }";

        let path: PathBuf = DATA_PATH.into();
        let secret = random32();
        let (first_app, verifying_key, _) = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
            LogService::start(),
        )
        .await
        .unwrap();
        let first_user_id = base64_encode(&verifying_key);

        let path: PathBuf = DATA_PATH.into();
        let secret = random32();
        let (second_app, verifying_key, _) = GraphDatabaseService::start(
            "authorisation app",
            data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
            LogService::start(),
        )
        .await
        .unwrap();
        let second_user_id = base64_encode(&verifying_key);

        let mut param = Parameters::default();
        param.add("user_id", first_user_id.clone()).unwrap();
        let room = first_app
            .mutate_raw(
                r#"mutate mut {
                    sys.Room{
                        admin: [{
                            verif_key:$user_id
                        }]

                        authorisations:[{
                            name:"admin"
                            rights:[{
                                entity:"Person"
                                mutate_self:true
                                mutate_all:true
                            }]
                            users: [{
                                verif_key:$user_id
                            }]
                            user_admin: [{
                                verif_key:$user_id
                            }]
                        }]
                    }
                }"#,
                Some(param),
            )
            .await
            .unwrap();

        let room_insert = &room.mutate_entities[0];
        let room_id = base64_encode(&room_insert.node_to_mutate.id);

        let auth_insert = &room_insert.sub_nodes.get(ROOM_AUTHORISATION_FIELD).unwrap()[0];
        let auth_id = base64_encode(&auth_insert.node_to_mutate.id);

        let node = first_app
            .get_room_node(room_insert.node_to_mutate.id)
            .await
            .unwrap()
            .unwrap();
        //serialize and deserialize to get rid of the local_id
        let ser = bincode::serialize(&node).unwrap();
        let node: RoomNode = bincode::deserialize(&ser).unwrap();

        second_app.add_room_node(node.clone()).await.unwrap();

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        first_app
            .mutate_raw(
                r#"mutate mut {
            Person{
                room_id: $room_id
                name:"someone"
            }

        }"#,
                Some(param),
            )
            .await
            .expect("first_user can insert");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        second_app
            .mutate_raw(
                r#"mutate mut {
                Person{
                    room_id: $room_id
                    name:"someone"
                }
    
            }"#,
                Some(param),
            )
            .await
            .expect_err("second_user cannot insert");

        //add second_user to the authorisation
        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("auth_id", auth_id.clone()).unwrap();
        param.add("user_id", second_user_id.clone()).unwrap();

        first_app
            .mutate_raw(
                r#"mutate mut {
                sys.Room{
                    id:$room_id
                    authorisations:[{
                        id:$auth_id
                        users: [{
                            verif_key:$user_id
                        }]
                    }]
                }

            }"#,
                Some(param),
            )
            .await
            .expect("first user can modify the room");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("auth_id", auth_id.clone()).unwrap();
        param.add("user_id", second_user_id.clone()).unwrap();

        second_app
            .mutate_raw(
                r#"mutate mut {
                    sys.Room{
                        id:$room_id
                        authorisations:[{
                            id:$auth_id
                            users: [{
                                verif_key:$user_id
                            }]
                        }]
                    }
                }"#,
                Some(param),
            )
            .await
            .expect_err("second user cannot modify the room");

        let node = first_app
            .get_room_node(room_insert.node_to_mutate.id)
            .await
            .unwrap()
            .unwrap();
        //serialize and deserialize to get rid of the local_id
        let ser = bincode::serialize(&node).unwrap();
        let node: RoomNode = bincode::deserialize(&ser).unwrap();

        second_app.add_room_node(node.clone()).await.unwrap();

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        second_app
            .mutate_raw(
                r#"mutate mut {
                Person{
                    room_id: $room_id
                    name:"someone"
                }
    
            }"#,
                Some(param),
            )
            .await
            .expect("second_user can now insert");

        //remove second_user to the authorisation
        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("auth_id", auth_id.clone()).unwrap();
        param.add("user_id", second_user_id.clone()).unwrap();

        first_app
            .mutate_raw(
                r#"mutate mut {
                    sys.Room{
                        id:$room_id
                        authorisations:[{
                            id:$auth_id
                            users: [{
                                verif_key:$user_id
                                enabled: false
                            }]
                        }]
                    }
                }"#,
                Some(param),
            )
            .await
            .expect("first user can modify the room");

        let node = first_app
            .get_room_node(room_insert.node_to_mutate.id)
            .await
            .unwrap()
            .unwrap();

        //serialize and deserialize to get rid of the local_id
        let ser = bincode::serialize(&node).unwrap();
        let node: RoomNode = bincode::deserialize(&ser).unwrap();

        second_app.add_room_node(node.clone()).await.unwrap();

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        second_app
            .mutate_raw(
                r#"mutate mut {
                Person{
                    room_id: $room_id
                    name:"someone"
                }
            }"#,
                Some(param),
            )
            .await
            .expect_err("second_user cannot insert anymore");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn admin_rights() {
        init_database_path();

        let path: PathBuf = DATA_PATH.into();
        let secret = random32();
        let (first_app, verifying_key, _) = GraphDatabaseService::start(
            "authorisation app",
            "",
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
            LogService::start(),
        )
        .await
        .unwrap();
        let first_user_id = base64_encode(&verifying_key);

        let path: PathBuf = DATA_PATH.into();
        let secret = random32();
        let (second_app, verifying_key, _) = GraphDatabaseService::start(
            "authorisation app",
            "",
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
            LogService::start(),
        )
        .await
        .unwrap();
        let second_user_id = base64_encode(&verifying_key);

        let mut param = Parameters::default();
        param.add("user_id", first_user_id.clone()).unwrap();
        let room = first_app
            .mutate_raw(
                r#"mutate mut {
                    sys.Room{
                        admin: [{
                            verif_key:$user_id
                        }]
                    }
                }"#,
                Some(param),
            )
            .await
            .unwrap();

        let room_insert = &room.mutate_entities[0];
        let room_id = base64_encode(&room_insert.node_to_mutate.id);

        let node = first_app
            .get_room_node(room_insert.node_to_mutate.id)
            .await
            .unwrap()
            .unwrap();
        //serialize and deserialize to get rid of the local_id
        let ser = bincode::serialize(&node).unwrap();
        let node: RoomNode = bincode::deserialize(&ser).unwrap();
        second_app.add_room_node(node.clone()).await.unwrap();

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("second_user", second_user_id.clone()).unwrap();
        first_app
            .mutate_raw(
                r#"mutate mut {
                    sys.Room{
                        id: $room_id
                        admin: [{
                            verif_key:$second_user
                        }]
                    }
                }"#,
                Some(param),
            )
            .await
            .expect("first_app can mutate room");

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("second_user", second_user_id.clone()).unwrap();
        second_app
            .mutate_raw(
                r#"mutate mut {
                        sys.Room{
                            id: $room_id
                            admin: [{
                                verif_key:$second_user
                            }]                           
                        }
                    }"#,
                Some(param),
            )
            .await
            .expect_err("second app cannot mutate room");

        let node = first_app
            .get_room_node(room_insert.node_to_mutate.id)
            .await
            .unwrap()
            .unwrap();
        //serialize and deserialize to get rid of the local_id
        let ser = bincode::serialize(&node).unwrap();
        let node: RoomNode = bincode::deserialize(&ser).unwrap();
        second_app.add_room_node(node.clone()).await.unwrap();

        let third_user = base64_encode(&random32());
        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("third_user", third_user.clone()).unwrap();

        first_app
            .mutate_raw(
                r#"mutate mut {
                sys.Room{
                    id: $room_id
                    admin: [{
                        verif_key:$third_user
                    }]                   
                }
            }"#,
                Some(param),
            )
            .await
            .expect("first_app can mutate room");

        let third_user = base64_encode(&random32());
        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();
        param.add("third_user", third_user.clone()).unwrap();

        second_app
            .mutate_raw(
                r#"mutate mut {
                sys.Room{
                    id: $room_id
                    admin: [{
                        verif_key:$third_user
                    }]
                }
            }"#,
                Some(param),
            )
            .await
            .expect("second_app can mutate room");

        let node = first_app
            .get_room_node(room_insert.node_to_mutate.id)
            .await
            .unwrap()
            .unwrap();
        //serialize and deserialize to get rid of the local_id
        let ser = bincode::serialize(&node).unwrap();
        let node: RoomNode = bincode::deserialize(&ser).unwrap();
        second_app.add_room_node(node.clone()).await.unwrap();

        let node = second_app
            .get_room_node(room_insert.node_to_mutate.id)
            .await
            .unwrap()
            .unwrap();
        //serialize and deserialize to get rid of the local_id
        let ser = bincode::serialize(&node).unwrap();
        let node: RoomNode = bincode::deserialize(&ser).unwrap();
        first_app.add_room_node(node.clone()).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn invalid() {
        init_database_path();

        let path: PathBuf = DATA_PATH.into();
        let secret = random32();
        let (first_app, verifying_key, _) = GraphDatabaseService::start(
            "authorisation app",
            "",
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
            LogService::start(),
        )
        .await
        .unwrap();
        let first_user_id = base64_encode(&verifying_key);

        let path: PathBuf = DATA_PATH.into();
        let secret = random32();
        let (second_app, _, _) = GraphDatabaseService::start(
            "authorisation app",
            "",
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            EventService::new(),
            LogService::start(),
        )
        .await
        .unwrap();

        let mut param = Parameters::default();
        param.add("user_id", first_user_id.clone()).unwrap();
        let room = first_app
            .mutate_raw(
                r#"mutate mut {
                    sys.Room{
                        admin: [{
                            verif_key:$user_id
                        }]
                    }
                }"#,
                Some(param),
            )
            .await
            .unwrap();

        let room_insert = &room.mutate_entities[0];

        let bad_signing = Ed25519SigningKey::create_from(&random32());
        let mut node = first_app
            .get_room_node(room_insert.node_to_mutate.id)
            .await
            .unwrap()
            .unwrap();
        //will trigger a right error
        node.admin_nodes[0].node.sign(&bad_signing).unwrap();
        //serialize and deserialize to get rid of the local_id
        let ser = bincode::serialize(&node).unwrap();
        let node: RoomNode = bincode::deserialize(&ser).unwrap();
        second_app
            .add_room_node(node.clone())
            .await
            .expect_err("right error");

        let mut node = first_app
            .get_room_node(room_insert.node_to_mutate.id)
            .await
            .unwrap()
            .unwrap();
        //trigger a consistency error
        node.admin_edges[0].dest = new_uid();
        node.admin_edges[0].sign(&bad_signing).unwrap();
        //serialize and deserialize to get rid of the local_id
        let ser = bincode::serialize(&node).unwrap();
        let node: RoomNode = bincode::deserialize(&ser).unwrap();
        second_app
            .add_room_node(node.clone())
            .await
            .expect_err("edge must point to a node that is is in the corresponding *_edge");

        let mut node = first_app
            .get_room_node(room_insert.node_to_mutate.id)
            .await
            .unwrap()
            .unwrap();
        //does not trigger right error
        node.admin_edges[0].sign(&bad_signing).unwrap();
        //serialize and deserialize to get rid of the local_id
        let ser = bincode::serialize(&node).unwrap();
        let node: RoomNode = bincode::deserialize(&ser).unwrap();
        second_app
            .add_room_node(node.clone())
            .await
            .expect("no right error, protected by a previous consitency check, the edge point a node that will be verified");
    }
}
