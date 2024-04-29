use rusqlite::Connection;

use crate::cryptography::base64_decode;

use super::{
    authorisation_service::{Authorisation, EntityRight, Room, User},
    configuration::{
        AUTHORISATION_ENT_SHORT, AUTH_RIGHTS_FIELD_SHORT, AUTH_USER_FIELD_SHORT,
        ENTITY_RIGHT_ENT_SHORT, RIGHT_DELETE_SHORT, RIGHT_ENTITY_SHORT, RIGHT_MUTATE_SELF_SHORT,
        RIGHT_MUTATE_SHORT, ROOM_ADMIN_FIELD_SHORT, ROOM_AUTHORISATION_FIELD_SHORT, ROOM_ENT_SHORT,
        ROOM_USER_ADMIN_FIELD_SHORT, USER_AUTH_ENT_SHORT, USER_ENABLED_SHORT,
        USER_VERIFYING_KEY_SHORT,
    },
    edge::Edge,
    node::Node,
    Error, Result,
};

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
    pub admin_nodes: Vec<UserNode>,

    pub user_admin_edges: Vec<Edge>,
    pub user_admin_nodes: Vec<UserNode>,

    pub auth_edges: Vec<Edge>,
    pub auth_nodes: Vec<AuthorisationNode>,

    pub need_update: bool,
}
impl RoomNode {
    pub fn check_consistency(&self) -> Result<()> {
        self.node.verify()?;

        //check user_admin consistency
        if self.user_admin_edges.len() != self.user_admin_nodes.len() {
            return Err(Error::InvalidNode(
                "RoomNode user_admin edge and node have different size".to_string(),
            ));
        }
        for user_admin_edge in &self.user_admin_edges {
            user_admin_edge.verify()?;
            if !user_admin_edge.src.eq(&self.node.id) {
                return Err(Error::InvalidNode(
                    "Invalid RoomNode user_admin edge src".to_string(),
                ));
            }
            let user_node = self
                .user_admin_nodes
                .iter()
                .find(|user| user.node.id.eq(&user_admin_edge.dest));

            match user_node {
                Some(user) => user.node.verify()?,
                None => {
                    return Err(Error::InvalidNode(
                        "RoomNode has an invalid admin egde".to_string(),
                    ))
                }
            }
        }

        //check admin consistency
        if self.admin_edges.len() != self.admin_nodes.len() {
            return Err(Error::InvalidNode(
                "RoomNode admin edge and node have different size".to_string(),
            ));
        }
        for admin_edge in &self.admin_edges {
            admin_edge.verify()?;
            if !admin_edge.src.eq(&self.node.id) {
                return Err(Error::InvalidNode(
                    "Invalid RoomNode admin edge src".to_string(),
                ));
            }
            let user_node = self
                .admin_nodes
                .iter()
                .find(|user| user.node.id.eq(&admin_edge.dest));

            match user_node {
                Some(user) => user.node.verify()?,
                None => {
                    return Err(Error::InvalidNode(
                        "RoomNode has an invalid admin egde".to_string(),
                    ))
                }
            }
        }

        //check authorisation consistency
        if self.auth_edges.len() != self.auth_nodes.len() {
            return Err(Error::InvalidNode(
                "RoomNode authorisation edge and node have different size".to_string(),
            ));
        }
        for auth_edge in &self.auth_edges {
            auth_edge.verify()?;
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

    pub fn write(&mut self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        if self.need_update {
            self.node.write(conn, false, &None, &None)?;
        }

        for a in &self.admin_edges {
            a.write(conn)?;
        }

        for a in &mut self.admin_nodes {
            a.write(conn)?;
        }

        for a in &self.user_admin_edges {
            a.write(conn)?;
        }

        for a in &mut self.user_admin_nodes {
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
            let user_opt = UserNode::read(conn, &edge.dest)?;
            if let Some(user) = user_opt {
                admin_nodes.push(user);
            }
        }

        let mut user_admin_edges = Edge::get_edges(id, ROOM_USER_ADMIN_FIELD_SHORT, conn)?;
        //user insertion order is mandatory
        user_admin_edges.sort_by(|a, b| b.cdate.cmp(&a.cdate));

        let mut user_admin_nodes = Vec::new();
        for edge in &user_admin_edges {
            let user_opt = UserNode::read(conn, &edge.dest)?;
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
            need_update: true,
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
    pub user_nodes: Vec<UserNode>,
    pub need_update: bool,
}
impl AuthorisationNode {
    pub fn check_consistency(&self) -> Result<()> {
        self.node.verify()?;
        //check right consistency
        if self.right_edges.len() != self.right_nodes.len() {
            return Err(Error::InvalidNode(
                "AuthorisationNode Rights edges and nodes have different size".to_string(),
            ));
        }
        for right_edge in &self.right_edges {
            right_edge.verify()?;
            if !right_edge.src.eq(&self.node.id) {
                return Err(Error::InvalidNode(
                    "Invalid AuthorisationNode Right edge source".to_string(),
                ));
            }
            let right_node = self
                .right_nodes
                .iter()
                .find(|right| right.node.id.eq(&right_edge.dest));

            match right_node {
                Some(right) => right.node.verify()?,
                None => {
                    return Err(Error::InvalidNode(
                        "AuthorisationNode has an invalid Right egde".to_string(),
                    ))
                }
            }
        }

        //check user consistency
        if self.user_edges.len() != self.user_nodes.len() {
            return Err(Error::InvalidNode(
                "AuthorisationNode user edges and nodes have different size".to_string(),
            ));
        }
        for user_edge in &self.user_edges {
            user_edge.verify()?;
            if !user_edge.src.eq(&self.node.id) {
                return Err(Error::InvalidNode(
                    "Invalid AuthorisationNode user edge source".to_string(),
                ));
            }
            let user_node = self
                .user_nodes
                .iter()
                .find(|user| user.node.id.eq(&user_edge.dest));

            match user_node {
                Some(user) => user.node.verify()?,
                None => {
                    return Err(Error::InvalidNode(
                        "AuthorisationNode has an invalid user egde".to_string(),
                    ))
                }
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
            let user_opt = UserNode::read(conn, &edge.dest)?;
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
            need_update: true,
        }))
    }
}

///
/// User database definition that is used for data synchronisation
///
#[derive(Debug)]
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
        if self.node._local_id.is_none() {
            self.node.write(conn, false, &None, &None)?;
        }
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

// validate the room node against the existing one
// returns true if the node has changes to be inserted
pub fn validate_existing_room_node(
    room: &Room,
    old_room_node: &RoomNode,
    room_node: &mut RoomNode,
) -> Result<bool> {
    let mut need_update = false;
    let mut room = room.clone();

    //ensure that existing admin edges exists in the room_node
    for old_edge in &old_room_node.admin_edges {
        let admin_edge = &room_node.admin_edges.iter().find(|edge| edge.eq(&old_edge));
        if admin_edge.is_none() {
            return Err(Error::InvalidNode(
                "RoomNode does not contain a previouly existing Administrator user edge"
                    .to_string(),
            ));
        }
    }

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
                return Err(Error::InvalidNode(
                    "RoomNode does not contain a previouly existing Administrator node".to_string(),
                ))
            }
        }
    }

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
            match room.is_admin(&new_admin.node._verifying_key, new_admin.node.mdate) {
                true => {
                    let user = parse_user_node(new_admin)?;
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

    //ensure that existing user_admin edges exists in the room_node
    for old_edge in &old_room_node.user_admin_edges {
        let user_admin_edge = &room_node
            .user_admin_edges
            .iter()
            .find(|edge| edge.eq(&old_edge));
        if user_admin_edge.is_none() {
            return Err(Error::InvalidNode(
                "RoomNode does not contain a previouly existing User Administrator edge"
                    .to_string(),
            ));
        }
    }

    for old_user in &old_room_node.user_admin_nodes {
        let user_admin_node = room_node
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
                return Err(Error::InvalidNode(
                    "RoomNode does not contain a previouly existing User Administrator node"
                        .to_string(),
                ))
            }
        }
    }

    //
    // Find new admins and add them to the cloned room
    // the cloned room will be then used to validate every other room update
    //
    for new_user_admin in &room_node.user_admin_nodes {
        let user_admin_node = old_room_node
            .user_admin_nodes
            .iter()
            .find(|user| user.node.id.eq(&new_user_admin.node.id));
        if user_admin_node.is_none() {
            match room.is_admin(
                &new_user_admin.node._verifying_key,
                new_user_admin.node.mdate,
            ) {
                true => {
                    let user = parse_user_node(new_user_admin)?;
                    room.add_user_admin_user(user)?;
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

    //check for update on the room itself
    //run after the user admin updates because the modification could have been made by a new user
    if old_room_node.node.mdate < room_node.node.mdate {
        match room.is_admin(&room_node.node._verifying_key, room_node.node.mdate) {
            true => {
                room_node.node._local_id = old_room_node.node._local_id;
                room_node.need_update = true;
            }
            false => {
                return Err(Error::InvalidNode(
                    "RoomNode mutation is not authorised".to_string(),
                ))
            }
        }
    } else {
        room_node.node = old_room_node.node.clone();
        room_node.need_update = false;
    }

    //check authorisation
    for old_edge in &old_room_node.auth_edges {
        let auth_edge = &room_node.auth_edges.iter().find(|edge| edge.eq(&old_edge));
        if auth_edge.is_none() {
            return Err(Error::InvalidNode(
                "RoomNode does not contain a previouly existing Authorisation edge".to_string(),
            ));
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
                        if !room.is_admin(&new_auth.node._verifying_key, new_auth.node.mdate) {
                            return Err(Error::InvalidNode(
                                "RoomNode Authorisation mutation not authorised".to_string(),
                            ));
                        }
                        need_update = true;
                        validate_existing_auth_node(&room, old_auth, new_auth)?;
                    }
                    false => {
                        new_auth.node = old_auth.node.clone();
                        new_auth.need_update = false;
                        if validate_existing_auth_node(&room, old_auth, new_auth)? {
                            need_update = true;
                        }
                    }
                };
            }
            None => {
                return Err(Error::InvalidNode(
                    "RoomNode does not contain a previouly existing User Authorisation node"
                        .to_string(),
                ))
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
            match room.is_admin(&new_auth.node._verifying_key, new_auth.node.mdate) {
                true => {
                    validate_new_auth_node(&room, new_auth)?;
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

    //parse room node to ensure that the json defintion is valid
    parse_room_node(room_node)?;
    //parse new node
    //return
    Ok(need_update)
}

// validate the room node against the existing one
// returns true if the node has changes to be inserted
pub fn validate_new_room_node(room_node: &RoomNode) -> Result<()> {
    let room = parse_room_node(room_node)?;
    //verify rights
    for admin in &room_node.admin_nodes {
        if !room.is_admin(&admin.node._verifying_key, admin.node.mdate) {
            return Err(Error::InvalidNode(
                "New RoomNode Administrator not authorised".to_string(),
            ));
        }
    }

    for user_admin in &room_node.user_admin_nodes {
        if !room.is_admin(&user_admin.node._verifying_key, user_admin.node.mdate) {
            return Err(Error::InvalidNode(
                "New RoomNode User Administrator not authorised".to_string(),
            ));
        }
    }

    for auth in &room_node.auth_nodes {
        match room.is_admin(&auth.node._verifying_key, auth.node.mdate) {
            true => {
                for user in &auth.user_nodes {
                    if !room.is_admin(&user.node._verifying_key, user.node.mdate) {
                        return Err(Error::InvalidNode(
                            "New RoomNode Authorisation User not authorised".to_string(),
                        ));
                    }
                }
                for right in &auth.right_nodes {
                    if !room.is_admin(&right.node._verifying_key, right.node.mdate) {
                        return Err(Error::InvalidNode(
                            "New RoomNode Authorisation Right not authorised".to_string(),
                        ));
                    }
                }
            }
            false => {
                return Err(Error::InvalidNode(
                    "New RoomNode Authorisation not authorised".to_string(),
                ))
            }
        }
    }
    Ok(())
}

pub fn validate_existing_auth_node(
    room: &Room,
    old_auth: &AuthorisationNode,
    new_auth: &mut AuthorisationNode,
) -> Result<bool> {
    let mut need_update = false;

    //ensure that existing user edges and nodes are included in the new Authorisation
    for old_edge in &old_auth.user_edges {
        let user_edge = &new_auth.user_edges.iter().find(|edge| edge.eq(&old_edge));
        if user_edge.is_none() {
            return Err(Error::InvalidNode(
                "RoomNode Authorisation does not contain a previouly existing User edge"
                    .to_string(),
            ));
        }
    }

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
                return Err(Error::InvalidNode(
                    "RoomNode Authorisation does not contain a previouly existing User  node"
                        .to_string(),
                ))
            }
        }
    }

    //
    // verify new users
    //
    for new_user in &new_auth.user_nodes {
        let user_node = old_auth
            .user_nodes
            .iter()
            .find(|user| user.node.id.eq(&new_user.node.id));

        if user_node.is_none() {
            match room.is_user_admin(&new_user.node._verifying_key, new_user.node.mdate) {
                true => {
                    need_update = true;
                }
                false => {
                    return Err(Error::InvalidNode(
                        "RoomNode Authorisation new User is not authorised".to_string(),
                    ))
                }
            }
        }
    }

    //ensure that existing Right edges and nodes are included in the new Authorisation
    for old_edge in &old_auth.right_edges {
        let right_edge = &new_auth.right_edges.iter().find(|edge| edge.eq(&old_edge));
        if right_edge.is_none() {
            return Err(Error::InvalidNode(
                "RoomNode Authorisation does not contain a previouly existing Right edge"
                    .to_string(),
            ));
        }
    }

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
                return Err(Error::InvalidNode(
                    "RoomNode Authorisation does not contain a previouly existing Right node"
                        .to_string(),
                ))
            }
        }
    }

    //
    // verify new right
    //
    for new_right in &new_auth.right_nodes {
        let right_node = old_auth
            .right_nodes
            .iter()
            .find(|user| user.node.id.eq(&new_right.node.id));

        if right_node.is_none() {
            match room.is_user_admin(&new_right.node._verifying_key, new_right.node.mdate) {
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

pub fn validate_new_auth_node(room: &Room, new_auth: &AuthorisationNode) -> Result<()> {
    for new_user in &new_auth.user_nodes {
        if !room.is_user_admin(&new_user.node._verifying_key, new_user.node.mdate) {
            return Err(Error::InvalidNode(
                "RoomNode Authorisation new user is not authorised".to_string(),
            ));
        }
    }
    for new_right in &new_auth.right_nodes {
        if !room.is_user_admin(&new_right.node._verifying_key, new_right.node.mdate) {
            return Err(Error::InvalidNode(
                "RoomNode Authorisation new Right is not authorised".to_string(),
            ));
        }
    }
    Ok(())
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

fn parse_user_node(user_node: &UserNode) -> Result<User> {
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
