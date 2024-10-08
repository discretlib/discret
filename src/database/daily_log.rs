use std::collections::{HashMap, HashSet, VecDeque};

use rusqlite::{params_from_iter, Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::{
    date_utils::{date, date_next_day},
    security::Uid,
};

use super::{sqlite_database::Writeable, VEC_OVERHEAD};

///
/// Stores the modified dates for each rooms during the batch insert.
///
/// At the end of the batch, update the hash to null for all impacted daily logs entries
/// recompute will be performed later
/// this avoids an update of the log for every inserted rows and is specially usefull during room synchronisation
///
#[derive(Default, Debug)]
pub struct DailyMutations {
    room_dates: HashMap<Uid, HashMap<String, HashSet<i64>>>,
}
impl DailyMutations {
    #[cfg(test)]
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn set_need_update(&mut self, room: Uid, entity: &String, mut_date: i64) {
        let room_entry = self.room_dates.entry(room).or_default();
        let entity_entry = room_entry.entry(entity.to_owned()).or_default();
        entity_entry.insert(date(mut_date));
    }

    pub fn write(&self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        let mut node_daily_stmt = conn.prepare_cached(
            "INSERT INTO _daily_log (
                    room_id,
                    entity,
                    date,
                    entry_number,
                    daily_hash,
                    history_hash,
                    need_recompute
                ) values (?,?,?, 0, NULL, NULL, 1)
                ON CONFLICT(room_id, entity, date) 
                DO UPDATE SET daily_hash = NULL , need_recompute = 1;
            ",
        )?;
        for room in &self.room_dates {
            let room_id = room.0;
            for entity in room.1 {
                let entity_id = entity.0;
                for date in entity.1 {
                    //  println!("{} {} {}", base64_encode(room_id), entity_id, date);
                    node_daily_stmt.execute((room_id, entity_id, date))?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Default, Debug, Clone)]
pub struct DailyLogsUpdate {
    pub room_dates: HashMap<Uid, HashSet<DailyLog>>,
}
impl DailyLogsUpdate {
    ///
    /// comptute the daily hash and the hash history
    /// history allow to verify the history by only checking the last log entry.
    /// it makes mutations a slower when updating an old node but it makes room synchronisation between peers much easier
    ///
    pub fn compute(&mut self, conn: &Connection) -> Result<(), rusqlite::Error> {
        let mut daily_log_stmt = conn.prepare_cached(
            " 
            SELECT room_id, entity, date, need_recompute, daily_hash, history_hash
            FROM _daily_log daily
            WHERE date >= (
                IFNULL (
                    (
                        SELECT max(date) from _daily_log 
                        WHERE 
                            daily.room_id = room_id AND
                            daily.entity = entity
                        AND date < (
                            SELECT min(date) from _daily_log 
                            WHERE 
                                daily.room_id = room_id AND
                                daily.entity = entity AND
                                need_recompute = 1
                        )
                    ),(		
                        SELECT min(date) from _daily_log 
                        WHERE 
                            daily.room_id = room_id AND
                            daily.entity = entity AND
                            need_recompute = 1
                    )
                )
            ) 
            ORDER BY room_id, entity, date
        ",
        )?;

        let mut compute_stmt = conn.prepare_cached(
            "
                -- node deletion 
                SELECT signature
                FROM _node_deletion_log 
                WHERE 
                    room_id = ?1 AND
                    entity = ?2 AND
                    deletion_date >= ?3 AND deletion_date < ?4 
                
                -- edge deletion 
                UNION ALL
                SELECT signature 
                FROM _edge_deletion_log 
                WHERE 
                    room_id = ?1 AND 
                    src_entity = ?2 AND
                    deletion_date >= ?3 AND deletion_date < ?4 
                
                -- nodes 
                UNION ALL
                SELECT _signature as signature
                FROM _node 
                WHERE
                    room_id = ?1 AND
                    _entity = ?2 AND 
                    mdate >= ?3 AND mdate < ?4 
                    
                --applies to the whole union
                ORDER by signature
        ",
        )?;

        let mut update_computed_stmt = conn.prepare_cached(
            "
            UPDATE _daily_log 
            SET 
                entry_number = ?, 
                daily_hash = ?, 
                history_hash = ?,
                need_recompute = 0
            WHERE
                room_id = ? AND
                entity = ? AND
                date = ?
            ",
        )?;

        let mut update_history_stmt = conn.prepare_cached(
            "
            UPDATE _daily_log 
            SET 
                history_hash = ?
            WHERE
                room_id = ? AND
                entity = ? AND
                date = ?
            ",
        )?;

        let mut rows = daily_log_stmt.query([])?;

        let mut previous_room: Uid = [0; 16];
        let mut previous_entity: String = "-".to_string();
        let mut previous_hash: Option<Vec<u8>> = None;
        let mut previous_history: Option<Vec<u8>> = None;

        while let Some(row) = rows.next()? {
            let room: Uid = row.get(0)?;
            let entity: String = row.get(1)?;
            let date: i64 = row.get(2)?;
            let need_recompute: bool = row.get(3)?;

            let daily_hash: Option<Vec<u8>> = row.get(4)?;
            let history_hash: Option<Vec<u8>> = row.get(5)?;

            if !need_recompute {
                if previous_room.eq(&room) && previous_entity.eq(&entity) {
                    if let Some(previous) = &previous_history {
                        let mut hasher = blake3::Hasher::new();
                        hasher.update(previous);
                        if let Some(daily) = &previous_hash {
                            hasher.update(daily);
                        }
                        let hash = hasher.finalize().as_bytes().to_vec();
                        // update
                        update_history_stmt.execute((&hash, &room, &entity, date))?;
                        previous_history = Some(hash);
                    } else {
                        previous_history = history_hash;
                    }
                    previous_hash = daily_hash;
                } else {
                    previous_hash = None;
                    previous_history = None;
                }
                previous_room = room;
                previous_entity = entity;
            } else {
                let mut comp_rows =
                    compute_stmt.query((&room, &entity, date, date_next_day(date)))?;

                let mut entry_number: u32 = 0;
                let mut hasher = blake3::Hasher::new();

                while let Some(comp) = comp_rows.next()? {
                    let signature: Vec<u8> = comp.get(0)?;
                    hasher.update(&signature);
                    entry_number += 1;
                }

                let daily_hash = if hasher.count() == 0 {
                    None
                } else {
                    let hash = hasher.finalize();
                    Some(hash.as_bytes().to_vec())
                };

                let history_hash = if previous_room.eq(&room) {
                    if let Some(previous) = &previous_history {
                        let mut hasher = blake3::Hasher::new();
                        hasher.update(previous);
                        if let Some(daily) = &previous_hash {
                            hasher.update(daily);
                        }
                        let hash = hasher.finalize().as_bytes().to_vec();
                        Some(hash)
                    } else {
                        None
                    }
                } else {
                    //this is the first room date
                    daily_hash.clone()
                };

                update_computed_stmt.execute((
                    entry_number,
                    &daily_hash,
                    &history_hash,
                    &room,
                    &entity,
                    date,
                ))?;

                self.add_log(DailyLog {
                    room_id: room,
                    entity: entity.clone(),
                    date,
                    entry_number,
                    daily_hash: daily_hash.clone(),
                    history_hash: history_hash.clone(),
                    need_recompute: false,
                });
                previous_hash = daily_hash;
                previous_history = history_hash;
                previous_room = room;
                previous_entity = entity;
            }
        }
        Ok(())
    }

    fn add_log(&mut self, log: DailyLog) {
        let entry = self.room_dates.entry(log.room_id).or_default();
        entry.insert(log);
    }
}

#[derive(Default, Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct DailyLog {
    pub room_id: Uid,
    pub date: i64,
    pub entity: String,
    pub entry_number: u32,
    pub daily_hash: Option<Vec<u8>>,
    pub history_hash: Option<Vec<u8>>,
    pub need_recompute: bool,
}
impl DailyLog {
    pub fn create_tables(conn: &Connection) -> Result<(), rusqlite::Error> {
        conn.execute(
            "CREATE TABLE _daily_log (
                room_id BLOB NOT NULL,
                entity TEXT NOT NULL,
                date INTEGER NOT NULL,
                entry_number INTEGER NOT NULL DEFAULT 0,
                daily_hash BLOB,
                history_hash BLOB,
                need_recompute INTEGER, 
                PRIMARY KEY (room_id, entity, date)
            ) WITHOUT ROWID, STRICT",
            [],
        )?;
        conn.execute(
            "CREATE INDEX _daily_log_recompute_room_date ON _daily_log (room_id, entity, need_recompute,  date)",
            [],
        )?;

        conn.execute(
            "
            CREATE TABLE _room_changelog (
                room_id BLOB NOT NULL,
                mdate INTEGER NOT NULL,
                PRIMARY KEY(room_id)
            ) WITHOUT ROWID, STRICT",
            [],
        )?;
        Ok(())
    }

    ///
    /// Get the daily log for a room
    ///
    pub fn get_room_log(
        room_id: &Uid,
        batch_size: usize,
        sender: &mpsc::Sender<Result<Vec<Self>, super::Error>>,
        conn: &Connection,
    ) -> Result<(), super::Error> {
        let mut stmt = conn.prepare_cached(
            "SELECT 
                room_id ,
                entity, 
                date ,
                entry_number ,
                daily_hash ,
                history_hash ,
                need_recompute 
            FROM _daily_log
            WHERE room_id = ?
            ORDER BY date, entity ASC
            ",
        )?;
        let mut rows = stmt.query([room_id])?;
        let mut res = Vec::new();
        let mut len = 0;
        while let Some(row) = rows.next()? {
            let log = Self {
                room_id: row.get(0)?,
                entity: row.get(1)?,
                date: row.get(2)?,
                entry_number: row.get(3)?,
                daily_hash: row.get(4)?,
                history_hash: row.get(5)?,
                need_recompute: row.get(6)?,
            };
            let size = bincode::serialized_size(&log)?;
            let insert_len = len + size + VEC_OVERHEAD;
            if insert_len > batch_size as u64 {
                let ready = res;
                res = Vec::new();
                len = 0;
                let s = sender.blocking_send(Ok(ready));
                if s.is_err() {
                    break;
                }
            } else {
                len = insert_len;
            }

            res.push(log);
        }
        if !res.is_empty() {
            let _ = sender.blocking_send(Ok(res));
        }
        Ok(())
    }

    ///
    /// Get the daily log for a room at a specific date
    ///
    pub fn get_room_log_at(
        room_id: &Uid,
        date: i64,
        conn: &Connection,
    ) -> Result<Vec<Self>, rusqlite::Error> {
        let mut stmt = conn.prepare_cached(
            "SELECT 
                room_id ,
                entity, 
                date ,
                entry_number ,
                daily_hash ,
                history_hash ,
                need_recompute 
            FROM _daily_log
            WHERE 
                room_id = ? AND
                date = ?
            ORDER BY date, entity ASC
            ",
        )?;
        let mut rows = stmt.query((room_id, date))?;
        let mut res = Vec::new();
        while let Some(row) = rows.next()? {
            res.push(Self {
                room_id: row.get(0)?,
                entity: row.get(1)?,
                date: row.get(2)?,
                entry_number: row.get(3)?,
                daily_hash: row.get(4)?,
                history_hash: row.get(5)?,
                need_recompute: row.get(6)?,
            });
        }
        Ok(res)
    }

    ///
    /// get room list sorted by modification date
    /// allows synchronisation to start with the most recently updated rooms
    ///
    pub fn sort_rooms(
        room_ids: &HashSet<Uid>,
        batch_size: usize,
        sender: &mpsc::Sender<Result<VecDeque<Uid>, super::Error>>,
        conn: &Connection,
    ) -> Result<(), super::Error> {
        let it = &mut room_ids.iter().peekable();
        let mut id_date_list: Vec<(Uid, i64)> = Vec::with_capacity(room_ids.len());
        struct QueryParams<'a> {
            in_clause: String,
            ids: Vec<&'a Uid>,
        }
        //limit the IN clause to a reasonable size, avoiding the 32766 parameter limit in sqlite
        let row_per_query = 500;
        let mut query_list = Vec::new();
        let mut row_num = 0;
        let mut current_query = QueryParams {
            in_clause: String::new(),
            ids: Vec::new(),
        };

        while let Some(nid) = it.next() {
            current_query.in_clause.push('?');
            current_query.ids.push(nid);

            row_num += 1;
            if row_num < row_per_query {
                if it.peek().is_some() {
                    current_query.in_clause.push(',');
                }
            } else {
                query_list.push(current_query);
                row_num = 0;
                current_query = QueryParams {
                    in_clause: String::new(),
                    ids: Vec::new(),
                };
            }
        }
        if !current_query.ids.is_empty() {
            query_list.push(current_query);
        }

        for current_query in &query_list {
            let ids = &current_query.ids;
            let in_clause = &current_query.in_clause;

            let query = format!(
                "
                SELECT 
                    rcl.room_id, 
                    dl.date
                FROM _room_changelog rcl
                LEFT JOIN (
                    SELECT 
                        _dl.room_id,
                        _dl.date
                    FROM _daily_log _dl
                    WHERE date = (SELECT MAX(date) FROM _daily_log WHERE _dl.room_id=_daily_log.room_id)
                ) as dl ON rcl.room_id=dl.room_id
                WHERE rcl.room_id in ({})
                ",
                in_clause
            );
            let mut stmt = conn.prepare(&query)?;
            let mut rows = stmt.query(params_from_iter(ids.iter()))?;
            while let Some(row) = rows.next()? {
                let date: Option<i64> = row.get(1)?;
                let date = match date {
                    Some(date) => date,
                    None => i64::MAX, //null values will be push at the end of the list
                };
                id_date_list.push((row.get(0)?, date));
            }
        }
        id_date_list.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        let mut res = VecDeque::new();
        let mut len = 0;
        for uid in id_date_list {
            let uid = uid.0;
            let insert_len = len + uid.len() + VEC_OVERHEAD as usize;

            if insert_len > batch_size {
                let ready = res;
                res = VecDeque::new();
                len = 0;
                let s = sender.blocking_send(Ok(ready));
                if s.is_err() {
                    break;
                }
            } else {
                len = insert_len;
            }
            res.push_back(uid);
        }

        if !res.is_empty() {
            let _ = sender.blocking_send(Ok(res));
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn write(&self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        let mut node_daily_stmt = conn.prepare_cached(
            "INSERT OR REPLACE INTO _daily_log (
                    room_id,
                    entity,
                    date,
                    entry_number,
                    daily_hash,
                    history_hash,
                    need_recompute
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ",
        )?;
        node_daily_stmt.execute((
            &self.room_id,
            &self.entity,
            &self.date,
            &self.entry_number,
            &self.daily_hash,
            &self.history_hash,
            &self.need_recompute,
        ))?;

        Ok(())
    }
}

const ROOM_LOG_INSERT: &str = "INSERT OR REPLACE INTO _room_changelog(room_id, mdate) VALUES (?,?)";

pub struct RoomChangelog {
    pub room_id: Uid,
    pub mdate: i64,
}
impl RoomChangelog {
    pub fn log_room_definition(
        room_id: &Uid,
        mdate: i64,
        conn: &Connection,
    ) -> Result<(), rusqlite::Error> {
        let mut stmt = conn.prepare_cached(ROOM_LOG_INSERT)?;
        stmt.execute((room_id, mdate))?;
        Ok(())
    }
}
impl Writeable for RoomChangelog {
    fn write(&mut self, conn: &rusqlite::Connection) -> std::result::Result<(), rusqlite::Error> {
        let mut stmt = conn.prepare_cached(ROOM_LOG_INSERT)?;
        stmt.execute((self.room_id, self.mdate))?;
        Ok(())
    }
}

///
/// Used to transmit in one packet
///  - The room modification date to check whether the room defintion needs to be synchronized
///  - The last _daily_log entry to check whether the room data needs to be synchronized
///
#[derive(Serialize, Deserialize)]
pub struct RoomDefinitionLog {
    pub room_id: Uid,
    pub room_def_date: i64,
    pub last_data_date: Option<i64>,
    pub entry_number: Option<u32>,
    pub daily_hash: Option<Vec<u8>>,
    pub history_hash: Option<Vec<u8>>,
}
impl RoomDefinitionLog {
    pub fn get(
        room_id: &Uid,
        conn: &Connection,
    ) -> Result<Option<RoomDefinitionLog>, rusqlite::Error> {
        let query = "
            SELECT 
                rcl.room_id as room_id,  
                rcl.mdate as room_def_date, 
                dl.date as last_data,
                dl.entry_number,
                dl.daily_hash,
                dl.history_hash
            FROM _room_changelog rcl
            LEFT JOIN (
                SELECT 
                    _dl.room_id,
                    _dl.date,
                    _dl.entry_number,
                    _dl.daily_hash,
                    _dl.history_hash
                FROM _daily_log _dl
                WHERE date = (SELECT MAX(date) FROM _daily_log WHERE _dl.room_id=_daily_log.room_id)
            ) as dl ON rcl.room_id=dl.room_id
            WHERE rcl.room_id = ?
            ";
        let mut stmt = conn.prepare(query)?;
        let mut rows = stmt.query([&room_id])?;
        let res = if let Some(row) = rows.next()? {
            Some(RoomDefinitionLog {
                room_id: row.get(0)?,
                room_def_date: row.get(1)?,
                last_data_date: row.get(2)?,
                entry_number: row.get(3)?,
                daily_hash: row.get(4)?,
                history_hash: row.get(5)?,
            })
        } else {
            None
        };
        Ok(res)
    }
}
#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use rand::{rngs::OsRng, Rng};
    use rusqlite::Connection;

    use crate::{
        configuration::Configuration,
        database::{
            graph_database::GraphDatabaseService,
            query_language::parameter::{Parameters, ParametersAdd},
            Error,
        },
        date_utils::{date, now},
        event_service::EventService,
        security::{base64_encode, default_uid, new_uid, random32},
    };

    use super::*;

    const DATA_PATH: &str = "test_data/database/daily_log/";
    fn init_database_path() {
        let path: PathBuf = DATA_PATH.into();
        fs::create_dir_all(&path).unwrap();
        let paths = fs::read_dir(path).unwrap();

        for path in paths {
            let dir = path.unwrap().path();
            let paths = fs::read_dir(dir).unwrap();
            for file in paths {
                let files = file.unwrap().path();
                // println!("Name: {}", files.display());
                let _ = fs::remove_file(&files);
            }
        }
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn daily_log() {
        init_database_path();
        let data_model = "{Person{ name:String, parents:[Person] nullable }}";

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let event_service = EventService::new();
        let mut events = event_service.subcribe().await;

        let (app, verifying_key, _) = GraphDatabaseService::start(
            "delete app",
            &data_model,
            &secret,
            &random32(),
            path,
            &Configuration::default(),
            event_service,
        )
        .await
        .unwrap();
        //receive daily_log event done during startup
        while let Ok(e) = events.recv().await {
            match e {
                crate::event_service::Event::DataChanged(log) => {
                    assert_eq!(0, log.rooms.len());
                    break;
                }
                _ => {}
            }
        }
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
                        }]
                    }
                }"#,
                Some(param),
            )
            .await
            .unwrap();

        //receive daily_log event
        while let Ok(e) = events.recv().await {
            match e {
                crate::event_service::Event::DataChanged(log) => {
                    assert_eq!(0, log.rooms.len());
                    break;
                }
                _ => {}
            }
        }

        let room_insert = &room.mutate_entities[0];
        let bin_room_id = &room_insert.node_to_mutate.id;

        let room_id = base64_encode(bin_room_id);

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();

        let _ = app
            .mutate_raw(
                r#"
        mutate mutmut {
            P2: Person {room_id:$room_id name:"Alice" parents:[{name:"someone"}] }
            P3: Person {room_id:$room_id name:"Bob"  parents:[{name:"some_other"}] }
        } "#,
                Some(param),
            )
            .await
            .unwrap();

        //receive daily_log event
        while let Ok(e) = events.recv().await {
            match e {
                crate::event_service::Event::DataChanged(log) => {
                    let dates = log.rooms.get(&room_id).unwrap();
                    assert_eq!(1, dates.len());

                    break;
                }

                _ => {}
            }
        }

        let mut room_log_receiv = app.get_room_log(bin_room_id.clone()).await;
        let room_log = room_log_receiv.recv().await.unwrap().unwrap();
        assert_eq!(1, room_log.len());
        let rlog = &room_log[0];
        assert_eq!(date(now()), rlog.date);
        assert_eq!(4, rlog.entry_number);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn room_log() {
        let conn = Connection::open_in_memory().unwrap();
        DailyLog::create_tables(&conn).unwrap();
        let room_id = new_uid();
        RoomChangelog::log_room_definition(&room_id, 100, &conn).unwrap();

        let def = RoomDefinitionLog::get(&room_id, &conn).unwrap().unwrap();
        assert_eq!(def.room_id, room_id);
        assert_eq!(def.room_def_date, 100);
        assert_eq!(def.last_data_date, None);
        assert_eq!(def.entry_number, None);
        assert_eq!(def.daily_hash, None);
        assert_eq!(def.history_hash, None);

        let daily_log_1 = DailyLog {
            room_id: room_id,
            entity: "0.1".to_string(),
            date: 500,
            entry_number: 1,
            daily_hash: Some(random32().to_vec()),
            history_hash: Some(random32().to_vec()),
            need_recompute: false,
        };
        daily_log_1.write(&conn).unwrap();

        let daily_log_0 = DailyLog {
            room_id: room_id,
            entity: "0.1".to_string(),
            date: 200,
            entry_number: 1,
            daily_hash: Some(random32().to_vec()),
            history_hash: Some(random32().to_vec()),
            need_recompute: false,
        };
        daily_log_0.write(&conn).unwrap();

        let def = RoomDefinitionLog::get(&room_id, &conn).unwrap().unwrap();
        assert_eq!(def.room_id, room_id);
        assert_eq!(def.room_def_date, 100);
        assert_eq!(def.last_data_date.unwrap(), daily_log_1.date);
        assert_eq!(def.entry_number.unwrap(), daily_log_1.entry_number);
        assert_eq!(def.daily_hash, daily_log_1.daily_hash);
        assert_eq!(def.history_hash, daily_log_1.history_hash);

        //RoomDefinitionLog
    }

    #[test]
    fn room_log_sort() {
        let conn = Connection::open_in_memory().unwrap();
        DailyLog::create_tables(&conn).unwrap();
        let mut rooms = HashMap::new();
        let num_room = 721;
        let mut room_ids = HashSet::new();
        for _ in 0..num_room {
            let room_id = new_uid();
            let date: i64 = OsRng.gen();
            RoomChangelog::log_room_definition(&room_id, 100, &conn).unwrap();
            let daily_log = DailyLog {
                room_id: room_id,
                entity: "0.1".to_string(),
                date,
                entry_number: 1,
                daily_hash: Some(random32().to_vec()),
                history_hash: Some(random32().to_vec()),
                need_recompute: false,
            };
            daily_log.write(&conn).unwrap();
            rooms.insert(room_id, date);
            room_ids.insert(room_id);
        }

        let empty_room_id = new_uid();
        RoomChangelog::log_room_definition(&empty_room_id, 100, &conn).unwrap();
        rooms.insert(empty_room_id, i64::MAX);
        room_ids.insert(empty_room_id);

        let batch_size = 256;

        let (reply, mut receive) = mpsc::channel::<Result<VecDeque<Uid>, Error>>(100000);
        DailyLog::sort_rooms(&room_ids, batch_size, &reply, &conn).unwrap();
        drop(reply);
        let mut last = i64::MIN;
        let mut last_id = default_uid();
        while let Some(room_ids) = receive.blocking_recv() {
            let mut room_ids = room_ids.unwrap();
            for room_id in &room_ids {
                let date = *rooms.get(room_id).unwrap();
                assert!(date >= last);
                last = date;
            }
            last_id = room_ids.pop_back().unwrap();
        }

        assert_eq!(empty_room_id, last_id);
    }
}
