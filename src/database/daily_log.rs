use std::collections::{HashMap, HashSet};

use rusqlite::{params_from_iter, Connection};
use serde::{Deserialize, Serialize};

use crate::date_utils::{date, date_next_day};

use super::{
    configuration::{
        AUTHORISATION_ENT_SHORT, ENTITY_RIGHT_ENT_SHORT, ROOM_ENT_SHORT, USER_AUTH_ENT_SHORT,
    },
    sqlite_database::RowMappingFn,
};

///
/// Stores the modified dates for each rooms during the batch insert.
///
/// At the end of the batch, update the hash to null for all impacted daily logs entries
/// recompute will be performed later
/// this avoids an update of the log for every inserted rows and is specially usefull during room synchronisation
///
#[derive(Default, Debug)]
pub struct DailyMutations {
    room_dates: HashMap<Vec<u8>, HashSet<i64>>,
}
impl DailyMutations {
    pub fn set_need_update(&mut self, room: Vec<u8>, mut_date: i64) {
        let entry = self.room_dates.entry(room).or_default();
        entry.insert(date(mut_date));
        //   println!("insert node daily");
    }

    pub fn write(&self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        //println!("Writing daily");
        let mut node_daily_stmt = conn.prepare_cached(
            "INSERT INTO _daily_log (
                    room_id,
                    date,
                    entry_number,
                    daily_hash,
                    history_hash,
                    need_recompute
                ) values (?,?, 0, NULL, NULL, 1)
                ON CONFLICT(room_id, date) 
                DO UPDATE SET need_recompute=1;
            ",
        )?;
        for room in &self.room_dates {
            for date in room.1 {
                node_daily_stmt.execute((room.0, date))?;
            }
        }
        Ok(())
    }
}

#[derive(Default, Debug, Clone)]
pub struct DailyLogsUpdate {
    room_dates: HashMap<Vec<u8>, HashSet<DailyLog>>,
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
            SELECT room_id, date, need_recompute, daily_hash, history_hash
            FROM _daily_log daily
            WHERE date >= (
                IFNULL (
                    (
                        SELECT max(date) from _daily_log 
                        WHERE daily.room_id = room_id
                        AND date < (
                            SELECT min(date) from _daily_log 
                            WHERE daily.room_id = room_id
                            AND need_recompute = 1
                        )
                    ),(		
                        SELECT min(date) from _daily_log 
                        WHERE daily.room_id = room_id
                        AND need_recompute = 1
                    )
                )
            ) 
            ORDER BY room_id, date
        ",
        )?;

        let compute_sql = format!(
            "
                -- node deletion 
                SELECT signature 
                FROM _node_deletion_log 
                WHERE 
                    room_id = ?1 AND
                    deletion_date >= ?2 AND deletion_date < ?3 
                
                -- edge deletion 
                UNION ALL
                SELECT signature 
                FROM _edge_deletion_log 
                WHERE 
                    room_id = ?1 AND 
                    deletion_date >= ?2 AND deletion_date < ?3 
                
                -- nodes 
                UNION ALL
                SELECT _signature as signature
                FROM _node 
                WHERE
                    room_id = ?1 AND
                    mdate >= ?2 AND mdate < ?3 AND 
                    -- filter room definition entity
                    _entity NOT IN (
                        {},
                        {},
                        {},
                        {}
                    )
                --applies to the whole union
                ORDER by signature
        ",
            ROOM_ENT_SHORT, AUTHORISATION_ENT_SHORT, USER_AUTH_ENT_SHORT, ENTITY_RIGHT_ENT_SHORT
        );
        let mut compute_stmt = conn.prepare_cached(&compute_sql)?;

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
                date = ?
            ",
        )?;

        let mut rows = daily_log_stmt.query([])?;

        let mut previous_room: Vec<u8> = Vec::new();
        let mut previous_hash: Option<Vec<u8>> = None;
        let mut previous_history: Option<Vec<u8>> = None;

        while let Some(row) = rows.next()? {
            let room: Vec<u8> = row.get(0)?;
            let date: i64 = row.get(1)?;
            let need_recompute: bool = row.get(2)?;
            let daily_hash: Option<Vec<u8>> = row.get(3)?;
            let history_hash: Option<Vec<u8>> = row.get(4)?;
            if !need_recompute {
                if previous_room.eq(&room) {
                    if let Some(previous) = &previous_history {
                        let mut hasher = blake3::Hasher::new();
                        hasher.update(previous);
                        if let Some(daily) = &previous_hash {
                            hasher.update(&daily);
                        }
                        let hash = hasher.finalize().as_bytes().to_vec();
                        // update
                        update_history_stmt.execute((&hash, &room, date))?;
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
            } else {
                let mut comp_rows = compute_stmt.query((&room, date, date_next_day(date)))?;

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
                        hasher.update(&previous);
                        if let Some(daily) = &previous_hash {
                            hasher.update(&daily);
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
                    date,
                ))?;

                self.add_log(DailyLog {
                    room_id: room.clone(),
                    date,
                    entry_number,
                    daily_hash: daily_hash.clone(),
                    history_hash: history_hash.clone(),
                    need_recompute: false,
                });
                previous_hash = daily_hash;
                previous_history = history_hash;
                previous_room = room;
            }
        }
        Ok(())
    }

    fn add_log(&mut self, log: DailyLog) {
        let entry = self.room_dates.entry(log.room_id.clone()).or_default();
        entry.insert(log);
    }
}

#[derive(Default, Debug, Clone, Eq, Hash, PartialEq)]
pub struct DailyLog {
    pub room_id: Vec<u8>,
    pub date: i64,
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
            date INTEGER NOT NULL,
            entry_number INTEGER NOT NULL DEFAULT 0,
            daily_hash BLOB,
            history_hash BLOB,
            need_recompute INTEGER, 
            PRIMARY KEY (room_id, date)
        ) WITHOUT ROWID, STRICT",
            [],
        )?;
        conn.execute(
            "CREATE INDEX _daily_log_recompute_room_date ON _daily_log (room_id, need_recompute,  date)",
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

    pub const MAPPING: RowMappingFn<Self> = |row| {
        Ok(Box::new(Self {
            room_id: row.get(0)?,
            date: row.get(1)?,
            entry_number: row.get(2)?,
            daily_hash: row.get(3)?,
            history_hash: row.get(4)?,
            need_recompute: row.get(5)?,
        }))
    };
}

#[derive(Serialize, Deserialize)]
pub struct RoomLog {
    pub date: i64,
    pub entry_number: u32,
    pub daily_hash: Vec<u8>,
}
impl RoomLog {
    pub const LOG_QUERY: &'static str = "
        SELECT date, entry_number,  daily_hash
        FROM _daily_log 
        WHERE room_id = ? 
        ORDER BY date ASC
    ";

    pub fn get_all(room_id: &Vec<u8>, conn: &Connection) -> Result<Vec<RoomLog>, rusqlite::Error> {
        let mut stmt = conn.prepare_cached(Self::LOG_QUERY)?;
        let mut rows = stmt.query([room_id])?;
        let mut res = Vec::new();
        while let Some(row) = rows.next()? {
            res.push(RoomLog {
                date: row.get(0)?,
                entry_number: row.get(1)?,
                daily_hash: row.get(2)?,
            });
        }
        Ok(res)
    }
}

///
/// Used to transmit in one packet
///  - The room modification date to check whether the room defintion needs to be synchronized
///  - The last _daily_log entry to check whether the room data needs to be synchronized
///
#[derive(Serialize, Deserialize)]
pub struct RoomDefinitionLog {
    pub room_id: Vec<u8>,
    pub room_def_date: i64,
    pub last_data_date: i64,
    pub entry_number: i64,
    pub daily_hash: Option<Vec<u8>>,
    pub history_hash: Option<Vec<u8>>,
}
impl RoomDefinitionLog {
    pub fn add(room_id: &Vec<u8>, mdate: i64, conn: &Connection) -> Result<(), rusqlite::Error> {
        let mut stmt = conn.prepare_cached(
            "INSERT OR REPLACE INTO _room_changelog(room_id, mdate) VALUES (?,?)",
        )?;
        stmt.execute((room_id, mdate))?;
        Ok(())
    }
    pub fn get_logs(
        room_ids: &HashSet<Vec<u8>>,
        conn: &Connection,
    ) -> Result<Vec<RoomDefinitionLog>, rusqlite::Error> {
        let it = &mut room_ids.iter().peekable();
        let mut q = String::new();
        let mut ids = Vec::new();
        while let Some(nid) = it.next() {
            q.push('?');
            if it.peek().is_some() {
                q.push(',');
            }
            ids.push(nid);
        }
        let query = format!(
            "
            SELECT 
                rcl.room_id as room_id,  
                rcl.mdate as room_defintion_date, 
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
            WHERE room_id IN ({})
            ",
            q
        );
        let mut stmt = conn.prepare(&query)?;
        let mut rows = stmt.query(params_from_iter(ids.iter()))?;
        let mut result = Vec::new();
        while let Some(row) = rows.next()? {
            result.push(RoomDefinitionLog {
                room_id: row.get(0)?,
                room_def_date: row.get(1)?,
                last_data_date: row.get(2)?,
                entry_number: row.get(3)?,
                daily_hash: row.get(4)?,
                history_hash: row.get(5)?,
            })
        }
        Ok(result)
    }
}
#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use crate::{
        cryptography::{base64_decode, base64_encode, random32},
        database::{
            configuration::Configuration,
            daily_log::DailyLog,
            graph_database::GraphDatabaseService,
            query_language::parameter::{Parameters, ParametersAdd},
        },
        date_utils::{date, now},
        event_service::EventService,
    };

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
        let data_model = "Person{ name:String, parents:[Person] nullable }";

        let secret = random32();
        let path: PathBuf = DATA_PATH.into();
        let event_service = EventService::new();
        let mut events = event_service.subcribe_for_events().await;

        let app = GraphDatabaseService::start(
            "delete app",
            &data_model,
            &secret,
            path,
            Configuration::default(),
            event_service,
        )
        .await
        .unwrap();

        let user_id = base64_encode(app.verifying_key());

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        let room = app
            .mutate_raw(
                r#"mutation mut {
                    _Room{
                        admin: [{
                            verifying_key:$user_id
                        }]
                        user_admin: [{
                            verifying_key:$user_id
                        }]
                        authorisations:[{
                            name:"admin"
                            rights:[{
                                entity:"Person"
                                mutate_self:true
                                mutate_all:true
                            }]
                            users: [{
                                verifying_key:$user_id
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
                crate::event_service::EventMessage::ComputedDailyLog(log) => {
                    let s = log.unwrap();
                    assert_eq!(0, s.room_dates.len());

                    break;
                }
                _ => {}
            }
        }

        let room_insert = &room.mutate_entities[0];
        let bin_room_id = &room_insert.node_to_mutate.id;
        let mutate_date = room_insert.node_to_mutate.date;
        let room_id = base64_encode(&bin_room_id);

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();

        let _ = app
            .mutate_raw(
                r#"
        mutation mutmut {
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
                crate::event_service::EventMessage::ComputedDailyLog(log) => {
                    let log = log.unwrap();
                    let dates = log.room_dates.get(bin_room_id).unwrap();
                    assert_eq!(1, dates.len());
                    let daily_log = dates.into_iter().next().unwrap();
                    assert_eq!(date(mutate_date), daily_log.date);
                    assert!(!daily_log.need_recompute);
                    assert_eq!(4, daily_log.entry_number);
                    assert!(daily_log.daily_hash.is_some());
                    break;
                }
                _ => {}
            }
        }

        let daily_edge_log = "
            SELECT
                room_id,
                date,
                entry_number,
                daily_hash,
                history_hash,
                need_recompute
            from _daily_log ";

        let edge_log = app
            .select(daily_edge_log.to_string(), Vec::new(), DailyLog::MAPPING)
            .await
            .unwrap();
        assert_eq!(1, edge_log.len());
        println!("{:?}", edge_log);
        for nd in edge_log {
            assert_eq!(date(now()), nd.date);
            assert!(!nd.need_recompute);
            assert_eq!(4, nd.entry_number); //each person has
            assert_eq!(base64_decode(room_id.as_bytes()).unwrap(), nd.room_id);
        }

        let room_log = app.get_room_log(bin_room_id.clone()).await.unwrap();
        assert_eq!(1, room_log.len());
        let rlog = &room_log[0];
        assert_eq!(date(now()), rlog.date);
        assert_eq!(4, rlog.entry_number);
    }
}
