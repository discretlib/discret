use std::collections::{HashMap, HashSet};

use rusqlite::Connection;

use crate::date_utils::{date, date_next_day};

use super::{configuration::ROOMS_FIELD_SHORT, sqlite_database::RowMappingFn};

///
/// stores the modified dates for each rooms during the batch insert
/// at the end of the batch, update the hash to null for all impacted daily logs entries
/// recompute will be performed later
/// this avoids an update of the log for every inserted rows and is specially usefull during room synchronisation
///
#[derive(Default, Debug)]
pub struct DailyMutations {
    room_dates: HashMap<Vec<u8>, HashSet<i64>>,
}
impl DailyMutations {
    pub fn add_room_date(&mut self, room: Vec<u8>, mut_date: i64) {
        let entry = self.room_dates.entry(room).or_default();
        entry.insert(date(mut_date));
        //   println!("insert node daily");
    }

    pub fn write(&self, conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        //println!("Writing daily");
        let mut node_daily_stmt = conn.prepare_cached(
            "INSERT INTO _daily_log (
                    room,
                    date,
                    entry_number,
                    daily_hash,
                    need_recompute
                ) values (?,?,0,NULL,1)
                ON CONFLICT(room, date) 
                DO UPDATE SET entry_number=0, daily_hash=NULL, need_recompute=1;
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
    pub fn compute(&mut self, conn: &Connection) -> Result<(), rusqlite::Error> {
        let mut daily_log_stmt = conn.prepare_cached(
            " 
            SELECT 
                room,
                date
            FROM _daily_log
            WHERE need_recompute = 1
        ",
        )?;

        let compute_sql = format!("
                -- node deletion 
                SELECT signature FROM _node_deletion_log WHERE room = ?1 AND deletion_date >= ?2 AND deletion_date < ?3 
                
                -- edge deletion 
                UNION ALL
                SELECT signature FROM _edge_deletion_log WHERE room = ?1 AND deletion_date >= ?2 AND deletion_date < ?3 
                
                -- nodes 
                UNION ALL
                SELECT _node._signature as signature
                FROM _node JOIN _edge on _node.id = _edge.src 
                WHERE
                    _edge.label = '{0}' AND
                    _edge.dest = ?1 AND
                    mdate >= ?2 
                    AND mdate < ?3 

                -- edges 
                UNION ALL	
                SELECT _edge.signature as signature FROM _edge
                JOIN (
                    SELECT _node.id
                    FROM _node 
                    JOIN _edge rooms on _node.id = rooms.src 
                    WHERE
                        rooms.label = '{0}' AND
                        rooms.dest = ?1 
                    ) as nodes on nodes.id=_edge.src
                WHERE	
                    _edge.cdate >= ?2
                    AND
                    _edge.cdate < ?3

                --applies to the whole union
                ORDER by signature
        ",ROOMS_FIELD_SHORT);
        let mut compute_stmt = conn.prepare_cached(&compute_sql)?;

        let mut update_stmt = conn.prepare_cached(
            "
            UPDATE _daily_log 
            SET 
                entry_number = ?, 
                daily_hash = ?, 
                need_recompute = 0
            WHERE
                room = ? AND
                date = ?
            ",
        )?;

        let mut rows = daily_log_stmt.query([])?;
        while let Some(row) = rows.next()? {
            let room: Vec<u8> = row.get(0)?;
            let date: i64 = row.get(1)?;

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

            update_stmt.execute((entry_number, &daily_hash, &room, date))?;
            self.add_log(DailyLog {
                room,
                date,
                entry_number,
                daily_hash,
                need_recompute: false,
            });
        }
        Ok(())
    }

    fn add_log(&mut self, log: DailyLog) {
        let entry = self.room_dates.entry(log.room.clone()).or_default();
        entry.insert(log);
    }
}

#[derive(Default, Debug, Clone, Eq, Hash, PartialEq)]
pub struct DailyLog {
    pub room: Vec<u8>,
    pub date: i64,
    pub entry_number: u32,
    pub daily_hash: Option<Vec<u8>>,
    pub need_recompute: bool,
}
impl DailyLog {
    pub fn create_tables(conn: &Connection) -> Result<(), rusqlite::Error> {
        conn.execute(
            "CREATE TABLE _daily_log (
            room BLOB NOT NULL,
            date INTEGER NOT NULL,
            entry_number INTEGER NOT NULL DEFAULT 0,
            daily_hash BLOB,
            need_recompute INTEGER, 
            PRIMARY KEY (room, date)
        ) WITHOUT ROWID, STRICT",
            [],
        )?;
        conn.execute(
            "CREATE INDEX _daily_log_recompute_room_date ON _daily_log (need_recompute, room, date)",
            [],
        )?;
        Ok(())
    }

    pub const MAPPING: RowMappingFn<Self> = |row| {
        Ok(Box::new(Self {
            room: row.get(0)?,
            date: row.get(1)?,
            entry_number: row.get(2)?,
            daily_hash: row.get(3)?,
            need_recompute: row.get(4)?,
        }))
    };
}
#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use crate::{
        cryptography::{base64_decode, base64_encode, random},
        database::{
            configuration::Configuration,
            daily_log::DailyLog,
            graph_database::GraphDatabaseService,
            query_language::parameter::{Parameters, ParametersAdd},
        },
        date_utils::{date, now},
    };

    const DATA_PATH: &str = "test/data/database/daily_log/";
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

        let secret = random();
        let path: PathBuf = DATA_PATH.into();
        let app = GraphDatabaseService::start(
            "delete app",
            &data_model,
            &secret,
            path,
            Configuration::default(),
        )
        .await
        .unwrap();
        let mut events = app.subcribe_for_events().await.unwrap();

        let user_id = base64_encode(app.verifying_key());

        let mut param = Parameters::default();
        param.add("user_id", user_id.clone()).unwrap();

        let room = app
            .mutate(
                r#"mutation mut {
                    _Room{
                        type: "whatever"
                        authorisations:[{
                            name:"admin"
                            credentials: [{
                                mutate_room:true
                                mutate_room_users:true
                                rights:[{
                                    entity:"Person"
                                    mutate_self:true
                                    delete_all:true
                                    mutate_all:true
                                }]
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
        let e = events.recv().await.unwrap();
        match e {
            crate::database::event_service::EventMessage::ComputedDailyLog(log) => {
                let s = log.unwrap();
                //the room as no parent room and is not synchronized
                assert_eq!(0, s.room_dates.len());
            }
        }

        let room_insert = &room.mutate_entities[0];
        let bin_room_id = &room_insert.node_to_mutate.id;
        let mutate_date = room_insert.node_to_mutate.date;
        let room_id = base64_encode(&bin_room_id);

        let mut param = Parameters::default();
        param.add("room_id", room_id.clone()).unwrap();

        let _ = app
            .mutate(
                r#"
        mutation mutmut {
            P2: Person {_rooms:[{id:$room_id}] name:"Alice" parents:[{name:"someone"}] }
            P3: Person {_rooms:[{id:$room_id}] name:"Bob"  parents:[{name:"some_other"}] }
        } "#,
                Some(param),
            )
            .await
            .unwrap();

        //receive daily_log event
        let e = events.recv().await.unwrap();
        match e {
            crate::database::event_service::EventMessage::ComputedDailyLog(log) => {
                let log = log.unwrap();
                let dates = log.room_dates.get(bin_room_id).unwrap();
                assert_eq!(1, dates.len());
                let daily_log = dates.into_iter().next().unwrap();
                assert_eq!(date(mutate_date), daily_log.date);
                assert!(!daily_log.need_recompute);
                assert_eq!(10, daily_log.entry_number);
                assert!(daily_log.daily_hash.is_some());
            }
        }

        let daily_edge_log = "
            SELECT 
                room,
                date,
                entry_number,
                daily_hash,
                need_recompute
            from _daily_log ";

        let edge_log = app
            .select(daily_edge_log.to_string(), Vec::new(), DailyLog::MAPPING)
            .await
            .unwrap();
        assert_eq!(1, edge_log.len());
        for nd in edge_log {
            assert_eq!(date(now()), nd.date);
            assert!(!nd.need_recompute);
            assert_eq!(10, nd.entry_number); //each person has
            assert_eq!(base64_decode(room_id.as_bytes()).unwrap(), nd.room);
        }
    }
}
