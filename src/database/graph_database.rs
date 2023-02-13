const NODE_TABLE: &str = "CREATE TABLE node (
	id TEXT NOT NULL,
	schema TEXT  NOT NULL,
	cdate INTEGER  NOT NULL,
	flag TEXT,
	string TEXT,
	json TEXT,
	binary BLOB,
	pub_key BLOB,
	signature BLOB,
	PRIMARY KEY (id)
) STRICT;

CREATE UNIQUE INDEX node_idx  ON entity (id, schema, cdate);";

const NODE_FTS_TABLE: &str = "
    CREATE VIRTUAL TABLE node_fts USING fts5(string, json, cdate, content='node');

    CREATE TRIGGER node_ai_trg AFTER INSERT ON node BEGIN
	INSERT INTO node_fts (rowid,string, json, cdate) VALUES (new.rowid,new.string, new.json, new.cdate);
    END;
    
    CREATE TRIGGER node_ad_trg AFTER DELETE ON node BEGIN
	    INSERT INTO node_fts (documents_fts, rowid, string, json) VALUES('delete', old.rowid, old.string,  old.json, old.cdate);
    END;
    
    CREATE TRIGGER node_au_trg AFTER UPDATE ON node BEGIN
	    INSERT INTO node_fts (documents_fts, rowid, string, json, cdate) VALUES('delete', old.rowid, old.string,  old.json, old.cdate);
	    INSERT INTO node_fts (rowid,string, json, cdate) VALUES (new.rowid,new.string, new.json,  new.cdate);
    END;
";

const EDGE_TABLE: &str = "
CREATE TABLE edge (
	source TEXT NOT NULL,
	target TEXT NOT NULL,
	flag TEXT,
	schema TEXT NOT NULL,
	pub_key BLOB,
	signature BLOB,
	PRIMARY KEY (source,target),
	FOREIGN KEY(source) REFERENCES node(id),
    FOREIGN KEY(target) REFERENCES node(id)
) STRICT;

CREATE INDEX edge_target_source_idx(target, source);
";

const SYNCH_LOG_TABLE: &str = "
CREATE TABLE synch_log (
	source TEXT NOT NULL,
	target TEXT NOT NULL,
	schema TEXT NOT NULL,
	target_date INTEGER NOT NULL, 
	cdate INTEGER NOT NULL
) STRICT;

CREATE INDEX synch_log_idx  ON synch_log(source, schema, target_date );";

const DAILY_SYNCH_LOG_TABLE:&str ="
CREATE TABLE daily_synch_log (
	source TEXT NOT NULL,
	schema TEXT NOT NULL,
	day INTEGER NOT NULL,
	previous_day INTEGER,
	daily_hash BLOB,
	history_hash BLOB,
	PRIMARY KEY (source, schema, day)
)STRICT;

CREATE INDEX daily_synch_log_idx  ON synch_log(source, schema, day );
";