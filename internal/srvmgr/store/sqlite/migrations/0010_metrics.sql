-- Monitoring points of servers: samples (step 0) are kept 48 hours,
-- 15-minute averages (step 900) 30 days. at is the sample time or the
-- start of the average, in Unix seconds. cpu, rx and tx are NULL when
-- unknown (the first sample, a counter reset).
CREATE TABLE metrics (
	server_id  INTEGER NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
	step       INTEGER NOT NULL CHECK (step IN (0, 900)),
	at         INTEGER NOT NULL,
	cpu        REAL,
	mem_used   REAL NOT NULL,
	mem_total  REAL NOT NULL,
	disk_used  REAL NOT NULL,
	disk_total REAL NOT NULL,
	load1      REAL NOT NULL,
	rx         REAL,
	tx         REAL,
	PRIMARY KEY (server_id, step, at)
) WITHOUT ROWID;
