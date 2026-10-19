-- Jobs over several servers (P3-02: a cascade link changes the entry and
-- the exit): the servers of a job besides jobs.server_id. A server has at
-- most one unfinished job, counting these.
CREATE TABLE job_servers (
	job_id    INTEGER NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
	server_id INTEGER NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
	PRIMARY KEY (job_id, server_id)
);
CREATE INDEX job_servers_server ON job_servers (server_id, job_id);
