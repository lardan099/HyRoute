-- The port hopping interval of the server's client links and configs
-- (P2-07), in seconds; 0: the client's default. A client setting, so it
-- lives with the server and changes without touching the server itself.
ALTER TABLE servers ADD COLUMN hop_interval INTEGER NOT NULL DEFAULT 0 CHECK (hop_interval = 0 OR hop_interval BETWEEN 5 AND 3600);
