-- The firewall rules HyRoute opened on a server (ufw or firewalld): a
-- rollback or a port change closes only these, never rules that were
-- there before. firewall_keep: the admin chose at deploy to leave the
-- firewall alone.
ALTER TABLE installations ADD COLUMN firewall_tool TEXT NOT NULL DEFAULT '';
ALTER TABLE installations ADD COLUMN firewall_ports TEXT NOT NULL DEFAULT '';
ALTER TABLE installations ADD COLUMN firewall_keep INTEGER NOT NULL DEFAULT 0 CHECK (firewall_keep IN (0, 1));
