package config

import (
	"flag"
	"io"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestBackupFlags(t *testing.T) {
	c, err := Load(nil, env(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.BackupInterval != 0 || c.BackupKeep != DefaultBackupKeep || c.BackupPassphraseFile != "" || c.BackupDir() != filepath.Join(c.DataDir, "backups") {
		t.Fatalf("defaults %+v", c)
	}
	c, err = Load(nil, env(map[string]string{"HYROUTE_SERVER_BACKUP_INTERVAL": "24h", "HYROUTE_SERVER_BACKUP_KEEP": "3"}), io.Discard)
	if err != nil || c.BackupInterval != 24*time.Hour || c.BackupKeep != 3 {
		t.Fatalf("env %+v %v", c, err)
	}
	for _, args := range [][]string{{"-backup-interval", "5m"}, {"-backup-interval", "-1h"}, {"-backup-keep", "0"}} {
		if _, err := Load(args, env(nil), io.Discard); err == nil {
			t.Errorf("%v: no error", args)
		}
	}
}

// A maintenance command takes the data flags of the controller and its
// own, and gets the arguments after them.
func TestLoadTool(t *testing.T) {
	var force bool
	c, rest, err := LoadTool("restore", []string{"-data-dir", "/srv/x", "-force", "copy.db"}, env(map[string]string{"HYROUTE_SERVER_BACKUP_KEEP": "2"}), io.Discard, func(fs *flag.FlagSet) {
		fs.BoolVar(&force, "force", false, "")
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.DataDir != "/srv/x" || c.MasterKeyFile != filepath.Join("/srv/x", "master.key") || c.BackupKeep != 2 || !force || !slices.Equal(rest, []string{"copy.db"}) {
		t.Fatalf("%+v %v %v", c, force, rest)
	}
	if _, _, err := LoadTool("backup", []string{"-listen", "x"}, env(nil), io.Discard, nil); err == nil {
		t.Fatal("a controller flag on a command")
	}
}
