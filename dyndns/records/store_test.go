package records

import (
	"errors"
	"github.com/w3K-one/docker-ddns-server/dyndns/model"
	"github.com/w3K-one/docker-ddns-server/dyndns/nswrapper"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"path/filepath"
	"testing"
)

func TestRRsetsAndLegacyOwnership(t *testing.T) {
	db, e := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "test.db")), &gorm.Config{})
	if e != nil {
		t.Fatal(e)
	}
	db.AutoMigrate(&model.Record{}, &model.Host{}, &model.CName{})
	s := &Store{DB: db, Zones: []string{"example.test"}, Apply: func([]nswrapper.RRset) error { return nil }}
	if e = s.Replace("example.test", "@", "TXT", 600, []string{"one", "two"}); e != nil {
		t.Fatal(e)
	}
	s.Apply = func([]nswrapper.RRset) error { return errors.New("offline") }
	if e = s.Replace("example.test", "@", "TXT", 600, []string{"lost"}); e == nil {
		t.Fatal("DNS failure accepted")
	}
	var rows []model.Record
	db.Find(&rows)
	if len(rows) != 2 {
		t.Fatal("rollback lost records", rows)
	}
	s.Apply = func([]nswrapper.RRset) error { return nil }
	if e = s.Replace("other.test", "@", "TXT", 60, []string{"no"}); e == nil {
		t.Fatal("zone bypass")
	}
	if e = s.Replace("example.test", "alias", "CNAME", 60, []string{"www.example.net"}); e != nil {
		t.Fatal(e)
	}
	if e = s.Replace("example.test", "alias", "TXT", 60, []string{"no"}); e == nil {
		t.Fatal("CNAME conflict")
	}
	host := model.Host{Hostname: "router", Domain: "example.test"}
	db.Create(&host)
	db.Create(&model.CName{Hostname: "legacy", TargetID: host.ID})
	for _, tc := range []struct{ n, k, v string }{{"router", "A", "192.0.2.2"}, {"*.router", "AAAA", "2001:db8::2"}, {"legacy", "TXT", "no"}, {"_acme-challenge", "TXT", "no"}} {
		if e = s.Replace("example.test", tc.n, tc.k, 60, []string{tc.v}); e == nil {
			t.Fatalf("ownership bypass %+v", tc)
		}
	}
	if e = s.Replace("example.test", "router", "TXT", 60, []string{"kept"}); e != nil {
		t.Fatal(e)
	}
}
