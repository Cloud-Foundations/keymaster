package main

import (
	"io/ioutil"
	stdlog "log"
	"os"
	"testing"

	"github.com/Cloud-Foundations/Dominator/lib/log/debuglogger"
	"github.com/Cloud-Foundations/golib/pkg/log/testlogger"
	"github.com/Cloud-Foundations/keymaster/keymasterd/eventnotifier"
)

func init() {
	slogger := stdlog.New(os.Stderr, "", stdlog.LstdFlags)
	logger = debuglogger.New(slogger)
	eventNotifier = eventnotifier.New(logger)
}

func newTestingState(t *testing.T) (*RuntimeState, string, error) {
	tmpdir, err := ioutil.TempDir("", "keymasterd")
	if err != nil {
		return nil, "", err
	}
	state := &RuntimeState{logger: testlogger.New(t)}
	state.Config.Base.DataDirectory = tmpdir
	return state, tmpdir, nil
}

func TestDBCopy(t *testing.T) {
	state, tmpdir, err := newTestingState(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	err = initDB(state)
	if err != nil {
		t.Fatal(err)
	}
	// copy blank db
	err = copyDBIntoSQLite(state.db, state.cacheDB, "sqlite")
	if err != nil {
		t.Fatal(err)
	}
	// make a profile and push back to db
	profile, _, _, err := state.LoadUserProfile("username")
	if err != nil {
		t.Fatal(err)
	}
	err = state.SaveUserProfile("username", profile)
	if err != nil {
		t.Fatal(err)
	}
	// copy the db now with one user
	err = copyDBIntoSQLite(state.db, state.cacheDB, "sqlite")
	if err != nil {
		t.Fatal(err)
	}
}

func TestFetchFromCache(t *testing.T) {
	state, tmpdir, err := newTestingState(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	err = initDB(state)
	if err != nil {
		t.Fatal(err)
	}
	// make a profile and push back to db
	profile, _, _, err := state.LoadUserProfile("username")
	if err != nil {
		t.Fatal(err)
	}
	err = state.SaveUserProfile("username", profile)
	if err != nil {
		t.Fatal(err)
	}
	// copy blank with one user...
	err = copyDBIntoSQLite(state.db, state.cacheDB, "sqlite")
	if err != nil {
		t.Fatal(err)
	}
	state.remoteDBQueryTimeout = 0
	_, _, fromCache, err := state.LoadUserProfile("username")
	if err != nil {
		t.Fatal(err)
	}
	if !fromCache {
		t.Fatal("did NOT got data from cache")
	}
	_, ok, fromCache, err := state.LoadUserProfile("unknown-user")
	if err != nil {
		t.Fatal(err)
	}

	if !fromCache {
		t.Fatal("did NOT got data from cache")
	}
	if ok {
		t.Fatal("This should have failed for invalid user")
	}
}
