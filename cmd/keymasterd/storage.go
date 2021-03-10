package main

import (
	"bytes"
	"database/sql"
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Cloud-Foundations/golib/pkg/awsutil/metadata"
	"github.com/Cloud-Foundations/golib/pkg/awsutil/secretsmgr"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

const (
	userProfilePrefix = "profile_"
	userProfileSuffix = ".gob"
	profileDBFilename = "userProfiles.sqlite3"
	cachedDBFilename  = "cachedDB.sqlite3"

	dbConnectionLifetimeDefault = time.Minute * 15
	dbConnectionLifetimeMaximum = time.Hour

	dbSyncDelayDefault = time.Second * 3
	dbSyncDelayMinimum = time.Second
	dbSyncDelayMaximum = time.Minute

	dbSyncIntervalDefault = time.Minute * 5
	dbSyncIntervalMinimum = time.Second * 5
	dbSyncIntervalMaximum = time.Minute * 15
)

func (config *ProfileStorageConfig) setSyncLimits() {
	if config.SyncDelay < 1 {
		config.SyncDelay = dbSyncDelayDefault
	} else if config.SyncDelay < dbSyncDelayMinimum {
		config.SyncDelay = dbSyncDelayMinimum
	} else if config.SyncDelay > dbSyncDelayMaximum {
		config.SyncDelay = dbSyncDelayMaximum
	}
	if config.SyncInterval < 1 {
		config.SyncInterval = dbSyncIntervalDefault
	} else if config.SyncInterval < dbSyncIntervalMinimum {
		config.SyncInterval = dbSyncIntervalMinimum
	} else if config.SyncInterval > dbSyncIntervalMaximum {
		config.SyncInterval = dbSyncIntervalMaximum
	}
	if config.ConnectionLifetime < 1 {
		config.ConnectionLifetime = dbConnectionLifetimeDefault
	}
	if config.ConnectionLifetime < config.SyncInterval {
		config.ConnectionLifetime = config.SyncInterval
	} else if config.ConnectionLifetime > dbConnectionLifetimeMaximum {
		config.ConnectionLifetime = dbConnectionLifetimeMaximum
	}
}

func (state *RuntimeState) expandStorageUrl() error {
	config := &state.Config.ProfileStorage
	if config.AwsSecretId == "" {
		return nil
	}
	metadataClient, err := metadata.GetMetadataClient()
	if err != nil {
		return err
	}
	secrets, err := secretsmgr.GetAwsSecret(metadataClient, config.AwsSecretId,
		state.logger)
	if err != nil {
		return err
	}
	config.StorageUrl = os.Expand(config.StorageUrl,
		func(variableName string) string {
			return secrets[variableName]
		})
	return nil
}

func initDB(state *RuntimeState) (err error) {
	logger.Debugf(3, "Top of initDB")
	state.Config.ProfileStorage.setSyncLimits()
	//open/create cache DB first
	cacheDBFilename := filepath.Join(state.Config.Base.DataDirectory,
		cachedDBFilename)
	state.cacheDB, err = initFileDBSQLite(cacheDBFilename, state.cacheDB)
	if err != nil {
		logger.Printf("Failure on creation of cacheDB")
		return err
	}
	logger.Debugf(3, "storage=%s", state.Config.ProfileStorage.StorageUrl)
	storageURL := state.Config.ProfileStorage.StorageUrl
	if storageURL == "" {
		storageURL = "sqlite:"
	}
	splitString := strings.SplitN(storageURL, ":", 2)
	if len(splitString) < 1 {
		logger.Printf("invalid string")
		err := errors.New("Bad storage url string")
		return err
	}
	state.remoteDBQueryTimeout = time.Second * 2
	go state.BackgroundDBCopy(state.Config.ProfileStorage.SyncDelay)
	switch splitString[0] {
	case "sqlite":
		logger.Printf("doing sqlite")
		return initDBSQlite(state)
	case "postgresql":
		logger.Printf("doing postgres")
		return initDBPostgres(state)
	default:
		logger.Printf("invalid storage url string")
		err := errors.New("Bad storage url string")
		return err
	}
}

func initDBPostgres(state *RuntimeState) (err error) {
	state.dbType = "postgres"
	state.db, err = sql.Open("postgres", state.Config.ProfileStorage.StorageUrl)
	if err != nil {
		return err
	}
	/// This should be changed to take care of DB schema
	if true {
		sqlStmt := `create table if not exists user_profile (id serial not null primary key, username text unique, profile_data bytea);`
		_, err = state.db.Exec(sqlStmt)
		if err != nil {
			logger.Printf("init postgres err: %s: %q\n", err, sqlStmt)
			return err
		}
		sqlStmt = `create table if not exists expiring_signed_user_data(id serial not null primary key, username text not null, jws_data text not null, type integer not null, expiration_epoch integer not null, update_epoch integer not null, UNIQUE(username,type));`
		_, err = state.db.Exec(sqlStmt)
		if err != nil {
			logger.Printf("init postgres err: %s: %q\n", err, sqlStmt)
			return err
		}
	}
	// Ensure that broken connections are replaced.
	state.db.SetConnMaxLifetime(state.Config.ProfileStorage.ConnectionLifetime)
	return nil
}

// This call initializes the database if it does not exist.
func initDBSQlite(state *RuntimeState) (err error) {
	state.dbType = "sqlite"
	dbFilename := filepath.Join(state.Config.Base.DataDirectory,
		profileDBFilename)
	state.db, err = initFileDBSQLite(dbFilename, state.db)
	if err != nil {
		return err
	}
	state.db.SetMaxIdleConns(0) // Make the DB NFS-friendly.
	return nil
}

var sqliteinitializationStatements = []string{
	`create table if not exists user_profile (id integer not null primary key, username text unique, profile_data blob);`,
	`create table if not exists expiring_signed_user_data(id integer not null primary key, username text not null, jws_data text not null, type integer not null, expiration_epoch integer not null, update_epoch integer no null, UNIQUE(username,type));`,
}

func initializeSQLitetables(db *sql.DB) error {
	for _, sqlStmt := range sqliteinitializationStatements {
		logger.Debugf(2, "initializing sqlite, statement =%q", sqlStmt)
		_, err := db.Exec(sqlStmt)
		if err != nil {
			logger.Printf("%s: %q\n", err, sqlStmt)
			return err
		}
	}
	return nil
}

// This call initializes the database if it does not exist.
// TODO: update  to perform auto-updates of the db.
func initFileDBSQLite(dbFilename string, currentDB *sql.DB) (*sql.DB, error) {
	if _, err := os.Stat(dbFilename); os.IsNotExist(err) {
		//CREATE NEW DB
		fileDB, err := sql.Open("sqlite3", dbFilename)
		if err != nil {
			logger.Printf("Failure creating new db: %s", dbFilename)
			return nil, err
		}
		logger.Printf("post DB open")
		err = initializeSQLitetables(fileDB)
		if err != nil {
			return nil, err
		}
		return fileDB, nil
	}
	// try open the DB
	if currentDB == nil {
		fileDB, err := sql.Open("sqlite3", dbFilename)
		if err != nil {
			return nil, err
		}
		err = initializeSQLitetables(fileDB)
		if err != nil {
			return nil, err
		}
		return fileDB, nil
	}
	return currentDB, nil
}

func (state *RuntimeState) BackgroundDBCopy(initialSleep time.Duration) {
	time.Sleep(initialSleep)
	for {
		logger.Debugf(0, "starting db copy")
		err := copyDBIntoSQLite(state.db, state.cacheDB, "sqlite")
		if err != nil {
			logger.Printf("err='%s'", err)
		} else {
			logger.Debugf(0, "db copy success")
		}
		cleanupDBData(state.db)
		cleanupDBData(state.cacheDB)
		time.Sleep(state.Config.ProfileStorage.SyncInterval)
	}
}

func cleanupDBData(db *sql.DB) error {
	if db == nil {
		err := errors.New("nil database on cleanup")
		return err
	}
	queryStr := fmt.Sprintf(
		"DELETE from expiring_signed_user_data WHERE expiration_epoch < %d",
		time.Now().Unix())
	rows, err := db.Query(queryStr)
	if err != nil {
		logger.Printf("err='%s'", err)
		return err
	}
	defer rows.Close()
	return nil
}

func copyDBIntoSQLite(source, destination *sql.DB,
	destinationType string) error {
	if source == nil || destination == nil {
		err := errors.New("nil databases")
		return err
	}
	// Copy user profiles
	rows, err := source.Query("SELECT username,profile_data FROM user_profile")
	if err != nil {
		logger.Printf("err='%s'", err)
		return err
	}
	defer rows.Close()
	queryStr := fmt.Sprintf(
		"SELECT username, type, jws_data, expiration_epoch,update_epoch FROM expiring_signed_user_data WHERE expiration_epoch > %d",
		time.Now().Unix())
	genericRows, err := source.Query(queryStr)
	if err != nil {
		logger.Printf("err='%s'", err)
		return err
	}
	defer genericRows.Close()
	tx, err := destination.Begin()
	if err != nil {
		logger.Printf("err='%s'", err)
		return err
	}
	defer tx.Rollback()
	deleteProfilesQueryStr := fmt.Sprintf("DELETE from user_profile ")
	if rows, err := destination.Query(deleteProfilesQueryStr); err != nil {
		logger.Printf("err='%s'", err)
		return err
	} else {
		rows.Close()
	}
	stmtText := saveUserProfileStmt[destinationType]
	stmt, err := tx.Prepare(stmtText)
	if err != nil {
		logger.Printf("err='%s'", err)
		return err
	}
	defer stmt.Close()
	for rows.Next() {
		var (
			username     string
			profileBytes []byte
		)
		if err := rows.Scan(&username, &profileBytes); err != nil {
			logger.Printf("err='%s'", err)
			return err
		}
		_, err = stmt.Exec(username, profileBytes)
		if err != nil {
			logger.Printf("err='%s'", err)
			return err
		}
	}
	if err := rows.Err(); err != nil {
		logger.Printf("err='%s'", err)
		return err
	}
	expiringUpsertText := saveSignedUserDataStmt[destinationType]
	expiringUpsertStmt, err := tx.Prepare(expiringUpsertText)
	if err != nil {
		logger.Printf("err='%s'", err)
		return err
	}
	defer expiringUpsertStmt.Close()
	for genericRows.Next() {
		var (
			username        string
			dataType        int
			jwsData         string
			expirationEpoch int64
			updateEpoch     int64
		)
		if err := genericRows.Scan(&username, &dataType, &jwsData,
			&expirationEpoch, &updateEpoch); err != nil {
			logger.Printf("err='%s'", err)
			return err
		}
		//username, type, jws_data, expiration_epoch, update_epoch
		_, err = expiringUpsertStmt.Exec(username, dataType, jwsData,
			expirationEpoch, updateEpoch)
		if err != nil {
			logger.Printf("err='%s'", err)
			return err
		}
	}
	err = tx.Commit()
	if err != nil {
		logger.Printf("err='%s'", err)
		return err
	}
	return nil
}

var getUsersStmt = map[string]string{
	"sqlite":   "select username from user_profile order by username",
	"postgres": "select username from user_profile order by username",
}

type getUsersData struct {
	Names []string
	Err   error
}

func gatherUsers(stmt *sql.Stmt) ([]string, error) {
	rows, err := stmt.Query()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return names, nil
}

func (state *RuntimeState) GetUsers() ([]string, bool, error) {
	ch := make(chan getUsersData, 1)
	start := time.Now()
	go func() {
		stmtText := getUsersStmt[state.dbType]
		stmt, err := state.db.Prepare(stmtText)
		if err != nil {
			logger.Printf("Error Preparing getUsers statement primary DB: %s",
				err)
			return
		}
		defer stmt.Close()
		if state.remoteDBQueryTimeout == 0 {
			time.Sleep(10 * time.Millisecond)
		}
		names, dbErr := gatherUsers(stmt)
		ch <- getUsersData{Names: names, Err: dbErr}
		close(ch)
	}()
	select {
	case dbMessage := <-ch:
		if dbMessage.Err != nil {
			logger.Printf("Problem with db ='%s'", dbMessage.Err)
		} else {
			metricLogExternalServiceDuration("storage-read", time.Since(start))
		}
		return dbMessage.Names, false, dbMessage.Err
	case <-time.After(state.remoteDBQueryTimeout):
		logger.Println("GetUsers: timed out on primary DB")
		stmtText := getUsersStmt["sqlite"]
		stmt, err := state.cacheDB.Prepare(stmtText)
		if err != nil {
			logger.Printf("Error Preparing getUsers statement cached DB: %s",
				err)
			return nil, false, err
		}
		defer stmt.Close()
		names, dbErr := gatherUsers(stmt)
		if dbErr != nil {
			logger.Printf("Problem with db = '%s'", err)
		} else {
			logger.Println("GetUsers: got data from DB cache")
		}
		return names, true, dbErr
	}
}

var loadUserProfileStmt = map[string]string{
	"sqlite":   "select profile_data from user_profile where username = ?",
	"postgres": "select profile_data from user_profile where username = $1",
}

/// Adding api to be load/save per user

// Notice: each operation load/save should be atomic.

type loadUserProfileData struct {
	//fromDB       bool
	ProfileBytes []byte
	Err          error
}

// If there a valid user profile returns: profile, true nil
// If there is NO user profile returns default_object, false, nil
// Any other case: nil, false, error
func (state *RuntimeState) LoadUserProfile(username string) (
	profile *userProfile, ok bool, fromCache bool, err error) {
	var defaultProfile userProfile
	defaultProfile.U2fAuthData = make(map[int64]*u2fAuthData)
	defaultProfile.TOTPAuthData = make(map[int64]*totpAuthData)
	ch := make(chan loadUserProfileData, 1)
	start := time.Now()
	go func(username string) { //loads profile from DB
		var profileMessage loadUserProfileData
		stmtText := loadUserProfileStmt[state.dbType]
		stmt, err := state.db.Prepare(stmtText)
		if err != nil {
			logger.Printf("Error Preparing statement LoadUsers primary DB: %s",
				err)
			return
		}
		defer stmt.Close()
		// if the remoteDBQueryTimeout == 0 this means we are actuallty trying
		// to force the cached db. In single core systems, we need to ensure
		// this goroutine yields to sthis sleep is necesary
		if state.remoteDBQueryTimeout == 0 {
			time.Sleep(10 * time.Millisecond)
		}
		profileMessage.Err = stmt.QueryRow(username).Scan(
			&profileMessage.ProfileBytes)
		ch <- profileMessage
	}(username)
	var profileBytes []byte
	fromCache = false
	select {
	case dbMessage := <-ch:
		err = dbMessage.Err
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				logger.Printf("err='%s'", err)
				return &defaultProfile, false, fromCache, nil
			} else {
				logger.Printf("Problem with db ='%s'", err)
				return nil, false, fromCache, err
			}
		}
		metricLogExternalServiceDuration("storage-read", time.Since(start))
		profileBytes = dbMessage.ProfileBytes
	case <-time.After(state.remoteDBQueryTimeout):
		logger.Println("LoadUserProfile: timed out on primary DB")
		fromCache = true
		// load from cache
		stmtText := loadUserProfileStmt["sqlite"]
		stmt, err := state.cacheDB.Prepare(stmtText)
		if err != nil {
			logger.Printf("Error Preparing statement LoadUsers cache DB: %s",
				err)
			return nil, false, false, err
		}
		defer stmt.Close()
		err = stmt.QueryRow(username).Scan(&profileBytes)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				logger.Printf("err='%s'", err)
				return &defaultProfile, false, true, nil
			} else {
				logger.Printf("Problem with db ='%s'", err)
				return nil, false, true, err
			}
		}
		logger.Println("LoadUserProfile: got data from DB cache")
	}
	logger.Debugf(10, "profile bytes len=%d", len(profileBytes))
	//gobReader := bytes.NewReader(fileBytes)
	gobReader := bytes.NewReader(profileBytes)
	decoder := gob.NewDecoder(gobReader)
	err = decoder.Decode(&defaultProfile)
	if err != nil {
		return nil, false, fromCache, err
	}
	logger.Debugf(1, "loaded profile=%+v", defaultProfile)
	return &defaultProfile, true, fromCache, nil
}

var saveUserProfileStmt = map[string]string{
	"sqlite":   "insert or replace into user_profile(username, profile_data) values(?, ?)",
	"postgres": "insert into user_profile(username, profile_data) values ($1,$2) on CONFLICT(username) DO UPDATE set  profile_data = excluded.profile_data",
}

func (state *RuntimeState) SaveUserProfile(username string,
	profile *userProfile) error {
	var gobBuffer bytes.Buffer
	encoder := gob.NewEncoder(&gobBuffer)
	if err := encoder.Encode(profile); err != nil {
		return err
	}
	start := time.Now()
	//insert into DB
	tx, err := state.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmtText := saveUserProfileStmt[state.dbType]
	stmt, err := tx.Prepare(stmtText)
	if err != nil {
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec(username, gobBuffer.Bytes())
	if err != nil {
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	metricLogExternalServiceDuration("storage-save", time.Since(start))
	return nil
}

var deleteUserProfileStmt = map[string]string{
	"sqlite":   "delete from  user_profile where username = ?",
	"postgres": "delete from  user_profile where username = $1",
}

func (state *RuntimeState) DeleteUserProfile(username string) error {
	//delete from DB
	tx, err := state.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmtText := deleteUserProfileStmt[state.dbType]
	stmt, err := tx.Prepare(stmtText)
	if err != nil {
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec(username)
	if err != nil {
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

var deleteSignedUserDataStmt = map[string]string{
	"sqlite":   "delete from expiring_signed_user_data where username = ? and type = ?",
	"postgres": "delete from expiring_signed_user_data where username = $1 and type = $2",
}

func (state *RuntimeState) DeleteSigned(username string, dataType int) error {
	//insert into DB
	tx, err := state.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmtText := deleteSignedUserDataStmt[state.dbType]
	stmt, err := tx.Prepare(stmtText)
	if err != nil {
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec(username, dataType)
	if err != nil {
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

type getSignedData struct {
	JWSData string
	Err     error
}

var getSignedUserDataStmt = map[string]string{
	"sqlite":   "select jws_data from expiring_signed_user_data where username = ? and type =? and expiration_epoch > ?",
	"postgres": "select jws_data from expiring_signed_user_data where username = $1 and type = $2 and expiration_epoch > $3",
}

func (state *RuntimeState) GetSigned(username string,
	dataType int) (bool, string, error) {
	logger.Printf("top of GetSigned")
	//var jwsData string
	ch := make(chan getSignedData, 1)
	//start := time.Now()
	go func(username string, dataType int) { //loads profile from DB
		var signedDataMessage getSignedData
		stmtText := getSignedUserDataStmt[state.dbType]
		stmt, err := state.db.Prepare(stmtText)
		if err != nil {
			logger.Printf("Error Preparing statement GetSigned Primary DB: %s",
				err)
			return
		}
		defer stmt.Close()
		if state.remoteDBQueryTimeout == 0 {
			time.Sleep(10 * time.Millisecond)
		}
		signedDataMessage.Err = stmt.QueryRow(username, dataType,
			time.Now().Unix()).Scan(&signedDataMessage.JWSData)
		ch <- signedDataMessage
	}(username, dataType)
	var jwsData string
	select {
	case dbMessage := <-ch:
		logger.Debugf(2, "got data from db. dbMessage=%+v", dbMessage)
		err := dbMessage.Err
		if err != nil {
			err = dbMessage.Err
			if err.Error() == "sql: no rows in result set" {
				logger.Printf("err='%s'", err)
				return false, "", nil
			} else {
				logger.Printf("Problem with db ='%s'", err)
				return false, "", err
			}
		}
		jwsData = dbMessage.JWSData
	case <-time.After(state.remoteDBQueryTimeout):
		logger.Println("GetSigned: timed out on primary DB")
		// load from cache
		stmtText := getSignedUserDataStmt["sqlite"]
		stmt, err := state.cacheDB.Prepare(stmtText)
		if err != nil {
			logger.Printf("Error Preparing statement GetSigned Cache DB: %s",
				err)
			return false, "", err
		}
		defer stmt.Close()
		err = stmt.QueryRow(username, dataType, time.Now().Unix()).Scan(
			&jwsData)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				logger.Printf("err='%s'", err)
				return false, "", nil
			} else {
				logger.Printf("Problem with db ='%s'", err)
				return false, "", err
			}
		}
		logger.Println("GetSigned: got data from DB cache")
	}
	logger.Println("GetSigned: got jwsdata")
	storageJWT, err := state.getStorageDataFromStorageStringDataJWT(jwsData)
	if err != nil {
		logger.Debugf(2, "failed to get storage data %s data=%s", err, jwsData)
		return false, "", err
	}
	if storageJWT.Subject != username {
		logger.Debugf(2, "%s for %s", err, username)
		return false, "", errors.New("inconsistent data coming from DB")
	}
	return true, storageJWT.Data, nil
}

var saveSignedUserDataStmt = map[string]string{
	"sqlite":   "insert or replace into expiring_signed_user_data(username, type, jws_data, expiration_epoch, update_epoch) values(?,?, ?, ?, ?)",
	"postgres": "insert into expiring_signed_user_data(username, type, jws_data, expiration_epoch, update_epoch) values ($1,$2,$3,$4, $5) ON CONFLICT(username,type) DO UPDATE SET  jws_data = excluded.jws_data, expiration_epoch = excluded.expiration_epoch",
}

func (state *RuntimeState) UpsertSigned(username string, dataType int,
	expirationEpoch int64, data string) error {
	logger.Debugf(2, "top of UpsertSigned")
	//expirationEpoch := expiration.Unix()
	stringData, err := state.genNewSerializedStorageStringDataJWT(username,
		dataType, data, expirationEpoch)
	if err != nil {
		return err
	}
	start := time.Now()
	//insert into DB
	tx, err := state.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmtText := saveSignedUserDataStmt[state.dbType]
	stmt, err := tx.Prepare(stmtText)
	if err != nil {
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec(username, dataType, stringData, expirationEpoch,
		time.Now().Unix())
	if err != nil {
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	metricLogExternalServiceDuration("storage-save", time.Since(start))
	return nil
}
