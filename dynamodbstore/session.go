package dynamodbstore

import (
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/gorilla/sessions"
	"github.com/jjeffery/sessions/sessionstore"
)

// NewSessionStore returns a new session store that uses the underlying DynamoDB table
// for storing both sessions and cookie secrets. If multiple applications use the same
// DynamoDB table for storage, then each application should use a different id so that
// the applications each use different cookie secrets for signing and encrypting the
// secure cookies.
func (store *DB) NewSessionStore(options sessions.Options, appid string) sessions.Store {
	return sessionstore.New(store, options, appid)
}

// New creates a new session store backed by an AWS DynamoDB table. Access to the
// DynamoDB table is provided by the dynamodb handle and tableName. Session options
// describe the session cookie. If multiple applications share the same DynamoDB
// table, then each application should have a different appid so that they will
// use different secrets for signing and encrypting the secure cookies. Otherwise,
// appid can be left blank.
func New(dynamodb *dynamodb.DynamoDB, tableName string, options sessions.Options, appid string) sessions.Store {
	db := NewDB(dynamodb, tableName)
	return db.NewSessionStore(options, appid)
}
