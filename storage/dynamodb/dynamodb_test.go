package dynamodb

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/jjeffery/sessions/internal/testhelper"
	"github.com/jjeffery/sessions/storage"
)

func newDynamoDB() *dynamodb.DynamoDB {
	session, _ := session.NewSession(&aws.Config{
		Region:      aws.String("us-east1"),
		Credentials: credentials.NewStaticCredentials("234", "123", ""),
		Endpoint:    aws.String("http://localhost:8000"),
		DisableSSL:  aws.Bool(true),
	})
	return dynamodb.New(session)
}

// do something
func TestDynamoDB(t *testing.T) {
	newDB := func() storage.Provider {
		db := New(newDynamoDB(), "http_sessions")
		if err := db.DropTable(); err != nil {
			t.Fatal(err)
		}
		if err := db.CreateTable(5, 5); err != nil {
			t.Fatal(err)
		}
		return db
	}

	testhelper.TestSessionStore(t, newDB)
	testhelper.TestStorageProvider(t, newDB())
}
