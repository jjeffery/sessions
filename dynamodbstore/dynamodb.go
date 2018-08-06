package dynamodbstore

import (
	"context"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/jjeffery/errors"
	"github.com/jjeffery/sessions/sessionstore"
)

// unversionedRecord represents an unversioned record in the DynamoDB table
type unversionedRecord struct {
	ID         string                 `dynamodbav:"id"`
	Values     map[string]interface{} `dynamodbav:"values"`
	Expiration int64                  `dynamodbav:"expiration_time"`
}

// versionedRecord represents a versioned record in the DynamoDB table
type versionedRecord struct {
	ID         string                 `dynamodbav:"id"`
	Version    int64                  `dynamodbav:"version"`
	Values     map[string]interface{} `dynamodbav:"values"`
	Expiration int64                  `dynamodbav:"expiration_time"`
}

// DB provides storage for sessions using an AWS DynamoDB table.
// It implements the sessionstore.DB interface.
//
// The structure of the DynamoDB table is described in the package
// comment.
type DB struct {
	dynamodb  *dynamodb.DynamoDB
	tableName string
}

// NewDB creates a new DynamoDB DB given the AWS session and the DynamoDB table name.
func NewDB(dynamodb *dynamodb.DynamoDB, tableName string) *DB {
	return &DB{
		dynamodb:  dynamodb,
		tableName: tableName,
	}
}

// CreateTable creates the dynamodb table.
func (db *DB) CreateTable(readCapacityUnits, writeCapacityUnits int64) error {
	errors := errors.With("table", db.tableName)
	_, err := db.dynamodb.CreateTable(&dynamodb.CreateTableInput{
		AttributeDefinitions: []*dynamodb.AttributeDefinition{
			{
				AttributeName: aws.String("id"),
				AttributeType: aws.String("S"),
			},
			// {
			// 	AttributeName: aws.String("expiration_time"),
			// 	AttributeType: aws.String("N"),
			// },
		},
		KeySchema: []*dynamodb.KeySchemaElement{
			{
				AttributeName: aws.String("id"),
				KeyType:       aws.String(dynamodb.KeyTypeHash),
			},
		},

		ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(readCapacityUnits),
			WriteCapacityUnits: aws.Int64(writeCapacityUnits),
		},
		TableName: aws.String(db.tableName),
	})

	if err != nil {
		return errors.Wrap(err, "unable to create dynamodb table")
	}

	_, err = db.dynamodb.UpdateTimeToLive(&dynamodb.UpdateTimeToLiveInput{
		TableName: aws.String(db.tableName),
		TimeToLiveSpecification: &dynamodb.TimeToLiveSpecification{
			AttributeName: aws.String("expiration_time"),
			Enabled:       aws.Bool(true),
		},
	})
	if err != nil {
		return errors.Wrap(err, "unable to set time to live")
	}

	return nil
}

// DropTable deletes the DynamoDB table.
func (db *DB) DropTable() error {
	_, err := db.dynamodb.DeleteTable(&dynamodb.DeleteTableInput{
		TableName: aws.String(db.tableName),
	})

	if err != nil {
		if hasErrorCode(err, "ResourceNotFoundException") {
			// table not found is not considered an error
			err = nil
		}
	}
	if err != nil {
		return errors.Wrap(err, "unable to delete dynamodb table")
	}

	return nil
}

// Get implements the sessionstore.DB interface.
func (db *DB) Get(ctx context.Context, id string) (*sessionstore.Record, error) {
	errors := errors.With("id", id, "table", db.tableName)
	input := &dynamodb.GetItemInput{
		TableName: aws.String(db.tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(id),
			},
		},
	}
	output, err := db.dynamodb.GetItemWithContext(ctx, input)
	if err != nil {
		return nil, errors.Wrap(err, "cannot get item")
	}
	if len(output.Item) == 0 {
		// not found
		return nil, nil
	}
	var rec versionedRecord
	if err := dynamodbattribute.UnmarshalMap(output.Item, &rec); err != nil {
		return nil, errors.Wrap(err, "unable to unmarshal record")
	}
	return &sessionstore.Record{
		ID:      rec.ID,
		Version: rec.Version,
		Values:  rec.Values,
		Expires: rec.Expiration,
	}, nil
}

// PutUnversioned implements the sessionstore.DB interface.
func (db *DB) PutUnversioned(ctx context.Context, rec *sessionstore.Record) error {
	errors := errors.With("id", rec.ID, "table", db.tableName)
	uvrec := unversionedRecord{
		ID:         rec.ID,
		Values:     rec.Values,
		Expiration: rec.Expires,
	}
	item, err := dynamodbattribute.MarshalMap(uvrec)
	if err != nil {
		return errors.Wrap(err, "failed to convert to dynamodb attribute value")
	}
	input := &dynamodb.PutItemInput{
		Item:      item,
		TableName: aws.String(db.tableName),
	}
	if _, err := db.dynamodb.PutItemWithContext(ctx, input); err != nil {
		return errors.Wrap(err, "unable to save record in dynamodb")
	}
	return nil
}

// PutVersioned implements the sessionstore.DB interface.
func (db *DB) PutVersioned(ctx context.Context, rec *sessionstore.Record, oldVersion int64) (ok bool, err error) {
	errors := errors.With("id", rec.ID, "table", db.tableName)
	vrec := versionedRecord{
		ID:         rec.ID,
		Version:    rec.Version,
		Values:     rec.Values,
		Expiration: rec.Expires,
	}
	item, err := dynamodbattribute.MarshalMap(vrec)
	if err != nil {
		return false, errors.Wrap(err, "failed to convert to dynamodb attribute value")
	}
	input := &dynamodb.PutItemInput{
		Item:      item,
		TableName: aws.String(db.tableName),
	}
	if oldVersion == 0 {
		input.ExpressionAttributeNames = make(map[string]*string)
		input.ExpressionAttributeNames["#id"] = aws.String("id")
		input.ConditionExpression = aws.String("attribute_not_exists(#id)")
	} else {
		input.ExpressionAttributeNames = make(map[string]*string)
		input.ExpressionAttributeNames["#version"] = aws.String("version")
		input.ExpressionAttributeValues = make(map[string]*dynamodb.AttributeValue)
		input.ExpressionAttributeValues[":version"] = &dynamodb.AttributeValue{
			N: aws.String(strconv.FormatInt(oldVersion, 10)),
		}
		input.ConditionExpression = aws.String("#version = :version")
	}
	if _, err := db.dynamodb.PutItemWithContext(ctx, input); err != nil {
		if hasErrorCode(err, "ConditionalCheckFailedException") {
			// optimistic locking check failed, return ok=false, but not an error
			return false, nil
		}
		return false, errors.Wrap(err, "unable to save record in dynamodb")
	}

	return true, nil
}

// Delete implements the sessionstore.DB interface.
func (db *DB) Delete(ctx context.Context, id string) error {
	errors := errors.With("id", id, "table", db.tableName)
	input := &dynamodb.DeleteItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(id),
			},
		},
		TableName: aws.String(db.tableName),
	}

	_, err := db.dynamodb.DeleteItemWithContext(ctx, input)
	if err != nil {
		return errors.Wrap(err, "unable to delete record")
	}

	return nil
}

func hasErrorCode(err error, code string) bool {
	if coder, ok := err.(interface{ Code() string }); ok {
		return coder.Code() == code
	}
	return false
}
