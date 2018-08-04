// Package dynamodbstore provides session storage using an AWS DynamoDB table.
// The session store is compatible with Gorilla sessions (github.com/gorilla/sessions).
//
// The DynamoDB table is expected to have the following structure:
//
//  Hash Key: name="id" type="S"
//  Sort Key: none
//  Time to Live Attribute: name="expiration_time"
//
// The DynamoDB table is used to store both session information and the secrets
// that are used to sign and encrypt the content of HTTP cookies. The secrets
// are automatically generated and rotated.
//
// The same DynamoDB table can be used by multiple independent applications. Each
// application provides a unique identifier that ensures that secrets and session
// data are kept separate.
//
// Obsolete session data is automatically purged from the table through the use of
// the DynamoDB time to live attribute.
package dynamodbstore
