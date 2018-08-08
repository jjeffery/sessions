// Package dynamodb has a storage provider that uses an AWS DynamoDB table.
//
// The DynamoDB table is expected to have the following structure:
//
//  Hash Key: name="id" type="S"
//  Sort Key: none
//  Time to Live Attribute: name="expiration_time"
package dynamodb
