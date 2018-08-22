# sessions

[![GoDoc](https://godoc.org/github.com/jjeffery/sessions?status.svg)](https://godoc.org/github.com/jjeffery/sessions)
[![License](http://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://raw.githubusercontent.com/jjeffery/sessions/master/LICENSE.md)
[![Build Status](https://travis-ci.org/jjeffery/sessions.svg?branch=master)](https://travis-ci.org/jjeffery/sessions)
[![Coverage Status](https://coveralls.io/repos/github/jjeffery/sessions/badge.svg?branch=master)](https://coveralls.io/github/jjeffery/sessions?branch=master)
[![GoReportCard](https://goreportcard.com/badge/github.com/jjeffery/sessions)](https://goreportcard.com/report/github.com/jjeffery/sessions)

This repository provides Go packages that supplement the popular
[Gorilla Sessions](https://github.com/gorilla/sessions) package.

Package [sessionstore](https://godoc.org/github.com/jjeffery/sessions/sessionstore)
provides a session store implementation that persists session information using
a simple [storage interface](https://godoc.org/github.com/jjeffery/sessions/storage#Provider).
Secret key material used for signing and encrypting
[secure cookies](https://github.com/gorilla/securecookie) is stored using the same storage provider.
The secret keying material is automatically generated and is rotated regularly.

Package [storage](https://godoc.org/github.com/jjeffery/sessions/storage) defines a simple interface
for storage of both session information and secret keying material. There are sub-directories
containing packages with implementations for the following:

- Package [dynamodb](https://godoc.org/github.com/jjeffery/sessions/storage/dynamodb): AWS DynamoDB
- Package [postgres](https://godoc.org/github.com/jjeffery/sessions/storage/postgres): PostgreSQL
- Package [memory](https://godoc.org/github.com/jjeffery/sessions/storage/memory): Memory (for testing only)
