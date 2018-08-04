# sessions

This repository provides Go packages that supplement the popular
[Gorilla Sessions](https://github.com/gorilla/sessions) package.

[dynamodbstore](https://godoc.org/github.com/jjeffery/sessions/dynamodbstore)
provides a session store that persists session information to an AWS
DynamoDB table. The secrets used to sign and encrypt the
[secure cookies](https://github.com/gorilla/securecookie) are created and
stored in the same DynamoDB table, and they are rotated regularly.

[sessionstore](https://godoc.org/github.com/jjeffery/sessions/sessionstore)
contains most of the implementation used in package dynamodbstore, and makes
it fairly easy to implement similar functionality using a different persistent
storage technology, such as Redis or Memstore.
