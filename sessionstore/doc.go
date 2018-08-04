// Package sessionstore provides a session store for persistance of HTTP session data.
// The session store is compatible with Gorilla sessions (github.com/gorilla/sessions).
//
// The session store also persists randomly generated secret keying material that
// is used for generating the keys used to sign and encrypt the secure session
// cookies. The secret keying material is regularly rotated.
package sessionstore
