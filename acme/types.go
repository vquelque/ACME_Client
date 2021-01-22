package main

import (
	"crypto/ecdsa"
	"fmt"
	"net/url"
	"time"
)

type cliArgs struct {
	dir     string
	record  string
	domains []string
	revoke  bool
}

// JSONObject represents an ACME json object with an URL provided in the request header
type JSONObject interface {
	SetURL(url *url.URL)
	GetURL() *url.URL
}

// Each ACME object goes through a state machine over its lifetine. The "status" field of
// the object indicates which state the object is currently in

//Directory object - RFC 8555 $7.1.1
type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	NewAuthz   string `json:"newAuthz"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
	// Directory url provided when creating a new acme client.
	URL *url.URL `json:"-"`
}

func (dir *Directory) SetURL(url *url.URL) {
	dir.URL = url
}
func (dir *Directory) GetURL() *url.URL {
	return dir.URL
}

// Account object - RFC 8555 $7.1.2
type Account struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact"`
	Orders  string   `json:"orders"`
	// Used to manage account. Given by the server in the Location http header when creating an account
	// Used as the "kid" value in the JWS authenticating subsequent requests for management on this account
	URL        *url.URL `json:"-"`
	privKey    *ecdsa.PrivateKey
	Thumbprint string //base64encoded. for computing challenge key authorization
}

func (acc *Account) SetURL(url *url.URL) {
	acc.URL = url
}

func (acc *Account) GetURL() *url.URL {
	return acc.URL
}

// Identifier object used when requesting a certificate
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// IdentifierFromString creates and Identifier object for a domain passed as a string
func IdentifierFromString(domain string) *Identifier {
	return &Identifier{
		Type:  "dns",
		Value: domain,
	}
}

type Order struct {
	Status         string       `json:"status"`
	Expires        time.Time    `json:"expires"`
	Identifiers    []Identifier `json:"identifiers"`
	NotBefore      time.Time    `json:"notBefore"`
	NotAfter       time.Time    `json:"notAfter"`
	Error          Problem      `json:"error"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate"` //optional

	// URL for the order object.
	// Provided by the rel="Location" Link http header
	URL *url.URL `json:"-"`

	AuthorizationsByID map[string]*Authorization
}

func (o *Order) SetURL(url *url.URL) {
	o.URL = url
}

func (o *Order) GetURL() *url.URL {
	return o.URL
}

//Authorization represents an ACME Authorization object
type Authorization struct {
	Identifier Identifier  `json:"identifier"` //valid dns name only --> encoded as RFC 5280
	Status     string      `json:"status"`
	Expires    time.Time   `json:"expires"`
	Challenges []Challenge `json:"challenges"`
	Wildcard   bool        `json:"wildcard"`
	URL        *url.URL

	ChallengeByType map[ChallengeType]Challenge
	ChallengeByURL  map[string]Challenge
}

func (a *Authorization) SetURL(url *url.URL) {
	a.URL = url
}

func (a *Authorization) GetURL() *url.URL {
	return a.URL
}

// Challenge object. structure of the challenge object depends on the validation method being used
// RFC8555 $8
type Challenge struct {
	Type      string  `json:"type"`
	URL       string  `json:"url"`
	Status    string  `json:"status"`
	Validated string  `json:"validated"`
	Error     Problem `json:"error"`

	// Based on the challenge used
	Token            string `json:"token"`
	KeyAuthorization string `json:"keyAuthorization"`

	// Authorization url provided by the rel="up" Link http header
	AuthorizationURL *url.URL `json:"-"`
}

func (c *Challenge) SetURL(url *url.URL) {
	c.AuthorizationURL = url
}

func (c *Challenge) GetURL() *url.URL {
	return c.AuthorizationURL
}

// ChallengeType is the type of ACME challenge we can satisfy
type ChallengeType string

// Types of ACME challenges
const (
	ChallengeHTTP = "http-01"
	ChallengeDNS  = "dns-01"
)

// status state machine - RFC 8555 $7.1.6
const (
	PendingStatus      = "pending"
	ProcessingStatus   = "processing"
	ValidStatus        = "valid"
	InvalidStatus      = "invalid"
	ExpiredStatus      = "expired"      //for challenge
	DesactivatedStatus = "desactivated" //for challenge
	RevokedStatus      = "revoked"      //for challenge
	ReadyState         = "ready"        //for order
)

// Problem represents an error returned by the ACME server (see RFC 7807)
type Problem struct {
	Type        string       `json:"type"`
	Detail      string       `json:"detail,omitempty"`
	Status      int          `json:"status,omitempty"`
	Instance    string       `json:"instance,omitempty"`
	SubProblems []SubProblem `json:"subproblems,omitempty"`
}

// SubProblem is an ACME SubProblem
type SubProblem struct {
	Type       string     `json:"type"`
	Detail     string     `json:"detail"`
	Identifier Identifier `json:"identifier"`
}

func (p Problem) Error() string {
	return fmt.Sprintf("acme error : Type : %v, Detail : %v\n", p.Type, p.Detail)
}
