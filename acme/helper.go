package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

//inspired from https://go.googlesource.com/crypto/+/master/acme/jws.go

// keyID is the account identity provided by a CA during registration.
type keyID string

// noKeyID indicates that jwsEncodeJSON should compute and use JWK instead of a KID.
// See jwsEncodeJSON for details.
const noKeyID = keyID("")

// JwsEncodeJSON signs claimset using provided EC256 key and a nonce.
// The result is serialized in JSON format containing either kid or jwk
// fields based on the provided keyID value.
//
// If kid is non-empty, its quoted value is inserted in the protected head
// as "kid" field value. Otherwise, JWK is computed using jwkEncode and inserted
// as "jwk" field value. The "jwk" and "kid" fields are mutually exclusive.
//
// See https://tools.ietf.org/html/rfc7515#section-7.
func JwsEncodeJSON(claimset interface{}, key *ecdsa.PrivateKey, kid keyID, nonce, url string) ([]byte, error) {
	var phead string
	switch kid {
	case noKeyID:
		jwk, err := jwkEncode(&key.PublicKey)
		if err != nil {
			return nil, err
		}
		phead = fmt.Sprintf(`{"alg":%q,"jwk":%s,"nonce":%q,"url":%q}`, "ES256", jwk, nonce, url)
	default:
		phead = fmt.Sprintf(`{"alg":%q,"kid":%q,"nonce":%q,"url":%q}`, "ES256", kid, nonce, url)
	}
	phead = base64.RawURLEncoding.EncodeToString([]byte(phead))
	var payload string
	if claimset != nil {
		cs, err := json.Marshal(claimset)
		if err != nil {
			return nil, err
		}
		payload = base64.RawURLEncoding.EncodeToString(cs)
	}
	hash := sha256.New()
	hash.Write([]byte(phead + "." + payload))
	sig, err := jwsSign(key, hash.Sum(nil))
	if err != nil {
		return nil, err
	}
	enc := struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Sig       string `json:"signature"`
	}{
		Protected: phead,
		Payload:   payload,
		Sig:       base64.RawURLEncoding.EncodeToString(sig),
	}
	return json.Marshal(&enc)
}

// jwkEncode encodes public part of an RSA or ECDSA key into a JWK.
// The result is also suitable for creating a JWK thumbprint.
// https://tools.ietf.org/html/rfc7517
func jwkEncode(key *ecdsa.PublicKey) (string, error) {
	// https://tools.ietf.org/html/rfc7518#section-6.2.1
	p := key.Curve.Params()
	n := p.BitSize / 8
	if p.BitSize%8 != 0 {
		n++
	}
	x := key.X.Bytes()
	if n > len(x) {
		x = append(make([]byte, n-len(x)), x...)
	}
	y := key.Y.Bytes()
	if n > len(y) {
		y = append(make([]byte, n-len(y)), y...)
	}
	// Field order is important.
	// See https://tools.ietf.org/html/rfc7638#section-3.3 for details.
	return fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`,
		p.Name,
		base64.RawURLEncoding.EncodeToString(x),
		base64.RawURLEncoding.EncodeToString(y),
	), nil
}

// jwsSign signs the digest using the given key.
//RFC 7518  $3.4
func jwsSign(key *ecdsa.PrivateKey, digest []byte) ([]byte, error) {

	// The key.Sign method of ecdsa returns ASN1-encoded signature.
	// So, we use the package Sign function instead
	// to get R and S values directly and format the result accordingly.
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, err
	}
	rb, sb := r.Bytes(), s.Bytes()
	size := key.Params().BitSize / 8
	if size%8 > 0 {
		size++
	}
	sig := make([]byte, size*2)
	copy(sig[size-len(rb):], rb)
	copy(sig[size*2-len(sb):], sb)
	return sig, nil

}

// JWKThumbprint creates a JWK thumbprint out of public key
func JWKThumbprint(pub *ecdsa.PublicKey) (string, error) {
	jwk, err := jwkEncode(pub)
	if err != nil {
		return "", err
	}
	b := sha256.Sum256([]byte(jwk))
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// ParseJSON unmarshalls the JSON body from the http response to the provided output object
func ParseJSON(res *http.Response, out JSONObject) error {
	if out != nil {
		defer res.Body.Close()
		err := json.NewDecoder(res.Body).Decode(out)
		if err != nil {
			return fmt.Errorf("error parsing json. error : %v", err)
		}
		loc, err := res.Location()
		if loc != nil {
			out.SetURL(loc)
		}
	}
	return nil
}

// CheckError displays an ACME error
func CheckError(resp *http.Response) error {

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading error body: %v", err)
	}

	acmeError := Problem{}
	if err := json.Unmarshal(body, &acmeError); err != nil {
		return fmt.Errorf("parsing error body: %v - %v", err, string(body))
	}

	return acmeError
}

func decodePEMCert(bundle []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	var certBlocks *pem.Block

	for {
		certBlocks, bundle = pem.Decode(bundle)
		if certBlocks == nil {
			break
		}

		cert, err := x509.ParseCertificate(certBlocks.Bytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, cert)

	}

	if len(certificates) == 0 {
		return nil, errors.New("no certificates were found while parsing the bundle")
	}

	return certificates, nil
}
