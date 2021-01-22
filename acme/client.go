package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"
)

// ACMEClient is the main structure for storing all the fields related to the ACME Client
type ACMEClient struct {
	httpClient     *http.Client
	dir            *Directory
	account        *Account
	dnsRecord      string //ip address to answer for all dns requests
	certPrivateKey *ecdsa.PrivateKey
	nonce          string
}

// MAX_RETRY defines the number of time we retry to fullfill a challenge in case of failure
const MAX_RETRY = 5

// RETRY_TIME defines the time in seconds before retrying a request to the ACME server
const RETRY_TIME = 2 //in seconds

// NewACMEClient creates a new ACMEv2 client from directory url
func NewACMEClient(dirURL string, RootCertificatePath string, DNSrecord string) *ACMEClient {
	// create a Certificate pool to hold one or more CA certificates
	rootCAPool := x509.NewCertPool()

	// read minica certificate (which is CA in our case) and add to the Certificate Pool
	rootCA, err := ioutil.ReadFile(RootCertificatePath)
	if err != nil {
		log.Fatalf("reading cert failed : %v", err)
	}
	rootCAPool.AppendCertsFromPEM(rootCA)
	log.Println("RootCA loaded")

	c := ACMEClient{
		httpClient: &http.Client{Timeout: 5 * time.Second,
			Transport: &http.Transport{
				IdleConnTimeout: 10 * time.Second,
				TLSClientConfig: &tls.Config{RootCAs: rootCAPool},
			}},
		dir:       &Directory{},
		dnsRecord: DNSrecord,
	}
	if _, err := c.get(dirURL, c.dir, http.StatusOK); err != nil {
		log.Fatal("acme : error getting directory")
	}

	return &c
}

func (c *ACMEClient) get(url string, out interface{}, expectedStatus int) (*http.Response, error) {
	res, err := c.httpClient.Get(url)
	if err != nil || res.StatusCode != expectedStatus {
		return res, err
	}

	body, err := ioutil.ReadAll(res.Body)

	if err != nil {
		panic(err.Error())
	}

	if err = json.Unmarshal(body, out); err != nil {
		return res, fmt.Errorf("error while parsing json body %v", err)
	}

	return res, nil
}

func (c *ACMEClient) post(url string, key *ecdsa.PrivateKey, kid string, payload interface{}) (*http.Response, error) {
	retry := 0
	var err error
	var resp *http.Response
	var nonce string
	//retry if bad nonce
	for retry < 1 {
		retry++
		nonce, err = c.fetchNonce()
		if err != nil {
			return nil, err
		}
		data, err := JwsEncodeJSON(payload, key, keyID(kid), nonce, url)
		if err != nil {
			return nil, fmt.Errorf("post : jws encoding error : %v", err)
		}
		resp, err = c.httpClient.Post(url, "application/jose+json", bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("post : error doing http request : %v", err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			break
			//do not retry
		}
		//bad nonce error => retry
	}
	nonce = resp.Header.Get("Replay-Nonce")
	if nonce != "" {
		c.nonce = nonce
	}
	return resp, err
}

// fetchNonce fetches a fresh nonce from the ACME server
func (c *ACMEClient) fetchNonce() (string, error) {
	if c.dir.NewNonce == "" {
		return "", fmt.Errorf("new nonce url not set")
	}
	if c.nonce != "" {
		nonce := c.nonce
		c.nonce = ""
		return nonce, nil
	}
	res, err := c.httpClient.Head(c.dir.NewNonce)
	if err != nil {
		return "", fmt.Errorf("error getting a new nonce from server %v", err)
	}
	return res.Header.Get("Replay-Nonce"), nil
}

// NewAccount registers a new account on the ACME server
func (c *ACMEClient) NewAccount() (*Account, error) {
	req := map[string]interface{}{"termsOfServiceAgreed": true}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	acc := &Account{privKey: key}
	res, err := c.post(c.dir.NewAccount, key, "", req)
	if err != nil {
		return nil, fmt.Errorf("error posting new account request")
	}
	if res.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("received wrong http status code when creating acme account. code : %v", CheckError(res))
	}
	err = ParseJSON(res, acc)
	if err != nil {
		return nil, fmt.Errorf("error while pasing json response when creating account. error : %v", err)
	}
	// compute thumbprint for answering challenges later
	thb, err := JWKThumbprint(&acc.privKey.PublicKey)
	acc.Thumbprint = thb
	if err != nil {
		return nil, fmt.Errorf("error computing account JWK thumbprint : %v", err)
	}
	return acc, nil
}

// RequestCertificateForDomains requets the x509 certificates for the domains using the required challenge
func (c *ACMEClient) RequestCertificateForDomains(domains []string, challenge string, dnsHandler chan []string) ([]*x509.Certificate, error) {
	ord, err := c.createOrderRequest(domains)
	if err != nil {
		return nil, err
	}
	err = c.getAuthorizations(ord)
	if err != nil {
		return nil, err
	}
	log.Print("got authorization. Starting answering challenges")
	for k, auth := range ord.AuthorizationsByID {
		//check if we need to satisfy dns or http challenge if http -> http challenge else -> dns challenge
		switch challenge {
		case "http01":
			cha, ok := auth.ChallengeByType[ChallengeHTTP]
			if !ok {
				return nil, fmt.Errorf("no HTTP challenge found")
			}
			err = c.AnswerHTTPChallenge(&cha, k, auth)
			if err != nil {
				return nil, err
			}
			break
		case "dns01":
			cha, ok := auth.ChallengeByType[ChallengeDNS]
			if !ok {
				return nil, fmt.Errorf("no DNS challenge found")
			}
			err = c.AnswerDNSChallenge(&cha, k, auth, dnsHandler)
			if err != nil {
				return nil, err
			}
			break
		}

	}
	certs, err := c.finalizeAndDownloadCertificate(ord, domains)
	if err != nil {
		return nil, err
	}
	return certs, nil
}

func (c *ACMEClient) createOrderRequest(domains []string) (*Order, error) {
	identifiers := []*Identifier{}
	for _, d := range domains {
		id := IdentifierFromString(d)
		identifiers = append(identifiers, id)
	}
	newOrderReq := map[string]interface{}{
		"identifiers": identifiers,
	}
	// post order request
	res, err := c.post(c.dir.NewOrder, c.account.privKey, c.account.URL.String(), newOrderReq)
	if err != nil {
		return nil, fmt.Errorf("error posting new account request. error : err")
	}
	if res.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("received wrong http status code when posting acme order. code : %v", CheckError(res))
	}
	order := &Order{}
	err = ParseJSON(res, order)
	if err != nil {
		log.Printf("error parsing order reply from server \n")
	}
	log.Printf("order url: %s \n", order.URL)
	return order, nil
}

func (c *ACMEClient) getAuthorizations(order *Order) error {
	order.AuthorizationsByID = make(map[string]*Authorization)
	for _, authURL := range order.Authorizations {
		challengeByType := make(map[ChallengeType]Challenge)
		challengeByURL := make(map[string]Challenge)
		u, err := url.Parse(authURL)
		a := &Authorization{ChallengeByType: challengeByType, ChallengeByURL: challengeByURL, URL: u}
		res, err := c.post(a.URL.String(), c.account.privKey, c.account.URL.String(), nil)
		if err != nil || res.StatusCode != http.StatusOK {
			return fmt.Errorf("error getting challenge from server : %v", CheckError(res))
		}
		err = ParseJSON(res, a)
		if err != nil {
			log.Printf("error parsing auth reply from server \n")
		}
		if a.Wildcard {
			order.AuthorizationsByID["*"+a.Identifier.Value] = a
		} else {
			order.AuthorizationsByID[a.Identifier.Value] = a
		}
		for _, cha := range a.Challenges {
			cha.KeyAuthorization = fmt.Sprintf("%v.%v", cha.Token, c.account.Thumbprint)
			a.ChallengeByType[ChallengeType(cha.Type)] = cha
			a.ChallengeByURL[cha.URL] = cha
		}
	}
	return nil
}

// AnswerHTTPChallenge answers the provided HTTP challenge for the authorization
func (c *ACMEClient) AnswerHTTPChallenge(cha *Challenge, domain string, auth *Authorization) error {
	if cha.Type != ChallengeHTTP {
		log.Print("not an http challenge")
		return fmt.Errorf("not HTTP Challenge")
	}
	log.Printf("completing http challenge %v", cha)
	srv := newChallengeHTTPServer(cha.Token, cha.KeyAuthorization, c.dnsRecord)
	StartHTTPChallengeServer(srv)
	time.Sleep(2 * time.Second)
	//send empty json object to server to inform challenge is provisioned
	_, err := c.post(cha.URL, c.account.privKey, c.account.URL.String(), struct{}{})
	if err != nil {
		return fmt.Errorf("error posting new challenge answer request. error : err")
	}
	//check authorization status
	err = c.checkAuthStatus(auth)
	if err != nil {
		return fmt.Errorf("failed to complete authorization. error : %s", err)
	}
	log.Printf("authorization with URL %s completed. Status %s", auth.URL, auth.Status)
	StopHTTPChallengeServer(srv)
	return nil
}

func (c *ACMEClient) checkAuthStatus(auth *Authorization) error {

	count := 0
	for auth.Status != "valid" && count < MAX_RETRY {
		count++
		time.Sleep(RETRY_TIME * time.Second)

		//post as get request to get challenge status
		res, err := c.post(auth.URL.String(), c.account.privKey, c.account.URL.String(), nil)
		if err != nil {
			return fmt.Errorf("error requesting challenge status update. error : err")
		}
		err = ParseJSON(res, auth)
		if err != nil {
			return fmt.Errorf("error parsing challenge update. error : %v", err)
		}
	}
	if count >= MAX_RETRY {
		return fmt.Errorf("challenge not valdiated. max retry exceeded")
	}
	return nil
}

func (c *ACMEClient) generateCSR(domains []string) *x509.CertificateRequest {
	log.Printf("generating csr")
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("error generating certificate private key")
	}
	c.certPrivateKey = privKey
	subj := pkix.Name{
		CommonName: domains[0],
	}
	tpl := &x509.CertificateRequest{
		PublicKey:          c.certPrivateKey.Public(),
		Subject:            subj,
		DNSNames:           domains,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, tpl, privKey)
	if err != nil {
		log.Fatalf("Error creating certificate request: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		log.Fatalf("Error parsing certificate request: %v", err)
	}
	return csr
}

func (c *ACMEClient) finalizeAndDownloadCertificate(order *Order, domains []string) ([]*x509.Certificate, error) {
	log.Print("Generating CSR and downloading certificate")
	csr := c.generateCSR(domains)
	csr64 := base64.RawURLEncoding.EncodeToString(csr.Raw)
	req := map[string]interface{}{"csr": csr64}
	res, err := c.post(order.Finalize, c.account.privKey, c.account.URL.String(), req)
	if err != nil {
		return nil, fmt.Errorf("error posting csr request. error : %v", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got wrong status code when finalizing order. error : %v", CheckError(res))
	}
	err = ParseJSON(res, order)
	if err != nil {
		log.Fatal("error parsing csr json order reply ")
	}
	err = c.checkOrderStatus(order)
	if err != nil {
		log.Print("error with order !")
		return nil, err
	}
	log.Printf("order finalized. status : %v", order.Status)
	//download certificate. post as get request to certificate url
	log.Print("downloading certificate")
	res, err = c.post(order.Certificate, c.account.privKey, c.account.URL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("error while fetching certificate from server. error : %v", err)
	}
	resBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading certificate answer from server")
	}
	defer res.Body.Close()
	cert, err := decodePEMCert(resBytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}
	return cert, nil
}

func (c *ACMEClient) checkOrderStatus(order *Order) error {
	count := 0
	for order.Status != "valid" && order.Status != "invalid" && count < MAX_RETRY {
		count++
		time.Sleep(RETRY_TIME * time.Second)

		//post as get request to get challenge status
		res, err := c.post(order.URL.String(), c.account.privKey, c.account.URL.String(), nil)
		if err != nil {
			return fmt.Errorf("error requesting challenge status update. error : err")
		}
		err = ParseJSON(res, order)
		if err != nil {
			log.Fatalf("error parsing csr order update. error : %v", err)
		}
	}
	if count >= MAX_RETRY {
		return fmt.Errorf("couldn't validate order. max retry exceeded")
	}
	if order.Status == "invalid" {
		return fmt.Errorf("order invalid")
	}
	return nil
}

// AnswerDNSChallenge answers the provided DNS challenge
func (c *ACMEClient) AnswerDNSChallenge(cha *Challenge, domain string, auth *Authorization, DNSHandler chan []string) error {
	if cha.Type != ChallengeDNS {
		log.Print("not a dns challenge")
		return fmt.Errorf("not a dns challenge")
	}
	log.Printf("completing dns challenge %v", cha)
	//generate dns token
	host := fmt.Sprintf("_acme-challenge.%s.", auth.Identifier.Value)
	token := GenerateDNSToken(cha.KeyAuthorization)
	//send empty json object to server to inform challenge is provisioned
	_, err := c.post(cha.URL, c.account.privKey, c.account.URL.String(), struct{}{})
	DNSHandler <- []string{host, token}
	if err != nil {
		return fmt.Errorf("error posting new challenge answer request. error : err")
	}
	//check authorization status
	err = c.checkAuthStatus(auth)
	if err != nil {
		return fmt.Errorf("failed to complete authorization. error : %s", err)
	}
	log.Printf("authorization with URL %s completed. Status %s", auth.URL, auth.Status)
	return nil
}

// GenerateDNSToken generates the keyautorization token to be put in the TXT record
func GenerateDNSToken(keyAutorization string) string {
	h := sha256.Sum256([]byte(keyAutorization))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// RevokeCertificate revokes the x509 certificate given as argument to the ACME server
func (c *ACMEClient) RevokeCertificate(cert *x509.Certificate) error {
	req := map[string]interface{}{
		"certificate": base64.RawURLEncoding.EncodeToString(cert.Raw),
	}

	res, err := c.post(c.dir.RevokeCert, c.account.privKey, c.account.URL.String(), req)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		log.Print("wrong status code when revoking certificates")
		log.Printf("%v", CheckError(res))
		return fmt.Errorf("failed to revoke certificate")
	}
	return nil
}
