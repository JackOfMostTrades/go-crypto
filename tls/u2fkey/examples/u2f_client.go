package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/tls/u2fkey"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"
)

func generateCert(commonName string, isCA bool, parent *x509.Certificate, parentKey crypto.PrivateKey) (*x509.Certificate, crypto.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if parentKey == nil {
		parentKey = key
	}
	cert, err := generateCertWithKey(commonName, isCA, key.Public(), parent, parentKey)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func generateCertWithKey(commonName string, isCA bool, key crypto.PublicKey, parent *x509.Certificate, parentKey crypto.PrivateKey) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	if parent == nil {
		parent = template
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, key, parentKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func main() {
	serverCa, serverCaKey, err := generateCert("Server CA", true, nil, nil)
	if err != nil {
		panic(err)
	}
	serverCert, serverKey, err := generateCert("localhost", false, serverCa, serverCaKey)
	if err != nil {
		panic(err)
	}
	clientCa, clientCaKey, err := generateCert("Client CA", true, nil, nil)
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
	})
	pool := x509.NewCertPool()
	pool.AddCert(clientCa)
	server := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{serverCert.Raw},
					PrivateKey:  serverKey,
				},
			},
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  pool,
		},
	}
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go server.ServeTLS(ln, "", "")

	log.Println("Generating U2F key. Touch token to generate...")
	k, err := u2fkey.GenerateKey("example.com")
	if err != nil {
		panic(err)
	}
	clientU2fCert, err := generateCertWithKey("u2f-client", false, k.Public(), clientCa, clientCaKey)
	if err != nil {
		panic(err)
	}

	pool = x509.NewCertPool()
	pool.AddCert(serverCa)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{
					{
						Certificate: [][]byte{clientU2fCert.Raw},
						PrivateKey:  k,
					},
				},
				RootCAs: pool,
			},
		},
	}
	log.Println("Performing GET request with U2F token. Touch token to complete TLS handshake.")
	res, err := client.Get(fmt.Sprintf("https://localhost:%d", port))
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}
	if string(body) != "Hello, \"/\"" {
		panic("Bad body: " + string(body))
	}
}
