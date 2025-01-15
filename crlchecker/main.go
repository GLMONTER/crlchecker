package crlchecker

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

const DefaultCRLPath = "/pki/crl/crl.pem"

type Config struct {
	CRLFilePath string `json:"crlFilePath"`
}

func CreateConfig() *Config {
	return &Config{
		CRLFilePath: DefaultCRLPath,
	}
}

type CRLData struct {
	revokedSerials []string
	modTime        time.Time
}

type TLSCRLChecker struct {
	next    http.Handler
	name    string
	config  *Config
	crlData atomic.Value
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.CRLFilePath == "" {
		config.CRLFilePath = DefaultCRLPath
	}
	log.Printf("Starting TLS CRL Checker plugin %q with config: %+v\n", name, config)

	tc := &TLSCRLChecker{
		next:   next,
		name:   name,
		config: config,
	}

	tc.loadCRL()

	go tc.watchCRLFile()

	return tc, nil
}

func (tc *TLSCRLChecker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "TLS client certificate is required for authentication.", http.StatusUnauthorized)
		return
	}

	clientCert := r.TLS.PeerCertificates[0]

	crlDataInterface := tc.crlData.Load()
	if crlDataInterface == nil {
		log.Println("CRL data is not available. Proceeding without CRL checks.")
		tc.next.ServeHTTP(w, r)
		return
	}
	crlData := crlDataInterface.(*CRLData)

	serialStr := clientCert.SerialNumber.String()
	if slices.Contains(crlData.revokedSerials, serialStr) {
		serialHex := fmt.Sprintf("%X", clientCert.SerialNumber)
		var serialParts []string
		for i := 0; i < len(serialHex); i += 2 {
			end := i + 2
			if end > len(serialHex) {
				end = len(serialHex)
			}
			serialParts = append(serialParts, serialHex[i:end])
		}
		serialFormatted := strings.Join(serialParts, ":")

		commonName := clientCert.Subject.CommonName

		sans := getCertificateSANs(clientCert)

		log.Printf("Revoked certificate detected: CN=%s, SANs=%s, Serial Number: %s\n", commonName, sans, serialFormatted)

		http.Error(w, "Certificate is revoked.", http.StatusUnauthorized)
		return
	}

	tc.next.ServeHTTP(w, r)
}

func getCertificateSANs(cert *x509.Certificate) string {
	var sans []string

	for _, email := range cert.EmailAddresses {
		sans = append(sans, fmt.Sprintf("Email:%s", email))
	}

	return strings.Join(sans, ", ")
}

func (tc *TLSCRLChecker) loadCRL() {
	crlBytes, err := os.ReadFile(tc.config.CRLFilePath)
	if err != nil {
		log.Printf("Failed to read CRL file at %s: %v", tc.config.CRLFilePath, err)
		return
	}

	var revokedSerials []string

	//iterate through all CRLs in concatenated CRL file and get the revoked serials
	for {
		block, rest := pem.Decode(crlBytes)
		if block == nil {
			break
		}
		parsedCRL, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			log.Printf("Failed to parse CRL file at %s: %v", tc.config.CRLFilePath, err)
			return
		}
		crlBytes = rest
		for _, rc := range parsedCRL.RevokedCertificateEntries {
			revokedSerials = append(revokedSerials, rc.SerialNumber.String())
		}
	}

	info, err := os.Stat(tc.config.CRLFilePath)
	if err != nil {
		log.Printf("Failed to stat CRL file at %s: %v", tc.config.CRLFilePath, err)
		return
	}

	newCRLData := &CRLData{
		revokedSerials: revokedSerials,
		modTime:        info.ModTime(),
	}

	tc.crlData.Store(newCRLData)
	log.Println("CRL file loaded successfully.")
}

func (tc *TLSCRLChecker) watchCRLFile() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		info, err := os.Stat(tc.config.CRLFilePath)
		if err != nil {
			log.Printf("Error accessing CRL file: %v\n", err)
			continue
		}

		crlDataInterface := tc.crlData.Load()
		var lastModTime time.Time
		if crlDataInterface != nil {
			lastModTime = crlDataInterface.(*CRLData).modTime
		}

		if info.ModTime().After(lastModTime) {
			tc.loadCRL()
		}
	}
}
