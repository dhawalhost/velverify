package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dhawalhost/wardseal/internal/license"
)

func main() {
	var (
		customer = flag.String("customer", "", "Customer name")
		days     = flag.Int("days", 365, "Validity in days")
		plan     = flag.String("plan", "enterprise", "Plan name")
		features = flag.String("features", "sso,mfa,audit", "Comma-separated features")
		keyPath  = flag.String("key", "private.pem", "Path to RSA private key")
		genKey   = flag.Bool("gen-key", false, "Generate new key pair")
	)
	flag.Parse()

	if *genKey {
		generateKeys()
		return
	}

	if *customer == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Load private key
	keyBytes, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatalf("Failed to read private key: %v", err)
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		log.Fatal("Failed to decode private key PEM")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try parsing as PKCS8
		k, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			log.Fatalf("Failed to parse private key: %v (PKCS1) / %v (PKCS8)", err, err2)
		}
		privKey = k.(*rsa.PrivateKey)
	}

	// Create claims
	claims := license.LicenseClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   *customer,
			Issuer:    "WardSeal",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(*days) * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Plan:     *plan,
		Features: strings.Split(*features, ","),
	}

	// Sign token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		log.Fatalf("Failed to sign token: %v", err)
	}

	fmt.Printf("\nLicense Key for %s:\n\n%s\n\n", *customer, tokenString)
	fmt.Printf("Expires: %s\n", claims.ExpiresAt.Format(time.RFC822))
}

func generateKeys() {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	// Save private key
	privBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})
	if err := os.WriteFile("private.pem", privPEM, 0600); err != nil {
		log.Fatalf("Failed to write private.pem: %v", err)
	}

	// Save public key
	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	if err := os.WriteFile("public.pem", pubPEM, 0600); err != nil {
		log.Fatalf("Failed to write public.pem: %v", err)
	}

	fmt.Println("Keys generated: private.pem, public.pem")
}
