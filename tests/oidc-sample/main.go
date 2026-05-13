package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

var (
	clientID     = os.Getenv("OIDC_CLIENT_ID")
	clientSecret = os.Getenv("OIDC_CLIENT_SECRET")
	issuer       = os.Getenv("OIDC_ISSUER")
	redirectURL  = os.Getenv("OIDC_REDIRECT_URL")
)

func main() {
	if clientID == "" || clientSecret == "" || issuer == "" || redirectURL == "" {
		log.Println("OIDC_CLIENT_ID:", clientID)
		log.Println("OIDC_CLIENT_SECRET:", "[SET]")
		log.Println("OIDC_ISSUER:", issuer)
		log.Println("OIDC_REDIRECT_URL:", redirectURL)
		log.Fatal("Missing required environment variables")
	}

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Fatalf("Failed to query provider %q: %v", issuer, err)
	}

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	// For simplicity in this sample, we use a static state.
	// In production, this should be unique per request and stored in a session.
	state := "wardseal-oidc-test-state"

	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, `
			<html>
			<head><title>WardSeal OIDC Sample</title></head>
			<body style="font-family: sans-serif; max-width: 800px; margin: 40px auto; line-height: 1.6;">
				<h1>WardSeal OIDC Sample (with PKCE)</h1>
				<p>This application demonstrates how to integrate with WardSeal using OpenID Connect and PKCE.</p>
				<div style="background: #f4f4f4; padding: 20px; border-radius: 8px;">
					<a href="/login" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; font-weight: bold;">Login with WardSeal</a>
				</div>
			</body>
			</html>
		`)
	})

	r.GET("/login", func(c *gin.Context) {
		// PKCE: Generate verifier and challenge
		verifier := randString(32)
		sha := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(sha[:])

		// Store verifier in a cookie (use session in production)
		c.SetCookie("oidc_verifier", verifier, 300, "/", "", false, true)

		// Redirect with PKCE params
		url := config.AuthCodeURL(state,
			oauth2.SetAuthURLParam("code_challenge", challenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
		c.Redirect(http.StatusFound, url)
	})

	r.GET("/callback", func(c *gin.Context) {
		if c.Query("state") != state {
			c.String(http.StatusBadRequest, "Invalid state")
			return
		}

		// PKCE: Retrieve verifier from cookie
		verifier, err := c.Cookie("oidc_verifier")
		if err != nil {
			c.String(http.StatusBadRequest, "Missing code verifier cookie")
			return
		}

		// Exchange code with PKCE verifier
		token, err := config.Exchange(ctx, c.Query("code"), oauth2.SetAuthURLParam("code_verifier", verifier))
		if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to exchange token: %v", err))
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			c.String(http.StatusInternalServerError, "No id_token found in token response")
			return
		}

		verifierObj := provider.Verifier(&oidc.Config{ClientID: clientID})
		idToken, err := verifierObj.Verify(ctx, rawIDToken)
		if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to verify ID token: %v", err))
			return
		}

		var claims struct {
			Subject       string `json:"sub"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Name          string `json:"name"`
		}
		if err := idToken.Claims(&claims); err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to parse claims: %v", err))
			return
		}

		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, fmt.Sprintf(`
			<html>
			<head><title>Login Successful</title></head>
			<body style="font-family: sans-serif; max-width: 800px; margin: 40px auto; line-height: 1.6;">
				<h1 style="color: #28a745;">Login Successful!</h1>
				<p>Verified with PKCE.</p>
				<div style="background: #e9ecef; padding: 20px; border-radius: 8px;">
					<p><strong>Subject (User ID):</strong> %s</p>
					<p><strong>Name:</strong> %s</p>
					<p><strong>Email:</strong> %s</p>
				</div>
				<h3>Raw ID Token (JWT)</h3>
				<pre style="background: #f8f9fa; padding: 15px; border: 1px solid #dee2e6; overflow-x: auto; white-space: pre-wrap; word-break: break-all;">%s</pre>
				<hr>
				<a href="/">Back to Home</a>
			</body>
			</html>
		`, claims.Subject, claims.Name, claims.Email, rawIDToken))
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting OIDC sample app (PKCE enabled) on :%s", port)
	r.Run(":" + port)
}

func randString(n int) string {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
