package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const (
	tenantHeader    = "X-Tenant-ID"
	defaultBaseURL  = "http://localhost:8082"
	defaultTenantID = "demo-tenant"
)

type oauthClient struct {
	ClientID      string   `json:"client_id"`
	TenantID      string   `json:"tenant_id"`
	ClientType    string   `json:"client_type"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	RedirectURIs  []string `json:"redirect_uris"`
	AllowedScopes []string `json:"allowed_scopes"`
}

type listClientsResponse struct {
	Clients []oauthClient `json:"clients"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "list":
		err = runList(os.Args[2:])
	case "get":
		err = runGet(os.Args[2:])
	case "create":
		err = runCreate(os.Args[2:])
	case "delete":
		err = runDelete(os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return
	default:
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	baseURL, tenant := addCommonFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	body, _, err := doRequest(http.MethodGet, *baseURL, "/api/v1/oauth/clients", *tenant, nil)
	if err != nil {
		return err
	}
	var resp listClientsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if len(resp.Clients) == 0 {
		fmt.Println("No OAuth clients found for tenant", *tenant)
		return nil
	}

	for _, c := range resp.Clients {
		fmt.Printf("- %s (%s) [%s]\n", c.ClientID, c.Name, c.ClientType)
		fmt.Printf("  Redirect URIs: %s\n", strings.Join(c.RedirectURIs, ", "))
		fmt.Printf("  Allowed scopes: %s\n", strings.Join(c.AllowedScopes, ", "))
		if c.Description != "" {
			fmt.Printf("  Description: %s\n", c.Description)
		}
	}
	return nil
}

func runGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	baseURL, tenant := addCommonFlags(fs)
	clientID := fs.String("client-id", "", "Client identifier")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *clientID == "" {
		return fmt.Errorf("client-id is required")
	}

	path := fmt.Sprintf("/api/v1/oauth/clients/%s", *clientID)
	body, _, err := doRequest(http.MethodGet, *baseURL, path, *tenant, nil)
	if err != nil {
		return err
	}
	var client oauthClient
	if err := json.Unmarshal(body, &client); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	prettyPrint(client)
	return nil
}

func runCreate(args []string) error {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	baseURL, tenant := addCommonFlags(fs)
	clientID := fs.String("client-id", "", "Client identifier")
	name := fs.String("name", "", "Display name")
	clientType := fs.String("type", "public", "Client type: public or confidential")
	description := fs.String("description", "", "Optional description")
	redirectURIs := fs.String("redirects", "", "Comma-separated redirect URIs")
	scopes := fs.String("scopes", "", "Comma-separated scopes")
	secret := fs.String("secret", "", "Client secret (required for confidential clients)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *clientID == "" || *name == "" {
		return fmt.Errorf("client-id and name are required")
	}
	redirects := splitAndClean(*redirectURIs)
	if len(redirects) == 0 {
		return fmt.Errorf("at least one redirect URI is required")
	}
	allowedScopes := splitAndClean(*scopes)
	if len(allowedScopes) == 0 {
		return fmt.Errorf("at least one scope is required")
	}
	if strings.EqualFold(*clientType, "confidential") && strings.TrimSpace(*secret) == "" {
		return fmt.Errorf("secret is required for confidential clients")
	}

	payload := map[string]interface{}{
		"client_id":      *clientID,
		"name":           *name,
		"client_type":    strings.ToLower(*clientType),
		"redirect_uris":  redirects,
		"allowed_scopes": allowedScopes,
	}
	if strings.TrimSpace(*description) != "" {
		payload["description"] = *description
	}
	if strings.TrimSpace(*secret) != "" {
		payload["client_secret"] = *secret
	}

	body, _, err := doRequest(http.MethodPost, *baseURL, "/api/v1/oauth/clients", *tenant, payload)
	if err != nil {
		return err
	}
	var client oauthClient
	if err := json.Unmarshal(body, &client); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	fmt.Println("Client created:")
	prettyPrint(client)
	return nil
}

func runDelete(args []string) error {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	baseURL, tenant := addCommonFlags(fs)
	clientID := fs.String("client-id", "", "Client identifier")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *clientID == "" {
		return fmt.Errorf("client-id is required")
	}

	path := fmt.Sprintf("/api/v1/oauth/clients/%s", *clientID)
	_, _, err := doRequest(http.MethodDelete, *baseURL, path, *tenant, nil)
	if err != nil {
		return err
	}
	fmt.Println("Client deleted")
	return nil
}

func addCommonFlags(fs *flag.FlagSet) (*string, *string) {
	baseURL := fs.String("base-url", defaultBaseURL, "Governance service base URL")
	tenant := fs.String("tenant", defaultTenantID, "Tenant identifier")
	return baseURL, tenant
}

func doRequest(method, baseURL, path, tenantID string, payload interface{}) ([]byte, int, error) {
	endpoint := strings.TrimRight(baseURL, "/") + path
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to marshal payload: %w", err)
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to build request: %w", err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(tenantHeader, tenantID)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return respBody, resp.StatusCode, fmt.Errorf("request failed: %s - %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	return respBody, resp.StatusCode, nil
}

func splitAndClean(values string) []string {
	if strings.TrimSpace(values) == "" {
		return nil
	}
	parts := strings.Split(values, ",")
	var cleaned []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}
	return cleaned
}

func prettyPrint(v interface{}) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Println(v)
		return
	}
	fmt.Println(string(data))
}

func usage() {
	fmt.Println(`Usage: admincli <command> [options]

Commands:
  list        List OAuth clients for a tenant
  get         Fetch a single OAuth client
  create      Register a new OAuth client
  delete      Remove an OAuth client

Global options:
  -base-url   Governance service base URL (default http://localhost:8082)
  -tenant     Tenant identifier header (default demo-tenant)
`)
}
