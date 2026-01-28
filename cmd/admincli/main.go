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
	"time"
)

const (
	tenantHeader         = "X-Tenant-ID"
	defaultBaseURL       = "http://localhost:8082" // Governance Service
	defaultDirServiceURL = "http://localhost:8081" // Directory Service
	defaultTenantID      = "11111111-1111-1111-1111-111111111111"
)

// OAuth Client structs
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

// User structs (mirroring internal/directory/endpoint.go)
type User struct {
	ID        string    `json:"id,omitempty"`
	TenantID  string    `json:"tenant_id,omitempty"`
	Email     string    `json:"email"`
	Password  string    `json:"password,omitempty"`
	Status    string    `json:"status,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

type CreateUserRequest struct {
	User User `json:"user"`
}

type CreateUserResponse struct {
	UserID string `json:"user_id"`
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
	case "user":
		err = runUser(os.Args[2:])
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

func runUser(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("user subcommand required: list, create, delete")
	}
	switch args[0] {
	case "list":
		return runUserList(args[1:])
	case "create":
		return runUserCreate(args[1:])
	case "delete":
		return runUserDelete(args[1:])
	default:
		return fmt.Errorf("unknown user subcommand: %s", args[0])
	}
}

func runUserList(args []string) error {
	fs := flag.NewFlagSet("user list", flag.ExitOnError)
	baseURL, tenant := addCommonFlags(fs, defaultDirServiceURL)
	email := fs.String("email", "", "Email to search for")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *email != "" {
		path := fmt.Sprintf("/users?email=%s", *email)
		body, _, err := doRequest(http.MethodGet, *baseURL, path, *tenant, nil)
		if err != nil {
			return err
		}
		var resp struct {
			User User `json:"user"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
		if resp.User.Email == "" {
			fmt.Println("User not found")
			return nil
		}
		prettyPrint(resp.User)
		return nil
	}

	return fmt.Errorf("list all users not supported by API yet; use -email to find specific user")
}

func runUserCreate(args []string) error {
	fs := flag.NewFlagSet("user create", flag.ExitOnError)
	baseURL, tenant := addCommonFlags(fs, defaultDirServiceURL)
	email := fs.String("email", "", "User email")
	password := fs.String("password", "", "User password")
	status := fs.String("status", "active", "User status (active, inactive)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" || *password == "" {
		return fmt.Errorf("email and password are required")
	}

	req := CreateUserRequest{
		User: User{
			Email:    *email,
			Password: *password,
			Status:   *status,
		},
	}

	body, _, err := doRequest(http.MethodPost, *baseURL, "/users", *tenant, req)
	if err != nil {
		return err
	}

	var resp CreateUserResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	fmt.Printf("User created with ID: %s\n", resp.UserID)
	return nil
}

func runUserDelete(args []string) error {
	fs := flag.NewFlagSet("user delete", flag.ExitOnError)
	baseURL, tenant := addCommonFlags(fs, defaultDirServiceURL)
	userID := fs.String("id", "", "User ID")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *userID == "" {
		return fmt.Errorf("user id is required")
	}

	path := fmt.Sprintf("/users/%s", *userID)
	_, _, err := doRequest(http.MethodDelete, *baseURL, path, *tenant, nil)
	if err != nil {
		return err
	}
	fmt.Println("User deleted")
	return nil
}

// Existing client functions
func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	baseURL, tenant := addCommonFlags(fs, defaultBaseURL)
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
	baseURL, tenant := addCommonFlags(fs, defaultBaseURL)
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
	baseURL, tenant := addCommonFlags(fs, defaultBaseURL)
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
	baseURL, tenant := addCommonFlags(fs, defaultBaseURL)
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

func addCommonFlags(fs *flag.FlagSet, defaultURL string) (*string, *string) {
	baseURL := fs.String("base-url", defaultURL, "Service base URL")
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
	defer func() { _ = resp.Body.Close() }()

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
	fmt.Print(`Usage: admincli <command> [options]

Commands:
  list        List OAuth clients for a tenant
  get         Fetch a single OAuth client
  create      Register a new OAuth client
  delete      Remove an OAuth client
  user        Manage users (create, list, delete)

User Subcommands:
  user create -email <email> -password <pass>
  user list -email <email>
  user delete -id <id>

Global options:
	-base-url   Service base URL (defaults to :8082 for clients, :8081 for users)
	-tenant     Tenant identifier header (default 11111111-1111-1111-1111-111111111111)
`)
}
