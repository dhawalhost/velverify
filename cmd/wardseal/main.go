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
	tenantHeader          = "X-Tenant-ID"
	userHeader            = "X-User-ID"
	defaultBaseURL        = "http://localhost:8082" // Governance Service
	defaultDirServiceURL  = "http://localhost:8081" // Directory Service
	defaultAuthServiceURL = "http://localhost:8080" // Auth Service
	defaultTenantID       = "11111111-1111-1111-1111-111111111111"
)

// OAuth Client structs
type oauthClient struct {
	ClientID      string   `json:"client_id"`
	TenantID      string   `json:"tenant_id"`
	ClientType    string   `json:"client_type"`
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	RedirectURIs  []string `json:"redirect_uris"`
	AllowedScopes []string `json:"allowed_scopes"`
}

type listClientsResponse struct {
	Clients []oauthClient `json:"clients"`
}

// User structs
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

// Group structs
type Group struct {
	ID        string    `json:"id,omitempty"`
	TenantID  string    `json:"tenant_id,omitempty"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// Access Request structs (Aligned with internal/governance/types.go)
type AccessRequest struct {
	ID           string `json:"id"`
	RequesterID  string `json:"requester_id"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Status       string `json:"status"`
	Reason       string `json:"reason,omitempty"`
	CreatedAt    string `json:"created_at"`
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
	case "update":
		err = runUpdate(os.Args[2:])
	case "delete":
		err = runDelete(os.Args[2:])
	case "user":
		err = runUser(os.Args[2:])
	case "group":
		err = runGroup(os.Args[2:])
	case "request":
		err = runRequest(os.Args[2:])
	case "auth":
		err = runAuth(os.Args[2:])
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

// --- OAuth Client Functions ---

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	baseURL, tenant, _ := addCommonFlags(fs, defaultBaseURL)
	if err := fs.Parse(args); err != nil {
		return err
	}

	body, _, err := doRequest(http.MethodGet, *baseURL, "/api/v1/oauth/clients", *tenant, "", nil)
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
	}
	return nil
}

func runGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	baseURL, tenant, _ := addCommonFlags(fs, defaultBaseURL)
	clientID := fs.String("client-id", "", "Client identifier")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *clientID == "" {
		return fmt.Errorf("client-id is required")
	}

	path := fmt.Sprintf("/api/v1/oauth/clients/%s", *clientID)
	body, _, err := doRequest(http.MethodGet, *baseURL, path, *tenant, "", nil)
	if err != nil {
		return err
	}
	var client oauthClient
	json.Unmarshal(body, &client)
	prettyPrint(client)
	return nil
}

func runCreate(args []string) error {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	baseURL, tenant, _ := addCommonFlags(fs, defaultBaseURL)
	clientID := fs.String("client-id", "", "Client identifier")
	name := fs.String("name", "", "Display name")
	clientType := fs.String("type", "public", "Client type")
	description := fs.String("description", "", "Optional description")
	redirectURIs := fs.String("redirects", "", "Comma-separated redirect URIs")
	scopes := fs.String("scopes", "", "Comma-separated scopes")
	secret := fs.String("secret", "", "Client secret")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *clientID == "" || *name == "" {
		return fmt.Errorf("client-id and name are required")
	}

	payload := map[string]interface{}{
		"client_id":      *clientID,
		"name":           *name,
		"client_type":    strings.ToLower(*clientType),
		"redirect_uris":  splitAndClean(*redirectURIs),
		"allowed_scopes": splitAndClean(*scopes),
		"description":    *description,
		"client_secret":  *secret,
	}
	body, _, err := doRequest(http.MethodPost, *baseURL, "/api/v1/oauth/clients", *tenant, "", payload)
	if err != nil {
		return err
	}
	var client oauthClient
	json.Unmarshal(body, &client)
	fmt.Println("Client created:")
	prettyPrint(client)
	return nil
}

func runUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	baseURL, tenant, _ := addCommonFlags(fs, defaultBaseURL)
	clientID := fs.String("client-id", "", "Client identifier")
	name := fs.String("name", "", "New name")
	description := fs.String("description", "", "New description")
	clientType := fs.String("type", "", "New client type")
	redirectURIs := fs.String("redirects", "", "New redirect URIs")
	scopes := fs.String("scopes", "", "New scopes")
	secret := fs.String("secret", "", "New secret")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *clientID == "" {
		return fmt.Errorf("client-id is required")
	}

	payload := make(map[string]interface{})
	if *name != "" {
		payload["name"] = *name
	}
	if *description != "" {
		payload["description"] = *description
	}
	if *clientType != "" {
		payload["client_type"] = *clientType
	}
	if *secret != "" {
		payload["client_secret"] = *secret
	}
	if *redirectURIs != "" {
		payload["redirect_uris"] = splitAndClean(*redirectURIs)
	}
	if *scopes != "" {
		payload["allowed_scopes"] = splitAndClean(*scopes)
	}

	path := fmt.Sprintf("/api/v1/oauth/clients/%s", *clientID)
	body, _, err := doRequest(http.MethodPut, *baseURL, path, *tenant, "", payload)
	if err != nil {
		return err
	}
	var client oauthClient
	json.Unmarshal(body, &client)
	fmt.Println("Client updated:")
	prettyPrint(client)
	return nil
}

func runDelete(args []string) error {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	baseURL, tenant, _ := addCommonFlags(fs, defaultBaseURL)
	clientID := fs.String("client-id", "", "Client identifier")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *clientID == "" {
		return fmt.Errorf("client-id is required")
	}

	path := fmt.Sprintf("/api/v1/oauth/clients/%s", *clientID)
	_, _, err := doRequest(http.MethodDelete, *baseURL, path, *tenant, "", nil)
	if err != nil {
		return err
	}
	fmt.Println("Client deleted")
	return nil
}

// --- User Functions ---

func runUser(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("user subcommand required")
	}
	switch args[0] {
	case "list":
		return runUserList(args[1:])
	case "get":
		return runUserGet(args[1:])
	case "create":
		return runUserCreate(args[1:])
	case "update":
		return runUserUpdate(args[1:])
	case "delete":
		return runUserDelete(args[1:])
	default:
		return fmt.Errorf("unknown user subcommand: %s", args[0])
	}
}

func runUserList(args []string) error {
	fs := flag.NewFlagSet("user list", flag.ExitOnError)
	baseURL, tenant, _ := addCommonFlags(fs, defaultDirServiceURL)
	email := fs.String("email", "", "Search by email")
	limit := fs.Int("limit", 10, "Limit")
	offset := fs.Int("offset", 0, "Offset")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := "/users"
	if *email != "" {
		path = fmt.Sprintf("/users?email=%s", *email)
	} else {
		path = fmt.Sprintf("/users?limit=%d&offset=%d", *limit, *offset)
	}

	body, _, err := doRequest(http.MethodGet, *baseURL, path, *tenant, "", nil)
	if err != nil {
		return err
	}
	if *email != "" {
		var resp struct {
			User User `json:"user"`
		}
		json.Unmarshal(body, &resp)
		prettyPrint(resp.User)
	} else {
		var resp struct {
			Users []User `json:"users"`
			Total int    `json:"total"`
		}
		json.Unmarshal(body, &resp)
		fmt.Printf("Total: %d\n", resp.Total)
		for _, u := range resp.Users {
			fmt.Printf("- %s (%s)\n", u.ID, u.Email)
		}
	}
	return nil
}

func runUserGet(args []string) error {
	fs := flag.NewFlagSet("user get", flag.ExitOnError)
	baseURL, tenant, _ := addCommonFlags(fs, defaultDirServiceURL)
	id := fs.String("id", "", "User UUID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("id is required")
	}

	path := fmt.Sprintf("/users/%s", *id)
	body, _, err := doRequest(http.MethodGet, *baseURL, path, *tenant, "", nil)
	if err != nil {
		return err
	}
	var resp struct {
		User User `json:"user"`
	}
	json.Unmarshal(body, &resp)
	prettyPrint(resp.User)
	return nil
}

func runUserCreate(args []string) error {
	fs := flag.NewFlagSet("user create", flag.ExitOnError)
	baseURL, tenant, _ := addCommonFlags(fs, defaultDirServiceURL)
	email := fs.String("email", "", "Email")
	password := fs.String("password", "", "Password")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" || *password == "" {
		return fmt.Errorf("email and password required")
	}

	payload := CreateUserRequest{User: User{Email: *email, Password: *password, Status: "active"}}
	body, _, err := doRequest(http.MethodPost, *baseURL, "/users", *tenant, "", payload)
	if err != nil {
		return err
	}
	var resp CreateUserResponse
	json.Unmarshal(body, &resp)
	fmt.Printf("User created: %s\n", resp.UserID)
	return nil
}

func runUserUpdate(args []string) error {
	fs := flag.NewFlagSet("user update", flag.ExitOnError)
	baseURL, tenant, _ := addCommonFlags(fs, defaultDirServiceURL)
	id := fs.String("id", "", "User UUID")
	status := fs.String("status", "", "New status")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("id is required")
	}

	payload := map[string]interface{}{"user": map[string]interface{}{"status": *status}}
	_, _, err := doRequest(http.MethodPut, *baseURL, "/users/"+*id, *tenant, "", payload)
	if err != nil {
		return err
	}
	fmt.Println("User updated")
	return nil
}

func runUserDelete(args []string) error {
	fs := flag.NewFlagSet("user delete", flag.ExitOnError)
	baseURL, tenant, _ := addCommonFlags(fs, defaultDirServiceURL)
	id := fs.String("id", "", "User UUID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("id required")
	}

	_, _, err := doRequest(http.MethodDelete, *baseURL, "/users/"+*id, *tenant, "", nil)
	if err != nil {
		return err
	}
	fmt.Println("User deleted")
	return nil
}

// --- Group Functions ---

func runGroup(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("group subcommand required")
	}
	switch args[0] {
	case "create":
		return runGroupCreate(args[1:])
	case "get":
		return runGroupGet(args[1:])
	case "update":
		return runGroupUpdate(args[1:])
	case "delete":
		return runGroupDelete(args[1:])
	case "add-user":
		return runGroupAddUser(args[1:])
	case "remove-user":
		return runGroupRemoveUser(args[1:])
	default:
		return fmt.Errorf("unknown group subcommand: %s", args[0])
	}
}

func runGroupCreate(args []string) error {
	fs := flag.NewFlagSet("group create", flag.ExitOnError)
	baseURL, tenant, _ := addCommonFlags(fs, defaultDirServiceURL)
	name := fs.String("name", "", "Name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("name required")
	}

	payload := map[string]interface{}{"group": map[string]interface{}{"name": *name}}
	body, _, err := doRequest(http.MethodPost, *baseURL, "/groups", *tenant, "", payload)
	if err != nil {
		return err
	}
	var resp struct {
		GroupID string `json:"group_id"`
	}
	json.Unmarshal(body, &resp)
	fmt.Printf("Group created: %s\n", resp.GroupID)
	return nil
}

func runGroupGet(args []string) error {
	fs := flag.NewFlagSet("group get", flag.ExitOnError)
	baseURL, tenant, _ := addCommonFlags(fs, defaultDirServiceURL)
	id := fs.String("id", "", "Group UUID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("id is required")
	}

	path := fmt.Sprintf("/groups/%s", *id)
	body, _, err := doRequest(http.MethodGet, *baseURL, path, *tenant, "", nil)
	if err != nil {
		return err
	}
	var resp struct {
		Group Group `json:"group"`
	}
	json.Unmarshal(body, &resp)
	prettyPrint(resp.Group)
	return nil
}

func runGroupUpdate(args []string) error {
	fs := flag.NewFlagSet("group update", flag.ExitOnError)
	baseURL, tenant, _ := addCommonFlags(fs, defaultDirServiceURL)
	id := fs.String("id", "", "Group UUID")
	name := fs.String("name", "", "New name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("id is required")
	}

	update := map[string]interface{}{"name": *name}
	path := fmt.Sprintf("/groups/%s", *id)
	_, _, err := doRequest(http.MethodPut, *baseURL, path, *tenant, "", update)
	if err != nil {
		return err
	}
	fmt.Println("Group updated")
	return nil
}

func runGroupDelete(args []string) error {
	fs := flag.NewFlagSet("group delete", flag.ExitOnError)
	baseURL, tenant, _ := addCommonFlags(fs, defaultDirServiceURL)
	id := fs.String("id", "", "Group UUID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("id required")
	}

	_, _, err := doRequest(http.MethodDelete, *baseURL, "/groups/"+*id, *tenant, "", nil)
	if err != nil {
		return err
	}
	fmt.Println("Group deleted")
	return nil
}

func runGroupAddUser(args []string) error {
	fs := flag.NewFlagSet("group add-user", flag.ExitOnError)
	baseURL, tenant, _ := addCommonFlags(fs, defaultDirServiceURL)
	groupID := fs.String("group-id", "", "Group UUID")
	userID := fs.String("user-id", "", "User UUID")
	if err := fs.Parse(args); err != nil {
		return err
	}

	payload := map[string]interface{}{"user_id": *userID}
	_, _, err := doRequest(http.MethodPost, *baseURL, fmt.Sprintf("/groups/%s/users", *groupID), *tenant, "", payload)
	if err != nil {
		return err
	}
	fmt.Println("User added to group")
	return nil
}

func runGroupRemoveUser(args []string) error {
	fs := flag.NewFlagSet("group remove-user", flag.ExitOnError)
	baseURL, tenant, _ := addCommonFlags(fs, defaultDirServiceURL)
	groupID := fs.String("group-id", "", "Group UUID")
	userID := fs.String("user-id", "", "User UUID")
	if err := fs.Parse(args); err != nil {
		return err
	}

	_, _, err := doRequest(http.MethodDelete, *baseURL, fmt.Sprintf("/groups/%s/users/%s", *groupID, *userID), *tenant, "", nil)
	if err != nil {
		return err
	}
	fmt.Println("User removed from group")
	return nil
}

// --- Access Request Functions ---

func runRequest(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("request subcommand required")
	}
	switch args[0] {
	case "list":
		return runRequestList(args[1:])
	case "create":
		return runRequestCreate(args[1:])
	case "approve":
		return runDecision(args[1:], "approve")
	case "reject":
		return runDecision(args[1:], "reject")
	default:
		return fmt.Errorf("unknown request subcommand: %s", args[0])
	}
}

func runRequestList(args []string) error {
	fs := flag.NewFlagSet("request list", flag.ExitOnError)
	baseURL, tenant, _ := addCommonFlags(fs, defaultBaseURL)
	status := fs.String("status", "", "Filter status")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := "/api/v1/governance/requests"
	if *status != "" {
		path += "?status=" + *status
	}
	body, _, err := doRequest(http.MethodGet, *baseURL, path, *tenant, "", nil)
	if err != nil {
		return err
	}
	var resp struct {
		Requests []AccessRequest `json:"requests"`
	}
	json.Unmarshal(body, &resp)
	if len(resp.Requests) == 0 {
		fmt.Println("No requests found")
		return nil
	}
	for _, r := range resp.Requests {
		fmt.Printf("- %s: %s [%s] (%s)\n", r.ID, r.RequesterID, r.Status, r.Reason)
	}
	return nil
}

func runRequestCreate(args []string) error {
	fs := flag.NewFlagSet("request create", flag.ExitOnError)
	baseURL, tenant, user := addCommonFlags(fs, defaultBaseURL)
	resType := fs.String("type", "", "Resource type (e.g., client)")
	resID := fs.String("id", "", "Resource ID")
	reason := fs.String("reason", "", "Reason")
	if err := fs.Parse(args); err != nil {
		return err
	}

	payload := map[string]interface{}{"resource_type": *resType, "resource_id": *resID, "reason": *reason}
	body, _, err := doRequest(http.MethodPost, *baseURL, "/api/v1/governance/requests", *tenant, *user, payload)
	if err != nil {
		return err
	}
	fmt.Println("Request created:")
	fmt.Println(string(body))
	return nil
}

func runDecision(args []string, action string) error {
	fs := flag.NewFlagSet("request "+action, flag.ExitOnError)
	baseURL, tenant, user := addCommonFlags(fs, defaultBaseURL)
	id := fs.String("id", "", "Request UUID")
	comment := fs.String("comment", "", "Comment")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("id required")
	}

	payload := map[string]interface{}{"comment": *comment}
	_, _, err := doRequest(http.MethodPost, *baseURL, fmt.Sprintf("/api/v1/governance/requests/%s/%s", *id, action), *tenant, *user, payload)
	if err != nil {
		return err
	}
	fmt.Printf("Request %s %sed\n", *id, action)
	return nil
}

// --- Auth Functions ---

func runAuth(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("auth subcommand required: login, setup")
	}
	switch args[0] {
	case "login":
		return runAuthLogin(args[1:])
	case "setup":
		return runAuthSetup(args[1:])
	default:
		return fmt.Errorf("unknown auth subcommand: %s", args[0])
	}
}

func runAuthLogin(args []string) error {
	fs := flag.NewFlagSet("auth login", flag.ExitOnError)
	baseURL, _, _ := addCommonFlags(fs, defaultAuthServiceURL)
	user := fs.String("username", "", "Username (email)")
	pass := fs.String("password", "", "Password")
	if err := fs.Parse(args); err != nil {
		return err
	}

	payload := map[string]interface{}{"username": *user, "password": *pass}
	body, _, err := doRequest(http.MethodPost, *baseURL, "/api/v1/login", "", "", payload)
	if err != nil {
		return err
	}
	fmt.Println("Login successful:")
	fmt.Println(string(body))
	return nil
}

func runAuthSetup(args []string) error {
	fs := flag.NewFlagSet("auth setup", flag.ExitOnError)
	baseURL, _, _ := addCommonFlags(fs, defaultAuthServiceURL)
	if err := fs.Parse(args); err != nil {
		return err
	}

	body, _, err := doRequest(http.MethodPost, *baseURL, "/api/v1/setup", "", "", nil)
	if err != nil {
		return err
	}
	fmt.Println("Setup initiated:")
	fmt.Println(string(body))
	return nil
}

// --- Utils ---

func addCommonFlags(fs *flag.FlagSet, defaultURL string) (*string, *string, *string) {
	baseURL := fs.String("base-url", defaultURL, "Service base URL")
	tenant := fs.String("tenant", defaultTenantID, "Tenant ID")
	user := fs.String("user-id", "", "User ID (acting user)")
	return baseURL, tenant, user
}

func doRequest(method, baseURL, path, tenantID, userID string, payload interface{}) ([]byte, int, error) {
	endpoint := strings.TrimRight(baseURL, "/") + path
	var body io.Reader
	if payload != nil {
		data, _ := json.Marshal(payload)
		body = bytes.NewReader(data)
	}
	req, _ := http.NewRequest(method, endpoint, body)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if tenantID != "" {
		req.Header.Set(tenantHeader, tenantID)
	}
	if userID != "" {
		req.Header.Set(userHeader, userID)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return respBody, resp.StatusCode, fmt.Errorf("status: %s, body: %s", resp.Status, string(respBody))
	}
	return respBody, resp.StatusCode, nil
}

func splitAndClean(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var res []string
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			res = append(res, t)
		}
	}
	return res
}

func prettyPrint(v interface{}) {
	data, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(data))
}

func usage() {
	fmt.Print(`Usage: wardseal <command> [options]
Commands: list, get, create, update, delete, user, group, request, auth
Global: -base-url, -tenant, -user-id
`)
}
