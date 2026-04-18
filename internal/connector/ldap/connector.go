package ldap

import (
	"context"
	"fmt"
	"strings"

	"github.com/dhawalhost/wardseal/internal/connector"
	"github.com/go-ldap/ldap/v3"
)

// Connector implements the connector.Connector interface for LDAP/Active Directory.
type Connector struct {
	config connector.Config
	conn   *ldap.Conn
	baseDN string
}

// New creates a new LDAP connector.
func New(config connector.Config) (connector.Connector, error) {
	return &Connector{
		config: config,
		baseDN: config.Settings["base_dn"],
	}, nil
}

func (c *Connector) ID() string   { return c.config.ID }
func (c *Connector) Name() string { return c.config.Name }
func (c *Connector) Type() string { return "ldap" }

func (c *Connector) Initialize(ctx context.Context, config connector.Config) error {
	c.config = config
	c.baseDN = config.Settings["base_dn"]
	return c.connect()
}

func (c *Connector) connect() error {
	conn, err := ldap.DialURL(c.config.Endpoint)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}

	// Bind with credentials
	bindDN := c.config.Credentials["bind_dn"]
	bindPassword := c.config.Credentials["bind_password"]
	if err := conn.Bind(bindDN, bindPassword); err != nil {
		_ = conn.Close()
		return fmt.Errorf("failed to bind: %w", err)
	}

	c.conn = conn
	return nil
}

func (c *Connector) HealthCheck(ctx context.Context) error {
	if c.conn == nil {
		return c.connect()
	}
	// Simple search to verify connection
	_, err := c.conn.Search(&ldap.SearchRequest{
		BaseDN: c.baseDN,
		Scope:  ldap.ScopeBaseObject,
		Filter: "(objectClass=*)",
	})
	return err
}

func (c *Connector) Close() error {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	return nil
}

// User operations
func (c *Connector) CreateUser(ctx context.Context, user connector.User) (string, error) {
	userDN := fmt.Sprintf("cn=%s,%s", user.Username, c.getUsersOU())

	addReq := ldap.NewAddRequest(userDN, nil)
	addReq.Attribute("objectClass", []string{"inetOrgPerson", "organizationalPerson", "person", "top"})
	addReq.Attribute("cn", []string{user.Username})
	addReq.Attribute("sn", []string{user.LastName})
	addReq.Attribute("givenName", []string{user.FirstName})
	addReq.Attribute("mail", []string{user.Email})
	addReq.Attribute("uid", []string{user.Username})
	if user.DisplayName != "" {
		addReq.Attribute("displayName", []string{user.DisplayName})
	}

	if err := c.conn.Add(addReq); err != nil {
		return "", fmt.Errorf("failed to create user: %w", err)
	}
	return userDN, nil
}

func (c *Connector) GetUser(ctx context.Context, id string) (connector.User, error) {
	filter := fmt.Sprintf("(|(uid=%s)(cn=%s))", ldap.EscapeFilter(id), ldap.EscapeFilter(id))
	result, err := c.conn.Search(&ldap.SearchRequest{
		BaseDN:     c.getUsersOU(),
		Scope:      ldap.ScopeWholeSubtree,
		Filter:     filter,
		Attributes: []string{"uid", "cn", "sn", "givenName", "mail", "displayName"},
	})
	if err != nil {
		return connector.User{}, err
	}
	if len(result.Entries) == 0 {
		return connector.User{}, fmt.Errorf("user not found")
	}

	entry := result.Entries[0]
	return connector.User{
		ExternalID:  entry.DN,
		Username:    entry.GetAttributeValue("uid"),
		Email:       entry.GetAttributeValue("mail"),
		FirstName:   entry.GetAttributeValue("givenName"),
		LastName:    entry.GetAttributeValue("sn"),
		DisplayName: entry.GetAttributeValue("displayName"),
		Active:      true, // LDAP typically doesn't have active flag
	}, nil
}

func (c *Connector) UpdateUser(ctx context.Context, id string, user connector.User) error {
	// Find user DN
	u, err := c.GetUser(ctx, id)
	if err != nil {
		return err
	}

	modReq := ldap.NewModifyRequest(u.ExternalID, nil)
	if user.Email != "" {
		modReq.Replace("mail", []string{user.Email})
	}
	if user.FirstName != "" {
		modReq.Replace("givenName", []string{user.FirstName})
	}
	if user.LastName != "" {
		modReq.Replace("sn", []string{user.LastName})
	}
	if user.DisplayName != "" {
		modReq.Replace("displayName", []string{user.DisplayName})
	}

	return c.conn.Modify(modReq)
}

func (c *Connector) DeleteUser(ctx context.Context, id string) error {
	u, err := c.GetUser(ctx, id)
	if err != nil {
		return err
	}
	return c.conn.Del(ldap.NewDelRequest(u.ExternalID, nil))
}

func (c *Connector) ListUsers(ctx context.Context, filter string, limit, offset int) ([]connector.User, int, error) {
	searchFilter := "(objectClass=inetOrgPerson)"
	if filter != "" {
		searchFilter = fmt.Sprintf("(&%s(%s))", searchFilter, filter)
	}

	result, err := c.conn.Search(&ldap.SearchRequest{
		BaseDN:     c.getUsersOU(),
		Scope:      ldap.ScopeWholeSubtree,
		Filter:     searchFilter,
		Attributes: []string{"uid", "cn", "sn", "givenName", "mail", "displayName"},
	})
	if err != nil {
		return nil, 0, err
	}

	total := len(result.Entries)
	end := offset + limit
	if end > total {
		end = total
	}
	if offset > total {
		return []connector.User{}, total, nil
	}

	users := make([]connector.User, 0, end-offset)
	for i := offset; i < end; i++ {
		entry := result.Entries[i]
		users = append(users, connector.User{
			ExternalID:  entry.DN,
			Username:    entry.GetAttributeValue("uid"),
			Email:       entry.GetAttributeValue("mail"),
			FirstName:   entry.GetAttributeValue("givenName"),
			LastName:    entry.GetAttributeValue("sn"),
			DisplayName: entry.GetAttributeValue("displayName"),
			Active:      true,
		})
	}
	return users, total, nil
}

// Group operations
func (c *Connector) CreateGroup(ctx context.Context, group connector.Group) (string, error) {
	groupDN := fmt.Sprintf("cn=%s,%s", group.Name, c.getGroupsOU())

	addReq := ldap.NewAddRequest(groupDN, nil)
	addReq.Attribute("objectClass", []string{"groupOfNames", "top"})
	addReq.Attribute("cn", []string{group.Name})
	if group.Description != "" {
		addReq.Attribute("description", []string{group.Description})
	}
	// groupOfNames requires at least one member
	addReq.Attribute("member", []string{c.baseDN}) // Placeholder

	if err := c.conn.Add(addReq); err != nil {
		return "", fmt.Errorf("failed to create group: %w", err)
	}
	return groupDN, nil
}

func (c *Connector) GetGroup(ctx context.Context, id string) (connector.Group, error) {
	filter := fmt.Sprintf("(cn=%s)", ldap.EscapeFilter(id))
	result, err := c.conn.Search(&ldap.SearchRequest{
		BaseDN:     c.getGroupsOU(),
		Scope:      ldap.ScopeWholeSubtree,
		Filter:     filter,
		Attributes: []string{"cn", "description"},
	})
	if err != nil {
		return connector.Group{}, err
	}
	if len(result.Entries) == 0 {
		return connector.Group{}, fmt.Errorf("group not found")
	}

	entry := result.Entries[0]
	return connector.Group{
		ExternalID:  entry.DN,
		Name:        entry.GetAttributeValue("cn"),
		Description: entry.GetAttributeValue("description"),
	}, nil
}

func (c *Connector) UpdateGroup(ctx context.Context, id string, group connector.Group) error {
	g, err := c.GetGroup(ctx, id)
	if err != nil {
		return err
	}

	modReq := ldap.NewModifyRequest(g.ExternalID, nil)
	if group.Description != "" {
		modReq.Replace("description", []string{group.Description})
	}
	return c.conn.Modify(modReq)
}

func (c *Connector) DeleteGroup(ctx context.Context, id string) error {
	g, err := c.GetGroup(ctx, id)
	if err != nil {
		return err
	}
	return c.conn.Del(ldap.NewDelRequest(g.ExternalID, nil))
}

func (c *Connector) ListGroups(ctx context.Context, filter string, limit, offset int) ([]connector.Group, int, error) {
	searchFilter := "(objectClass=groupOfNames)"
	result, err := c.conn.Search(&ldap.SearchRequest{
		BaseDN:     c.getGroupsOU(),
		Scope:      ldap.ScopeWholeSubtree,
		Filter:     searchFilter,
		Attributes: []string{"cn", "description"},
	})
	if err != nil {
		return nil, 0, err
	}

	total := len(result.Entries)
	end := offset + limit
	if end > total {
		end = total
	}

	groups := make([]connector.Group, 0, end-offset)
	for i := offset; i < end && i < total; i++ {
		entry := result.Entries[i]
		groups = append(groups, connector.Group{
			ExternalID:  entry.DN,
			Name:        entry.GetAttributeValue("cn"),
			Description: entry.GetAttributeValue("description"),
		})
	}
	return groups, total, nil
}

func (c *Connector) AddUserToGroup(ctx context.Context, userID, groupID string) error {
	u, err := c.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	g, err := c.GetGroup(ctx, groupID)
	if err != nil {
		return err
	}

	modReq := ldap.NewModifyRequest(g.ExternalID, nil)
	modReq.Add("member", []string{u.ExternalID})
	return c.conn.Modify(modReq)
}

func (c *Connector) RemoveUserFromGroup(ctx context.Context, userID, groupID string) error {
	u, err := c.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	g, err := c.GetGroup(ctx, groupID)
	if err != nil {
		return err
	}

	modReq := ldap.NewModifyRequest(g.ExternalID, nil)
	modReq.Delete("member", []string{u.ExternalID})
	return c.conn.Modify(modReq)
}

func (c *Connector) GetGroupMembers(ctx context.Context, groupID string) ([]connector.User, error) {
	g, err := c.GetGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}

	result, err := c.conn.Search(&ldap.SearchRequest{
		BaseDN:     g.ExternalID,
		Scope:      ldap.ScopeBaseObject,
		Filter:     "(objectClass=*)",
		Attributes: []string{"member"},
	})
	if err != nil {
		return nil, err
	}
	if len(result.Entries) == 0 {
		return []connector.User{}, nil
	}

	members := result.Entries[0].GetAttributeValues("member")
	users := make([]connector.User, 0, len(members))
	for _, memberDN := range members {
		if memberDN == c.baseDN {
			continue // Skip placeholder
		}
		// Extract CN from DN
		parts := strings.Split(memberDN, ",")
		if len(parts) > 0 {
			cn := strings.TrimPrefix(parts[0], "cn=")
			u, err := c.GetUser(ctx, cn)
			if err == nil {
				users = append(users, u)
			}
		}
	}
	return users, nil
}

func (c *Connector) DiscoverResources(ctx context.Context) ([]connector.Resource, error) {
	if c.conn == nil {
		if err := c.connect(); err != nil {
			return nil, err
		}
	}

	resources := []connector.Resource{}

	// 1. Discover OUs (Potential Resource Containers)
	ouResult, err := c.conn.Search(&ldap.SearchRequest{
		BaseDN:     c.baseDN,
		Scope:      ldap.ScopeWholeSubtree,
		Filter:     "(objectClass=organizationalUnit)",
		Attributes: []string{"ou", "description"},
	})
	if err == nil {
		for _, entry := range ouResult.Entries {
			resources = append(resources, connector.Resource{
				ExternalID: entry.DN,
				Type:       "ou",
				Name:       entry.GetAttributeValue("ou"),
				Metadata: map[string]string{
					"dn":          entry.DN,
					"description": entry.GetAttributeValue("description"),
				},
			})
		}
	}

	// 2. Discover Groups (Potential Application access points)
	groupResult, err := c.conn.Search(&ldap.SearchRequest{
		BaseDN:     c.baseDN,
		Scope:      ldap.ScopeWholeSubtree,
		Filter:     "(objectClass=groupOfNames)",
		Attributes: []string{"cn", "description"},
	})
	if err == nil {
		for _, entry := range groupResult.Entries {
			resources = append(resources, connector.Resource{
				ExternalID: entry.DN,
				Type:       "group",
				Name:       entry.GetAttributeValue("cn"),
				Metadata: map[string]string{
					"dn":          entry.DN,
					"description": entry.GetAttributeValue("description"),
				},
			})
		}
	}

	return resources, nil
}

func (c *Connector) getUsersOU() string {
	if ou, ok := c.config.Settings["users_ou"]; ok {
		return ou
	}
	return "ou=users," + c.baseDN
}

func (c *Connector) getGroupsOU() string {
	if ou, ok := c.config.Settings["groups_ou"]; ok {
		return ou
	}
	return "ou=groups," + c.baseDN
}
