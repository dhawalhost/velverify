package scim

// User represents a SCIM 2.0 User resource.
type User struct {
	Schemas  []string `json:"schemas"`
	ID          string   `json:"id,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	UserName    string   `json:"userName"`
	DisplayName string   `json:"displayName,omitempty"`
	Password    string   `json:"password,omitempty"`
	Name     struct {
		GivenName  string `json:"givenName,omitempty"`
		FamilyName string `json:"familyName,omitempty"`
	} `json:"name,omitempty"`
	Emails []Email    `json:"emails,omitempty"`
	PhoneNumbers []PhoneNumber `json:"phoneNumbers,omitempty"`
	PrimaryEmail string `json:"primaryEmail,omitempty"`
	Groups []GroupRef `json:"groups,omitempty"`
	Active bool       `json:"active"`
	Title  string     `json:"title,omitempty"`
	Department string `json:"department,omitempty"`
	Timezone string   `json:"timezone,omitempty"`
	Meta   Meta       `json:"meta,omitempty"`
}

type GroupRef struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

// Group represents a SCIM 2.0 Group resource.
type Group struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id,omitempty"`
	DisplayName string   `json:"displayName"`
	Members     []Member `json:"members,omitempty"`
	Meta        Meta     `json:"meta,omitempty"`
}

type Email struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type PhoneNumber struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type Member struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"` // User or Group
}

type Meta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
}

// ListResponse represents a SCIM list response.
type ListResponse struct {
	Schemas      []string      `json:"schemas"`
	TotalResults int           `json:"totalResults"`
	StartIndex   int           `json:"startIndex"`
	ItemsPerPage int           `json:"itemsPerPage"`
	Resources    []interface{} `json:"Resources"`
}

// Error represents a SCIM error response.
type Error struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	Detail   string   `json:"detail,omitempty"`
	ScimType string   `json:"scimType,omitempty"`
}

// PatchRequest represents a SCIM PATCH request body.
type PatchRequest struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}

// PatchOperation represents a single SCIM PATCH operation.
type PatchOperation struct {
	Op    string      `json:"op"`              // add, remove, replace
	Path  string      `json:"path,omitempty"`  // attribute path
	Value interface{} `json:"value,omitempty"` // new value
}

const (
	UserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	GroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	ListSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	ErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"
	PatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)
