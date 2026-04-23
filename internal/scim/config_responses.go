package scim

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ServiceProviderConfig returns the SCIM 2.0 service provider configuration.
func (h *HTTPHandler) getServiceProviderConfig(c *gin.Context) {
	config := gin.H{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch": gin.H{
			"supported": true,
		},
		"bulk": gin.H{
			"supported":      false, // Future enhancement
			"maxOperations":  1000,
			"maxPayloadSize": 1048576,
		},
		"filter": gin.H{
			"supported":  true,
			"maxResults": 200,
		},
		"changePassword": gin.H{
			"supported": false,
		},
		"sort": gin.H{
			"supported": false,
		},
		"etag": gin.H{
			"supported": false,
		},
		"authenticationSchemes": []gin.H{
			{
				"name":        "OAuth Bearer Token",
				"description": "Authentication scheme using the OAuth Bearer Token Standard",
				"specUri":     "http://www.rfc-editor.org/info/rfc6750",
				"type":        "oauthbearertoken",
				"primary":     true,
			},
		},
		"meta": gin.H{
			"resourceType": "ServiceProviderConfig",
			"location":     fmt.Sprintf("%s/scim/v2/ServiceProviderConfig", c.Request.Host),
		},
	}
	c.JSON(http.StatusOK, config)
}

// ResourceTypes returns the SCIM 2.0 resource types.
func (h *HTTPHandler) getResourceTypes(c *gin.Context) {
	types := []gin.H{
		{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":          "User",
			"name":        "User",
			"endpoint":    "/Users",
			"description": "User Account",
			"schema":      UserSchema,
			"meta": gin.H{
				"resourceType": "ResourceType",
				"location":     fmt.Sprintf("%s/scim/v2/ResourceTypes/User", c.Request.Host),
			},
		},
		{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":          "Group",
			"name":        "Group",
			"endpoint":    "/Groups",
			"description": "Group",
			"schema":      GroupSchema,
			"meta": gin.H{
				"resourceType": "ResourceType",
				"location":     fmt.Sprintf("%s/scim/v2/ResourceTypes/Group", c.Request.Host),
			},
		},
	}
	c.JSON(http.StatusOK, gin.H{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": 2,
		"Resources":    types,
	})
}

// Schemas returns the SCIM 2.0 schemas.
func (h *HTTPHandler) getSchemas(c *gin.Context) {
	schemas := []gin.H{
		{
			"id":          UserSchema,
			"name":        "User",
			"description": "User Account",
			"attributes": []gin.H{
				{
					"name":        "userName",
					"type":        "string",
					"multiValued": false,
					"description": "Unique identifier for the User",
					"required":    true,
					"caseExact":   false,
					"mutability":  "readWrite",
					"returned":    "default",
					"uniqueness":  "server",
				},
				{
					"name":        "emails",
					"type":        "complex",
					"multiValued": true,
					"description": "Email addresses for the user",
					"required":    false,
					"subAttributes": []gin.H{
						{"name": "value", "type": "string", "multiValued": false},
						{"name": "type", "type": "string", "multiValued": false},
						{"name": "primary", "type": "boolean", "multiValued": false},
					},
				},
				{
					"name":        "active",
					"type":        "boolean",
					"multiValued": false,
					"description": "Whether the user is active",
					"required":    false,
				},
			},
		},
		{
			"id":          GroupSchema,
			"name":        "Group",
			"description": "Group",
			"attributes": []gin.H{
				{
					"name":        "displayName",
					"type":        "string",
					"multiValued": false,
					"description": "A human-readable name for the Group",
					"required":    true,
				},
				{
					"name":        "members",
					"type":        "complex",
					"multiValued": true,
					"description": "A list of members of the Group",
					"subAttributes": []gin.H{
						{"name": "value", "type": "string", "multiValued": false, "description": "Identifier of the member"},
						{"name": "display", "type": "string", "multiValued": false, "description": "Human readable name of the member"},
					},
				},
			},
		},
	}
	c.JSON(http.StatusOK, gin.H{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": 2,
		"Resources":    schemas,
	})
}
