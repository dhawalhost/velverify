package middleware

import (
	"bytes"
	"testing"
)

func TestSanitizeJSONPayload(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple password redaction",
			input:    `{"username":"user","password":"secretpassword"}`,
			expected: `{"password":"[REDACTED]","username":"user"}`,
		},
		{
			name:     "nested token redaction",
			input:    `{"auth":{"token":"xyz123","expiry":3600}}`,
			expected: `{"auth":{"expiry":3600,"token":"[REDACTED]"}}`,
		},
		{
			name:     "array of sensitive data",
			input:    `[{"secret":"sssh"},{"normal":"data"}]`,
			expected: `[{"secret":"[REDACTED]"},{"normal":"data"}]`,
		},
		{
			name:     "invalid json remains untouched",
			input:    `{"broken":`,
			expected: `{"broken":`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := sanitizeJSONPayload([]byte(tt.input))
			if !bytes.Equal(output, []byte(tt.expected)) {
				t.Errorf("expected %s, got %s", tt.expected, string(output))
			}
		})
	}
}
