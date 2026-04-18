package types

// Secret is a string wrapper that masks its content when printed.
// Use this for any sensitive data like tokens, API keys, or private keys.
type Secret string

// String implements fmt.Stringer and returns a masked representation.
func (s Secret) String() string {
	if len(s) == 0 {
		return ""
	}
	return "[MASKED]"
}

// GoString implements fmt.GoStringer and returns a masked representation.
func (s Secret) GoString() string {
	return s.String()
}

// UnmarshalText implements encoding.TextUnmarshaler to allow Viper/Mapstructure to fill the secret.
func (s *Secret) UnmarshalText(text []byte) error {
	*s = Secret(string(text))
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (s Secret) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// Raw returns the underlying unmasked string.
func (s Secret) Raw() string {
	return string(s)
}

// IsEmpty returns true if the secret is empty.
func (s Secret) IsEmpty() bool {
	return len(s) == 0
}
