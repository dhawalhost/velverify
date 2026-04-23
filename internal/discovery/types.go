package discovery

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
)

// JSONMap is a map[string]interface{} that implements sql.Scanner and driver.Valuer
// to allow mapping with Postgres JSONB columns.
type JSONMap map[string]interface{}

// Scan implements the sql.Scanner interface for database -> struct mapping.
func (j *JSONMap) Scan(value interface{}) error {
	if value == nil {
		*j = make(JSONMap)
		return nil
	}

	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return errors.New("type assertion to []byte/string failed")
	}

	return json.Unmarshal(bytes, j)
}

// Value implements the driver.Valuer interface for struct -> database mapping.
func (j JSONMap) Value() (driver.Value, error) {
	if j == nil {
		return json.Marshal(make(JSONMap))
	}
	return json.Marshal(j)
}
