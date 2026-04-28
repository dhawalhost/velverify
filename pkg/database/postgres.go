package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq" // postgres driver
	"github.com/dhawalhost/wardseal/pkg/middleware"
)

// Config holds the configuration for the database connection.
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// NewConnection creates a new database connection.
func NewConnection(config Config) (*sqlx.DB, error) { // Use sqlx.DB
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.User, config.Password, config.DBName, config.SSLMode)

	db, err := sqlx.Connect("postgres", connStr) // Use sqlx.Connect
	if err != nil {
		return nil, err
	}

	// It's a good practice to set connection pool parameters.
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Ping the database to verify the connection.
	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}

// RunInTenantTx executes a callback within a transaction where the tenant ID is set for RLS.
func RunInTenantTx(ctx context.Context, db *sqlx.DB, fn func(tx *sqlx.Tx) error) error {
	tenantID, _ := middleware.TenantIDFromContext(ctx)
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if tenantID != "" {
		_, err = tx.ExecContext(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", tenantID)
		if err != nil {
			return err
		}
	}

	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit()
}
