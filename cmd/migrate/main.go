package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}

	files, err := os.ReadDir("db/migrations")
	if err != nil {
		log.Fatalf("read migrations: %v", err)
	}
	var names []string
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".sql") {
			names = append(names, f.Name())
		}
	}
	sort.Strings(names)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := ensureTable(ctx, db); err != nil {
		log.Fatalf("ensure migrations table: %v", err)
	}

	applied, err := loadApplied(ctx, db)
	if err != nil {
		log.Fatalf("load applied: %v", err)
	}

	for _, name := range names {
		if applied[name] {
			continue
		}
		if err := applyMigration(ctx, db, name); err != nil {
			log.Fatalf("apply %s: %v", name, err)
		}
		log.Printf("applied %s", name)
	}
	log.Println("migrations complete")
}

func ensureTable(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
    CREATE TABLE IF NOT EXISTS schema_migrations (
        name TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`)
	return err
}

func loadApplied(ctx context.Context, db *sql.DB) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		result[name] = true
	}
	return result, rows.Err()
}

func applyMigration(ctx context.Context, db *sql.DB, name string) error {
	sqlBytes, err := os.ReadFile(fmt.Sprintf("db/migrations/%s", name))
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, string(sqlBytes)); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, name); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
