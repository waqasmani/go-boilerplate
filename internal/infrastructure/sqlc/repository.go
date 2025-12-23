package sqlc

import (
	"context"
	"database/sql"
)

type Repository struct {
	db *sql.DB
	*Queries
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{
		db:      db,
		Queries: New(db),
	}
}

func (r *Repository) WithTransaction(ctx context.Context, fn func(*Queries) error) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	q := r.Queries.WithTx(tx)
	err = fn(q)
	if err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return rbErr
		}
		return err
	}
	return tx.Commit()
}
