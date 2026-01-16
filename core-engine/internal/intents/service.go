package intents

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// Service handles intent lifecycle.
type Service struct {
	db             *pgxpool.Pool
	rdb            *redis.Client
	idempotencyTTL int
	adapter        Adapter
}

// Adapter is a stub interface for provider adapters.
type Adapter interface {
	Send(msisdn string, amount string) error
}

// NewService creates a new intent service.
func NewService(db *pgxpool.Pool, rdb *redis.Client, ttl int, adapter Adapter) *Service {
	return &Service{db: db, rdb: rdb, idempotencyTTL: ttl, adapter: adapter}
}

// CreateParams holds input for creating an intent.
type CreateParams struct {
	SourceMsisdn      string
	SourceTelco       string
	DestinationMsisdn string
	DestinationTelco  string
	AssetType         string
	Amount            string
	BundleId          *string
	PartnerId         string
	IdempotencyKey    string
}

// FeeQuote is a stub for fee calculation.
type FeeQuote struct {
	FeePercent float32
	FeeAmount  string
	NetAmount  string
}

// CreateIntent creates a new intent (stubbed).
func (s *Service) CreateIntent(ctx context.Context, params CreateParams) (string, *FeeQuote, string, error) {
	// TODO: implement DB + Redis logic
	return "intent-123", &FeeQuote{FeePercent: 2.5, FeeAmount: "25", NetAmount: "975"}, "2026-01-16T15:04:05Z", nil
}
