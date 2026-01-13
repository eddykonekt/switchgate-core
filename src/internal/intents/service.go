package intents

import (
    "context"
    "database/sql"
    "encoding/json"
    "errors"
    "time"

    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/redis/go-redis/v9"

    "github.com/switchgate/switchgate-core/src/core-engine/internal/idempotency"
    "github.com/switchgate/switchgate-core/src/core-engine/internal/adapters"
)

type Service struct {
    db     *pgxpool.Pool
    idem   *idempotency.Store
    adapter adapters.Adapter
}

type CreateParams struct {
    SourceMsisdn      string
    SourceTelco       string
    DestinationMsisdn string
    DestinationTelco  string
    AssetType         string
    Amount            string
    BundleId          *string
    IdempotencyKey    string
    PartnerId         string
}

type FeeQuote struct {
    FeePercent string `json:"feePercent"`
    FeeAmount  string `json:"feeAmount"`
    NetAmount  string `json:"netAmount"`
}

func NewService(db *pgxpool.Pool, rdb *redis.Client, ttl time.Duration, adapter adapters.Adapter) *Service {
    return &Service{
        db:     db,
        idem:   idempotency.NewStore(rdb, ttl),
        adapter: adapter,
    }
}

func (s *Service) CreateIntent(ctx context.Context, p CreateParams) (string, FeeQuote, time.Time, error) {
    // Normalize payload for idempotency
    payload := map[string]any{
        "source":       map[string]string{"msisdn": p.SourceMsisdn, "telco": p.SourceTelco},
        "destination":  map[string]string{"msisdn": p.DestinationMsisdn, "telco": p.DestinationTelco},
        "assetType":    p.AssetType,
        "amount":       p.Amount,
        "bundleId":     p.BundleId,
        "partnerId":    p.PartnerId,
    }
    b, _ := json.Marshal(payload)

    if _, err := s.idem.Begin(ctx, p.IdempotencyKey, string(b)); err != nil {
        return "", FeeQuote{}, time.Time{}, err
    }

    // Fee quote (placeholder—replace with policy engine)
    fee := FeeQuote{FeePercent: "0.02", FeeAmount: "20.00", NetAmount: "980.00"}

    expires := time.Now().Add(10 * time.Minute)

    tx, err := s.db.Begin(ctx)
    if err != nil {
        return "", FeeQuote{}, time.Time{}, err
    }
    defer tx.Rollback(ctx)

    var intentId string
    feeJSON, _ := json.Marshal(fee)
    err = tx.QueryRow(ctx, `
        INSERT INTO transfer_intents (
            source_msisdn, source_telco, destination_msisdn, destination_telco,
            asset_type, amount, bundle_id, fee_quote_json, status, expires_at,
            idempotency_key, partner_id
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'PENDING_PIN',$9,$10,$11)
        RETURNING intent_id
    `, p.SourceMsisdn, p.SourceTelco, p.DestinationMsisdn, p.DestinationTelco,
        p.AssetType, p.Amount, p.BundleId, feeJSON, expires, p.IdempotencyKey, p.PartnerId).Scan(&intentId)
    if err != nil {
        // If unique violation on idempotency_key, fetch existing intent
        var existing string
        e := tx.QueryRow(ctx, `SELECT intent_id FROM transfer_intents WHERE idempotency_key=$1`, p.IdempotencyKey).Scan(&existing)
        if e == nil {
            intentId = existing
        } else {
            return "", FeeQuote{}, time.Time{}, err
        }
    }

    if err := tx.Commit(ctx); err != nil {
        return "", FeeQuote{}, time.Time{}, err
    }

    return intentId, fee, expires, nil
}

func (s *Service) SubmitPin(ctx context.Context, intentId, telcoPin string) (string, time.Time, error) {
    // Load intent
    var sourceMsisdn, sourceTelco string
    err := s.db.QueryRow(ctx, `SELECT source_msisdn, source_telco FROM transfer_intents WHERE intent_id=$1`, intentId).
        Scan(&sourceMsisdn, &sourceTelco)
    if err != nil {
        return "", time.Time{}, err
    }

    // Validate PIN via adapter
    res, err := s.adapter.ValidatePin(ctx, sourceMsisdn, telcoPin)
    if err != nil || !res.Valid {
        return "", time.Time{}, errors.New("invalid_pin")
    }

    // Send OTP
    otp, err := s.adapter.SendOtp(ctx, sourceMsisdn)
    if err != nil || !otp.Sent {
        return "", time.Time{}, errors.New("otp_send_failed")
    }

    // Update status
    _, err = s.db.Exec(ctx, `UPDATE transfer_intents SET status='OTP_SENT', updated_at=now() WHERE intent_id=$1`, intentId)
    if err != nil {
        return "", time.Time{}, err
    }

    return "OTP_SENT", otp.ExpiresAt, nil
}