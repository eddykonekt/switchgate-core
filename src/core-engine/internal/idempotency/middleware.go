package idempotency

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "time"

    "github.com/redis/go-redis/v9"
)

var ErrConflict = errors.New("idempotency conflict")

type Store struct {
    rdb *redis.Client
    ttl time.Duration
}

func NewStore(rdb *redis.Client, ttl time.Duration) *Store {
    return &Store{rdb: rdb, ttl: ttl}
}

type Record struct {
    Key     string
    Payload string // normalized JSON
}

func hashPayload(p string) string {
    sum := sha256.Sum256([]byte(p))
    return hex.EncodeToString(sum[:])
}

func (s *Store) Begin(ctx context.Context, key string, payload string) (string, error) {
    h := hashPayload(payload)
    // SETNX to avoid race; store hash as value
    ok, err := s.rdb.SetNX(ctx, key, h, s.ttl).Result()
    if err != nil {
        return "", err
    }
    if ok {
        return h, nil // first time
    }
    // existing key—check hash
    existing, err := s.rdb.Get(ctx, key).Result()
    if err != nil {
        return "", err
    }
    if existing != h {
        return "", ErrConflict
    }
    return h, nil // safe replay
}

func (s *Store) Complete(ctx context.Context, key string) error {
    // Optionally extend TTL or store result reference
    return nil
}