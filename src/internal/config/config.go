package config

import (
    "time"

    "github.com/spf13/viper"
)

type Config struct {
    GRPCPort          int
    HTTPPort          int
    PostgresURL       string
    RedisURL          string
    KafkaBrokers      []string
    ServiceName       string
    Env               string
    IdempotencyTTL    time.Duration
    VaultAddr         string
    VaultToken        string
}

func Load() (*Config, error) {
    v := viper.New()
    v.SetEnvPrefix("SWITCHGATE")
    v.AutomaticEnv()

    v.SetDefault("GRPC_PORT", 8081)
    v.SetDefault("HTTP_PORT", 8080)
    v.SetDefault("IDEMPOTENCY_TTL", "15m")
    v.SetDefault("SERVICE_NAME", "core-engine")
    v.SetDefault("ENV", "production")

    cfg := &Config{
        GRPCPort:       v.GetInt("GRPC_PORT"),
        HTTPPort:       v.GetInt("HTTP_PORT"),
        PostgresURL:    v.GetString("POSTGRES_URL"),
        RedisURL:       v.GetString("REDIS_URL"),
        KafkaBrokers:   v.GetStringSlice("KAFKA_BROKERS"),
        ServiceName:    v.GetString("SERVICE_NAME"),
        Env:            v.GetString("ENV"),
        IdempotencyTTL: v.GetDuration("IDEMPOTENCY_TTL"),
        VaultAddr:      v.GetString("VAULT_ADDR"),
        VaultToken:     v.GetString("VAULT_TOKEN"),
    }
    return cfg, nil
}