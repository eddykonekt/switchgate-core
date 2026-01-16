package config

import (
	"os"
)

type Config struct {
	AppEnv         string
	Port           string
	PostgresURL    string
	RedisURL       string
	KafkaBroker    string
	JWTSecret      string
	HashSalt       string
	IdempotencyTTL int
}

func Load() (*Config, error) {
	return &Config{
		AppEnv:         getEnv("APP_ENV", "production"),
		Port:           getEnv("PORT", "8080"),
		PostgresURL:    getEnv("POSTGRES_URL", ""),
		RedisURL:       getEnv("REDIS_URL", ""),
		KafkaBroker:    getEnv("KAFKA_BROKER", ""),
		JWTSecret:      getEnv("JWT_SECRET", ""),
		HashSalt:       getEnv("HASH_SALT", ""),
		IdempotencyTTL: 300, // seconds
	}, nil
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
