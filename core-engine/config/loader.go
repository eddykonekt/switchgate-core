package config

import "os"

// Load reads environment variables into Config.
func Load() (*config, error) {
	return &config{
		AppEnv:         getEnv("APP_ENV", "production"),
		Port:           getEnv("PORT", "8080"),
		PostgresURL:    getEnv("POSTGRES_URL", ""),
		RedisURL:       getEnv("REDIS_URL", ""),
		KafkaBroker:    getEnv("KAFKA_BROKER", ""),
		JWTSecret:      getEnv("JWT_SECRET", ""),
		HashSalt:       getEnv("HASH_SALT", ""),
		IdempotencyTTL: 300,
	}, nil
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
