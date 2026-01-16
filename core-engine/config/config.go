package config

// Config holds application configuration values.
type config struct {
	AppEnv         string
	Port           string
	PostgresURL    string
	RedisURL       string
	KafkaBroker    string
	JWTSecret      string
	HashSalt       string
	IdempotencyTTL int
}
