package config

// Types.go can hold strongly typed config values.
// For now, just a stub struct.
type DatabaseConfig struct {
	URL      string
	MaxConns int
}

type RedisConfig struct {
	Addr string
	DB   int
}
