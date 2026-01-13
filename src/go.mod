module github.com/switchgate/switchgate-core/src/core-engine

go 1.22

require (
    github.com/segmentio/kafka-go v0.5.2
    github.com/jackc/pgx/v5 v5.5.4
    github.com/redis/go-redis/v9 v9.5.1
    google.golang.org/grpc v1.62.2
    google.golang.org/protobuf v1.33.0
    github.com/grpc-ecosystem/go-grpc-middleware v1.4.0
    github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
    github.com/cenkalti/backoff/v4 v4.2.1
    github.com/spf13/viper v1.18.2
    go.opentelemetry.io/otel v1.24.0
    go.opentelemetry.io/otel/sdk v1.24.0
    go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.49.0
)