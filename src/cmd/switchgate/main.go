package main

import (
    "context"
    "log"
    "net"

    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/redis/go-redis/v9"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"

    "github.com/switchgate/switchgate-core/src/core-engine/internal/config"
    "github.com/switchgate/switchgate-core/src/core-engine/internal/intents"
    "github.com/switchgate/switchgate-core/src/core-engine/internal/adapters"
    intentspb "github.com/switchgate/switchgate-core/src/core-engine/pkg/proto/gen/intents"
)

type IntentServer struct {
    intentspb.UnimplementedIntentServiceServer
    svc *intents.Service
}

func (s *IntentServer) CreateIntent(ctx context.Context, req *intentspb.CreateIntentRequest) (*intentspb.CreateIntentResponse, error) {
    params := intents.CreateParams{
        SourceMsisdn:      req.Source.Msisdn,
        SourceTelco:       req.Source.Telco,
        DestinationMsisdn: req.Destination.Msisdn,
        DestinationTelco:  req.Destination.Telco,
        AssetType:         req.AssetType,
        Amount:            req.Amount,
        PartnerId:         req.PartnerId,
        IdempotencyKey:    req.IdempotencyKey,
    }
    intentId, fee, expires, err := s.svc.CreateIntent(ctx, params)
    if err != nil {
        return nil, err
    }
    return &intentspb.CreateIntentResponse{
        IntentId: intentId,
        Status:   "PENDING_PIN",
        FeeQuote: &intentspb.FeeQuote{
            FeePercent: fee.FeePercent,
            FeeAmount:  fee.FeeAmount,
            NetAmount:  fee.NetAmount,
        },
        ExpiresAt: expires.UTC().Format("2006-01-02T15:04:05Z"),
    }, nil
}

func main() {
    cfg, err := config.Load()
    if err != nil {
        log.Fatal(err)
    }

    pool, err := pgxpool.New(context.Background(), cfg.PostgresURL)
    if err != nil {
        log.Fatal(err)
    }
    defer pool.Close()

    rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisURL})
    defer rdb.Close()

    // TODO: initialize concrete adapter (production)
    var adapter adapters.Adapter = /* your provider adapter */

    svc := intents.NewService(pool, rdb, cfg.IdempotencyTTL, adapter)

    // mTLS credentials (load certs from Vault or secure store)
    creds, err := credentials.NewServerTLSFromFile("certs/server.crt", "certs/server.key")
    if err != nil {
        log.Fatal(err)
    }

    grpcServer := grpc.NewServer(grpc.Creds(creds))
    intentspb.RegisterIntentServiceServer(grpcServer, &IntentServer{svc: svc})

    lis, err := net.Listen("tcp", ":8081")
    if err != nil {
        log.Fatal(err)
    }
    log.Println("gRPC server listening on :8081")
    if err := grpcServer.Serve(lis); err != nil {
        log.Fatal(err)
    }
}