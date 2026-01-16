package main

import (
	"context"
	"log"
	"net"

	"github.com/eddykonekt/switchgate-core/core-engine/config"
	"github.com/eddykonekt/switchgate-core/core-engine/internal/adapters"
	"github.com/eddykonekt/switchgate-core/core-engine/internal/intents"
	intentspb "github.com/eddykonekt/switchgate-core/core-engine/proto/gen/intents"
	import transactionspb "github.com/eddykonekt/switchgate-core/core-engine/proto/gen/transactions"
	import ledgerpb "github.com/eddykonekt/switchgate-core/core-engine/proto/gen/ledger"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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
		BundleId:          nil,
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
	// Load config
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("failed to load config:", err)
	}

	// Connect Postgres
	pool, err := pgxpool.New(context.Background(), cfg.PostgresURL)
	if err != nil {
		log.Fatal("failed to connect postgres:", err)
	}
	defer pool.Close()

	// Connect Redis
	rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisURL})
	defer rdb.Close()

	// Initialize provider adapter (stub for now)
	var adapter adapters.Adapter = adapters.NewMockAdapter()

	// Initialize service
	svc := intents.NewService(pool, rdb, cfg.IdempotencyTTL, adapter)

	// gRPC server
	grpcServer := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
	intentspb.RegisterIntentServiceServer(grpcServer, &IntentServer{svc: svc})

	lis, err := net.Listen("tcp", ":"+cfg.Port)
	if err != nil {
		log.Fatal("failed to listen:", err)
	}

	log.Println("Core Engine gRPC server listening on port", cfg.Port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatal("gRPC server failed:", err)
	}
}
