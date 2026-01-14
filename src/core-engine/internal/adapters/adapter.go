package adapters

import (
    "context"
    "time"
)

type PinResult struct {
    Valid bool
}

type OtpResult struct {
    Sent        bool
    Channel     string
    ExpiresAt   time.Time
}

type DebitResult struct {
    Reference string
    Amount    string // decimal as string
}

type CreditResult struct {
    Reference string
    Amount    string
}

type BalanceResult struct {
    Amount string
}

type Adapter interface {
    ValidatePin(ctx context.Context, msisdn, pin string) (PinResult, error)
    SendOtp(ctx context.Context, msisdn string) (OtpResult, error)
    VerifyOtp(ctx context.Context, msisdn, otp string) (bool, error)
    Debit(ctx context.Context, msisdn, assetType, amountOrBundle string) (DebitResult, error)
    Credit(ctx context.Context, msisdn, assetType, amountOrBundle string) (CreditResult, error)
    Balance(ctx context.Context, msisdn string) (BalanceResult, error)
}