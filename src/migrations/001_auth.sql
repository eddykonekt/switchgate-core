CREATE TABLE admins (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  require_otp BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  msisdn TEXT UNIQUE NOT NULL,
  telco TEXT NOT NULL,
  kyc_status TEXT DEFAULT 'PENDING',
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  msisdn TEXT NOT NULL REFERENCES users(msisdn) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE (msisdn, fingerprint)
);

CREATE TABLE clients (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  partner_id TEXT UNIQUE NOT NULL,          -- e.g., MTN-NG, GOV-NG-SOCIAL
  role TEXT NOT NULL CHECK (role IN ('PARTNER','ENTERPRISE','GOVERNMENT')),
  division TEXT,
  client_id TEXT UNIQUE NOT NULL,
  client_secret_hash TEXT NOT NULL,
  scopes TEXT[] NOT NULL DEFAULT '{}',
  enabled BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE otp_store (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key TEXT UNIQUE NOT NULL,
  code TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  attempts INT DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS transfer_intents (
  intent_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  source_msisdn VARCHAR NOT NULL,
  source_telco VARCHAR NOT NULL,
  destination_msisdn VARCHAR NOT NULL,
  destination_telco VARCHAR NOT NULL,
  asset_type VARCHAR NOT NULL,
  amount NUMERIC(18,6),
  bundle_id VARCHAR,
  fee_quote_json JSONB NOT NULL,
  status VARCHAR NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  idempotency_key VARCHAR NOT NULL UNIQUE,
  partner_id VARCHAR NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_intents_status ON transfer_intents(status);
CREATE INDEX IF NOT EXISTS idx_intents_expires ON transfer_intents(expires_at);

CREATE TABLE IF NOT EXISTS transactions (
  transaction_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  intent_id UUID NOT NULL REFERENCES transfer_intents(intent_id),
  partner_id VARCHAR NOT NULL,
  status VARCHAR NOT NULL,
  initiated_at TIMESTAMP,
  debited_at TIMESTAMP,
  credited_at TIMESTAMP,
  completed_at TIMESTAMP,
  failed_at TIMESTAMP,
  receipt_json JSONB,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_tx_intent ON transactions(intent_id);
CREATE INDEX IF NOT EXISTS idx_tx_status ON transactions(status);

CREATE TABLE IF NOT EXISTS ledger_entries (
  entry_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  transaction_id UUID NOT NULL REFERENCES transactions(transaction_id),
  type VARCHAR NOT NULL,
  account VARCHAR NOT NULL,
  asset_type VARCHAR NOT NULL,
  amount NUMERIC(18,6) NOT NULL,
  timestamp TIMESTAMP NOT NULL DEFAULT now(),
  hash VARCHAR NOT NULL,
  prev_hash VARCHAR
);

CREATE INDEX IF NOT EXISTS idx_ledger_tx ON ledger_entries(transaction_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_ledger_unique ON ledger_entries(transaction_id, type, account);

CREATE TABLE IF NOT EXISTS reversals (
  reversal_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  original_transaction_id UUID NOT NULL REFERENCES transactions(transaction_id),
  initiator VARCHAR NOT NULL,
  reason_code VARCHAR NOT NULL,
  status VARCHAR NOT NULL,
  initiated_at TIMESTAMP NOT NULL DEFAULT now(),
  finalized_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_reversals_orig ON reversals(original_transaction_id);
CREATE INDEX IF NOT EXISTS idx_reversals_status ON reversals(status);