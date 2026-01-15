# **README.md — Pan-African Switching Engine**

## **Overview**

The **Pan-African Multi-Rails Switching Engine** is a high-performance distributed platform built in **Go**, designed to abstract value units (VU), manage multi-provider routing, orchestrate idempotent transactions, and maintain a real-time double-entry ledger across multiple African countries.

The switching engine connects **telecom operators**, **utility providers**, **banks**, **wallets**, **payment aggregators**, and **local settlement partners** into a unified programmable interface.

The system enables:

* **Value Abstraction (VU Layer)** to normalize airtime, data bundles, utility tokens, power units (kWh), TV subscriptions, meter top-ups, etc.
* **Provider Routing Engine** for intelligent routing based on success rate, cost, SLA, or geographic limitations.
* **Idempotent Execution** (no duplicate charges or double provisioning).
* **Double-Entry Ledgering** for every financial movement.
* **Reservation + Settlement Model** where switching events go through hold → commit → release → reverse flows.
* **Event Streaming (Kafka)** for audit, notifications, external integrations.
* **Multi-Country Support** with strict money-laundering controls limiting switching only within the same country.
* **Revenue Logic** supporting our 2–5% fee model charged to providers and optionally to users.


## **Core Principles**

### **1. Pan-African but Country-Bound Switching (AML Control)**

* Nigerian users switch only Nigerian assets.
* Ghanaian users switch only Ghana assets.
* Kenyan users switch only Kenya assets.
* No cross-border switching of prepaid values (e.g., Nigerian airtime → Ghanaian airtime is **not allowed**).
* Cross-border activity (future phase) will only occur via **regulated FX partners**.

### **2. Provider-Charged Model**

We earn **2–5%** of every successful transaction that flows through our rails:

* Providers pay per request processed.
* Users are charged **only** when they directly use our app or web platform.
* Partner-integrated systems (via API) never show charges to end-users; we invoice partners monthly.

### **3. Fail-Safe Execution**

Each transaction has:

* **Trace ID**
* **Idempotency Key**
* **Two-phase commit transaction flow**
* **Guarantees exactly-once execution**



# **Architecture**

```
                    ┌──────────────────────────┐
                    │      Mobile / Web App    │
                    └─────────────┬────────────┘
                                  │ REST / gRPC
┌─────────────────────────────────▼────────────────────────────────┐
│                         API Gateway                              │
└─────────────────────────┬─────────────────────────┬──────────────┘
                          │                         │
                     Auth Service               Partner API
                          │                         │
                          ▼                         ▼
┌───────────────────────────────────────────────────────────────────┐
│                        Switching Engine (Go)                      │
│                                                                   │
│  ┌─────────────┐   ┌──────────────────┐   ┌───────────────────┐  │
│  │ VU Layer     │   │ Routing Engine   │   │ Transaction Core   │ │
│  │ Normalization│   │ Provider Scoring │   │ Ledger + Reserve   │ │
│  └─────────────┘   └──────────────────┘   └───────────────────┘  │
│                                                                   │
└──────────────────────────┬────────────────────────────────────────┘
                           │
                           ▼
                ┌────────────────────────────┐
                │  Provider Connectors       │
                │  (Telcos, Utility APIs)    │
                └────────────────────────────┘
                           │
                           ▼
                       Kafka Bus
                           │
                           ▼
         ┌────────────────────────────────────────┐
         │ Settlement, Reconciliation, Reporting   │
         └────────────────────────────────────────┘




# **Key Components**

### **1. VU (Value Unit) Abstraction Layer**

Normalizes prepaid values to a universal structure:


{
  "vuCode": "MTN_NG_DATA_2GB",
  "country": "NG",
  "provider": "MTN",
  "type": "DATA",
  "denomination": 2000,
  "currency": "NGN",
  "metadata": {...}
}


### **2. Routing Engine**

Smart routing based on:

* Cost
* Success rate
* Latency
* SLA
* Country restrictions
* Provider health score

### **3. Transaction Execution**

Transaction states:

| State     | Meaning                         |
| --------- | ------------------------------- |
| RESERVED  | Amount held but not yet settled |
| COMMITTED | Provider confirmed success      |
| RELEASED  | Funds moved to provider         |
| REVERSED  | Rolled back                     |

### **4. Double-Entry Ledger**


Debit: User Wallet
Credit: Provider Settlement Wallet


Guarantees full auditability.



# **Fee Structure**

### **Provider-Pay Model**

We charge providers **2–5%** per transaction:

| Provider Type     | Typical Charge |
| ----------------- | -------------- |
| Telcos            | 2–3%           |
| Utility Companies | 3–4%           |
| Aggregators       | 4–5%           |

Partners receive invoicing monthly or real-time auto-billing.

### **End-User Charges**

Users only pay when using our native app/web:


Base Fee: 1% – 2%
+
Convenience Fee: 10 – 50 Naira / 1 – 5 GHS / 10 KES (country dependent)




# **Repository File Structure (Advanced)**


/switching-engine
│
├── cmd/
│   ├── api/
│   │   └── main.go                 # REST/gRPC server bootstrap
│   └── worker/
│       └── main.go                 # Kafka consumers, background jobs
│
├── internal/
│   ├── config/                     # Environment + config loader
│   ├── auth/                       # JWT, API keys, HMAC validation
│   ├── vu/                         # Value abstraction engine
│   ├── routing/                    # Provider routing + scoring
│   ├── transaction/                # Reservation → Commit → Reverse logic
│   │   ├── service.go
│   │   ├── idempotency.go
│   │   └── validator.go
│   ├── ledger/                     # Double-entry accounting engine
│   ├── provider/                   # Provider connectors + SDKs
│   │   ├── mtn/
│   │   ├── airtel/
│   │   ├── glo/
│   │   ├── vodafone/
│   │   ├── kenya-power/
│   │   └── etc...
│   ├── fees/                       # Provider and user fee computation
│   ├── country/                    # AML rules, country restrictions
│   ├── settlement/                 # Automated settlement jobs
│   └── notifications/              # Webhooks, email, SMS
│
├── pkg/
│   ├── utils/                      # Helper functions
│   ├── logger/                     # Centralized logging
│   ├── middleware/                 # Rate limits, tracing, auth
│   └── events/                     # Kafka producers + consumers
│
├── api/
│   ├── proto/                      # gRPC service definitions
│   └── openapi/                    # REST API documentation
│
├── deployments/
│   ├── docker/                     # Dockerfiles
│   ├── k8s/                        # Kubernetes manifests
│   └── terraform/                  # Infrastructure as Code
│
├── scripts/
│   ├── migrate.sh                  # DB migrations
│   ├── seed.sh                     # Test data
│   └── benchmark.sh                # Load testing
│
├── migrations/                     # Schema migrations (SQL)
│
├── Makefile                        # Build/test shortcuts
├── docker-compose.yaml
├── go.mod
└── README.md




# **Environment Variables (.env)**


APP_ENV=production
PORT=8080

DB_HOST=
DB_PORT=
DB_USER=
DB_PASS=
DB_NAME=

KAFKA_BROKER=
JWT_SECRET=
HASH_SALT=

PROVIDER_MTN_KEY=
PROVIDER_AIRTEL_KEY=
PROVIDER_VODAFONE_KEY=
```



# **REST API Workflow Example**

### **POST /v1/transactions/switch**

```json
{
  "country": "NG",
  "userId": "USER-1212",
  "vuCode": "MTN_AIRTIME_1000",
  "amount": 1000,
  "channel": "PARTNER_API",
  "idempotencyKey": "abc123"
}
```

### **Response**

```json
{
  "status": "RESERVED",
  "transactionId": "TX-8844992",
  "fee": 25,
  "providerChargeApplied": true
}
```



# **Kafka Event Streams**

| Topic               | Purpose               |
| ------------------- | --------------------- |
| switching.reserved  | Holds event           |
| switching.committed | Provider confirmed    |
| switching.reversed  | Error rollback        |
| settlement.process  | Daily settlement      |
| ledger.entry        | All double-entry logs |

---

# **Developer Onboarding**

### **1. Install Dependencies**

```
git clone <repo>
cd switching-engine
go mod tidy
```

### **2. Setup Database**

```
docker-compose up -d postgres
./scripts/migrate.sh
```

### **3. Run API Service**

```
go run cmd/api/main.go
```

### **4. Run Worker Service**

```
go run cmd/worker/main.go
```

---

# **Code Quality & Standards**

We enforce:

* GolangCI-Lint
* Conventional commits
* 80–90% test coverage target
* No business logic in handlers
* Hexagonal architecture
* Trace IDs for every request

---

# **Compliance Considerations**

To operate across Africa:

| Area        | Requirement                            |
| ----------- | -------------------------------------- |
| AML         | Country-bounded switching enforcement  |
| KYC         | Partner validation before API issuance |
| Logging     | 7-year retention for regulated data    |
| Encryption  | AES-256 at rest, TLS 1.3 in transit    |
| Audit       | Provider-by-provider traceability      |
| Rate Limits | Per partner & global throttle          |
