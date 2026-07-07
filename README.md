# SOC Entity Management

A platform for automated security entity management in SOC environments. It ingests raw log and alert data, normalizes events to an OCSF-compatible schema, extracts security entities (users, hosts, IPs, domains, file hashes, processes), enriches them with contextual data, infers relationships, and stores everything as a queryable graph — enabling analysts to investigate threats through a unified interface.

## Architecture Overview

```
Client / SIEM Agent
        │
        ▼
┌─────────────────────────────────┐
│   FastAPI Backend               │   JWT auth · REST API · /metrics
│   POST /api/events/ingest-file  │
│   GET  /api/entities            │
│   GET  /api/graph/:id           │
└──────────────┬──────────────────┘
               │ publish
               ▼
┌──────────────────────────────────────┐
│   Kafka                              │
│   raw-events · ocsf-events · DLQ    │
└──────┬────────────────────┬──────────┘
       │                    │
       ▼                    ▼
┌──────────────┐   ┌───────────────────┐
│ Ingestion    │   │  Graph Worker     │
│ Worker       │   │  Extract entities │
│ Detect src   │   │  Enrich (Redis)   │
│ Normalize →  │   │  Infer relations  │
│ OCSF         │   │  Persist to Neo4j │
└──────────────┘   └───────────────────┘
                           │
               ┌───────────┼───────────┐
               ▼           ▼           ▼
           Neo4j       PostgreSQL    Redis
         (graph)     (audit/ingest) (cache)
```

**Stack:** FastAPI · React + Vite · Kafka (KRaft) · Neo4j 5 · PostgreSQL 16 · Redis 7 · Prometheus · Grafana · Docker Compose · Helm

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Local Development (without Docker)](#local-development-without-docker)
- [Full Stack with Docker Compose](#full-stack-with-docker-compose)
- [Running Tests](#running-tests)
- [Test Coverage](#test-coverage)
- [Environment Variables Reference](#environment-variables-reference)
- [Production Deployment (Helm / Kubernetes)](#production-deployment-helm--kubernetes)
- [Service URLs](#service-urls)
- [Project Structure](#project-structure)

---

## Prerequisites

| Tool | Minimum version | Notes |
|---|---|---|
| Python | 3.11+ | Backend & workers |
| Node.js | 18+ | Frontend |
| Docker + Docker Compose | v2.20+ | Full-stack local run |
| kubectl | 1.28+ | Production deploy |
| Helm | 3.14+ | Chart install |

---

## Local Development (without Docker)

> Use this when you want hot-reload on the backend or frontend without building images.
> You still need Neo4j, Kafka, Redis, and PostgreSQL running — the easiest way is to
> start only the infrastructure services via Docker Compose (see below).

### 1. Clone and configure environment

```bash
git clone https://github.com/your-org/soc-entity-management.git
cd soc-entity-management

cp .env.example .env
# Edit .env — at minimum set a strong JWT_SECRET_KEY
```

### 2. Set up the Python virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install -r backend/requirements.txt
pip install -r backend/requirements-dev.txt
```

### 3. Start infrastructure only

```bash
docker compose up -d postgresql redis neo4j kafka kafka-init-topics
```

Wait ~15 seconds for Neo4j and Kafka to be ready, then verify:

```bash
docker compose ps   # all should be "running" or "exited (0)"
```

### 4. Run the backend API

```bash
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

API available at **http://localhost:8000**
Swagger UI at **http://localhost:8000/docs**

### 5. Run the workers (each in a separate terminal)

```bash
# Terminal 2 — ingestion worker
cd backend
python -m app.workers.kafka_ingestion_worker

# Terminal 3 — graph worker
cd backend
python -m app.workers.kafka_graph_worker
```

### 6. Run the frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend available at **http://localhost:5173**

---

## Full Stack with Docker Compose

The easiest way to run the entire system — backend, workers, frontend, and all infrastructure — in one command.

### 1. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and set at minimum:

```env
JWT_SECRET_KEY=your-secret-key-at-least-32-characters
DOCKER_NEO4J_PASSWORD=your-neo4j-password
NEO4J_AUTH=neo4j/your-neo4j-password
POSTGRES_PASSWORD=your-postgres-password
```

> For enrichment features, also set `ENRICHMENT_IPINFO_TOKEN` and `ENRICHMENT_MALWARE_BAZAAR_AUTH_KEY`.

### 2. Start all services

```bash
docker compose up -d
```

This starts:
- `backend` — FastAPI API server
- `kafka-ingestion-worker` — normalizes raw events to OCSF
- `kafka-graph-worker` — extracts entities, enriches, infers relationships
- `frontend` — React UI
- `postgresql` — tenant/auth/audit/ingestion metadata
- `redis` — enrichment cache
- `neo4j` — graph database
- `kafka` + `kafka-init-topics` — event streaming (KRaft mode, no Zookeeper)
- `kafka-ui` — Kafka topic browser
- `prometheus` + `grafana` — monitoring

### 3. Check service health

```bash
curl http://localhost:8000/health
```

Expected response:

```json
{
  "status": "ok",
  "services": {
    "postgresql": {"status": "ok"},
    "redis": {"status": "ok"},
    "neo4j": {"status": "ok"},
    "kafka": {"status": "ok"}
  }
}
```

### 4. Stop and clean up

```bash
docker compose down      # stop containers, keep volumes
docker compose down -v   # stop containers AND remove all volumes
```

---

## Running Tests

Tests run against SQLite (in-memory) and mock all external services. No live Neo4j, Redis, or Kafka required.

```bash
# Activate virtual environment first
source .venv/bin/activate

# Run all tests from the project root
.venv/bin/pytest backend/tests/ -v
```

### Run a specific test file

```bash
.venv/bin/pytest backend/tests/test_graph.py -v
.venv/bin/pytest backend/tests/test_graph_repository.py -v
```

### Integration tests (require live services)

Some tests are skipped unless environment variables are set:

```bash
# Neo4j integration tests
NEO4J_TEST_URI=bolt://localhost:7687 \
NEO4J_TEST_USER=neo4j \
NEO4J_TEST_PASSWORD=neo4j_password \
.venv/bin/pytest backend/tests/test_graph_integration.py -v

# Redis enrichment integration tests
REDIS_TEST_URL=redis://localhost:6379/1 \
.venv/bin/pytest backend/tests/test_enrichment_integration.py -v
```

### CI environment

The CI pipeline (`.github/workflows/ci.yml`) uses `.env.ci.test` which provides a SQLite-backed configuration with all external services mocked.

---

## Test Coverage

```bash
# Collect coverage and print terminal report
.venv/bin/coverage run -m pytest backend/tests/
.venv/bin/coverage report --include="backend/app/**" -m

# Generate HTML report
.venv/bin/coverage html
open backend/htmlcov/index.html
```

Current coverage: **90%** across 3,034 statements (176 test cases).

| Module group | Coverage |
|---|---|
| API layer (auth, entities, events, audit, parsers) | 94–100% |
| Auth (security, service, schemas, dependencies) | 83–98% |
| Ingestion (schemas, kafka_client, kafka_messages, service) | 85–100% |
| Entity extraction | 92% |
| Enrichment | 89–100% |
| Graph (repository, service, inference) | 79–85% |
| Workers (ingestion, graph) | 98% |
| Normalization | 95% |

---

## Environment Variables Reference

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET_KEY` | *(required)* | Secret for signing JWT tokens — use a random 32+ char string in production |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Token lifetime in minutes |
| `DATABASE_URL` | `sqlite:///./soc_entity_management.db` | SQLAlchemy DSN — local dev uses SQLite |
| `DOCKER_DATABASE_URL` | `postgresql+psycopg://soc:...` | PostgreSQL DSN used inside Docker Compose |
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j Bolt URI |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | `password` | Neo4j password |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka broker address |
| `KAFKA_RAW_EVENTS_TOPIC` | `soc.raw-events.v1` | Topic for raw ingested events |
| `KAFKA_OCSF_EVENTS_TOPIC` | `soc.ocsf-events.v1` | Topic for normalized OCSF events |
| `KAFKA_DEAD_LETTER_TOPIC` | `soc.ingest-dlq.v1` | Dead-letter queue for failed messages |
| `ENRICHMENT_PROVIDER_MODE` | `ipinfo_malwarebazaar` | Enrichment provider(s) to enable |
| `ENRICHMENT_IPINFO_TOKEN` | *(empty)* | [ipinfo.io](https://ipinfo.io) API token for IP enrichment |
| `ENRICHMENT_MALWARE_BAZAAR_AUTH_KEY` | *(empty)* | MalwareBazaar API key for file hash enrichment |
| `ENRICHMENT_CACHE_TTL_SECONDS` | `86400` | Redis TTL for cached enrichment results (24 h) |
| `ENRICHMENT_ENABLED` | `true` | Toggle enrichment on/off |
| `VITE_API_PROXY_TARGET` | `http://localhost:8000` | Backend URL proxied by Vite dev server |

---

## Production Deployment (Helm / Kubernetes)

The Helm chart at `charts/soc-entity-management/` deploys the full stack to a Kubernetes cluster. It has been tested on GKE but works on any Kubernetes 1.28+ cluster.

### Prerequisites

- A Kubernetes cluster with a running Ingress controller
- A container registry accessible from the cluster
- `kubectl` configured to point to the target cluster

### 1. Build and push images

```bash
REGISTRY=your-registry.example.com/soc-entity-management
TAG=$(git rev-parse --short HEAD)

docker build -t $REGISTRY/backend:$TAG -f backend/Dockerfile .
docker build -t $REGISTRY/frontend:$TAG -f frontend/Dockerfile .

docker push $REGISTRY/backend:$TAG
docker push $REGISTRY/frontend:$TAG
```

### 2. Create the namespace and secrets

```bash
kubectl create namespace soc

kubectl create secret generic soc-secrets \
  --namespace soc \
  --from-literal=jwt-secret-key="<your-jwt-secret>" \
  --from-literal=postgres-password="<your-postgres-password>" \
  --from-literal=neo4j-password="<your-neo4j-password>" \
  --from-literal=enrichment-ipinfo-token="<your-ipinfo-token>" \
  --from-literal=enrichment-malwarebazaar-auth-key="<your-mb-key>"
```

### 3. Configure values

```bash
cp charts/soc-entity-management/values-gke.yaml my-values.yaml
```

Key fields to update in `my-values.yaml`:

```yaml
global:
  imageRegistry: your-registry.example.com/soc-entity-management
  imageTag: "abc1234"   # Git short SHA from step 1

secrets:
  create: false         # Use the secret created in step 2
  name: soc-secrets

ingress:
  enabled: true
  className: gce        # or nginx, traefik, etc.
  hosts:
    - soc.yourdomain.com
```

### 4. Install or upgrade the chart

```bash
helm upgrade --install soc-entity-management \
  charts/soc-entity-management \
  --namespace soc \
  --create-namespace \
  --values my-values.yaml \
  --wait --timeout 10m
```

### 5. Verify the deployment

```bash
kubectl get pods -n soc
kubectl get ingress -n soc

curl https://soc.yourdomain.com/health
```

### Scaling workers

```bash
# Scale graph workers for higher throughput
kubectl scale deployment soc-kafka-graph-worker --replicas=3 -n soc
```

Or set `workers.graph.replicas: 3` in `my-values.yaml` and re-run `helm upgrade`.

### Upgrading to a new image

```bash
TAG=$(git rev-parse --short HEAD)

helm upgrade soc-entity-management \
  charts/soc-entity-management \
  --namespace soc \
  --values my-values.yaml \
  --set global.imageTag=$TAG \
  --wait
```

---

## Service URLs

### Local (Docker Compose)

| Service | URL |
|---|---|
| Frontend | http://localhost:5173 |
| Backend API | http://localhost:8000 |
| Swagger UI | http://localhost:8000/docs |
| Neo4j Browser | http://localhost:7474 |
| Kafka UI | http://localhost:18080 |
| Prometheus | http://localhost:9090 |
| Grafana | http://localhost:3000 (admin / admin) |

### Local (bare metal)

| Service | URL |
|---|---|
| Backend API | http://localhost:8000 |
| Swagger UI | http://localhost:8000/docs |
| Frontend | http://localhost:5173 |

---

## Project Structure

```
soc-entity-management/
├── backend/
│   ├── app/
│   │   ├── api/           # FastAPI routers (auth, events, entities, audit, parsers)
│   │   ├── auth/          # JWT auth, tenant context, role-based access
│   │   ├── database/      # SQLAlchemy models, session management
│   │   ├── enrichment/    # IP/hash enrichment providers + Redis cache
│   │   ├── entities/      # Entity schemas + extraction logic
│   │   ├── graph/         # Neo4j repository, relationship inference, graph service
│   │   ├── ingestion/     # Kafka producers, batch tracking, error records
│   │   ├── normalization/ # OCSF event normalization helpers
│   │   ├── ocsf/          # OCSF schema + vendor adapters (Wazuh, Sysmon, WinSec)
│   │   ├── parsers/       # YAML-driven log parser registry
│   │   ├── workers/       # kafka_ingestion_worker, kafka_graph_worker
│   │   ├── observability/ # Prometheus metrics
│   │   └── main.py        # FastAPI app entry point
│   ├── tests/             # 176 test cases (unit + integration)
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── App.tsx         # Main app — entity list, detail, graph view, ingest
│       ├── GraphView.tsx   # Force-graph visualization
│       ├── api.ts          # API client functions
│       └── types.ts        # TypeScript types
├── charts/
│   └── soc-entity-management/  # Helm chart for Kubernetes deployment
├── infra/
│   └── monitoring/
│       ├── prometheus/     # prometheus.yml scrape config
│       └── grafana/        # Provisioned datasources + dashboards
├── config/
│   └── parsers/            # YAML parser definitions
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Contributing

1. Fork the repository and create a feature branch
2. Run existing tests before making changes: `.venv/bin/pytest backend/tests/ -v`
3. Add tests for new behavior
4. Ensure coverage does not drop below 85% on changed modules
5. Open a pull request — CI will run tests automatically via GitHub Actions
