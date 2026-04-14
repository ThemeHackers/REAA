# Ghidra Headless REST API - Production Ready

A production-ready REST API for Ghidra headless analysis, designed for AI-Assisted Reverse Engineering and malware analysis. Built with FastAPI, Celery, and Redis for scalable, async task processing.

## Features

- **Async Task Queue**: Uses Celery + Redis for background analysis jobs (no server hangs)
- **Production Docker**: Optimized Dockerfile with Ubuntu 22.04, Java 17, and Ghidra 11.3.2
- **Structured Logging**: JSON-based logging with structlog for production monitoring
- **Health Checks**: Built-in health check and metrics endpoints
- **Auto Cleanup**: Periodic cleanup of old completed jobs
- **MCP Integration**: Model Context Protocol tool definitions for AI integration
- **Comprehensive Analysis**: Functions, decompilation, cross-references, imports, strings

## Architecture

```
┌─────────────┐      ┌─────────────┐      ┌──────────────┐
│   FastAPI   │─────▶│    Redis    │◀─────│  Celery      │
│   (API)     │      │  (Broker)   │      │  Worker      │
└─────────────┘      └─────────────┘      └──────────────┘
                                               │
                                               ▼
                                        ┌──────────────┐
                                        │   Ghidra     │
                                        │  Headless    │
                                        └──────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- At least 4GB RAM (8GB recommended for large binaries)

### Deployment

1. **Clone and configure**:
```bash
git clone <repository>
cd REAA
cp .env.example .env
# Edit .env with your settings if needed
```

2. **Build and start services**:
```bash
docker-compose up -d
```

3. **Verify deployment**:
```bash
curl http://localhost:8000/health
```

## API Endpoints

### Analysis

- `POST /analyze` - Upload binary file for analysis
- `POST /analyze_b64` - Upload base64-encoded binary
- `GET /status/{job_id}` - Get job status
- `GET /status/{job_id}/celery` - Get detailed Celery task status
- `GET /jobs` - List all jobs

### Results

- `GET /results/{job_id}/functions` - List functions (paginated)
- `GET /results/{job_id}/function/{addr}/decompile` - Get decompiled pseudocode
- `GET /results/{job_id}/xrefs/{addr}` - Get cross-references
- `GET /results/{job_id}/imports` - List imported symbols
- `GET /results/{job_id}/strings` - List strings
- `POST /query` - Natural language search over artifacts

### Monitoring

- `GET /health` - Health check endpoint
- `GET /metrics` - Prometheus-style metrics

### MCP Integration

- `GET /mcp/descriptor` - MCP tool descriptor
- `GET /mcp/tools` - MCP tools definition
- `POST /tools/*` - MCP tool endpoints

## Usage Examples

### Analyze a binary

```bash
curl -X POST http://localhost:8000/analyze \
  -F "file=@malware.exe" \
  -F "persist=false"
```

Response:
```json
{
  "job_id": "a1b2c3d4e5f6...",
  "status": "queued",
  "task_id": "abc-123-def-456"
}
```

### Check status

```bash
curl http://localhost:8000/status/a1b2c3d4e5f6...
```

### List functions

```bash
curl http://localhost:8000/results/a1b2c3d4e5f6.../functions?offset=0&limit=100
```

### Get decompiled code

```bash
curl http://localhost:8000/results/a1b2c3d4e5f6.../function/0x401000/decompile
```

## Configuration

Environment variables in `.env`:

- `GHIDRA_HOME` - Path to Ghidra installation (default: `/opt/ghidra`)
- `DATA_DIR` - Directory for analysis artifacts (default: `/data/ghidra_projects`)
- `MAX_UPLOAD_SIZE` - Maximum file size in bytes (default: 209715200 = 200MB)
- `REDIS_URL` - Redis connection URL (default: `redis://localhost:6379/0`)
- `CELERY_BROKER_URL` - Celery broker URL (default: `redis://localhost:6379/0`)
- `CELERY_TASK_TIMEOUT` - Task timeout in seconds (default: 1800 = 30 minutes)

## Ghidra Scripts

Custom Ghidra analysis scripts are located in `ghidra_scripts/`:

- `export_json.py` - Main export script that extracts:
  - Functions with metadata
  - Cross-references
  - Imported symbols
  - Strings
  - Decompiled pseudocode

To add custom analysis, modify or add scripts in the `ghidra_scripts/` directory.

## Development

### Local development without Docker

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Install Ghidra 11.3.2 and set `GHIDRA_HOME` environment variable

3. Start Redis:
```bash
redis-server
```

4. Start Celery worker:
```bash
celery -A core.celery_app worker --loglevel=info
```

5. Start API server:
```bash
uvicorn core.app:app --reload --port 8000
```

## Monitoring

### Health Check
```bash
curl http://localhost:8000/health
```

Returns system status, Redis connectivity, Celery worker count, and system metrics.

### Metrics
```bash
curl http://localhost:8000/metrics
```

Returns job counts by status and system resource usage.

## Troubleshooting

### Celery worker not processing tasks
- Check worker logs: `docker-compose logs celery-worker`
- Verify Redis connection: `docker-compose logs redis`
- Check Celery broker URL in `.env`

### Ghidra analysis fails
- Check Ghidra binary path: `docker-compose exec ghidra-api ls -la $GHIDRA_BIN`
- Verify script path: `docker-compose exec ghidra-api ls -la $GHIDRA_SCRIPTS`
- Check worker logs for detailed error messages

### Out of memory errors
- Increase Docker memory limit in docker-compose.yml
- Reduce `CELERY_TASK_TIMEOUT` for faster cleanup
- Increase system RAM or use larger instance

## Production Considerations

1. **Persistence**: Mount volumes for data directory to persist analysis results
2. **Scaling**: Increase Celery worker count in docker-compose.yml for parallel processing
3. **Security**: Add authentication/authorization middleware for API endpoints
4. **Monitoring**: Integrate with Prometheus/Grafana for production monitoring
5. **Rate Limiting**: Add rate limiting to prevent abuse
6. **TLS**: Enable HTTPS for production deployments

## License

This project is based on the biniamfd/ghidra-headless-rest reference implementation.

## Contributing

Contributions are welcome! Please ensure all tests pass before submitting PRs.
