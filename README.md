# APIGuardian

Enterprise API Security Testing & Monitoring Platform

## Features

- **Security Analyzers**: JWT analysis, IDOR detection, rate limiting checks
- **Payload Fuzzing**: SQL injection, XSS, LFI testing with curated payloads
- **API Discovery**: OpenAPI/Swagger spec parsing and endpoint enumeration
- **Threat Intelligence**: VirusTotal, AbuseIPDB, and more (mock/live modes)
- **Real-time Dashboard**: WebSocket-powered live updates
- **SIEM Integration**: Splunk, Elasticsearch, QRadar connectors
- **Alert Notifications**: Slack, Teams, Email notifiers
- **Scheduled Scans**: Cron-based recurring security assessments

## Quick Start

```bash
# Start the server
cd /app/backend
python server.py

# Access dashboard
open http://localhost:8001/

# Run a scan
curl -X POST http://localhost:8001/api/jobs \
  -H "Content-Type: application/json" \
  -d '{"target": "https://api.example.com", "scan_type": "quick"}'
```

## Documentation

- [RUNBOOK.md](backend/RUNBOOK.md) - Operations guide
- [MANIFEST.txt](backend/MANIFEST.txt) - Project structure
- [SECRETS.env.example](backend/SECRETS.env.example) - API keys template

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web dashboard |
| `/health` | GET | Health check |
| `/api/metrics` | GET | Dashboard metrics |
| `/api/jobs` | GET/POST | List/create scans |
| `/api/findings` | GET | List security findings |
| `/api/threatintel/lookup` | POST | Threat intel lookup |
| `/ws/stream` | WS | Live updates |

## Tech Stack

- **Backend**: Python 3.11+, FastAPI, SQLAlchemy
- **Database**: SQLite
- **HTTP Client**: httpx (async)
- **Scheduler**: APScheduler
- **Templates**: Jinja2

## License

MIT License
