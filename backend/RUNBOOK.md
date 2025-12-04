# APIGuardian Operations Runbook

## Quick Start

### 1. Start the Server

```bash
# Via supervisor (production)
sudo supervisorctl restart backend

# Direct run (development)
cd /app/backend
python server.py
```

### 2. Access Dashboard

Open in browser: `http://localhost:8001/` (or your configured URL)

### 3. Run Your First Scan

```bash
# Via API
curl -X POST http://localhost:8001/api/jobs \
  -H "Content-Type: application/json" \
  -d '{"target": "https://api.example.com", "scan_type": "quick"}'
```

## Configuration

### API Keys Setup

1. Copy the secrets template:
   ```bash
   cp SECRETS.env.example SECRETS.env
   ```

2. Edit `SECRETS.env` and add your API keys

3. Load secrets in your environment or add to `.env`

### Live vs Mock Mode

By default, all integrations run in **mock mode** (no external API calls).

To use live mode for threat intelligence:

```bash
curl -X POST http://localhost:8001/api/threatintel/lookup \
  -H "Content-Type: application/json" \
  -d '{"indicator": "8.8.8.8", "indicator_type": "ip", "service": "virustotal", "mode": "live"}'
```

## Common Operations

### View Scan Status

```bash
curl http://localhost:8001/api/jobs
```

### Get Findings

```bash
# All findings
curl http://localhost:8001/api/findings

# Filter by severity
curl "http://localhost:8001/api/findings?severity=critical"

# Filter by status
curl "http://localhost:8001/api/findings?status=open"
```

### Update Finding Status

```bash
curl -X PATCH http://localhost:8001/api/findings/{finding_id} \
  -H "Content-Type: application/json" \
  -d '{"status": "resolved", "comment": "Fixed in PR #123"}'
```

### Schedule Recurring Scans

```bash
curl -X POST http://localhost:8001/api/scheduler/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Nightly API Scan",
    "target": "https://api.example.com",
    "cron_expression": "0 2 * * *",
    "scan_type": "full"
  }'
```

### WebSocket Live Updates

```javascript
const ws = new WebSocket('ws://localhost:8001/ws/stream');
ws.onmessage = (e) => console.log(JSON.parse(e.data));
```

## Troubleshooting

### Server Won't Start

1. Check logs:
   ```bash
   tail -f /var/log/supervisor/backend.err.log
   ```

2. Verify dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Check database permissions:
   ```bash
   ls -la /app/backend/apiguardian.db
   ```

### Scans Not Running

1. Check job status:
   ```bash
   curl http://localhost:8001/api/jobs
   ```

2. Look for errors in job details:
   ```bash
   curl http://localhost:8001/api/jobs/{job_id}
   ```

### Integration Not Working

1. Test integration in mock mode first:
   ```bash
   curl -X POST http://localhost:8001/api/integrations/test/messaging/slack?mode=mock
   ```

2. Verify API keys are set:
   ```bash
   curl http://localhost:8001/api/threatintel/services
   ```

## Health Monitoring

### Health Check

```bash
curl http://localhost:8001/health
```

### Prometheus Metrics

```bash
curl http://localhost:8001/metrics
```

### Dashboard Metrics

```bash
curl http://localhost:8001/api/metrics
```

## Security Best Practices

1. **Never enable destructive mode** (`enable_destructive: true`) against production APIs
2. **Use mock mode** for testing before running live scans
3. **Rate limit** requests to avoid overwhelming target APIs
4. **Review findings** before reporting to stakeholders
5. **Store API keys** in `SECRETS.env`, never commit to git
