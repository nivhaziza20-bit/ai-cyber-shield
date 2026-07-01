# AI Cyber Shield — GitHub Action

Scan any URL for security vulnerabilities directly inside your CI/CD pipeline. 17 OSINT tools, AI-powered analysis, SARIF upload, and a pipeline gate based on security grade.

![Security Score](https://api.aicybershield.com/api/v1/badge/example.com)

## Quick Start

```yaml
name: Security Scan
on: [push]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - name: Scan staging
        uses: your-org/ai-cyber-shield-action@v1
        with:
          target_url: 'https://staging.example.com'
          api_key: ${{ secrets.CYBERSHIELD_API_KEY }}
          fail_on_grade: 'C'
```

## Advanced — Deploy gate with SARIF upload

```yaml
name: Deploy with Security Gate
on:
  push:
    branches: [main]
jobs:
  deploy-staging:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Deploy to staging
        run: ./deploy-staging.sh

      - name: Security scan
        id: security
        uses: your-org/ai-cyber-shield-action@v1
        with:
          target_url: 'https://staging.example.com'
          api_key: ${{ secrets.CYBERSHIELD_API_KEY }}
          fail_on_grade: 'C'
          fail_on_critical: 'true'
          upload_sarif: 'true'

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scan-results.sarif

      - name: Deploy to production
        if: success()
        run: ./deploy-production.sh
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `target_url` | ✅ | — | URL to scan |
| `api_key` | ✅ | — | AI Cyber Shield API key |
| `api_endpoint` | ✗ | `https://your-api-url.com` | API base URL |
| `fail_on_grade` | ✗ | `D` | Fail if grade is this or worse (A/B/C/D/F) |
| `fail_on_critical` | ✗ | `true` | Fail if any CRITICAL finding exists |
| `timeout_minutes` | ✗ | `5` | Max wait time for scan completion |
| `upload_sarif` | ✗ | `true` | Upload SARIF to GitHub Code Scanning |

## Outputs

| Output | Description |
|--------|-------------|
| `overall_score` | Security score (0–100) |
| `overall_grade` | Security grade (A–F) |
| `findings_critical` | Number of critical findings |
| `findings_high` | Number of high findings |
| `findings_total` | Total findings count |
| `scan_url` | Link to full results in dashboard |
| `sarif_file` | Path to SARIF output file |

## Security badge

Add your live security score to your README:

```markdown
![Security](https://api.aicybershield.com/api/v1/badge/yoursite.com)
```

## Pricing

The free tier allows 5 scans/month. A CI/CD pipeline that runs on every push will exceed that quickly.

- **Starter (€20/mo)** — 50 scans/month + API access → good for small teams
- **Pro (€50/mo)** — 200 scans/month + CI/CD action + PT mode → recommended for active projects
- **Enterprise** — unlimited, SLA, SSO → contact us

[See full pricing →](https://aicybershield.com/#pricing)
