# Health Check Action

[![GitHub Release](https://img.shields.io/github/v/release/MrMiless44/Infamous-freight-enterprises?filter=health-check-*)](https://github.com/MrMiless44/Infamous-freight-enterprises/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](../../../LICENSE)

Performs health checks with configurable retries and validation for deployment pipelines.

## Features

- ✅ Configurable retry logic with exponential backoff
- ✅ HTTP status code validation
- ✅ JSON response validation
- ✅ JSON path verification
- ✅ Response time measurement
- ✅ Detailed logging and error messages
- ✅ GitHub Actions output variables

## Usage

### Basic Health Check

```yaml
- name: Check API Health
  uses: ./.github/actions/health-check
  with:
    url: https://api.example.com/health
```

### Advanced Configuration

```yaml
- name: Check API Health with Validation
  uses: ./.github/actions/health-check
  with:
    url: https://api.example.com/health
    max-retries: 15
    retry-delay: 10
    timeout: 30
    expected-status: "200"
    validate-json: "true"
    json-path: "status"
```

### Using Outputs

```yaml
- name: Health Check
  id: health
  uses: ./.github/actions/health-check
  with:
    url: https://api.example.com/health
    validate-json: "true"

- name: Use Health Check Results
  run: |
    echo "Success: ${{ steps.health.outputs.success }}"
    echo "Attempts: ${{ steps.health.outputs.attempts }}"
    echo "Response Time: ${{ steps.health.outputs.response-time }}ms"
    echo "Body: ${{ steps.health.outputs.response-body }}"
```

## Inputs

| Input             | Description                          | Required | Default |
| ----------------- | ------------------------------------ | -------- | ------- |
| `url`             | URL to health check endpoint         | ✅ Yes   | -       |
| `max-retries`     | Maximum number of retry attempts     | No       | `10`    |
| `retry-delay`     | Delay between retries (seconds)      | No       | `5`     |
| `timeout`         | Timeout for each request (seconds)   | No       | `10`    |
| `expected-status` | Expected HTTP status code            | No       | `200`   |
| `validate-json`   | Validate response is valid JSON      | No       | `false` |
| `json-path`       | JSON path to verify (e.g., `status`) | No       | ` `     |

## Outputs

| Output          | Description                                     |
| --------------- | ----------------------------------------------- |
| `success`       | Whether health check succeeded (`true`/`false`) |
| `attempts`      | Number of attempts made before success          |
| `response-time` | Response time in milliseconds                   |
| `response-body` | Response body from successful check             |

## Examples

### Production Deployment with Health Check

```yaml
- name: Deploy to Production
  run: ./deploy.sh

- name: Verify Deployment
  uses: ./.github/actions/health-check
  with:
    url: ${{ secrets.PRODUCTION_URL }}/api/health
    max-retries: 20
    retry-delay: 15
    validate-json: "true"
    json-path: "database"
```

### Multi-Service Health Checks

```yaml
- name: Check API
  uses: ./.github/actions/health-check
  with:
    url: https://api.example.com/health

- name: Check Web
  uses: ./.github/actions/health-check
  with:
    url: https://web.example.com/api/health

- name: Check Database
  uses: ./.github/actions/health-check
  with:
    url: https://api.example.com/health
    json-path: "database"
```

## Error Handling

The action will:

- Retry up to `max-retries` times with `retry-delay` between attempts
- Exit with status 1 if all retries fail
- Provide detailed error messages for debugging
- Output attempt count even on failure

## Contributing

See [CONTRIBUTING.md](../../../CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](../../../LICENSE)
