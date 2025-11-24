# certbot-dns-poweradmin

[![Test](https://github.com/poweradmin/certbot-dns-poweradmin/actions/workflows/test.yml/badge.svg)](https://github.com/poweradmin/certbot-dns-poweradmin/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/poweradmin/certbot-dns-poweradmin/graph/badge.svg?token=3686WTALGK)](https://codecov.io/gh/poweradmin/certbot-dns-poweradmin)
[![PyPI](https://img.shields.io/pypi/v/certbot-dns-poweradmin)](https://pypi.org/project/certbot-dns-poweradmin/)
[![Python](https://img.shields.io/pypi/pyversions/certbot-dns-poweradmin)](https://pypi.org/project/certbot-dns-poweradmin/)

PowerAdmin DNS Authenticator plugin for Certbot

This plugin automates the process of completing a `dns-01` challenge by creating, and subsequently removing, TXT records using the PowerAdmin API.

## Installation

```
pip install certbot-dns-poweradmin
```

## PowerAdmin Configuration

Your PowerAdmin installation needs to have the API enabled. The plugin supports both API v1 and v2.

You'll need an API key with permissions to:
- List zones
- Create DNS records
- Delete DNS records

## Usage

1. Create a credential file (e.g., `/etc/letsencrypt/poweradmin.ini`):

```ini
dns_poweradmin_api_url = https://poweradmin.example.com
dns_poweradmin_api_key = your-api-key-here
dns_poweradmin_api_version = v2
```

The `api_version` is optional and defaults to `v2`. Set it to `v1` if your PowerAdmin installation uses the older API.

2. Secure the credential file:

```
chmod 600 /etc/letsencrypt/poweradmin.ini
```

3. Run certbot:

```
certbot certonly \
  --authenticator dns-poweradmin \
  --dns-poweradmin-credentials /etc/letsencrypt/poweradmin.ini \
  -d example.com
```

## Arguments

| Argument                               | Description                                        |
|----------------------------------------|----------------------------------------------------|
| `--dns-poweradmin-credentials`         | Path to credentials INI file (required)            |
| `--dns-poweradmin-propagation-seconds` | Seconds to wait for DNS propagation (default: 120) |

## Examples

Get a certificate for a single domain:

```
certbot certonly \
  --authenticator dns-poweradmin \
  --dns-poweradmin-credentials /etc/letsencrypt/poweradmin.ini \
  -d example.com
```

Get a wildcard certificate:

```
certbot certonly \
  --authenticator dns-poweradmin \
  --dns-poweradmin-credentials /etc/letsencrypt/poweradmin.ini \
  -d example.com \
  -d "*.example.com"
```

With custom propagation time:

```
certbot certonly \
  --authenticator dns-poweradmin \
  --dns-poweradmin-credentials /etc/letsencrypt/poweradmin.ini \
  --dns-poweradmin-propagation-seconds 300 \
  -d example.com
```

## Docker

```dockerfile
FROM certbot/certbot
RUN pip install certbot-dns-poweradmin
```

Build and run:

```
docker build -t certbot/dns-poweradmin .

docker run --rm \
  -v /etc/letsencrypt:/etc/letsencrypt \
  -v /var/lib/letsencrypt:/var/lib/letsencrypt \
  certbot/dns-poweradmin certonly \
  --authenticator dns-poweradmin \
  --dns-poweradmin-credentials /etc/letsencrypt/poweradmin.ini \
  -d example.com
```

## Troubleshooting

### Plugin not found by certbot

If `certbot plugins` doesn't show `dns-poweradmin`, ensure both certbot and the plugin are installed in the same Python environment:

```bash
# Check where certbot is installed
which certbot

# If using system certbot but plugin in venv, either:
# Option 1: Install certbot in the same venv
pip install certbot certbot-dns-poweradmin

# Option 2: Use certbot from the venv
python -m certbot plugins
```

### Virtual environment usage

When using a virtual environment, install both certbot and the plugin together:

```bash
python3 -m venv certbot-env
source certbot-env/bin/activate
pip install certbot certbot-dns-poweradmin

# Run certbot from the venv
certbot plugins  # should show dns-poweradmin
```

### API connection issues

- Verify your API URL is correct and accessible
- Check that your API key has the required permissions

## License

Apache License 2.0
