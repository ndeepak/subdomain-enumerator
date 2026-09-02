# Subdomain Enumerator

A simple passive subdomain enumeration tool written in Python.

It collects subdomains from:

- SecurityTrails API (optional)
- crt.sh / Certificate Transparency logs
- Duplicate and wildcard cleanup
- Plain-text output

## Features

- Passive enumeration
- SecurityTrails API support
- crt.sh certificate-based discovery
- Retry and exponential backoff for crt.sh
- Duplicate removal
- Domain validation
- Simple `.txt` output

## Requirements

- Python 3.9+
- `requests`
- `urllib3`

Install dependencies:

```bash
pip install -r requirements.txt
```

## SecurityTrails API Key

Do **not** put API keys directly in the Python source code.

Set the API key as an environment variable.

Linux/macOS:

```bash
export SECURITYTRAILS_API_KEY="YOUR_API_KEY"
```

Windows PowerShell:

```powershell
$env:SECURITYTRAILS_API_KEY="YOUR_API_KEY"
```

An example environment file is provided as `.env.example`.

## Usage

```bash
python getSubDomains.py example.com
```

Example output:

```text
[+] Grabbing subdomains for example.com from SecurityTrails...
[+] Grabbing subdomains from crt.sh (with unexpired certificates)...
[+] Grabbing subdomains from crt.sh (all certificates)...
[+] Cleaning and deduplicating results...

42 unique subdomains found.
Output written to: example.com.txt
```

## Output

The tool creates:

```text
example.com.txt
```

with one discovered hostname per line.

Generated output files are excluded from Git using `.gitignore`.

## Responsible Use

This project is intended for authorized security testing, asset discovery, research, and reconnaissance of domains that are owned or explicitly authorized for testing.

Only enumerate targets where permission has been granted.

## License

MIT License
