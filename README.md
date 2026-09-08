# Subdomain Enumerator

A lightweight, passive subdomain discovery tool for authorized reconnaissance and asset discovery.

It pulls results from public certificate transparency data and, optionally, the SecurityTrails API, then normalizes and deduplicates the discovered hostnames into a clean output file.

## Why use it

- Fast and simple to run
- Faithful to passive discovery workflows
- No browser automation or noisy scanning
- Produces a plain-text list of valid subdomains
- Safe for open-source sharing with clear responsible-use guidance

## Sources used

- SecurityTrails API (optional, requires an API key)
- crt.sh certificate transparency logs
- Local validation and deduplication for clean output

## Features

- Passive subdomain enumeration
- Optional SecurityTrails integration
- crt.sh queries for certificate-based discovery
- Concurrent HTTP(S) probing of discovered hosts
- Retry, backoff, and rate-limit handling
- Duplicate and wildcard cleanup
- Domain validation for hostnames under the target domain
- Output saved as a `.txt` file with one hostname per line
- Optional live-service results saved as JSONL

## Requirements

- Python 3.9+
- `requests`
- `urllib3`

## Installation

Clone the repo and install dependencies:

```bash
git clone https://github.com/your-username/subdomain-enumerator.git
cd subdomain-enumerator
python -m pip install -r requirements.txt
```

Or install directly from source once the project metadata is available:

```bash
python -m pip install .
```

## Environment configuration

Do not hardcode API keys into the script.

Set the SecurityTrails key as an environment variable:

Linux/macOS:

```bash
export SECURITYTRAILS_API_KEY="YOUR_API_KEY"
```

Windows PowerShell:

```powershell
$env:SECURITYTRAILS_API_KEY="YOUR_API_KEY"
```

A template is included at `.env.example`.

## Usage

```bash
python getSubDomains.py example.com
```

Optional custom output path:

```bash
python getSubDomains.py example.com -o output/example-domains.txt
```

Runtime controls are available when tuning requests for a specific environment:

```bash
python getSubDomains.py example.com --workers 4 --timeout 30 --retries 3
python getSubDomains.py example.com --no-securitytrails
```

To run `gau` for multiple domains, place one domain per line in `all_domains.txt`.
Blank lines and comments beginning with `#` are ignored:

```bash
python gau_batch.py --input all_domains.txt --output-dir gau-results --delay 60
```

The batch runner invokes `gau` without a shell, reports failed processes, and returns
a non-zero exit status when any domain fails. Use `--gau-command` when the executable
is not on `PATH`.

Probe the enumerator output for reachable HTTP(S) services:

```bash
python probe_subdomains.py --input example.com.txt --output live-hosts.jsonl --workers 20
```

The probe tries HTTPS first and falls back to HTTP when TLS is unavailable. It records
the responding URL, redirect destination, status code, content type, page title, and
response time. Use `--insecure` for authorized environments with self-signed certificates.
The installed console command is also available:

```bash
subdomain-probe -i example.com.txt -o live-hosts.jsonl
```

Each output line is a JSON object. Hosts that do not respond include an `error` field;
responsive hosts include `status_code` and metadata suitable for further filtering.

Example output:

```text
[2026-09-02 10:15:04] Starting subdomain enumeration for example.com...
[2026-09-02 10:15:12] SecurityTrails: Found 12 new subdomains.
[2026-09-02 10:15:17] crt.sh: Found 29 new subdomains.
[2026-09-02 10:15:17] Cleaning and validating domain names...
[2026-09-02 10:15:17] Complete! Found 41 unique subdomains in 13.2s.
[2026-09-02 10:15:17] Results saved to example.com.txt
```

## Output format

The tool writes a plain-text file named:

```text
example.com.txt
```

Each line contains one valid subdomain, for example:

```text
www.example.com
api.example.com
mail.example.com
```

Generated output files are ignored by Git via `.gitignore`.

## Responsible use

This project is intended for authorized security testing, asset discovery, research, and reconnaissance of domains owned by the user or explicitly authorized for testing.

Do not use it against systems without permission. Unlawful or abusive use is strictly prohibited.

## Contributing

Contributions are welcome. If you would like to improve the tool, please:

1. Open an issue to discuss the change
2. Create a feature branch
3. Keep the project focused, readable, and security-conscious
4. Run the test suite before submitting a PR

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
