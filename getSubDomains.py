#!/usr/bin/env python3

import json
import os
import sys
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY")

if len(sys.argv) < 2:
    print(f"Usage: python {Path(sys.argv[0]).name} <domain>")
    sys.exit(1)

domain = sys.argv[1].lower().strip().rstrip(".")

all_subs = set()


def do_securitytrails():
    print(f"[+] Grabbing subdomains for {domain} from SecurityTrails...")

    if not SECURITYTRAILS_API_KEY:
        print("[!] SECURITYTRAILS_API_KEY is not set. Skipping SecurityTrails.")
        return

    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"apikey": SECURITYTRAILS_API_KEY}

    try:
        response = requests.get(
            url,
            headers=headers,
            verify=False,
            timeout=15,
        )

        if response.status_code == 200:
            data = response.json()
            for sub in data.get("subdomains", []):
                all_subs.add(f"{sub}.{domain}")

        elif response.status_code in (401, 403):
            print("[!] SecurityTrails: API key is invalid or unauthorized.")
        else:
            print(f"[!] SecurityTrails returned HTTP {response.status_code}")

    except requests.RequestException as exc:
        print(f"[!] SecurityTrails request failed: {exc}")


def query_crt_sh(url):
    """Query crt.sh with retries and exponential backoff."""
    headers = {
        "User-Agent": "subdomain-enumerator/1.0",
        "Accept": "application/json",
    }

    max_retries = 10
    backoff = 2

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=45,
                verify=False,
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, list):
                        return data
                except (ValueError, TypeError, json.JSONDecodeError):
                    pass

            elif response.status_code == 429:
                print(f"[!] crt.sh rate limited (attempt {attempt}/{max_retries})")

        except requests.RequestException as exc:
            print(f"[!] crt.sh request failed (attempt {attempt}/{max_retries}): {exc}")

        time.sleep(backoff)
        backoff = min(backoff * 2, 30)

    return []


def do_crt(exclude_expired=False):
    label = "with unexpired certificates" if exclude_expired else "all certificates"
    print(f"[+] Grabbing subdomains from crt.sh ({label})...")

    url = f"https://crt.sh/?q=%.{domain}&output=json"

    if exclude_expired:
        url += "&exclude=expired"

    results = query_crt_sh(url)

    for cert in results:
        name_value = cert.get("name_value", "")

        for name in name_value.splitlines():
            name = name.strip()
            if name:
                all_subs.add(name)


def clean_and_deduplicate():
    print("[+] Cleaning and deduplicating results...")

    final_subs = set()

    for sub in all_subs:
        cleaned = sub.lower().strip()

        if cleaned.startswith("*."):
            cleaned = cleaned[2:]

        cleaned = cleaned.rstrip(".")

        if cleaned == domain or cleaned.endswith(f".{domain}"):
            if all(c.isalnum() or c in "-." for c in cleaned):
                final_subs.add(cleaned)

    return sorted(final_subs)


def main():
    do_securitytrails()
    do_crt(exclude_expired=True)
    do_crt()

    final_subs = clean_and_deduplicate()
    output_file = f"{domain}.txt"

    try:
        with open(output_file, "w", encoding="utf-8") as output:
            for sub in final_subs:
                output.write(f"{sub}\n")

        print(f"\n[+] {len(final_subs)} unique subdomains found.")
        print(f"[+] Output written to: {output_file}")

    except OSError as exc:
        print(f"[!] Failed to write output file: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
