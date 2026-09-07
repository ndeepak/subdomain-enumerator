#!/usr/bin/env python3

import argparse
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")
MAX_WORKERS = max(3, min(8, (os.cpu_count() or 1) + 4))
TIMEOUT = 20
RETRY_ATTEMPTS = 5
INITIAL_BACKOFF = 1

lock = threading.Lock()
allSubs = set()


def log(message):
    with lock:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")


def get_common_headers():
    return {
        "User-Agent": "subdomain-enumerator/1.0",
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
    }


def normalize_subdomain(value, domain=None):
    cleaned = str(value).strip().lower().rstrip(".")
    if cleaned.startswith("*."):
        cleaned = cleaned[2:]
    if cleaned.startswith("."):
        cleaned = cleaned[1:]
    if not cleaned:
        return ""

    labels = cleaned.split(".")
    if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
        return ""

    if not all(char.isalnum() or char in "-." for char in cleaned):
        return ""

    if domain and cleaned != domain and not cleaned.endswith("." + domain):
        return ""

    return cleaned


def make_session():
    session = requests.Session()
    session.headers.update(get_common_headers())
    session.verify = False
    return session


def query_with_retry(
    url,
    headers=None,
    timeout=TIMEOUT,
    session=None,
    retry_attempts=RETRY_ATTEMPTS,
):
    if session is None:
        session = make_session()
    if headers is None:
        headers = get_common_headers()

    backoff = INITIAL_BACKOFF
    for attempt in range(1, retry_attempts + 1):
        try:
            response = session.get(url, headers=headers, timeout=timeout)

            if response.status_code == 200:
                try:
                    return response.json()
                except (ValueError, TypeError, json.JSONDecodeError):
                    log(f"[!] Invalid JSON response (attempt {attempt}/{retry_attempts})")

            elif response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                sleep_for = float(retry_after) if retry_after is not None else backoff * 3
                log(f"[!] Rate limited (attempt {attempt}/{retry_attempts}), backing off for {sleep_for:.1f}s")
                time.sleep(sleep_for)
                backoff = min(backoff * 2, 20)
                continue

            elif response.status_code in (404, 410):
                return []

            elif response.status_code in (401, 403):
                log(f"[!] Access denied: HTTP {response.status_code}")
                return []

            else:
                log(f"[!] HTTP {response.status_code} (attempt {attempt}/{retry_attempts})")

        except requests.exceptions.Timeout:
            log(f"[!] Request timed out (attempt {attempt}/{retry_attempts})")
        except requests.exceptions.RequestException as exc:
            log(f"[!] Request failed: {exc} (attempt {attempt}/{retry_attempts})")

        if attempt < retry_attempts:
            time.sleep(backoff)
            backoff = min(backoff * 2, 20)

    return []


def add_subdomain(subdomain, domain):
    cleaned = normalize_subdomain(subdomain, domain)
    if not cleaned:
        return False

    with lock:
        if cleaned not in allSubs:
            allSubs.add(cleaned)
            return True
    return False


def doSecurityTrails(domain, timeout=TIMEOUT, retries=RETRY_ATTEMPTS):
    if not API_KEY:
        log("[!] SECURITYTRAILS_API_KEY is not set. Skipping SecurityTrails.")
        return

    log("Querying SecurityTrails...")
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {**get_common_headers(), "apikey": API_KEY}

    try:
        data = query_with_retry(
            url,
            headers=headers,
            session=make_session(),
            timeout=timeout,
            retry_attempts=retries,
        )
        if not isinstance(data, dict):
            log("[!] SecurityTrails: Unexpected response format.")
            return

        count = 0
        for sub in data.get("subdomains", []):
            if isinstance(sub, str) and add_subdomain(f"{sub}.{domain}", domain):
                count += 1

        log(f"SecurityTrails: Found {count} new subdomains.")
    except Exception as exc:
        log(f"[!] SecurityTrails error: {exc}")


def doCRT(domain, timeout=TIMEOUT, retries=RETRY_ATTEMPTS):
    log("Querying crt.sh...")

    urls = [
        (f"https://crt.sh/?q=%.{domain}&output=json&exclude=expired", "unexpired certificates"),
        (f"https://crt.sh/?q=%.{domain}&output=json", "all certificates"),
    ]

    count = 0
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(query_crt_source, url, cert_type, domain, timeout, retries)
            for url, cert_type in urls
        ]

        for future in as_completed(futures):
            try:
                count += future.result()
            except Exception as exc:
                log(f"[!] crt.sh worker error: {exc}")

    log(f"crt.sh: Found {count} new subdomains.")


def query_crt_source(url, cert_type, domain, timeout=TIMEOUT, retries=RETRY_ATTEMPTS):
    log(f"crt.sh: Querying {cert_type}...")
    results = query_with_retry(
        url,
        session=make_session(),
        timeout=timeout,
        retry_attempts=retries,
    )

    if not isinstance(results, list):
        log(f"[!] crt.sh: Unexpected response for {cert_type}.")
        return 0

    count = 0
    for cert in results:
        if not isinstance(cert, dict):
            continue

        name_value = cert.get("name_value", "")
        if not isinstance(name_value, str):
            continue

        for name in name_value.splitlines():
            if name.strip() and add_subdomain(name, domain):
                count += 1

    return count


def clean_and_deduplicate(candidates, domain):
    cleaned = set()
    for sub in candidates:
        normalized = normalize_subdomain(sub, domain)
        if normalized:
            cleaned.add(normalized)
    return sorted(cleaned)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Enumerate subdomains using passive sources.")
    parser.add_argument("domain", help="Target domain to enumerate")
    parser.add_argument("--workers", type=int, default=MAX_WORKERS, help="Maximum concurrent source workers")
    parser.add_argument("--timeout", type=float, default=TIMEOUT, help="HTTP request timeout in seconds")
    parser.add_argument("--retries", type=int, default=RETRY_ATTEMPTS, help="Number of HTTP attempts per request")
    parser.add_argument(
        "--no-securitytrails",
        action="store_true",
        help="Skip the SecurityTrails source even when an API key is configured",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file path. Defaults to <domain>.txt",
    )
    args = parser.parse_args(argv)
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")
    if args.retries < 1:
        parser.error("--retries must be at least 1")
    return args


def main():
    args = parse_args()
    domain = args.domain.lower().strip().rstrip(".")

    if not domain:
        print("A valid domain is required.", file=sys.stderr)
        sys.exit(1)

    allSubs.clear()
    start_time = time.time()
    log(f"Starting subdomain enumeration for {domain}...")

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(doCRT, domain, args.timeout, args.retries)]
        if not args.no_securitytrails:
            futures.append(executor.submit(doSecurityTrails, domain, args.timeout, args.retries))
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as exc:
                log(f"[!] Worker error: {exc}")

    log("Cleaning and validating domain names...")
    finalSubs = clean_and_deduplicate(list(allSubs), domain)
    output_file = args.output or f"{domain}.txt"

    try:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as output:
            for subdomain in finalSubs:
                output.write(f"{subdomain}\n")

        elapsed = time.time() - start_time
        log(f"Complete! Found {len(finalSubs)} unique subdomains in {elapsed:.1f}s.")
        log(f"Results saved to {output_file}")
    except OSError as exc:
        log(f"[!] Failed to write output file: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
