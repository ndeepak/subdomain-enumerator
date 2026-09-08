#!/usr/bin/env python3

import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

from getSubDomains import normalize_subdomain


DEFAULT_TIMEOUT = 10
DEFAULT_WORKERS = 20
USER_AGENT = "subdomain-enumerator/1.0"


def read_hosts(input_path):
    hosts = set()
    with open(input_path, encoding="utf-8") as host_file:
        for line in host_file:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            normalized = normalize_subdomain(value)
            if normalized:
                hosts.add(normalized)
    return sorted(hosts)


def extract_title(response):
    content_type = response.headers.get("Content-Type", "")
    if "text/html" not in content_type.lower():
        return ""

    text = response.text[:200000]
    lower_text = text.lower()
    title_start = lower_text.find("<title")
    if title_start == -1:
        return ""
    title_start = lower_text.find(">", title_start)
    title_end = lower_text.find("</title>", title_start)
    if title_start == -1 or title_end == -1:
        return ""
    return " ".join(text[title_start + 1:title_end].split())


def probe_host(host, timeout=DEFAULT_TIMEOUT, verify=True, request_get=requests.get):
    errors = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        started = time.perf_counter()
        try:
            response = request_get(
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=timeout,
                allow_redirects=True,
                verify=verify,
            )
            elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
            return {
                "host": host,
                "url": url,
                "final_url": response.url,
                "status_code": response.status_code,
                "title": extract_title(response),
                "content_type": response.headers.get("Content-Type", ""),
                "elapsed_ms": elapsed_ms,
            }
        except requests.RequestException as exc:
            errors.append(f"{scheme}: {exc.__class__.__name__}")

    return {"host": host, "error": "; ".join(errors)}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Probe discovered hosts for HTTP(S) services.")
    parser.add_argument("-i", "--input", required=True, help="File containing one hostname per line")
    parser.add_argument("-o", "--output", default="live-hosts.jsonl", help="JSONL output file")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Maximum concurrent probes")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Request timeout in seconds")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification for HTTPS probes",
    )
    args = parser.parse_args(argv)
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")
    return args


def main(argv=None):
    args = parse_args(argv)
    hosts = read_hosts(args.input)
    results = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(probe_host, host, args.timeout, not args.insecure): host
            for host in hosts
        }
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda result: result["host"])
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as output_file:
        for result in results:
            output_file.write(json.dumps(result, sort_keys=True) + "\n")

    live_count = sum("status_code" in result for result in results)
    print(f"Probed {len(hosts)} hosts; {live_count} responded over HTTP(S).")
    print(f"Results saved to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())