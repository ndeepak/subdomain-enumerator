#!/usr/bin/env python3

import argparse
import subprocess
import sys
import time
from pathlib import Path

from getSubDomains import normalize_subdomain


def read_domains(input_path):
	with open(input_path, encoding="utf-8") as domain_file:
		domains = []
		for line in domain_file:
			value = line.strip()
			if not value or value.startswith("#"):
				continue
			normalized = normalize_subdomain(value)
			if normalized:
				domains.append(normalized)
		return domains


def run_gau(domain, output_dir, executable="gau", timeout=None):
	domain = normalize_subdomain(domain)
	if not domain:
		print("[!] Invalid domain", file=sys.stderr)
		return 2
	output_path = output_dir / f"{domain}.txt"
	command = [executable, domain, "--o", str(output_path)]
	try:
		result = subprocess.run(command, check=False, timeout=timeout)
	except FileNotFoundError:
		print(f"[!] Could not find executable: {executable}", file=sys.stderr)
		return 127
	except subprocess.TimeoutExpired:
		print(f"[!] {domain}: timed out", file=sys.stderr)
		return 124

	if result.returncode:
		print(f"[!] {domain}: gau exited with status {result.returncode}", file=sys.stderr)
	return result.returncode


def parse_args(argv=None):
	parser = argparse.ArgumentParser(description="Run gau for a list of domains.")
	parser.add_argument("-i", "--input", default="all_domains.txt", help="File containing one domain per line")
	parser.add_argument("-o", "--output-dir", default=".", help="Directory for gau output files")
	parser.add_argument("--delay", type=float, default=60, help="Seconds to wait between domains")
	parser.add_argument("--timeout", type=float, default=None, help="Optional timeout per gau process")
	parser.add_argument("--gau-command", default="gau", help="gau executable or path")
	args = parser.parse_args(argv)
	if args.delay < 0:
		parser.error("--delay cannot be negative")
	if args.timeout is not None and args.timeout <= 0:
		parser.error("--timeout must be greater than 0")
	return args


def main(argv=None):
	args = parse_args(argv)
	output_dir = Path(args.output_dir)
	output_dir.mkdir(parents=True, exist_ok=True)
	domains = read_domains(args.input)
	failures = 0

	for index, domain in enumerate(domains):
		failures += run_gau(domain, output_dir, args.gau_command, args.timeout) != 0
		if index < len(domains) - 1 and args.delay:
			time.sleep(args.delay)

	print(f"Processed {len(domains)} domains with {failures} failure(s).")
	return 1 if failures else 0


if __name__ == "__main__":
	raise SystemExit(main())