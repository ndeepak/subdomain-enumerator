import pytest

import getSubDomains


def test_normalize_subdomain_handles_wildcards_and_case():
    assert getSubDomains.normalize_subdomain("*.api.EXAMPLE.com.") == "api.example.com"
    assert getSubDomains.normalize_subdomain("  WWW.example.com  ") == "www.example.com"


def test_clean_and_deduplicate_keeps_valid_domain_names_only():
    values = {
        "example.com",
        "*.example.com",
        "app.example.com",
        "api.example.com",
        "bad_name",
        "-invalid.example.com",
        "foo..bar.example.com",
    }

    assert getSubDomains.clean_and_deduplicate(values, "example.com") == [
        "api.example.com",
        "app.example.com",
        "example.com",
    ]


def test_parse_args_supports_common_runtime_options():
    args = getSubDomains.parse_args([
        "example.com",
        "--workers",
        "6",
        "--timeout",
        "30",
        "--retries",
        "7",
        "--no-securitytrails",
        "--output",
        "results/example.txt",
    ])

    assert args.domain == "example.com"
    assert args.workers == 6
    assert args.timeout == 30
    assert args.retries == 7
    assert args.no_securitytrails is True
    assert args.output == "results/example.txt"


def test_parse_args_defaults_are_usable():
    args = getSubDomains.parse_args(["example.com"])

    assert args.workers >= 1
    assert args.timeout > 0
    assert args.retries >= 1
    assert args.no_securitytrails is False


def test_normalize_subdomain_rejects_invalid_labels():
    assert getSubDomains.normalize_subdomain("a_b.example.com", "example.com") == ""
    assert getSubDomains.normalize_subdomain("-bad.example.com", "example.com") == ""
    assert getSubDomains.normalize_subdomain("sub.example.com.evil.com", "example.com") == ""
