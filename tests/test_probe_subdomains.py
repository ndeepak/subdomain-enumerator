import requests

import probe_subdomains


def test_probe_host_prefers_https_and_extracts_metadata():
    response = requests.Response()
    response.status_code = 200
    response.url = "https://www.example.com/login"
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    response._content = b"<html><title> Example Login </title></html>"

    result = probe_subdomains.probe_host(
        "www.example.com",
        request_get=lambda url, **kwargs: response,
    )

    assert result["status_code"] == 200
    assert result["final_url"] == "https://www.example.com/login"
    assert result["title"] == "Example Login"


def test_probe_host_falls_back_to_http():
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        if url.startswith("https://"):
            raise requests.ConnectionError("TLS unavailable")
        response = requests.Response()
        response.status_code = 404
        response.url = url
        response.headers["Content-Type"] = "text/plain"
        return response

    result = probe_subdomains.probe_host("legacy.example.com", request_get=fake_get)

    assert calls == ["https://legacy.example.com", "http://legacy.example.com"]
    assert result["status_code"] == 404
    assert result["content_type"] == "text/plain"


def test_read_hosts_deduplicates_and_ignores_comments(tmp_path):
    input_file = tmp_path / "hosts.txt"
    input_file.write_text("Example.com\n\n# comment\nexample.com.\n", encoding="utf-8")

    assert probe_subdomains.read_hosts(input_file) == ["example.com"]