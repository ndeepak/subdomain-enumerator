import subprocess

import gau_batch


def test_run_gau_uses_argument_list_and_output_directory(tmp_path, monkeypatch):
    calls = []

    def fake_run(command, check, timeout):
        calls.append((command, check, timeout))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert gau_batch.run_gau("example.com", tmp_path, timeout=15) == 0
    assert calls == [
        (["gau", "example.com", "--o", str(tmp_path / "example.com.txt")], False, 15)
    ]


def test_read_domains_ignores_blank_and_comment_lines(tmp_path):
    input_file = tmp_path / "domains.txt"
    input_file.write_text("example.com\n\n# internal\nAPI.example.com.\nnot a domain\n", encoding="utf-8")

    assert gau_batch.read_domains(input_file) == ["example.com", "api.example.com"]