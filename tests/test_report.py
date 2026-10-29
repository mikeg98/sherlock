import csv
import json
import os
import sys

import pandas as pd
import pytest

from sherlock_project import sherlock
from sherlock_project.result import QueryResult, QueryStatus


def make_result(site, status, query_time=None, context=None, http_status=200):
    url_user = f"https://{site.lower()}.example/user"
    return {
        "url_main": f"https://{site.lower()}.example/",
        "url_user": url_user,
        "status": QueryResult("user", site, url_user, status, query_time, context),
        "http_status": http_status,
        "response_text": "",
    }


@pytest.fixture()
def results():
    return {
        "Alpha": make_result("Alpha", QueryStatus.CLAIMED, query_time=0.25),
        "Beta": make_result("Beta", QueryStatus.AVAILABLE, query_time=0.5, http_status=404),
        "Gamma": make_result("Gamma", QueryStatus.UNKNOWN, context="Timeout Error", http_status="?"),
    }


def test_report_rows_claimed_only(results):
    rows = sherlock.report_rows("user", results)
    assert [row["name"] for row in rows] == ["Alpha"]
    assert rows[0] == {
        "username": "user",
        "name": "Alpha",
        "url_main": "https://alpha.example/",
        "url_user": "https://alpha.example/user",
        "exists": "Claimed",
        "http_status": 200,
        "response_time_s": 0.25,
        "context": None,
    }


def test_report_rows_print_all(results):
    rows = sherlock.report_rows("user", results, print_all=True)
    assert [row["name"] for row in rows] == ["Alpha", "Beta", "Gamma"]
    assert rows[2]["exists"] == "Unknown"
    assert rows[2]["response_time_s"] is None
    assert rows[2]["context"] == "Timeout Error"


def test_report_file_path(tmp_path):
    assert sherlock.report_file_path("user", "json") == "user.json"

    folder = tmp_path / "nested" / "out"
    path = sherlock.report_file_path("user", "csv", str(folder))
    assert path == os.path.join(str(folder), "user.csv")
    assert folder.is_dir()


def test_write_json_report(tmp_path, results):
    rows = sherlock.report_rows("user", results, print_all=True)
    path = tmp_path / "user.json"
    sherlock.write_json_report("user", rows, str(path))

    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["username"] == "user"
    assert report["sherlock_version"] == sherlock.__version__
    assert report["generated_at"].endswith("+00:00")
    assert report["results"] == rows


def run_main(monkeypatch, tmp_path, results, cliargs):
    """Run sherlock.main() with network access replaced by canned results."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["sherlock", "--local", *cliargs])
    monkeypatch.setattr(sherlock.requests, "get", lambda *a, **kw: (_ for _ in ()).throw(OSError("offline")))
    monkeypatch.setattr(sherlock, "sherlock", lambda username, *a, **kw: results)
    sherlock.main()


def test_main_writes_all_reports_to_folder(monkeypatch, tmp_path, results):
    run_main(monkeypatch, tmp_path, results, ["--csv", "--xlsx", "--json-report", "--folderoutput", "out", "user"])

    out = tmp_path / "out"
    assert sorted(os.listdir(out)) == ["user.csv", "user.json", "user.xlsx"]

    with open(out / "user.csv", newline="", encoding="utf-8") as f:
        csv_rows = list(csv.DictReader(f))
    assert [row["name"] for row in csv_rows] == ["Alpha"]
    assert "context" not in csv_rows[0]

    xlsx = pd.read_excel(out / "user.xlsx")
    assert list(xlsx["name"]) == ["Alpha"]

    report = json.loads((out / "user.json").read_text(encoding="utf-8"))
    assert [row["name"] for row in report["results"]] == ["Alpha"]


def test_main_csv_blank_response_time(monkeypatch, tmp_path, results):
    run_main(monkeypatch, tmp_path, results, ["--csv", "--print-all", "user"])

    with open(tmp_path / "user.csv", newline="", encoding="utf-8") as f:
        csv_rows = {row["name"]: row for row in csv.DictReader(f)}
    assert csv_rows["Alpha"]["response_time_s"] == "0.25"
    assert csv_rows["Gamma"]["response_time_s"] == ""
