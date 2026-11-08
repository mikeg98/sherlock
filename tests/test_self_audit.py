import json

import pytest

from sherlock_project import self_audit
from sherlock_project.notify import QueryNotify
from sherlock_project.result import QueryResult, QueryStatus


@pytest.fixture()
def site_data():
    return {
        "Clean": {"isNSFW": False},
        "AdultOne": {"isNSFW": True},
        "AdultTwo": {"isNSFW": True},
    }


def fake_results(username, mapping):
    """Build a sherlock()-shaped results dict from {site: QueryStatus}."""
    results = {}
    for site, status in mapping.items():
        url = f"https://{site.lower()}.example/{username}"
        results[site] = {
            "url_main": f"https://{site.lower()}.example/",
            "url_user": url,
            "status": QueryResult(username, site, url, status),
            "http_status": 200,
            "response_text": "",
        }
    return results


def test_load_removal_resources_has_expected_sections():
    resources = self_audit.load_removal_resources()
    for section in ("breach_check", "search_engine_removal", "data_brokers", "guidance"):
        assert resources[section], f"{section} should be non-empty"
    for entry in resources["data_brokers"]:
        assert entry["url"].startswith("https://")
        assert entry["name"]


def test_audit_username_filters_and_flags(monkeypatch, site_data):
    mapping = {
        "Clean": QueryStatus.CLAIMED,
        "AdultOne": QueryStatus.CLAIMED,
        "AdultTwo": QueryStatus.AVAILABLE,
    }
    monkeypatch.setattr(
        self_audit, "sherlock", lambda username, *a, **kw: fake_results(username, mapping)
    )

    audit = self_audit.audit_username("me", site_data, QueryNotify())
    assert audit["username"] == "me"
    # Only CLAIMED sites; AdultTwo (AVAILABLE) excluded.
    sites = [f["site"] for f in audit["findings"]]
    assert sites == ["AdultOne", "Clean"]  # NSFW sorted first
    flags = {f["site"]: f["is_nsfw"] for f in audit["findings"]}
    assert flags == {"AdultOne": True, "Clean": False}


def test_build_report_summary(site_data):
    audits = [
        {
            "username": "me",
            "findings": [
                {"site": "AdultOne", "url": "https://adultone.example/me", "is_nsfw": True},
                {"site": "Clean", "url": "https://clean.example/me", "is_nsfw": False},
            ],
        }
    ]
    resources = self_audit.load_removal_resources()
    report = self_audit.build_report(audits, resources, email="a@b.com", phone="555")

    assert report["summary"] == {
        "usernames_checked": 1,
        "accounts_found": 2,
        "nsfw_accounts_found": 1,
    }
    assert report["subject"] == {"email": "a@b.com", "phone": "555"}
    assert report["version"] == self_audit.__version__


def test_render_markdown_contains_findings_and_resources():
    audits = [
        {
            "username": "me",
            "findings": [
                {"site": "AdultOne", "url": "https://adultone.example/me", "is_nsfw": True},
            ],
        },
        {"username": "empty", "findings": []},
    ]
    resources = self_audit.load_removal_resources()
    report = self_audit.build_report(audits, resources, email="a@b.com", phone=None)
    md = self_audit.render_markdown(report)

    assert "`me`" in md
    assert "**[adult/NSFW]**" in md
    assert "https://adultone.example/me" in md
    assert "No accounts detected." in md
    assert "Opt out of data brokers" in md
    assert "a@b.com" in md
    # Email given, phone not: phone line absent.
    assert "Phone:" not in md


def test_main_writes_markdown_and_json(monkeypatch, tmp_path, site_data):
    mapping = {"Clean": QueryStatus.CLAIMED, "AdultOne": QueryStatus.AVAILABLE}
    monkeypatch.setattr(
        self_audit, "sherlock", lambda username, *a, **kw: fake_results(username, mapping)
    )

    class FakeSites:
        def __init__(self, *a, **kw):
            self._data = site_data

        def remove_nsfw_sites(self, do_not_remove=None):
            self._data = {k: v for k, v in self._data.items() if not v["isNSFW"]}

        def __iter__(self):
            for name, info in self._data.items():
                yield type("S", (), {"name": name, "information": info})()

    monkeypatch.setattr(self_audit, "SitesInformation", FakeSites)

    md_path = tmp_path / "report.md"
    json_path = tmp_path / "report.json"
    monkeypatch.setattr(
        "sys.argv",
        ["sherlock-self-audit", "--quiet", "-o", str(md_path), "--json", str(json_path), "me"],
    )
    self_audit.main()

    md = md_path.read_text(encoding="utf-8")
    assert "Clean" in md
    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["summary"]["accounts_found"] == 1
    assert report["summary"]["usernames_checked"] == 1
