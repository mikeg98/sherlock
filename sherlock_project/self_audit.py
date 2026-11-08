#! /usr/bin/env python3

"""Sherlock Self-Exposure Audit Module

A consent-based wrapper around Sherlock for auditing *your own* online
footprint. You give it your own usernames; it reports where those usernames
are registered and bundles curated links for getting that information
removed (data-broker opt-outs, search-engine removal, breach checks).

This tool is intended for checking your own exposure or that of someone who
has asked you to help them. It does not gather anyone's personal data: it
reuses Sherlock's public username lookups and adds static, hand-curated
removal references that are never queried automatically.
"""

import json
import os
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from datetime import datetime, timezone

from sherlock_project.__init__ import __longname__, __version__
from sherlock_project.notify import QueryNotify, QueryNotifyPrint
from sherlock_project.result import QueryStatus
from sherlock_project.sherlock import sherlock, timeout_check
from sherlock_project.sites import SitesInformation

RESOURCES_PATH = os.path.join(
    os.path.dirname(__file__), "resources", "removal_resources.json"
)


def load_removal_resources(path: str = RESOURCES_PATH) -> dict:
    """Load the curated removal / opt-out reference data."""
    with open(path, encoding="utf-8") as resource_file:
        return json.load(resource_file)


def audit_username(
    username: str,
    site_data: dict,
    query_notify: QueryNotify,
    timeout: int = 60,
) -> dict:
    """Audit a single username and summarize where it is claimed.

    Keyword Arguments:
    username               -- The username to audit.
    site_data              -- Dictionary of site data (see SitesInformation).
    query_notify           -- QueryNotify object for progress reporting.
    timeout                -- Per-request timeout in seconds.

    Return Value:
    Dictionary with the username and a list of findings (one per site where
    the username was detected), each marked with whether the site is NSFW.
    """
    results = sherlock(username, site_data, query_notify, timeout=timeout)

    findings = []
    for site, result in results.items():
        status = result["status"]
        if status.status != QueryStatus.CLAIMED:
            continue
        findings.append(
            {
                "site": site,
                "url": result["url_user"],
                "is_nsfw": bool(site_data.get(site, {}).get("isNSFW", False)),
            }
        )

    findings.sort(key=lambda f: (not f["is_nsfw"], f["site"].lower()))
    return {"username": username, "findings": findings}


def build_report(
    audits: list[dict],
    resources: dict,
    email: str | None = None,
    phone: str | None = None,
) -> dict:
    """Assemble the full audit report as a serializable dictionary."""
    total_found = sum(len(audit["findings"]) for audit in audits)
    nsfw_found = sum(
        1 for audit in audits for finding in audit["findings"] if finding["is_nsfw"]
    )
    return {
        "tool": f"{__longname__} - Self-Exposure Audit",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "subject": {"email": email, "phone": phone},
        "summary": {
            "usernames_checked": len(audits),
            "accounts_found": total_found,
            "nsfw_accounts_found": nsfw_found,
        },
        "audits": audits,
        "removal_resources": resources,
    }


def _resource_section(title: str, entries: list[dict]) -> list[str]:
    lines = [f"### {title}", ""]
    for entry in entries:
        lines.append(f"- [{entry['name']}]({entry['url']})")
        if entry.get("note"):
            lines.append(f"  - {entry['note']}")
    lines.append("")
    return lines


def render_markdown(report: dict) -> str:
    """Render the audit report as human-readable Markdown."""
    lines = [
        f"# {report['tool']}",
        "",
        f"Generated: {report['generated_at']} (version {report['version']})",
        "",
        (
            "> This report covers your own public footprint. Use it to decide "
            "what to lock down or request removal of. Treat the removal links "
            "as starting points and verify each before acting."
        ),
        "",
        "## Summary",
        "",
        f"- Usernames checked: {report['summary']['usernames_checked']}",
        f"- Accounts found: {report['summary']['accounts_found']}",
        f"- Of those, on adult/NSFW sites: {report['summary']['nsfw_accounts_found']}",
        "",
    ]

    subject = report["subject"]
    if subject.get("email") or subject.get("phone"):
        lines.append("## Identifiers you provided")
        lines.append("")
        if subject.get("email"):
            lines.append(f"- Email: `{subject['email']}` — check breach exposure below.")
        if subject.get("phone"):
            lines.append(f"- Phone: `{subject['phone']}` — check the data brokers below.")
        lines.append("")

    lines.append("## Where your usernames appear")
    lines.append("")
    for audit in report["audits"]:
        lines.append(f"### `{audit['username']}`")
        lines.append("")
        if not audit["findings"]:
            lines.append("No accounts detected.")
            lines.append("")
            continue
        for finding in audit["findings"]:
            tag = " **[adult/NSFW]**" if finding["is_nsfw"] else ""
            lines.append(f"- {finding['site']}{tag}: {finding['url']}")
        lines.append("")

    lines.append("## Reducing your exposure")
    lines.append("")
    resources = report["removal_resources"]
    lines += _resource_section("Check for breached accounts", resources.get("breach_check", []))
    lines += _resource_section("Remove info from search engines", resources.get("search_engine_removal", []))
    lines += _resource_section("Opt out of data brokers", resources.get("data_brokers", []))
    lines += _resource_section("Further guidance", resources.get("guidance", []))

    return "\n".join(lines).rstrip() + "\n"


def main():
    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description=f"{__longname__} - Self-Exposure Audit (Version {__version__})",
        epilog=(
            "Audit your OWN online footprint. Provide usernames you use, and "
            "the report shows where they are registered plus curated links for "
            "requesting removal. Intended for checking your own exposure or "
            "helping someone who has asked you to."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{__longname__} self-audit v{__version__}",
    )
    parser.add_argument(
        "username",
        nargs="+",
        metavar="USERNAMES",
        help="One or more of your own usernames to audit.",
    )
    parser.add_argument(
        "--email",
        dest="email",
        default=None,
        help="Your email address. Recorded in the report as a reminder to check breach exposure (not queried).",
    )
    parser.add_argument(
        "--phone",
        dest="phone",
        default=None,
        help="Your phone number. Recorded in the report as a reminder to check data brokers (not queried).",
    )
    parser.add_argument(
        "--nsfw",
        action="store_true",
        default=False,
        help="Include adult/NSFW sites in the audit (off by default).",
    )
    parser.add_argument(
        "--timeout",
        type=timeout_check,
        default=60,
        metavar="TIMEOUT",
        help="Per-request timeout in seconds (Default: 60).",
    )
    parser.add_argument(
        "--output",
        "-o",
        dest="output",
        default=None,
        help="Write the Markdown report to this file (default: print to stdout).",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        default=None,
        metavar="JSON_FILE",
        help="Also write the full report as JSON to this file.",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        default=False,
        help="Suppress per-site progress output.",
    )
    args = parser.parse_args()

    sites = SitesInformation(
        os.path.join(os.path.dirname(__file__), "resources", "data.json")
    )
    if not args.nsfw:
        sites.remove_nsfw_sites()
    site_data = {site.name: site.information for site in sites}

    if args.quiet:
        query_notify = QueryNotify()
    else:
        query_notify = QueryNotifyPrint(result=None, verbose=False, print_all=False)

    audits = [
        audit_username(username, site_data, query_notify, timeout=args.timeout)
        for username in args.username
    ]

    resources = load_removal_resources()
    report = build_report(audits, resources, email=args.email, phone=args.phone)
    markdown = render_markdown(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as report_file:
            report_file.write(markdown)
        print(f"Wrote Markdown report to {args.output}")
    else:
        print(markdown)

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as json_file:
            json.dump(report, json_file, indent=2, ensure_ascii=False)
            json_file.write("\n")
        print(f"Wrote JSON report to {args.json_output}")


if __name__ == "__main__":
    main()
