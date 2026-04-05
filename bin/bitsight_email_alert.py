#!/usr/bin/env python3
# encoding: utf-8

"""
=============================================================================
 bin/bitsight_email_alert.py
 BitSight for Splunk App
 Email Alert Action
=============================================================================

PURPOSE

Sends email notifications for BitSight alert actions.
Builds plain text and HTML email bodies from the Splunk alert payload.
Supports recipient, cc, subject, priority, SMTP, result details,
and results link handling.

FILE LOCATION

App-relative path
bin/bitsight_email_alert.py

SCRIPT TYPE

Custom Splunk alert action script

EXECUTION MODEL

Invoked by Splunk alert actions
expects payload file path as argv[1]

GRANULAR DOCUMENTATION SPECIFICATION

INPUT SOURCE

Splunk alert action payload JSON file

PAYLOAD REQUIREMENT

argv[1]
payload file path

PAYLOAD SECTIONS USED

configuration
result
results_link

CONFIGURATION FIELDS

to
cc
subject
message
priority
include_results
include_link
smtp_server
smtp_port
smtp_use_tls
smtp_user
smtp_password
from_address
smtp_timeout

OUTPUT BEHAVIOR

stdout
INFO message on success

stderr
ERROR message on failure

EXIT CODES

0
success

1
failure

EMAIL CONTENT MODES

plain text
html

SMTP MODES

SMTP
SMTP with STARTTLS
SMTP over SSL on port 465

RECIPIENT SOURCES

to
cc

RESULT TABLE LOGIC

includes non-internal result fields
skips fields beginning with underscore

DEPENDENCIES

json
os
sys
html
ssl
smtplib
email.mime.multipart
email.mime.text
typing

=============================================================================
"""

import html
import json
import os
import smtplib
import ssl
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _split_addresses(value: str) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _safe_header(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    return text or default


def _build_plain_body(
    message_body: str,
    result: Dict[str, Any],
    results_link: str,
    include_results: bool,
    include_link: bool,
) -> str:
    lines: List[str] = []

    if message_body:
        lines.append(message_body.strip())
        lines.append("")

    if include_results and result:
        lines.append("Alert Details")
        lines.append("-------------")
        for key, value in result.items():
            if str(key).startswith("_"):
                continue
            lines.append(f"{key}: {value}")
        lines.append("")

    if include_link and results_link:
        lines.append(f"View Results in Splunk: {results_link}")

    return "\n".join(lines).strip()


def _build_html_body(
    message_body: str,
    result: Dict[str, Any],
    results_link: str,
    include_results: bool,
    include_link: bool,
) -> str:
    safe_message = html.escape(message_body).replace("\n", "<br>") if message_body else ""

    html_body = """
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; }
            .alert-header { background-color: #d9534f; color: white; padding: 15px; }
            .alert-body { padding: 15px; background-color: #f5f5f5; }
            .results-table { border-collapse: collapse; width: 100%; }
            .results-table th, .results-table td { border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
            .results-table th { background-color: #4a4a4a; color: white; width: 30%; }
        </style>
    </head>
    <body>
        <div class="alert-header">
            <h2>🔒 BitSight Security Alert</h2>
        </div>
        <div class="alert-body">
    """

    if safe_message:
        html_body += f"<p>{safe_message}</p>"

    if include_results and result:
        html_body += """
            <h3>Alert Details</h3>
            <table class="results-table">
        """
        for key, value in result.items():
            if str(key).startswith("_"):
                continue
            html_body += (
                f"<tr><th>{html.escape(str(key))}</th>"
                f"<td>{html.escape(str(value))}</td></tr>"
            )
        html_body += "</table>"

    if include_link and results_link:
        safe_link = html.escape(results_link, quote=True)
        html_body += f'<p><a href="{safe_link}">View Results in Splunk</a></p>'

    html_body += """
        </div>
    </body>
    </html>
    """

    return html_body


def send_email(config: Dict[str, Any], payload: Dict[str, Any]) -> Tuple[bool, str]:
    to_addresses = _split_addresses(str(config.get("to", "")))
    cc_addresses = _split_addresses(str(config.get("cc", "")))
    subject = _safe_header(config.get("subject"), "BitSight Alert")
    message_body = str(config.get("message", "") or "")
    priority = str(config.get("priority", "normal") or "normal").strip().lower()
    include_results = _as_bool(config.get("include_results"), True)
    include_link = _as_bool(config.get("include_link"), True)

    if not to_addresses and not cc_addresses:
        return False, "No recipient addresses configured"

    smtp_server = str(config.get("smtp_server", "localhost") or "localhost").strip()
    smtp_port = int(config.get("smtp_port", 25))
    smtp_use_tls = _as_bool(config.get("smtp_use_tls"), False)
    smtp_user = str(config.get("smtp_user", "") or "").strip()
    smtp_password = str(config.get("smtp_password", "") or "")
    from_address = _safe_header(config.get("from_address"), "splunk@localhost")
    smtp_timeout = int(config.get("smtp_timeout", 30))

    result = payload.get("result")
    if not isinstance(result, dict):
        result = {}

    results_link = str(payload.get("results_link", "") or "")

    plain_body = _build_plain_body(
        message_body=message_body,
        result=result,
        results_link=results_link,
        include_results=include_results,
        include_link=include_link,
    )

    html_body = _build_html_body(
        message_body=message_body,
        result=result,
        results_link=results_link,
        include_results=include_results,
        include_link=include_link,
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_address
    msg["To"] = ", ".join(to_addresses)

    if cc_addresses:
        msg["Cc"] = ", ".join(cc_addresses)

    if priority == "high":
        msg["X-Priority"] = "1"
        msg["Importance"] = "high"
    elif priority == "low":
        msg["X-Priority"] = "5"
        msg["Importance"] = "low"

    msg.attach(MIMEText(plain_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    all_recipients = to_addresses + cc_addresses

    try:
        if smtp_use_tls and smtp_port == 465:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(
                smtp_server,
                smtp_port,
                timeout=smtp_timeout,
                context=context,
            ) as server:
                if smtp_user and smtp_password:
                    server.login(smtp_user, smtp_password)
                server.sendmail(from_address, all_recipients, msg.as_string())
        else:
            with smtplib.SMTP(smtp_server, smtp_port, timeout=smtp_timeout) as server:
                server.ehlo()

                if smtp_use_tls:
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                    server.ehlo()

                if smtp_user and smtp_password:
                    server.login(smtp_user, smtp_password)

                server.sendmail(from_address, all_recipients, msg.as_string())

        return True, "Email sent successfully"
    except Exception as e:
        return False, str(e)


def main() -> None:
    if len(sys.argv) < 2:
        print("ERROR: No payload file provided", file=sys.stderr)
        sys.exit(1)

    payload_file = sys.argv[1]

    try:
        with open(payload_file, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception as e:
        print(f"ERROR: Failed to read payload: {e}", file=sys.stderr)
        sys.exit(1)

    configuration = payload.get("configuration", {})
    if not isinstance(configuration, dict):
        print("ERROR: Invalid configuration payload", file=sys.stderr)
        sys.exit(1)

    success, message = send_email(configuration, payload)

    if success:
        print(f"INFO: {message}")
        sys.exit(0)

    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
