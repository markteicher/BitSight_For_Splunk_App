#!/usr/bin/env python3
# encoding: utf-8

"""
=============================================================================
 bin/bitsight_webhook_alert.py
 BitSight for Splunk App
 Webhook Alert Action
=============================================================================

PURPOSE

Sends webhook notifications to external systems.

Builds an outbound webhook request from the Splunk alert action payload
and configuration.

Supports:

- webhook URL configuration
- HTTP method configuration
- content type configuration
- custom headers
- SSL verification control
- request timeout control
- payload template variable substitution
- requests library usage
- urllib fallback handling
- BitSight app file logging

FILE LOCATION

App-relative path
bin/bitsight_webhook_alert.py

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
results
search_name
trigger_time
app
owner
results_link

CONFIGURATION FIELDS

webhook_url
method
content_type
custom_headers
verify_ssl
timeout
payload_template

VARIABLE SUBSTITUTION MODEL

Supports $variable$ tokens

TOP-LEVEL TOKENS

name
search_name
trigger_time
app
owner
results_link
result.count

RESULT TOKENS

$result.field_name$

CUSTOM HEADER MODEL

Header lines are supplied as:
Header-Name: value

One header per line

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

HTTP TARGET

Configured webhook_url

HTTP METHODS

POST
PUT
PATCH

CONTENT TYPE

Configured content_type

SSL MODEL

verify_ssl controls certificate validation

APP LOG PATH MODEL

creates app-relative directory
var/log

creates app-relative file
var/log/bitsight.log

DEPENDENCIES

datetime
json
os
re
sys
typing
requests
urllib.request
urllib.error
ssl

=============================================================================
"""

import datetime
import json
import os
import re
import sys
from typing import Any, Dict, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

try:
    import requests
except ImportError:  # pragma: no cover
    import ssl
    import urllib.error
    import urllib.request

    requests = None


DEFAULT_TIMEOUT = 30
SUPPORTED_METHODS = {"POST", "PUT", "PATCH"}
APP_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
APP_LOG_DIR = os.path.join(APP_ROOT, "var", "log")
APP_LOG_FILE = os.path.join(APP_LOG_DIR, "bitsight.log")
COMPONENT_NAME = "bitsight_webhook_alert.py"


def ensure_bitsight_log_file() -> str:
    os.makedirs(APP_LOG_DIR, exist_ok=True)

    if not os.path.exists(APP_LOG_FILE):
        with open(APP_LOG_FILE, "a", encoding="utf-8"):
            pass

    return APP_LOG_FILE


def write_app_log(level: str, message: str) -> None:
    try:
        ensure_bitsight_log_file()
        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        safe_message = str(message).replace("\n", " ").replace("\r", " ").strip()

        with open(APP_LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(
                f"{timestamp} level={str(level).upper()} component={COMPONENT_NAME} message={safe_message}\n"
            )
    except Exception:
        pass


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _clean_string(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _result_count(payload: Dict[str, Any]) -> str:
    result = payload.get("result", {})
    results = payload.get("results", [])

    if isinstance(result, dict):
        count_value = result.get("count")
        if count_value not in (None, ""):
            return str(count_value)

    if isinstance(results, list):
        return str(len(results))

    return "0"


def substitute_variables(template: Any, payload: Dict[str, Any]) -> str:
    """Substitute $variable$ patterns with values from the payload."""

    if template is None:
        return ""

    result = payload.get("result", {})
    if not isinstance(result, dict):
        result = {}

    substitutions = {
        "name": str(payload.get("search_name", "") or ""),
        "search_name": str(payload.get("search_name", "") or ""),
        "trigger_time": str(payload.get("trigger_time", "") or ""),
        "app": str(payload.get("app", "bitsight") or "bitsight"),
        "owner": str(payload.get("owner", "") or ""),
        "results_link": str(payload.get("results_link", "") or ""),
        "result.count": _result_count(payload),
    }

    for key, value in result.items():
        substitutions[f"result.{key}"] = "" if value is None else str(value)

    def replace_var(match: re.Match[str]) -> str:
        var_name = match.group(1)
        return substitutions.get(var_name, "")

    return re.sub(r"\$([^$]+)\$", replace_var, str(template))


def _parse_custom_headers(custom_headers: str) -> Dict[str, str]:
    headers: Dict[str, str] = {}

    if not custom_headers:
        return headers

    for line in custom_headers.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key:
            headers[key] = value

    return headers


def send_webhook(config: Dict[str, Any], payload: Dict[str, Any]) -> Tuple[bool, str]:
    """Send webhook notification."""

    webhook_url = _clean_string(config.get("webhook_url"))
    method = _clean_string(config.get("method", "POST"), "POST").upper()
    content_type = _clean_string(config.get("content_type", "application/json"), "application/json")
    custom_headers = _clean_string(config.get("custom_headers"))
    verify_ssl = _as_bool(config.get("verify_ssl"), True)
    timeout = int(config.get("timeout", DEFAULT_TIMEOUT) or DEFAULT_TIMEOUT)
    payload_template = _clean_string(config.get("payload_template", "{}"), "{}")

    if not webhook_url:
        write_app_log("ERROR", "Webhook alert action failed: no webhook URL configured")
        return False, "No webhook URL configured"

    if method not in SUPPORTED_METHODS:
        write_app_log("ERROR", f"Webhook alert action failed: unsupported HTTP method={method}")
        return False, f"Unsupported HTTP method: {method}"

    try:
        payload_str = substitute_variables(payload_template, payload)
        webhook_payload = json.loads(payload_str)
    except json.JSONDecodeError as e:
        write_app_log("ERROR", f"Webhook alert action failed: invalid payload template JSON error={e}")
        return False, f"Invalid payload template JSON: {e}"

    headers = {"Content-Type": content_type}
    headers.update(_parse_custom_headers(custom_headers))

    request_body = json.dumps(webhook_payload).encode("utf-8")

    write_app_log(
        "INFO",
        (
            "Webhook alert action starting "
            f"method={method} "
            f"url={webhook_url} "
            f"content_type={content_type} "
            f"verify_ssl={verify_ssl} "
            f"timeout={timeout} "
            f"header_count={len(headers)}"
        ),
    )

    try:
        if requests is not None:
            response = requests.request(
                method=method,
                url=webhook_url,
                data=request_body,
                headers=headers,
                verify=verify_ssl,
                timeout=timeout,
            )

            if response.status_code >= 400:
                write_app_log(
                    "ERROR",
                    f"Webhook returned status={response.status_code} body={response.text}",
                )
                return False, f"Webhook returned status {response.status_code}: {response.text}"

            write_app_log(
                "INFO",
                f"Webhook sent successfully status={response.status_code}",
            )
            return True, f"Webhook sent successfully (status {response.status_code})"

        request = urllib.request.Request(
            webhook_url,
            data=request_body,
            headers=headers,
            method=method,
        )

        context = None
        if not verify_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            status = response.getcode()
            if status >= 400:
                write_app_log("ERROR", f"Webhook returned status={status}")
                return False, f"Webhook returned status {status}"

            write_app_log("INFO", f"Webhook sent successfully status={status}")
            return True, f"Webhook sent successfully (status {status})"

    except Exception as e:
        write_app_log("ERROR", f"Webhook request failed error={str(e)}")
        return False, f"Webhook request failed: {str(e)}"


def main() -> None:
    """Main entry point for alert action."""

    ensure_bitsight_log_file()

    if len(sys.argv) < 2:
        write_app_log("ERROR", "Webhook alert action failed: no payload file provided")
        print("ERROR: No payload file provided", file=sys.stderr)
        sys.exit(1)

    payload_file = sys.argv[1]
    write_app_log("INFO", f"Webhook alert action invoked payload_file={payload_file}")

    try:
        with open(payload_file, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception as e:
        write_app_log("ERROR", f"Failed to read webhook payload error={e}")
        print(f"ERROR: Failed to read payload: {e}", file=sys.stderr)
        sys.exit(1)

    config = payload.get("configuration", {})
    if not isinstance(config, dict):
        write_app_log("ERROR", "Webhook alert action failed: invalid configuration payload")
        print("ERROR: Invalid configuration payload", file=sys.stderr)
        sys.exit(1)

    success, message = send_webhook(config, payload)

    if success:
        print(f"INFO: {message}")
        sys.exit(0)

    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
