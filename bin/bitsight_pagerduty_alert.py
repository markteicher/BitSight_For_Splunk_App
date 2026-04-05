#!/usr/bin/env python3
# encoding: utf-8

"""
=============================================================================
 bin/bitsight_pagerduty_alert.py
 BitSight for Splunk App
 PagerDuty Alert Action
=============================================================================

PURPOSE

Triggers PagerDuty incidents for BitSight alerts.

Builds a PagerDuty Events API v2 payload from the Splunk alert action
payload and configuration.

Supports:

- routing key configuration
- severity configuration
- dedup key configuration
- event action configuration
- summary substitution
- source substitution
- component substitution
- group substitution
- class substitution
- custom details population
- requests library usage
- urllib fallback handling

FILE LOCATION

App-relative path
bin/bitsight_pagerduty_alert.py

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
search_name
trigger_time
app
owner
results_link

CONFIGURATION FIELDS

routing_key
severity
dedup_key
event_action
summary
source
component
group
class
timeout

VARIABLE SUBSTITUTION MODEL

Supports $variable$ tokens

TOP-LEVEL TOKENS

name
search_name
trigger_time
app
owner
results_link

RESULT TOKENS

$result.field_name$

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

https://events.pagerduty.com/v2/enqueue

HTTP METHODS

POST

CONTENT TYPE

application/json

DEPENDENCIES

json
os
re
sys
requests
urllib.request
urllib.error

=============================================================================
"""

import json
import os
import re
import sys
from typing import Any, Dict, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

try:
    import requests
except ImportError:  # pragma: no cover
    import urllib.error
    import urllib.request

    requests = None

PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"
DEFAULT_TIMEOUT = 30
VALID_SEVERITIES = {"critical", "error", "warning", "info"}
VALID_EVENT_ACTIONS = {"trigger", "acknowledge", "resolve"}


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
    }

    for key, value in result.items():
        substitutions[f"result.{key}"] = "" if value is None else str(value)

    def replace_var(match: re.Match[str]) -> str:
        var_name = match.group(1)
        return substitutions.get(var_name, match.group(0))

    return re.sub(r"\$([^$]+)\$", replace_var, str(template))


def _clean_string(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip() or default


def _validate_severity(value: str) -> str:
    severity = _clean_string(value, "error").lower()
    if severity not in VALID_SEVERITIES:
        return "error"
    return severity


def _validate_event_action(value: str) -> str:
    event_action = _clean_string(value, "trigger").lower()
    if event_action not in VALID_EVENT_ACTIONS:
        return "trigger"
    return event_action


def _build_custom_details(payload: Dict[str, Any]) -> Dict[str, Any]:
    result = payload.get("result", {})
    if not isinstance(result, dict):
        result = {}

    return {
        "search_name": payload.get("search_name", ""),
        "trigger_time": payload.get("trigger_time", ""),
        "app": payload.get("app", ""),
        "owner": payload.get("owner", ""),
        "results_link": payload.get("results_link", ""),
        "result": result,
    }


def send_pagerduty_event(config: Dict[str, Any], payload: Dict[str, Any]) -> Tuple[bool, str]:
    """Send PagerDuty event."""

    routing_key = _clean_string(config.get("routing_key"))
    severity = _validate_severity(config.get("severity", "error"))
    dedup_key = _clean_string(config.get("dedup_key"))
    event_action = _validate_event_action(config.get("event_action", "trigger"))
    summary = _clean_string(config.get("summary", "BitSight Alert"), "BitSight Alert")
    source = _clean_string(config.get("source", "Splunk BitSight App"), "Splunk BitSight App")
    component = _clean_string(config.get("component"))
    group = _clean_string(config.get("group", "vendor-risk"), "vendor-risk")
    event_class = _clean_string(config.get("class", "security-rating"), "security-rating")
    timeout = int(config.get("timeout", DEFAULT_TIMEOUT) or DEFAULT_TIMEOUT)

    if not routing_key:
        return False, "No PagerDuty routing key configured"

    summary = substitute_variables(summary, payload)
    dedup_key = substitute_variables(dedup_key, payload)
    source = substitute_variables(source, payload)
    component = substitute_variables(component, payload)
    group = substitute_variables(group, payload)
    event_class = substitute_variables(event_class, payload)

    pd_payload: Dict[str, Any] = {
        "routing_key": routing_key,
        "event_action": event_action,
        "payload": {
            "summary": summary or "BitSight Alert",
            "severity": severity,
            "source": source or "Splunk BitSight App",
            "group": group or "vendor-risk",
            "class": event_class or "security-rating",
            "custom_details": _build_custom_details(payload),
        },
    }

    if dedup_key:
        pd_payload["dedup_key"] = dedup_key

    if component:
        pd_payload["payload"]["component"] = component

    headers = {"Content-Type": "application/json"}

    try:
        if requests is not None:
            response = requests.post(
                PAGERDUTY_EVENTS_URL,
                json=pd_payload,
                headers=headers,
                timeout=timeout,
            )

            response_text = response.text
            if response.status_code >= 400:
                return False, f"PagerDuty returned status {response.status_code}: {response_text}"

            try:
                response_json = response.json()
            except Exception:
                response_json = {}

            returned_dedup_key = response_json.get("dedup_key") or dedup_key or "unknown"
            return True, f"PagerDuty event created: {returned_dedup_key}"

        data = json.dumps(pd_payload).encode("utf-8")
        request = urllib.request.Request(PAGERDUTY_EVENTS_URL, data=data, headers=headers)

        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.getcode()
            body = response.read().decode("utf-8", errors="replace")

            if status >= 400:
                return False, f"PagerDuty returned status {status}: {body}"

            try:
                response_json = json.loads(body)
            except Exception:
                response_json = {}

            returned_dedup_key = response_json.get("dedup_key") or dedup_key or "unknown"
            return True, f"PagerDuty event created: {returned_dedup_key}"

    except Exception as e:
        return False, f"PagerDuty request failed: {str(e)}"


def main() -> None:
    """Main entry point for alert action."""

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

    config = payload.get("configuration", {})
    if not isinstance(config, dict):
        print("ERROR: Invalid configuration payload", file=sys.stderr)
        sys.exit(1)

    success, message = send_pagerduty_event(config, payload)

    if success:
        print(f"INFO: {message}")
        sys.exit(0)

    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
