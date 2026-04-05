#!/usr/bin/env python3
# encoding: utf-8

"""
=============================================================================
 bin/bitsight_snow_alert.py
 BitSight for Splunk App
 ServiceNow Alert Action
=============================================================================

PURPOSE

Creates ServiceNow incidents for BitSight alerts.

Builds a ServiceNow incident request from the Splunk alert action payload
and configuration.

Supports:

- ServiceNow URL configuration
- ServiceNow username and password configuration
- incident category configuration
- incident subcategory configuration
- incident priority configuration
- short description substitution
- description substitution
- requests library usage
- urllib fallback handling

FILE LOCATION

App-relative path
bin/bitsight_snow_alert.py

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

snow_url
snow_user
snow_password
incident_category
incident_subcategory
incident_priority
incident_short_description
incident_description
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

Configured ServiceNow instance URL
api/now/table/incident

HTTP METHOD

POST

CONTENT TYPE

application/json

AUTHENTICATION MODEL

Basic authentication
snow_user
snow_password

DEPENDENCIES

base64
json
os
re
sys
typing
requests
urllib.request
urllib.error
urllib.parse
ssl

=============================================================================
"""

import base64
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
    import urllib.parse
    import urllib.request

    requests = None


DEFAULT_TIMEOUT = 30


def _clean_string(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _normalize_snow_url(snow_url: str) -> str:
    normalized = _clean_string(snow_url)
    if not normalized:
        return ""

    normalized = normalized.rstrip("/")

    if normalized.endswith("/api/now/table/incident"):
        return normalized

    if "/api/now/" in normalized:
        return normalized

    return normalized + "/api/now/table/incident"


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


def _build_incident_payload(config: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    short_description = substitute_variables(
        config.get("incident_short_description", "[BitSight] Alert"),
        payload,
    )
    description = substitute_variables(
        config.get("incident_description", "BitSight alert triggered."),
        payload,
    )
    category = substitute_variables(config.get("incident_category", "Security"), payload)
    subcategory = substitute_variables(config.get("incident_subcategory", "Vendor Risk"), payload)
    priority = substitute_variables(config.get("incident_priority", "3"), payload)

    result = payload.get("result", {})
    if not isinstance(result, dict):
        result = {}

    incident_payload: Dict[str, Any] = {
        "category": category,
        "subcategory": subcategory,
        "priority": priority,
        "short_description": short_description,
        "description": description,
        "u_search_name": str(payload.get("search_name", "") or ""),
        "u_trigger_time": str(payload.get("trigger_time", "") or ""),
        "u_results_link": str(payload.get("results_link", "") or ""),
    }

    company_name = result.get("company_name")
    if company_name not in (None, ""):
        incident_payload["u_company_name"] = str(company_name)

    rating = result.get("rating")
    if rating not in (None, ""):
        incident_payload["u_bitsight_rating"] = str(rating)

    rating_change = result.get("rating_change")
    if rating_change not in (None, ""):
        incident_payload["u_rating_change"] = str(rating_change)

    risk_vectors = result.get("risk_vectors")
    if risk_vectors not in (None, ""):
        incident_payload["u_risk_vectors"] = str(risk_vectors)

    severity = result.get("severity")
    if severity not in (None, ""):
        incident_payload["u_bitsight_severity"] = str(severity)

    return {k: v for k, v in incident_payload.items() if v not in (None, "")}


def send_servicenow_event(config: Dict[str, Any], payload: Dict[str, Any]) -> Tuple[bool, str]:
    """Create ServiceNow incident."""

    snow_url = _normalize_snow_url(config.get("snow_url", ""))
    snow_user = _clean_string(config.get("snow_user"))
    snow_password = str(config.get("snow_password", "") or "")
    timeout = int(config.get("timeout", DEFAULT_TIMEOUT) or DEFAULT_TIMEOUT)

    if not snow_url:
        return False, "No ServiceNow URL configured"

    if not snow_user:
        return False, "No ServiceNow username configured"

    if not snow_password:
        return False, "No ServiceNow password configured"

    incident_payload = _build_incident_payload(config, payload)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    try:
        if requests is not None:
            response = requests.post(
                snow_url,
                json=incident_payload,
                headers=headers,
                auth=(snow_user, snow_password),
                timeout=timeout,
            )

            if response.status_code >= 400:
                return False, f"ServiceNow returned status {response.status_code}: {response.text}"

            try:
                response_json = response.json()
            except Exception:
                response_json = {}

            result = response_json.get("result", {})
            incident_number = result.get("number") or "unknown"
            sys_id = result.get("sys_id") or "unknown"
            return True, f"ServiceNow incident created: {incident_number} ({sys_id})"

        request_body = json.dumps(incident_payload).encode("utf-8")
        auth_string = base64.b64encode(f"{snow_user}:{snow_password}".encode("utf-8")).decode("utf-8")

        request = urllib.request.Request(
            snow_url,
            data=request_body,
            headers={
                **headers,
                "Authorization": f"Basic {auth_string}",
            },
            method="POST",
        )

        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.getcode()
            body = response.read().decode("utf-8", errors="replace")

            if status >= 400:
                return False, f"ServiceNow returned status {status}: {body}"

            try:
                response_json = json.loads(body)
            except Exception:
                response_json = {}

            result = response_json.get("result", {})
            incident_number = result.get("number") or "unknown"
            sys_id = result.get("sys_id") or "unknown"
            return True, f"ServiceNow incident created: {incident_number} ({sys_id})"

    except Exception as e:
        return False, f"ServiceNow request failed: {str(e)}"


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

    success, message = send_servicenow_event(config, payload)

    if success:
        print(f"INFO: {message}")
        sys.exit(0)

    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
