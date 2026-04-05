#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
=============================================================================
 bin/bitsight_validation.py
 BitSight for Splunk App
 BitSight Validation Script
=============================================================================

PURPOSE

Validates BitSight for Splunk App configuration and connectivity.

This script provides:

- app configuration validation
- required field validation
- proxy configuration validation
- logging configuration validation
- BitSight API connectivity validation
- proxy transport validation
- validation stanza updates
- BitSight app log file creation
- BitSight app validation logging

PRIMARY ANALYSIS OBJECTIVE

Provide setup-time and runtime validation for the BitSight for Splunk App so
administrators can verify configuration and connectivity before enabling or
troubleshooting data collection.

FILE LOCATION

App-relative path
bin/bitsight_validation.py

SCRIPT TYPE

Standalone Python validation script

EXECUTION MODEL

Invoked manually or by app validation workflows

CONFIGURATION FILE READ

bitsight_settings

CONFIGURATION FILE UPDATED

local/bitsight_settings.conf

STANZAS READ

settings
proxy
logging
validation

STANZA UPDATED

validation

VALIDATION CHECKS

api_token present
api_token not masked
base_url present
timeout greater than zero
log_level valid
proxy_url present when proxy_enabled is true
BitSight API reachable
proxy transport reachable when proxy is enabled

VALIDATION OUTPUT

JSON to stdout

VALIDATION STATUS FIELDS

success
checks
messages
timestamp

VALIDATION STATE FIELDS WRITTEN

first_run
validated
last_validation

APP LOG PATH MODEL

creates app-relative directory
var/log

creates app-relative file
var/log/bitsight.log

DEPENDENCIES

base64
configparser
datetime
json
os
ssl
sys
urllib.error
urllib.parse
urllib.request

=============================================================================
"""

import base64
import configparser
import datetime
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

APP_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_CONF_PATH = os.path.join(APP_ROOT, "default", "bitsight_settings.conf")
LOCAL_CONF_PATH = os.path.join(APP_ROOT, "local", "bitsight_settings.conf")
APP_LOG_DIR = os.path.join(APP_ROOT, "var", "log")
APP_LOG_FILE = os.path.join(APP_LOG_DIR, "bitsight.log")

DEFAULT_BASE_URL = "https://api.bitsighttech.com"
DEFAULT_TIMEOUT = 60
VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR"}


def ensure_bitsight_log_file() -> str:
    os.makedirs(APP_LOG_DIR, exist_ok=True)
    if not os.path.exists(APP_LOG_FILE):
        with open(APP_LOG_FILE, "a", encoding="utf-8"):
            pass
    return APP_LOG_FILE


def write_log(level: str, component: str, message: str) -> None:
    ensure_bitsight_log_file()
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"{timestamp} level={level} component={component} message={message}\n"
    with open(APP_LOG_FILE, "a", encoding="utf-8") as handle:
        handle.write(line)


def as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    text = str(value).strip().lower()
    if not text:
        return default
    return text in {"1", "true", "yes", "on"}


def normalize_base_url(base_url: str) -> str:
    normalized = (base_url or DEFAULT_BASE_URL).rstrip("/")

    if normalized.endswith("/ratings/v1"):
        return normalized

    if normalized.endswith("/ratings"):
        return normalized + "/v1"

    return normalized + "/ratings/v1"


def build_auth_header(api_token: str) -> str:
    token = base64.b64encode(f"{api_token}:".encode("utf-8")).decode("utf-8")
    return f"Basic {token}"


def build_ssl_context(verify_ssl: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if not verify_ssl:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def build_proxy_handler(proxy_stanza: Dict[str, str]) -> Optional[urllib.request.ProxyHandler]:
    proxy_enabled = as_bool(proxy_stanza.get("proxy_enabled", "false"), default=False)
    proxy_url = proxy_stanza.get("proxy_url", "").strip()
    proxy_username = proxy_stanza.get("proxy_username", "").strip()
    proxy_password = proxy_stanza.get("proxy_password", "")

    if not proxy_enabled or not proxy_url:
        return None

    parsed = urllib.parse.urlsplit(proxy_url)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc or parsed.path

    if proxy_username and "@" not in netloc:
        quoted_user = urllib.parse.quote(proxy_username, safe="")
        quoted_pass = urllib.parse.quote(proxy_password, safe="")
        credentials = quoted_user
        if proxy_password:
            credentials = f"{quoted_user}:{quoted_pass}"
        netloc = f"{credentials}@{netloc}"

    normalized_proxy_url = urllib.parse.urlunsplit(
        (
            scheme,
            netloc,
            parsed.path if parsed.netloc else "",
            parsed.query,
            parsed.fragment,
        )
    )

    return urllib.request.ProxyHandler(
        {
            "http": normalized_proxy_url,
            "https": normalized_proxy_url,
        }
    )


def build_opener(proxy_stanza: Dict[str, str], verify_ssl: bool) -> urllib.request.OpenerDirector:
    handlers: List[Any] = []

    proxy_handler = build_proxy_handler(proxy_stanza)
    if proxy_handler is not None:
        handlers.append(proxy_handler)

    handlers.append(urllib.request.HTTPSHandler(context=build_ssl_context(verify_ssl)))

    return urllib.request.build_opener(*handlers)


def load_conf_file(path: str) -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser()
    parser.optionxform = str.lower

    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            parser.read_file(handle)

    return parser


def load_merged_settings() -> Dict[str, Dict[str, str]]:
    merged: Dict[str, Dict[str, str]] = {}

    for path in (DEFAULT_CONF_PATH, LOCAL_CONF_PATH):
        parser = load_conf_file(path)
        for section in parser.sections():
            if section not in merged:
                merged[section] = {}
            for key, value in parser.items(section):
                merged[section][key] = value

    return merged


def validate_required_settings(
    settings: Dict[str, str],
    proxy: Dict[str, str],
    logging_stanza: Dict[str, str],
) -> List[str]:
    errors: List[str] = []

    api_token = settings.get("api_token", "").strip()
    base_url = settings.get("base_url", "").strip()
    timeout_value = settings.get("timeout", str(DEFAULT_TIMEOUT)).strip()
    proxy_enabled = as_bool(proxy.get("proxy_enabled", "false"), default=False)
    proxy_url = proxy.get("proxy_url", "").strip()
    log_level = logging_stanza.get("log_level", "INFO").strip().upper()

    if not api_token:
        errors.append("api_token is not configured")
    elif api_token == "********":
        errors.append("api_token is masked and cannot be validated")

    if not base_url:
        errors.append("base_url is not configured")

    try:
        timeout = int(timeout_value or DEFAULT_TIMEOUT)
        if timeout <= 0:
            errors.append("timeout must be greater than zero")
    except ValueError:
        errors.append("timeout must be an integer")

    if proxy_enabled and not proxy_url:
        errors.append("proxy_url is required when proxy_enabled is true")

    if log_level not in VALID_LOG_LEVELS:
        errors.append("log_level must be one of: DEBUG, INFO, WARNING, ERROR")

    return errors


def test_api_connection(settings: Dict[str, str], proxy: Dict[str, str]) -> Tuple[bool, str]:
    api_token = settings.get("api_token", "").strip()
    base_url = normalize_base_url(settings.get("base_url", DEFAULT_BASE_URL))
    verify_ssl = as_bool(settings.get("verify_ssl", "true"), default=True)
    timeout = int(settings.get("timeout", str(DEFAULT_TIMEOUT)) or DEFAULT_TIMEOUT)

    url = f"{base_url}/users"
    request = urllib.request.Request(url)
    request.add_header("Authorization", build_auth_header(api_token))
    request.add_header("Accept", "application/json")
    request.add_header("Content-Type", "application/json")
    request.add_header("User-Agent", "Splunk-BitSight-App/1.0.0")

    opener = build_opener(proxy, verify_ssl)

    try:
        with opener.open(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8", errors="replace")

        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            data = {}

        user_count = 0
        if isinstance(data, list):
            user_count = len(data)
        elif isinstance(data, dict):
            users = data.get("results", data.get("users", []))
            if isinstance(users, list):
                user_count = len(users)

        return True, f"BitSight API validation succeeded. Retrieved {user_count} user records."

    except urllib.error.HTTPError as exc:
        return False, f"BitSight API validation failed. HTTP Error {exc.code}: {exc.reason}"
    except Exception as exc:
        return False, f"BitSight API validation failed. {exc}"


def test_proxy_connection(settings: Dict[str, str], proxy: Dict[str, str]) -> Tuple[bool, str]:
    proxy_enabled = as_bool(proxy.get("proxy_enabled", "false"), default=False)
    proxy_url = proxy.get("proxy_url", "").strip()

    if not proxy_enabled:
        return True, "Proxy validation skipped because proxy is not enabled."

    if not proxy_url:
        return False, "Proxy validation failed. proxy_url is not configured."

    verify_ssl = as_bool(settings.get("verify_ssl", "true"), default=True)
    base_url = normalize_base_url(settings.get("base_url", DEFAULT_BASE_URL))

    request = urllib.request.Request(base_url)
    request.add_header("User-Agent", "Splunk-BitSight-App/1.0.0")

    opener = build_opener(proxy, verify_ssl)

    try:
        with opener.open(request, timeout=10):
            pass

        return True, f"Proxy validation succeeded via {proxy_url}"

    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return True, f"Proxy validation succeeded via {proxy_url}"
        return False, f"Proxy validation failed. HTTP Error {exc.code}: {exc.reason}"
    except Exception as exc:
        return False, f"Proxy validation failed. {exc}"


def update_validation_stanza(success: bool) -> None:
    os.makedirs(os.path.dirname(LOCAL_CONF_PATH), exist_ok=True)

    parser = load_conf_file(LOCAL_CONF_PATH)

    if not parser.has_section("validation"):
        parser.add_section("validation")

    parser.set("validation", "first_run", "false")
    parser.set("validation", "validated", "true" if success else "false")
    parser.set("validation", "last_validation", datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))

    with open(LOCAL_CONF_PATH, "w", encoding="utf-8") as handle:
        parser.write(handle)


def main() -> int:
    ensure_bitsight_log_file()
    write_log("INFO", "bitsight_validation.py", "Starting BitSight validation")

    merged = load_merged_settings()
    settings = merged.get("settings", {})
    proxy = merged.get("proxy", {})
    logging_stanza = merged.get("logging", {})

    messages: List[str] = []
    checks: Dict[str, bool] = {}

    validation_errors = validate_required_settings(settings, proxy, logging_stanza)
    checks["configuration"] = len(validation_errors) == 0

    if validation_errors:
        messages.extend(validation_errors)
        for item in validation_errors:
            write_log("ERROR", "bitsight_validation.py", item)

        update_validation_stanza(False)

        result = {
            "success": False,
            "checks": checks,
            "messages": messages,
            "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "bitsight_log_file": APP_LOG_FILE,
        }
        print(json.dumps(result, indent=2))
        return 1

    api_ok, api_message = test_api_connection(settings, proxy)
    checks["api_connection"] = api_ok
    messages.append(api_message)
    write_log("INFO" if api_ok else "ERROR", "bitsight_validation.py", api_message)

    proxy_ok, proxy_message = test_proxy_connection(settings, proxy)
    checks["proxy_connection"] = proxy_ok
    messages.append(proxy_message)
    write_log("INFO" if proxy_ok else "ERROR", "bitsight_validation.py", proxy_message)

    success = all(checks.values())
    update_validation_stanza(success)

    final_message = "BitSight validation completed successfully." if success else "BitSight validation failed."
    messages.append(final_message)
    write_log("INFO" if success else "ERROR", "bitsight_validation.py", final_message)

    result = {
        "success": success,
        "checks": checks,
        "messages": messages,
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "bitsight_log_file": APP_LOG_FILE,
    }

    print(json.dumps(result, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
