#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
=============================================================================
 bin/bitsight_setup_handler.py
 BitSight for Splunk App
 BitSight Setup Handler for Splunk
=============================================================================

PURPOSE

Handles BitSight configuration management through Splunk setup endpoints.

This handler provides:

- setup configuration management
- masked sensitive field handling
- BitSight settings stanza management
- proxy stanza management
- input toggle stanza management
- collection stanza management
- logging stanza management
- validation stanza visibility
- API connection testing
- proxy connection testing
- BitSight app log directory creation
- BitSight app log file creation

PRIMARY ANALYSIS OBJECTIVE

Provide REST-backed setup handling for the BitSight for Splunk App so
administrators can manage configuration and validate connectivity through
the Splunk setup interface.

FILE LOCATION

App-relative path
bin/bitsight_setup_handler.py

SCRIPT TYPE

Splunk admin configuration handler

EXECUTION MODEL

Invoked by Splunk admin endpoint handlers
supports setup handler and test handler classes

CONFIGURATION FILE MANAGED

bitsight_settings

STANZAS MANAGED

settings
proxy
inputs
collection
logging
validation

SETUP ENTITIES SUPPORTED

settings
proxy
inputs
collection
logging

TEST ENTITIES SUPPORTED

test

GRANULAR DOCUMENTATION SPECIFICATION

SETTINGS FIELDS

api_token
base_url
verify_ssl
timeout

PROXY FIELDS

proxy_enabled
proxy_url
proxy_username
proxy_password

INPUT TOGGLE FIELDS

input_portfolio
input_ratings
input_ratings_history
input_ratings_history_csv
input_company_details
input_country_details
input_company_requests_summary
input_findings
input_findings_compromised
input_findings_diligence
input_findings_summary
input_finding_comments
input_risk_vectors
input_alerts
input_exposed_credentials
input_threats
input_users
input_user_quota
input_user_company_views
input_folders
input_tiers
input_industries
input_assets
input_asset_risk_matrix
input_infrastructure
input_infrastructure_changes
input_ip_by_country
input_diligence_statistics
input_observations_statistics
input_industry_statistics
input_user_behavior_statistics
input_service_providers
input_products
input_ratings_tree
input_observations
input_findings_summaries
input_findings_statistics
input_peer_analytics
input_rating_distribution
input_nist_csf_report
input_preview_report
input_risk_vectors_summary

COLLECTION FIELDS

portfolio_interval
ratings_interval
ratings_history_interval
ratings_history_csv_interval
company_details_interval
country_details_interval
company_requests_summary_interval
findings_interval
findings_compromised_interval
findings_diligence_interval
findings_summary_interval
finding_comments_interval
risk_vectors_interval
alerts_interval
threats_interval
exposed_credentials_interval
users_interval
user_quota_interval
user_company_views_interval
folders_interval
tiers_interval
industries_interval
assets_interval
asset_risk_matrix_interval
infrastructure_interval
infrastructure_changes_interval
ip_by_country_interval
diligence_statistics_interval
observations_statistics_interval
industry_statistics_interval
user_behavior_statistics_interval
service_providers_interval
products_interval
ratings_tree_interval
observations_interval
findings_summaries_interval
findings_statistics_interval
peer_analytics_interval
rating_distribution_interval
nist_csf_report_interval
preview_report_interval
risk_vectors_summary_interval
days_back

LOGGING FIELDS

log_level

VALIDATION FIELDS

first_run
validated
last_validation

SENSITIVE FIELDS

api_token
proxy_password

MASKING MODEL

Sensitive fields are masked as ******** in handleList output

TEST OPERATIONS

test_api
validates BitSight API authentication and connectivity

test_proxy
validates configured proxy connectivity

API TEST AUTH MODEL

Basic authentication
base64 encoded as api_token colon

API TEST TARGET

normalized BitSight API base URL
users endpoint

PROXY TEST MODEL

uses configured proxy opener
tests normalized BitSight API base URL reachability
401 and 403 responses count as successful transport validation

APP LOG PATH MODEL

creates app-relative directory
var/log

creates app-relative file
var/log/bitsight.log

DEPENDENCIES

base64
json
os
ssl
sys
urllib.error
urllib.parse
urllib.request
splunk.admin

=============================================================================
"""

import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

SPLUNK_IMPORT_ERROR: Optional[Exception] = None

try:
    import splunk.admin as admin
except ImportError as e:  # pragma: no cover
    admin = None
    SPLUNK_IMPORT_ERROR = e


APP_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
APP_LOG_DIR = os.path.join(APP_ROOT, "var", "log")
APP_LOG_FILE = os.path.join(APP_LOG_DIR, "bitsight.log")


def ensure_bitsight_log_file() -> str:
    """
    Ensure the BitSight app log directory and log file exist.

    Returns
    -------
    str
        Absolute path to the BitSight app log file.
    """
    os.makedirs(APP_LOG_DIR, exist_ok=True)

    if not os.path.exists(APP_LOG_FILE):
        with open(APP_LOG_FILE, "a", encoding="utf-8"):
            pass

    return APP_LOG_FILE


class BitsightSetupHandler(admin.MConfigHandler):
    """
    Setup handler for BitSight configuration.
    """

    CONF_FILE = "bitsight_settings"

    SETTINGS_FIELDS = [
        "api_token",
        "base_url",
        "verify_ssl",
        "timeout",
    ]

    PROXY_FIELDS = [
        "proxy_enabled",
        "proxy_url",
        "proxy_username",
        "proxy_password",
    ]

    INPUT_FIELDS = [
        "input_portfolio",
        "input_ratings",
        "input_ratings_history",
        "input_ratings_history_csv",
        "input_company_details",
        "input_country_details",
        "input_company_requests_summary",
        "input_findings",
        "input_findings_compromised",
        "input_findings_diligence",
        "input_findings_summary",
        "input_finding_comments",
        "input_risk_vectors",
        "input_alerts",
        "input_exposed_credentials",
        "input_threats",
        "input_users",
        "input_user_quota",
        "input_user_company_views",
        "input_folders",
        "input_tiers",
        "input_industries",
        "input_assets",
        "input_asset_risk_matrix",
        "input_infrastructure",
        "input_infrastructure_changes",
        "input_ip_by_country",
        "input_diligence_statistics",
        "input_observations_statistics",
        "input_industry_statistics",
        "input_user_behavior_statistics",
        "input_service_providers",
        "input_products",
        "input_ratings_tree",
        "input_observations",
        "input_findings_summaries",
        "input_findings_statistics",
        "input_peer_analytics",
        "input_rating_distribution",
        "input_nist_csf_report",
        "input_preview_report",
        "input_risk_vectors_summary",
    ]

    COLLECTION_FIELDS = [
        "portfolio_interval",
        "ratings_interval",
        "ratings_history_interval",
        "ratings_history_csv_interval",
        "company_details_interval",
        "country_details_interval",
        "company_requests_summary_interval",
        "findings_interval",
        "findings_compromised_interval",
        "findings_diligence_interval",
        "findings_summary_interval",
        "finding_comments_interval",
        "risk_vectors_interval",
        "alerts_interval",
        "threats_interval",
        "exposed_credentials_interval",
        "users_interval",
        "user_quota_interval",
        "user_company_views_interval",
        "folders_interval",
        "tiers_interval",
        "industries_interval",
        "assets_interval",
        "asset_risk_matrix_interval",
        "infrastructure_interval",
        "infrastructure_changes_interval",
        "ip_by_country_interval",
        "diligence_statistics_interval",
        "observations_statistics_interval",
        "industry_statistics_interval",
        "user_behavior_statistics_interval",
        "service_providers_interval",
        "products_interval",
        "ratings_tree_interval",
        "observations_interval",
        "findings_summaries_interval",
        "findings_statistics_interval",
        "peer_analytics_interval",
        "rating_distribution_interval",
        "nist_csf_report_interval",
        "preview_report_interval",
        "risk_vectors_summary_interval",
        "days_back",
    ]

    LOGGING_FIELDS = [
        "log_level",
    ]

    VALIDATION_FIELDS = [
        "first_run",
        "validated",
        "last_validation",
    ]

    EDIT_FIELD_MAP = {
        "settings": SETTINGS_FIELDS,
        "proxy": PROXY_FIELDS,
        "inputs": INPUT_FIELDS,
        "collection": COLLECTION_FIELDS,
        "logging": LOGGING_FIELDS,
        "validation": VALIDATION_FIELDS,
    }

    SENSITIVE_FIELDS = {
        "api_token",
        "proxy_password",
    }

    VALID_LOG_LEVELS = {
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
    }

    def setup(self):
        """
        Setup the handler with supported arguments.
        """
        if self.requestedAction == admin.ACTION_EDIT:
            for field_list in self.EDIT_FIELD_MAP.values():
                for field in field_list:
                    self.supportedArgs.addOptArg(field)

    def handleList(self, confInfo):
        """
        List current configuration.
        """
        ensure_bitsight_log_file()

        conf_dict = self.readConf(self.CONF_FILE)

        if conf_dict is None:
            return

        for stanza, settings in conf_dict.items():
            for key, val in settings.items():
                if key in self.SENSITIVE_FIELDS and val:
                    confInfo[stanza].append(key, "********")
                else:
                    confInfo[stanza].append(key, val)

    def handleEdit(self, confInfo):
        """
        Update configuration.
        """
        ensure_bitsight_log_file()

        stanza_name = str(self.callerArgs.id)
        args = self.callerArgs

        if stanza_name not in self.EDIT_FIELD_MAP:
            raise ValueError(f"Unsupported setup entity: {stanza_name}")

        updates = self._collect_updates(stanza_name, args.data)
        self._validate_updates(stanza_name, updates)

        if updates:
            self.writeConf(self.CONF_FILE, stanza_name, updates)

        confInfo[stanza_name].append("status", "updated")
        confInfo[stanza_name].append("bitsight_log_file", APP_LOG_FILE)

    def _collect_updates(self, stanza_name: str, args_data: Dict[str, List[str]]) -> Dict[str, str]:
        updates: Dict[str, str] = {}

        for field in self.EDIT_FIELD_MAP[stanza_name]:
            if field not in args_data:
                continue

            value = self._first_value(args_data, field)

            if field in self.SENSITIVE_FIELDS and value == "********":
                continue

            updates[field] = value

        return updates

    def _validate_updates(self, stanza_name: str, updates: Dict[str, str]) -> None:
        if not updates:
            return

        if stanza_name == "settings":
            if "base_url" in updates and not updates["base_url"].strip():
                raise ValueError("base_url cannot be empty")

            if "timeout" in updates:
                timeout = int(updates["timeout"])
                if timeout <= 0:
                    raise ValueError("timeout must be greater than zero")

        elif stanza_name == "proxy":
            proxy_enabled = self._as_bool(updates.get("proxy_enabled", "false"))
            proxy_url = updates.get("proxy_url", "").strip()

            if proxy_enabled and not proxy_url:
                raise ValueError("proxy_url is required when proxy_enabled is true")

        elif stanza_name == "collection":
            for field, value in updates.items():
                if field == "days_back":
                    if int(value) <= 0:
                        raise ValueError("days_back must be greater than zero")
                else:
                    if int(value) <= 0:
                        raise ValueError(f"{field} must be greater than zero")

        elif stanza_name == "logging":
            if "log_level" in updates:
                log_level = updates["log_level"].upper()
                if log_level not in self.VALID_LOG_LEVELS:
                    raise ValueError(
                        "log_level must be one of: {0}".format(
                            ", ".join(sorted(self.VALID_LOG_LEVELS))
                        )
                    )

        elif stanza_name == "validation":
            if "last_validation" in updates and not updates["last_validation"].strip():
                pass

    @staticmethod
    def _first_value(args_data: Dict[str, List[str]], field: str) -> str:
        values = args_data.get(field, [])
        if not values:
            return ""
        return str(values[0])

    @staticmethod
    def _as_bool(value: Any) -> bool:
        return str(value).strip().lower() in {"1", "true", "yes", "on"}


class BitsightTestHandler(admin.MConfigHandler):
    """
    Handler for testing API and proxy connections.
    """

    CONF_FILE = "bitsight_settings"
    DEFAULT_BASE_URL = "https://api.bitsighttech.com"
    DEFAULT_TIMEOUT = 60

    def setup(self):
        """
        Setup the handler.
        """
        if self.requestedAction == admin.ACTION_EDIT:
            self.supportedArgs.addOptArg("test_api")
            self.supportedArgs.addOptArg("test_proxy")

    def handleList(self, confInfo):
        """
        Return test status.
        """
        ensure_bitsight_log_file()
        confInfo["test"].append("status", "ready")
        confInfo["test"].append("bitsight_log_file", APP_LOG_FILE)

    def handleEdit(self, confInfo):
        """
        Execute connection tests.
        """
        ensure_bitsight_log_file()

        args = self.callerArgs

        if "test_api" in args.data:
            result = self._test_api_connection()
            confInfo["test"].append("api_result", result)

        if "test_proxy" in args.data:
            result = self._test_proxy_connection()
            confInfo["test"].append("proxy_result", result)

        confInfo["test"].append("bitsight_log_file", APP_LOG_FILE)

    def _test_api_connection(self) -> str:
        """
        Test BitSight API connection.
        """
        try:
            settings = self._read_stanza("settings")
            proxy = self._read_stanza("proxy")

            api_token = settings.get("api_token", "")
            base_url = self._normalize_base_url(settings.get("base_url", self.DEFAULT_BASE_URL))
            verify_ssl = self._as_bool(settings.get("verify_ssl", "true"), default=True)
            timeout = int(settings.get("timeout", self.DEFAULT_TIMEOUT) or self.DEFAULT_TIMEOUT)

            if not api_token or api_token == "********":
                return json.dumps(
                    {
                        "success": False,
                        "message": "API token not configured",
                    }
                )

            url = f"{base_url}/users"
            request = urllib.request.Request(url)
            request.add_header("Authorization", self._build_auth_header(api_token))
            request.add_header("Accept", "application/json")
            request.add_header("Content-Type", "application/json")
            request.add_header("User-Agent", "Splunk-BitSight-App/1.0.0")

            opener = self._build_opener(proxy, verify_ssl)
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

            return json.dumps(
                {
                    "success": True,
                    "message": f"Connected successfully to BitSight API. Retrieved {user_count} user records.",
                }
            )

        except urllib.error.HTTPError as e:
            return json.dumps(
                {
                    "success": False,
                    "message": f"HTTP Error {e.code}: {e.reason}",
                }
            )
        except Exception as e:
            return json.dumps(
                {
                    "success": False,
                    "message": str(e),
                }
            )

    def _test_proxy_connection(self) -> str:
        """
        Test proxy connection.
        """
        try:
            settings = self._read_stanza("settings")
            proxy = self._read_stanza("proxy")

            proxy_enabled = self._as_bool(proxy.get("proxy_enabled", "false"), default=False)
            proxy_url = proxy.get("proxy_url", "").strip()
            verify_ssl = self._as_bool(settings.get("verify_ssl", "true"), default=True)

            if not proxy_enabled:
                return json.dumps(
                    {
                        "success": False,
                        "message": "Proxy is not enabled",
                    }
                )

            if not proxy_url:
                return json.dumps(
                    {
                        "success": False,
                        "message": "Proxy URL not configured",
                    }
                )

            base_url = self._normalize_base_url(settings.get("base_url", self.DEFAULT_BASE_URL))
            request = urllib.request.Request(base_url)
            request.add_header("User-Agent", "Splunk-BitSight-App/1.0.0")

            opener = self._build_opener(proxy, verify_ssl)

            try:
                with opener.open(request, timeout=10):
                    pass

                return json.dumps(
                    {
                        "success": True,
                        "message": f"Proxy connection successful via {proxy_url}",
                    }
                )

            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    return json.dumps(
                        {
                            "success": True,
                            "message": f"Proxy connection successful via {proxy_url}",
                        }
                    )
                raise

        except Exception as e:
            return json.dumps(
                {
                    "success": False,
                    "message": str(e),
                }
            )

    def _read_stanza(self, stanza_name: str) -> Dict[str, str]:
        conf = self.readConf(self.CONF_FILE)
        if not conf:
            return {}
        return conf.get(stanza_name, {}) or {}

    def _build_opener(self, proxy_stanza: Dict[str, str], verify_ssl: bool) -> urllib.request.OpenerDirector:
        handlers: List[Any] = []

        proxy_handler = self._build_proxy_handler(proxy_stanza)
        if proxy_handler is not None:
            handlers.append(proxy_handler)

        handlers.append(urllib.request.HTTPSHandler(context=self._build_ssl_context(verify_ssl)))

        return urllib.request.build_opener(*handlers)

    def _build_proxy_handler(self, proxy_stanza: Dict[str, str]) -> Optional[urllib.request.ProxyHandler]:
        proxy_enabled = self._as_bool(proxy_stanza.get("proxy_enabled", "false"), default=False)
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

        normalized_proxy_url = urllib.parse.urlunsplit((scheme, netloc, parsed.path if parsed.netloc else "", parsed.query, parsed.fragment))

        return urllib.request.ProxyHandler(
            {
                "http": normalized_proxy_url,
                "https": normalized_proxy_url,
            }
        )

    @staticmethod
    def _build_auth_header(api_token: str) -> str:
        token = base64.b64encode(f"{api_token}:".encode("utf-8")).decode("utf-8")
        return f"Basic {token}"

    @staticmethod
    def _build_ssl_context(verify_ssl: bool) -> ssl.SSLContext:
        context = ssl.create_default_context()
        if not verify_ssl:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    @staticmethod
    def _normalize_base_url(base_url: str) -> str:
        normalized = (base_url or BitsightTestHandler.DEFAULT_BASE_URL).rstrip("/")

        if normalized.endswith("/ratings/v1"):
            return normalized

        if normalized.endswith("/ratings"):
            return normalized + "/v1"

        return normalized + "/ratings/v1"

    @staticmethod
    def _as_bool(value: Any, default: bool = False) -> bool:
        if value is None:
            return default
        text = str(value).strip().lower()
        if not text:
            return default
        return text in {"1", "true", "yes", "on"}


if __name__ == "__main__":
    if SPLUNK_IMPORT_ERROR is not None:
        print(f"ERROR: {SPLUNK_IMPORT_ERROR}", file=sys.stderr)
        sys.exit(1)

    script_name = os.path.basename(sys.argv[0])

    if script_name == "bitsight_test_handler.py":
        admin.init(BitsightTestHandler, admin.CONTEXT_NONE)
    else:
        admin.init(BitsightSetupHandler, admin.CONTEXT_NONE)
