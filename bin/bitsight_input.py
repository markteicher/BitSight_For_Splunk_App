#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
=============================================================================
 bin/bitsight_modular_input.py
 BitSight for Splunk App
 BitSight Modular Input for Splunk
=============================================================================

PURPOSE

Collects data from the BitSight Security Ratings API for Splunk ingestion.

This modular input provides:

- configurable index selection
- shared BitSight settings support
- per-input override support
- proxy configuration support
- configurable request timeout
- SSL verification control
- company and user scoped collection
- historical collection support
- risk vector filtering support
- paginated API collection support
- normalized underscore-based sourcetype mapping
- JSON and non-JSON response handling

PRIMARY ANALYSIS OBJECTIVE

Provide a single modular input implementation that can collect BitSight
portfolio, ratings, findings, alerts, threats, user, infrastructure,
statistics, and reporting data for indexing into Splunk.

FILE LOCATION

App-relative path
bin/bitsight_modular_input.py

SCRIPT TYPE

Splunk modular input script

EXECUTION MODEL

Invoked by Splunk modular input framework
runs through Script.run(sys.argv)

GRANULAR DOCUMENTATION SPECIFICATION

INPUT ARGUMENTS

api_token
optional per-input API token override

base_url
optional per-input API base URL override

endpoint
BitSight endpoint key to collect

index
target Splunk index

company_guid
company GUID for company-scoped endpoints

country_guid
country GUID for country-scoped endpoints

user_guid
user GUID for user-scoped endpoints

observation_id
observation or finding identifier for comment endpoints

risk_vectors
comma-separated risk vector filter for findings endpoints

days_back
historical lookback window in days

proxy_enabled
enable or disable proxy use

proxy_url
proxy URL

proxy_username
proxy authentication username

proxy_password
proxy authentication password

verify_ssl
enable or disable SSL certificate verification

timeout
request timeout in seconds

SETTINGS FILE FALLBACK

If per-input values are not supplied, the script reads:

default/bitsight_settings.conf
local/bitsight_settings.conf

SECTIONS USED FROM SETTINGS FILE

settings
proxy

SETTINGS FIELDS USED

api_token
base_url
verify_ssl
timeout

proxy_enabled
proxy_url
proxy_username
proxy_password

OUTPUT BEHAVIOR

Writes Splunk events with:

stanza
input stanza name

index
configured index

sourcetype
normalized underscore-based BitSight sourcetype mapping

time
collection timestamp

EVENT FIELDS ADDED BEFORE INDEXING

_collection_time
_collection_date
_endpoint
_input_name

SOURCETYPE STYLE

All sourcetypes use underscores
No colon-based sourcetypes are used

PAGINATION MODEL

Supports BitSight paginated responses using:
links.next

RESPONSE MODES

application/json
parsed and normalized

non-JSON
wrapped as raw_response event payload

RISK VECTOR FILTER MODEL

Applies only to findings endpoints
uses comma-separated risk_vector query value

DEPENDENCIES

base64
configparser
datetime
json
os
ssl
sys
time
typing
urllib.error
urllib.parse
urllib.request
splunklib.modularinput

=============================================================================
"""

import base64
import configparser
import datetime
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple, Union

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

SPLUNKLIB_IMPORT_ERROR: Optional[Exception] = None

try:
    from splunklib.modularinput import Argument, Event, EventWriter, Scheme, Script
except ImportError as e:  # pragma: no cover
    Argument = None
    Event = None
    EventWriter = None
    Scheme = None
    Script = object
    SPLUNKLIB_IMPORT_ERROR = e


JsonType = Union[Dict[str, Any], List[Any], str, int, float, bool, None]


class BitsightInput(Script):
    """BitSight modular input script."""

    DEFAULT_API_BASE = "https://api.bitsighttech.com/ratings/v1"
    DEFAULT_INDEX = "security_bitsight"
    DEFAULT_TIMEOUT = 60
    DEFAULT_DAYS_BACK = 365

    ENDPOINTS: Dict[str, str] = {
        "portfolio": "/portfolio",
        "company-details": "/companies/{guid}",
        "country-details": "/companies/{country_guid}",
        "company-search": "/companies/search",
        "rating-distribution": "/companies/distribution",
        "trending-companies": "/companies/search/trending",
        "ratings-tree": "/companies/{guid}/company-tree",
        "company-requests-summary": "/companies/infrastructure/requests/summaries",
        "current-ratings": "/companies/{guid}",
        "ratings-history": "/companies/{guid}/history/ratings",
        "ratings-history-csv": "/companies/{guid}/reports/ratings-history",
        "grade-history": "/companies/{guid}/history/grade",
        "findings": "/companies/{guid}/findings",
        "findings-summary": "/companies/{guid}/findings/summary",
        "findings-summaries": "/companies/{guid}/findings/summaries",
        "findings-statistics": "/companies/{guid}/findings/statistics",
        "finding-comments": "/companies/{guid}/findings/{observation_id}/comments",
        "observations": "/companies/{guid}/observations",
        "risk-vectors": "/companies/{guid}/risk-vectors",
        "risk-vectors-summary": "/companies/{guid}/risk-vectors/summaries",
        "diligence-statistics": "/companies/{guid}/diligence/statistics",
        "diligence-historical": "/companies/{guid}/diligence/historical-statistics",
        "industry-statistics": "/companies/{guid}/industries/statistics",
        "user-behavior-statistics": "/companies/{guid}/user-behavior/statistics",
        "observations-statistics": "/companies/{guid}/observations/statistics",
        "assets": "/companies/{guid}/assets",
        "assets-summaries": "/companies/{guid}/assets/summaries",
        "asset-risk-matrix": "/companies/{guid}/assets/statistics",
        "infrastructure": "/companies/{guid}/infrastructure",
        "infrastructure-changes": "/companies/{guid}/infrastructure/changes",
        "infrastructure-tags": "/companies/{guid}/tags",
        "ip-by-country": "/companies/{guid}/countries",
        "service-providers": "/companies/{guid}/providers",
        "products": "/companies/{guid}/products",
        "company-tree-providers": "/companies/{guid}/company-tree/providers",
        "company-tree-products": "/companies/{guid}/company-tree/products",
        "users": "/users",
        "user-details": "/users/{user_guid}",
        "user-quota": "/users/quota",
        "user-company-views": "/users/{user_guid}/company-views",
        "alerts": "/alerts",
        "exposed-credentials": "/exposed-credentials",
        "threats": "/threats",
        "folders": "/folders",
        "tiers": "/tiers",
        "subscriptions": "/subscriptions",
        "industries": "/industries",
        "peer-analytics": "/companies/{guid}/peer-analytics/peer-group/count",
        "nist-csf-report": "/companies/{guid}/regulatory/nist",
        "preview-report": "/companies/{guid}/reports/company-preview",
    }

    SOURCETYPE_MAP: Dict[str, str] = {
        "portfolio": "bitsight_portfolio",
        "company-details": "bitsight_company",
        "country-details": "bitsight_country",
        "company-search": "bitsight_company",
        "rating-distribution": "bitsight_rating_distribution",
        "trending-companies": "bitsight_company",
        "ratings-tree": "bitsight_ratings_tree",
        "company-requests-summary": "bitsight_company_requests",
        "current-ratings": "bitsight_ratings",
        "ratings-history": "bitsight_ratings_history",
        "ratings-history-csv": "bitsight_ratings_history_csv",
        "grade-history": "bitsight_ratings_history",
        "findings": "bitsight_findings",
        "findings-summary": "bitsight_findings_summary",
        "findings-summaries": "bitsight_findings_summaries",
        "findings-statistics": "bitsight_findings_statistics",
        "finding-comments": "bitsight_findings_comments",
        "observations": "bitsight_observations",
        "risk-vectors": "bitsight_risk_vectors",
        "risk-vectors-summary": "bitsight_risk_vectors_summary",
        "diligence-statistics": "bitsight_diligence_statistics",
        "diligence-historical": "bitsight_diligence_statistics",
        "industry-statistics": "bitsight_industry_statistics",
        "user-behavior-statistics": "bitsight_user_behavior_statistics",
        "observations-statistics": "bitsight_observations_statistics",
        "assets": "bitsight_assets",
        "assets-summaries": "bitsight_assets",
        "asset-risk-matrix": "bitsight_assets_statistics",
        "infrastructure": "bitsight_infrastructure",
        "infrastructure-changes": "bitsight_infrastructure_changes",
        "infrastructure-tags": "bitsight_infrastructure",
        "ip-by-country": "bitsight_ip_by_country",
        "service-providers": "bitsight_providers",
        "products": "bitsight_products",
        "company-tree-providers": "bitsight_providers",
        "company-tree-products": "bitsight_products",
        "users": "bitsight_users",
        "user-details": "bitsight_users",
        "user-quota": "bitsight_users_quota",
        "user-company-views": "bitsight_users_views",
        "alerts": "bitsight_alerts",
        "exposed-credentials": "bitsight_credentials",
        "threats": "bitsight_threats",
        "folders": "bitsight_folders",
        "tiers": "bitsight_tiers",
        "subscriptions": "bitsight_subscriptions",
        "industries": "bitsight_industries",
        "peer-analytics": "bitsight_peer_analytics",
        "nist-csf-report": "bitsight_nist_csf",
        "preview-report": "bitsight_preview_report",
    }

    RISK_VECTORS: List[str] = [
        "botnet_infections",
        "spam_propagation",
        "malware_servers",
        "unsolicited_comm",
        "potentially_exploited",
        "open_ports",
        "patching_cadence",
        "insecure_systems",
        "ssl_certificates",
        "ssl_configurations",
        "spf",
        "dkim",
        "dnssec",
        "mobile_application_security",
        "web_appsec",
        "application_security",
        "dmarc",
        "file_sharing",
        "desktop_software",
        "server_software",
        "mobile_software",
    ]

    RESULT_KEYS: Tuple[str, ...] = (
        "results",
        "companies",
        "alerts",
        "users",
        "folders",
        "tiers",
        "industries",
        "subscriptions",
        "assets",
        "providers",
        "products",
        "observations",
        "findings",
        "comments",
    )

    def get_scheme(self):
        if Scheme is None or Argument is None:
            raise RuntimeError("splunklib.modularinput is not available")

        scheme = Scheme("BitSight API")
        scheme.description = "Collects security ratings data from the BitSight API"
        scheme.use_external_validation = True
        scheme.use_single_instance = False

        self._add_argument(
            scheme=scheme,
            name="api_token",
            title="API Token",
            description="Optional per-input BitSight API token override",
            data_type=Argument.data_type_string,
            required_on_create=False,
            required_on_edit=False,
        )

        self._add_argument(
            scheme=scheme,
            name="base_url",
            title="API Base URL",
            description="Optional per-input BitSight API base URL override",
            data_type=Argument.data_type_string,
            required_on_create=False,
            required_on_edit=False,
        )

        self._add_argument(
            scheme=scheme,
            name="endpoint",
            title="Endpoint",
            description="BitSight endpoint key to collect from",
            data_type=Argument.data_type_string,
            required_on_create=True,
            required_on_edit=False,
        )

        self._add_argument(
            scheme=scheme,
            name="index",
            title="Index",
            description="Splunk index to store data",
            data_type=Argument.data_type_string,
            required_on_create=False,
            required_on_edit=False,
        )

        self._add_argument(
            scheme=scheme,
            name="company_guid",
            title="Company GUID",
            description="Company GUID for company-scoped endpoints",
            data_type=Argument.data_type_string,
            required_on_create=False,
            required_on_edit=False,
        )

        self._add_argument(
            scheme=scheme,
            name="country_guid",
            title="Country GUID",
            description="Country GUID for country-scoped endpoints",
            data_type=Argument.data_type_string,
            required_on_create=False,
            required_on_edit=False,
        )

        self._add_argument(
            scheme=scheme,
            name="user_guid",
            title="User GUID",
            description="User GUID for user-scoped endpoints",
            data_type=Argument.data_type_string,
            required_on_create=False,
            required_on_edit=False,
        )

        self._add_argument(
            scheme=scheme,
            name="observation_id",
            title="Observation ID",
            description="Observation or finding identifier for comment endpoints",
            data_type=Argument.data_type_string,
            required_on_create=False,
            required_on_edit=False,
        )

        self._add_argument(
            scheme=scheme,
            name="risk_vectors",
            title="Risk Vectors",
            description="Comma-separated list of risk vectors to filter findings",
            data_type=Argument.data_type_string,
            required_on_create=False,
            required_on_edit=False,
        )

        self._add_argument(
            scheme=scheme,
            name="days_back",
            title="Days Back",
            description="Historical lookback window in days",
            data_type=Argument.data_type_number,
            required_on_create=False,
            required_on_edit=False,
        )

        self._add_argument(
            scheme=scheme,
            name="proxy_enabled",
            title="Enable Proxy",
            description="Enable proxy for API requests",
            data_type=Argument.data_type_boolean,
            required_on_create=False,
            required_on_edit=False,
        )

        self._add_argument(
            scheme=scheme,
            name="proxy_url",
            title="Proxy URL",
            description="Proxy URL for API requests",
            data_type=Argument.data_type_string,
            required_on_create=False,
            required_on_edit=False,
        )

        self._add_argument(
            scheme=scheme,
            name="proxy_username",
            title="Proxy Username",
            description="Proxy authentication username",
            data_type=Argument.data_type_string,
            required_on_create=False,
            required_on_edit=False,
        )

        self._add_argument(
            scheme=scheme,
            name="proxy_password",
            title="Proxy Password",
            description="Proxy authentication password",
            data_type=Argument.data_type_string,
            required_on_create=False,
            required_on_edit=False,
        )

        self._add_argument(
            scheme=scheme,
            name="verify_ssl",
            title="Verify SSL",
            description="Verify SSL certificates",
            data_type=Argument.data_type_boolean,
            required_on_create=False,
            required_on_edit=False,
        )

        self._add_argument(
            scheme=scheme,
            name="timeout",
            title="Timeout",
            description="Request timeout in seconds",
            data_type=Argument.data_type_number,
            required_on_create=False,
            required_on_edit=False,
        )

        return scheme

    def validate_input(self, validation_definition):
        endpoint = str(validation_definition.parameters.get("endpoint", "")).strip()
        days_back = validation_definition.parameters.get("days_back", "")
        timeout = validation_definition.parameters.get("timeout", "")
        risk_vectors = str(validation_definition.parameters.get("risk_vectors", "")).strip()
        proxy_enabled = self._as_bool(validation_definition.parameters.get("proxy_enabled", False))
        proxy_url = str(validation_definition.parameters.get("proxy_url", "")).strip()

        if not endpoint:
            raise ValueError("Endpoint is required")

        if endpoint not in self.ENDPOINTS:
            raise ValueError(
                "Invalid endpoint: {0}. Valid endpoints: {1}".format(
                    endpoint, ", ".join(sorted(self.ENDPOINTS.keys()))
                )
            )

        if days_back not in ("", None):
            if int(days_back) <= 0:
                raise ValueError("days_back must be greater than zero")

        if timeout not in ("", None):
            if int(timeout) <= 0:
                raise ValueError("timeout must be greater than zero")

        if proxy_enabled and not proxy_url:
            raise ValueError("proxy_url is required when proxy_enabled is true")

        if risk_vectors:
            invalid_vectors = [
                item for item in self._split_csv(risk_vectors) if item not in self.RISK_VECTORS
            ]
            if invalid_vectors:
                raise ValueError(
                    "Invalid risk_vectors values: {0}".format(", ".join(invalid_vectors))
                )

    def stream_events(self, inputs, ew):
        app_settings = self._load_app_settings()

        for input_name, input_item in inputs.inputs.items():
            endpoint = str(input_item.get("endpoint", "")).strip()

            try:
                merged = self._build_runtime_config(input_item, app_settings)

                if not merged["api_token"]:
                    raise ValueError(
                        "API token is not configured in the input stanza or bitsight_settings.conf"
                    )

                ew.log(EventWriter.INFO, f"Starting BitSight data collection for endpoint: {endpoint}")

                data = self.fetch_bitsight_data(
                    api_token=merged["api_token"],
                    base_url=merged["base_url"],
                    endpoint=endpoint,
                    company_guid=merged["company_guid"],
                    country_guid=merged["country_guid"],
                    user_guid=merged["user_guid"],
                    observation_id=merged["observation_id"],
                    risk_vectors=merged["risk_vectors"],
                    days_back=merged["days_back"],
                    proxy_config=merged["proxy"],
                    verify_ssl=merged["verify_ssl"],
                    timeout=merged["timeout"],
                )

                event_count = self.write_events(
                    ew=ew,
                    input_name=input_name,
                    endpoint=endpoint,
                    data=data,
                    index=merged["index"],
                )

                ew.log(
                    EventWriter.INFO,
                    f"Successfully collected {event_count} events for endpoint: {endpoint}",
                )

            except Exception as e:
                ew.log(EventWriter.ERROR, f"Error fetching BitSight data for {endpoint}: {str(e)}")

    def fetch_bitsight_data(
        self,
        api_token: str,
        base_url: str,
        endpoint: str,
        company_guid: str = "",
        country_guid: str = "",
        user_guid: str = "",
        observation_id: str = "",
        risk_vectors: str = "",
        days_back: int = DEFAULT_DAYS_BACK,
        proxy_config: Optional[Dict[str, Any]] = None,
        verify_ssl: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> JsonType:
        endpoint_path = self.ENDPOINTS.get(endpoint, endpoint)

        if "{country_guid}" in endpoint_path:
            if not country_guid:
                raise ValueError(f"country_guid is required for endpoint: {endpoint}")
            endpoint_path = endpoint_path.replace("{country_guid}", country_guid)

        if "{observation_id}" in endpoint_path:
            if not observation_id:
                raise ValueError(f"observation_id is required for endpoint: {endpoint}")
            endpoint_path = endpoint_path.replace("{observation_id}", observation_id)

        if "{user_guid}" in endpoint_path:
            return self._fetch_user_scoped_data(
                api_token=api_token,
                base_url=base_url,
                endpoint=endpoint,
                endpoint_path=endpoint_path,
                user_guid=user_guid,
                proxy_config=proxy_config,
                verify_ssl=verify_ssl,
                timeout=timeout,
            )

        if "{guid}" in endpoint_path:
            return self._fetch_company_scoped_data(
                api_token=api_token,
                base_url=base_url,
                endpoint=endpoint,
                endpoint_path=endpoint_path,
                company_guid=company_guid,
                risk_vectors=risk_vectors,
                days_back=days_back,
                proxy_config=proxy_config,
                verify_ssl=verify_ssl,
                timeout=timeout,
            )

        request_path = self._apply_endpoint_query_params(
            endpoint=endpoint,
            endpoint_path=endpoint_path,
            risk_vectors=risk_vectors,
            days_back=days_back,
        )

        return self._make_request(
            api_token=api_token,
            base_url=base_url,
            endpoint_path=request_path,
            proxy_config=proxy_config,
            verify_ssl=verify_ssl,
            timeout=timeout,
        )

    def fetch_all_companies(
        self,
        api_token: str,
        base_url: str,
        proxy_config: Optional[Dict[str, Any]] = None,
        verify_ssl: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> List[Dict[str, Any]]:
        data = self._make_request(
            api_token=api_token,
            base_url=base_url,
            endpoint_path=self.ENDPOINTS["portfolio"],
            proxy_config=proxy_config,
            verify_ssl=verify_ssl,
            timeout=timeout,
        )
        return self._extract_company_list(data)

    def fetch_all_users(
        self,
        api_token: str,
        base_url: str,
        proxy_config: Optional[Dict[str, Any]] = None,
        verify_ssl: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> List[Dict[str, Any]]:
        data = self._make_request(
            api_token=api_token,
            base_url=base_url,
            endpoint_path=self.ENDPOINTS["users"],
            proxy_config=proxy_config,
            verify_ssl=verify_ssl,
            timeout=timeout,
        )
        return self._extract_record_list(data)

    def _fetch_company_scoped_data(
        self,
        api_token: str,
        base_url: str,
        endpoint: str,
        endpoint_path: str,
        company_guid: str,
        risk_vectors: str,
        days_back: int,
        proxy_config: Optional[Dict[str, Any]],
        verify_ssl: bool,
        timeout: int,
    ) -> JsonType:
        if company_guid:
            path = endpoint_path.replace("{guid}", company_guid)
            path = self._apply_endpoint_query_params(
                endpoint=endpoint,
                endpoint_path=path,
                risk_vectors=risk_vectors,
                days_back=days_back,
            )
            return self._make_request(
                api_token=api_token,
                base_url=base_url,
                endpoint_path=path,
                proxy_config=proxy_config,
                verify_ssl=verify_ssl,
                timeout=timeout,
            )

        companies = self.fetch_all_companies(
            api_token=api_token,
            base_url=base_url,
            proxy_config=proxy_config,
            verify_ssl=verify_ssl,
            timeout=timeout,
        )

        all_data: List[Dict[str, Any]] = []

        for company in companies:
            guid = str(company.get("guid", "") or "").strip()
            if not guid:
                continue

            path = endpoint_path.replace("{guid}", guid)
            path = self._apply_endpoint_query_params(
                endpoint=endpoint,
                endpoint_path=path,
                risk_vectors=risk_vectors,
                days_back=days_back,
            )

            data = self._make_request(
                api_token=api_token,
                base_url=base_url,
                endpoint_path=path,
                proxy_config=proxy_config,
                verify_ssl=verify_ssl,
                timeout=timeout,
            )

            for item in self._to_event_records(data):
                item["company_guid"] = guid
                item["company_name"] = company.get("name", "")
                all_data.append(item)

        return all_data

    def _fetch_user_scoped_data(
        self,
        api_token: str,
        base_url: str,
        endpoint: str,
        endpoint_path: str,
        user_guid: str,
        proxy_config: Optional[Dict[str, Any]],
        verify_ssl: bool,
        timeout: int,
    ) -> JsonType:
        if user_guid:
            path = endpoint_path.replace("{user_guid}", user_guid)
            return self._make_request(
                api_token=api_token,
                base_url=base_url,
                endpoint_path=path,
                proxy_config=proxy_config,
                verify_ssl=verify_ssl,
                timeout=timeout,
            )

        users = self.fetch_all_users(
            api_token=api_token,
            base_url=base_url,
            proxy_config=proxy_config,
            verify_ssl=verify_ssl,
            timeout=timeout,
        )

        all_data: List[Dict[str, Any]] = []

        for user in users:
            guid = str(user.get("guid", "") or "").strip()
            if not guid:
                continue

            path = endpoint_path.replace("{user_guid}", guid)
            data = self._make_request(
                api_token=api_token,
                base_url=base_url,
                endpoint_path=path,
                proxy_config=proxy_config,
                verify_ssl=verify_ssl,
                timeout=timeout,
            )

            for item in self._to_event_records(data):
                item["user_guid"] = guid
                item["user_email"] = user.get("email", "")
                all_data.append(item)

        return all_data

    def _make_request(
        self,
        api_token: str,
        base_url: str,
        endpoint_path: str,
        proxy_config: Optional[Dict[str, Any]] = None,
        verify_ssl: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> JsonType:
        url = self._build_url(base_url, endpoint_path)
        data = self._request_url(
            api_token=api_token,
            url=url,
            proxy_config=proxy_config,
            verify_ssl=verify_ssl,
            timeout=timeout,
        )
        return self._handle_pagination(
            api_token=api_token,
            base_url=base_url,
            initial_data=data,
            proxy_config=proxy_config,
            verify_ssl=verify_ssl,
            timeout=timeout,
        )

    def _request_url(
        self,
        api_token: str,
        url: str,
        proxy_config: Optional[Dict[str, Any]],
        verify_ssl: bool,
        timeout: int,
    ) -> JsonType:
        opener = self._build_opener(proxy_config=proxy_config, verify_ssl=verify_ssl, url=url)
        auth_string = base64.b64encode(f"{api_token}:".encode("utf-8")).decode("utf-8")

        request = urllib.request.Request(url)
        request.add_header("Authorization", f"Basic {auth_string}")
        request.add_header("Accept", "application/json")
        request.add_header("Content-Type", "application/json")
        request.add_header("User-Agent", "Splunk-BitSight-App/1.0.0")

        try:
            with opener.open(request, timeout=timeout) as response:
                raw_bytes = response.read()
                charset = response.headers.get_content_charset("utf-8")
                text = raw_bytes.decode(charset, errors="replace")
                content_type = response.headers.get("Content-Type", "")

                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    return {
                        "raw_response": text,
                        "_response_content_type": content_type,
                        "_response_url": url,
                    }

        except urllib.error.HTTPError as e:
            try:
                error_body = e.read().decode("utf-8", errors="replace")
            except Exception:
                error_body = ""
            raise Exception(f"HTTP Error {e.code}: {e.reason} {error_body}".strip())

        except urllib.error.URLError as e:
            raise Exception(f"URL Error: {e.reason}")

    def _handle_pagination(
        self,
        api_token: str,
        base_url: str,
        initial_data: JsonType,
        proxy_config: Optional[Dict[str, Any]],
        verify_ssl: bool,
        timeout: int,
    ) -> JsonType:
        if not isinstance(initial_data, dict):
            return initial_data

        initial_results = self._extract_results(initial_data)
        if not isinstance(initial_results, list):
            return initial_data

        aggregated = list(initial_results)
        next_url = ((initial_data.get("links") or {}).get("next") or "").strip()

        while next_url:
            page_url = self._build_url(base_url, next_url)
            page_data = self._request_url(
                api_token=api_token,
                url=page_url,
                proxy_config=proxy_config,
                verify_ssl=verify_ssl,
                timeout=timeout,
            )

            if not isinstance(page_data, dict):
                break

            page_results = self._extract_results(page_data)
            if not isinstance(page_results, list):
                break

            aggregated.extend(page_results)
            next_url = ((page_data.get("links") or {}).get("next") or "").strip()

        return aggregated

    def write_events(
        self,
        ew: EventWriter,
        input_name: str,
        endpoint: str,
        data: JsonType,
        index: str,
    ) -> int:
        sourcetype = self.SOURCETYPE_MAP.get(
            endpoint,
            f"bitsight_{endpoint.replace('-', '_')}",
        )

        collection_time = time.time()
        collection_date = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

        records = self._to_event_records(data)
        count = 0

        for record in records:
            record["_collection_time"] = collection_time
            record["_collection_date"] = collection_date
            record["_endpoint"] = endpoint
            record["_input_name"] = input_name

            event = Event()
            event.stanza = input_name
            event.data = json.dumps(record, ensure_ascii=False)
            event.sourcetype = sourcetype
            event.index = index
            event.time = collection_time
            ew.write_event(event)
            count += 1

        return count

    def _add_argument(
        self,
        scheme: Scheme,
        name: str,
        title: str,
        description: str,
        data_type: Any,
        required_on_create: bool,
        required_on_edit: bool,
    ) -> None:
        arg = Argument(name)
        arg.title = title
        arg.description = description
        arg.data_type = data_type
        arg.required_on_create = required_on_create
        arg.required_on_edit = required_on_edit
        scheme.add_argument(arg)

    def _load_app_settings(self) -> Dict[str, Dict[str, str]]:
        settings: Dict[str, Dict[str, str]] = {
            "settings": {},
            "proxy": {},
        }

        conf_paths = [
            os.path.join(os.path.dirname(__file__), "..", "default", "bitsight_settings.conf"),
            os.path.join(os.path.dirname(__file__), "..", "local", "bitsight_settings.conf"),
        ]

        parser = configparser.ConfigParser(interpolation=None)
        parser.optionxform = str

        existing_files = [path for path in conf_paths if os.path.exists(path)]
        if not existing_files:
            return settings

        parser.read(existing_files, encoding="utf-8")

        for section in settings.keys():
            if parser.has_section(section):
                settings[section] = {k: v for k, v in parser.items(section)}

        return settings

    def _build_runtime_config(
        self,
        input_item: Dict[str, Any],
        app_settings: Dict[str, Dict[str, str]],
    ) -> Dict[str, Any]:
        settings_section = app_settings.get("settings", {})
        proxy_section = app_settings.get("proxy", {})

        api_token = str(input_item.get("api_token") or settings_section.get("api_token", "")).strip()
        base_url = str(input_item.get("base_url") or settings_section.get("base_url", "")).strip()
        index = str(input_item.get("index") or self.DEFAULT_INDEX).strip()

        verify_ssl_value = (
            input_item.get("verify_ssl")
            if "verify_ssl" in input_item
            else settings_section.get("verify_ssl", "true")
        )
        verify_ssl = self._as_bool(verify_ssl_value, default=True)

        timeout_value = (
            input_item.get("timeout")
            if "timeout" in input_item
            else settings_section.get("timeout", str(self.DEFAULT_TIMEOUT))
        )
        timeout = int(timeout_value) if str(timeout_value).strip() else self.DEFAULT_TIMEOUT

        days_back_value = input_item.get("days_back", self.DEFAULT_DAYS_BACK)
        days_back = int(days_back_value) if str(days_back_value).strip() else self.DEFAULT_DAYS_BACK

        proxy_enabled_value = (
            input_item.get("proxy_enabled")
            if "proxy_enabled" in input_item
            else proxy_section.get("proxy_enabled", "false")
        )
        proxy_enabled = self._as_bool(proxy_enabled_value, default=False)

        proxy = {
            "enabled": proxy_enabled,
            "url": str(input_item.get("proxy_url") or proxy_section.get("proxy_url", "")).strip(),
            "username": str(
                input_item.get("proxy_username") or proxy_section.get("proxy_username", "")
            ).strip(),
            "password": str(
                input_item.get("proxy_password") or proxy_section.get("proxy_password", "")
            ),
        }

        return {
            "api_token": api_token,
            "base_url": self._normalize_base_url(base_url or self.DEFAULT_API_BASE),
            "index": index or self.DEFAULT_INDEX,
            "company_guid": str(input_item.get("company_guid", "") or "").strip(),
            "country_guid": str(input_item.get("country_guid", "") or "").strip(),
            "user_guid": str(input_item.get("user_guid", "") or "").strip(),
            "observation_id": str(input_item.get("observation_id", "") or "").strip(),
            "risk_vectors": str(input_item.get("risk_vectors", "") or "").strip(),
            "days_back": days_back,
            "verify_ssl": verify_ssl,
            "timeout": timeout,
            "proxy": proxy,
        }

    def _build_opener(
        self,
        proxy_config: Optional[Dict[str, Any]],
        verify_ssl: bool,
        url: str,
    ) -> urllib.request.OpenerDirector:
        handlers: List[Any] = []

        proxy_handler = self._setup_proxy_handler(proxy_config)
        if proxy_handler is not None:
            handlers.append(proxy_handler)

        if url.lower().startswith("https://"):
            handlers.append(urllib.request.HTTPSHandler(context=self._build_ssl_context(verify_ssl)))

        return urllib.request.build_opener(*handlers)

    def _setup_proxy_handler(
        self,
        proxy_config: Optional[Dict[str, Any]],
    ) -> Optional[urllib.request.ProxyHandler]:
        if not proxy_config:
            return None

        if not proxy_config.get("enabled"):
            return None

        proxy_url = str(proxy_config.get("url", "")).strip()
        if not proxy_url:
            return None

        username = str(proxy_config.get("username", "")).strip()
        password = str(proxy_config.get("password", ""))

        if username:
            parsed = urllib.parse.urlsplit(proxy_url)
            netloc = parsed.netloc or parsed.path
            if "@" not in netloc:
                userinfo = urllib.parse.quote(username, safe="")
                if password:
                    userinfo += ":" + urllib.parse.quote(password, safe="")
                netloc = f"{userinfo}@{netloc}"
                proxy_url = urllib.parse.urlunsplit(
                    (parsed.scheme, netloc, parsed.path if parsed.netloc else "", parsed.query, parsed.fragment)
                )

        return urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})

    def _build_ssl_context(self, verify_ssl: bool) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _apply_endpoint_query_params(
        self,
        endpoint: str,
        endpoint_path: str,
        risk_vectors: str,
        days_back: int,
    ) -> str:
        updated = endpoint_path

        if endpoint.startswith("findings") and risk_vectors:
            updated = self._append_query_param(updated, "risk_vector", ",".join(self._split_csv(risk_vectors)))

        if "history" in endpoint:
            end_date = datetime.date.today()
            start_date = end_date - datetime.timedelta(days=days_back)
            updated = self._append_query_param(updated, "start", start_date.isoformat())
            updated = self._append_query_param(updated, "end", end_date.isoformat())

        return updated

    def _append_query_param(self, path: str, key: str, value: str) -> str:
        parsed = urllib.parse.urlsplit(path)
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        query.append((key, value))
        new_query = urllib.parse.urlencode(query)
        return urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment)
        )

    def _build_url(self, base_url: str, endpoint_path: str) -> str:
        if endpoint_path.startswith("http://") or endpoint_path.startswith("https://"):
            return endpoint_path
        return urllib.parse.urljoin(base_url.rstrip("/") + "/", endpoint_path.lstrip("/"))

    def _normalize_base_url(self, base_url: str) -> str:
        return (base_url or self.DEFAULT_API_BASE).rstrip("/")

    def _extract_results(self, data: Dict[str, Any]) -> Optional[List[Any]]:
        for key in self.RESULT_KEYS:
            value = data.get(key)
            if isinstance(value, list):
                return value
        return None

    def _extract_company_list(self, data: JsonType) -> List[Dict[str, Any]]:
        return [item for item in self._extract_record_list(data) if isinstance(item, dict)]

    def _extract_record_list(self, data: JsonType) -> List[Dict[str, Any]]:
        records = self._to_event_records(data)
        return [item for item in records if isinstance(item, dict)]

    def _to_event_records(self, data: JsonType) -> List[Dict[str, Any]]:
        if isinstance(data, list):
            return [self._normalize_record(item) for item in data]

        if isinstance(data, dict):
            extracted = self._extract_results(data)
            if isinstance(extracted, list):
                return [self._normalize_record(item) for item in extracted]
            return [self._normalize_record(data)]

        return [self._normalize_record(data)]

    def _normalize_record(self, item: Any) -> Dict[str, Any]:
        if isinstance(item, dict):
            return dict(item)
        return {"value": item}

    def _as_bool(self, value: Any, default: bool = False) -> bool:
        if value in (None, ""):
            return default
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _split_csv(self, value: str) -> List[str]:
        if not value:
            return []
        return [item.strip() for item in str(value).split(",") if item.strip()]


if __name__ == "__main__":
    if SPLUNKLIB_IMPORT_ERROR is not None:
        print(f"ERROR: {SPLUNKLIB_IMPORT_ERROR}", file=sys.stderr)
        sys.exit(1)

    sys.exit(BitsightInput().run(sys.argv))
