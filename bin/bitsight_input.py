#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Bitsight Modular Input for Splunk
Collects data from the Bitsight Security Ratings API

Features:
- Configurable index selection
- Proxy support (HTTP/HTTPS/SOCKS)
- Configurable intervals
- All 21 risk vectors supported
- User and company data collection
- Historical trending data
"""

import sys
import os
import json
import time
import datetime
import urllib.request
import urllib.error
import ssl
import base64

# Add Splunk SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

try:
    from splunklib.modularinput import Script, Scheme, Argument, Event, EventWriter
except ImportError:
    pass


class BitsightInput(Script):
    """Bitsight Modular Input Script"""
    
    BITSIGHT_API_BASE = "https://api.bitsighttech.com/ratings/v1"
    
    ENDPOINTS = {
        # Portfolio & Companies (https://help.bitsighttech.com/hc/en-us/articles/115004541128)
        "portfolio": "/portfolio",
        "company-details": "/companies/{guid}",
        "country-details": "/companies/{country_guid}",
        "company-search": "/companies/search",
        "rating-distribution": "/companies/distribution",
        "trending-companies": "/companies/search/trending",
        "ratings-tree": "/companies/{guid}/company-tree",
        "company-requests-summary": "/companies/infrastructure/requests/summaries",
        
        # Ratings & History
        "current-ratings": "/ratings/v1/companies/{guid}",
        "ratings-history": "/companies/{guid}/history/ratings",
        "ratings-history-csv": "/companies/{guid}/reports/ratings-history",
        "grade-history": "/companies/{guid}/history/grade",
        
        # Findings (https://help.bitsighttech.com/hc/en-us/articles/360022913734)
        "findings": "/companies/{guid}/findings",
        "findings-summary": "/companies/{guid}/findings/summary",
        "findings-summaries": "/companies/{guid}/findings/summaries",
        "findings-statistics": "/companies/{guid}/findings/statistics",
        "finding-comments": "/companies/{guid}/findings/{observation_id}/comments",
        "observations": "/companies/{guid}/observations",
        
        # Risk Vectors
        "risk-vectors": "/companies/{guid}/risk-vectors",
        "risk-vectors-summary": "/companies/{guid}/risk-vectors/summaries",
        
        # Statistics (https://help.bitsighttech.com/hc/en-us/articles/360006842974)
        "diligence-statistics": "/companies/{guid}/diligence/statistics",
        "diligence-historical": "/companies/{guid}/diligence/historical-statistics",
        "industry-statistics": "/companies/{guid}/industries/statistics",
        "user-behavior-statistics": "/companies/{guid}/user-behavior/statistics",
        "observations-statistics": "/companies/{guid}/observations/statistics",
        
        # Assets & Infrastructure (https://help.bitsighttech.com/hc/en-us/articles/360060241513)
        "assets": "/companies/{guid}/assets",
        "assets-summaries": "/companies/{guid}/assets/summaries",
        "asset-risk-matrix": "/companies/{guid}/assets/statistics",
        "infrastructure": "/companies/{guid}/infrastructure",
        "infrastructure-changes": "/companies/{guid}/infrastructure/changes",
        "infrastructure-tags": "/companies/{guid}/tags",
        "ip-by-country": "/companies/{guid}/countries",
        
        # 4th Party / Supply Chain
        "service-providers": "/companies/{guid}/providers",
        "products": "/companies/{guid}/products",
        "company-tree-providers": "/companies/{guid}/company-tree/providers",
        "company-tree-products": "/companies/{guid}/company-tree/products",
        
        # Users
        "users": "/users",
        "user-details": "/users/{user_guid}",
        "user-quota": "/users/quota",
        "user-company-views": "/users/{user_guid}/company-views",
        
        # Alerts & Threats
        "alerts": "/alerts",
        "exposed-credentials": "/exposed-credentials",
        "threats": "/threats",
        
        # Organization
        "folders": "/folders",
        "tiers": "/tiers",
        "subscriptions": "/subscriptions",
        "industries": "/industries",
        
        # Peer Analytics
        "peer-analytics": "/companies/{guid}/peer-analytics/peer-group/count",
        
        # Reports & Regulatory
        "nist-csf-report": "/companies/{guid}/regulatory/nist",
        "preview-report": "/companies/{guid}/reports/company-preview",
    }
    
    RISK_VECTORS = [
        "botnet_infections", "spam_propagation", "malware_servers", 
        "unsolicited_comm", "potentially_exploited", "spf", "dkim",
        "ssl_certificates", "ssl_configurations", "open_ports", 
        "web_appsec", "patching_cadence", "insecure_systems",
        "server_software", "desktop_software", "mobile_software",
        "dnssec", "mobile_application_security", "application_security",
        "dmarc", "file_sharing"
    ]

    def get_scheme(self):
        """Define the input scheme"""
        scheme = Scheme("Bitsight API")
        scheme.description = "Collects security ratings data from the Bitsight API"
        scheme.use_external_validation = True
        scheme.use_single_instance = False

        # Required: API Token
        api_token = Argument("api_token")
        api_token.title = "API Token"
        api_token.description = "Bitsight API authentication token"
        api_token.data_type = Argument.data_type_string
        api_token.required_on_create = True
        api_token.required_on_edit = False
        scheme.add_argument(api_token)

        # Required: Endpoint
        endpoint = Argument("endpoint")
        endpoint.title = "Endpoint"
        endpoint.description = "Bitsight API endpoint to collect data from"
        endpoint.data_type = Argument.data_type_string
        endpoint.required_on_create = True
        endpoint.required_on_edit = False
        scheme.add_argument(endpoint)

        # Index Configuration
        index = Argument("index")
        index.title = "Index"
        index.description = "Splunk index to store data (default: main)"
        index.data_type = Argument.data_type_string
        index.required_on_create = False
        index.required_on_edit = False
        scheme.add_argument(index)

        # Company GUID
        company_guid = Argument("company_guid")
        company_guid.title = "Company GUID"
        company_guid.description = "Company GUID for company-specific endpoints (optional)"
        company_guid.data_type = Argument.data_type_string
        company_guid.required_on_create = False
        company_guid.required_on_edit = False
        scheme.add_argument(company_guid)
        
        # User GUID
        user_guid = Argument("user_guid")
        user_guid.title = "User GUID"
        user_guid.description = "User GUID for user-specific endpoints (optional)"
        user_guid.data_type = Argument.data_type_string
        user_guid.required_on_create = False
        user_guid.required_on_edit = False
        scheme.add_argument(user_guid)
        
        # Risk Vectors Filter
        risk_vectors = Argument("risk_vectors")
        risk_vectors.title = "Risk Vectors"
        risk_vectors.description = "Comma-separated list of risk vectors to filter findings (optional)"
        risk_vectors.data_type = Argument.data_type_string
        risk_vectors.required_on_create = False
        risk_vectors.required_on_edit = False
        scheme.add_argument(risk_vectors)
        
        # Days Back for History
        days_back = Argument("days_back")
        days_back.title = "Days Back"
        days_back.description = "Number of days of historical data to collect (default: 365)"
        days_back.data_type = Argument.data_type_number
        days_back.required_on_create = False
        days_back.required_on_edit = False
        scheme.add_argument(days_back)

        # Proxy Configuration
        proxy_enabled = Argument("proxy_enabled")
        proxy_enabled.title = "Enable Proxy"
        proxy_enabled.description = "Enable proxy for API requests (true/false)"
        proxy_enabled.data_type = Argument.data_type_boolean
        proxy_enabled.required_on_create = False
        proxy_enabled.required_on_edit = False
        scheme.add_argument(proxy_enabled)

        proxy_url = Argument("proxy_url")
        proxy_url.title = "Proxy URL"
        proxy_url.description = "Proxy server URL (e.g., http://proxy:8080 or socks5://proxy:1080)"
        proxy_url.data_type = Argument.data_type_string
        proxy_url.required_on_create = False
        proxy_url.required_on_edit = False
        scheme.add_argument(proxy_url)

        proxy_username = Argument("proxy_username")
        proxy_username.title = "Proxy Username"
        proxy_username.description = "Proxy authentication username (optional)"
        proxy_username.data_type = Argument.data_type_string
        proxy_username.required_on_create = False
        proxy_username.required_on_edit = False
        scheme.add_argument(proxy_username)

        proxy_password = Argument("proxy_password")
        proxy_password.title = "Proxy Password"
        proxy_password.description = "Proxy authentication password (optional)"
        proxy_password.data_type = Argument.data_type_string
        proxy_password.required_on_create = False
        proxy_password.required_on_edit = False
        scheme.add_argument(proxy_password)

        # SSL Verification
        verify_ssl = Argument("verify_ssl")
        verify_ssl.title = "Verify SSL"
        verify_ssl.description = "Verify SSL certificates (default: true)"
        verify_ssl.data_type = Argument.data_type_boolean
        verify_ssl.required_on_create = False
        verify_ssl.required_on_edit = False
        scheme.add_argument(verify_ssl)

        # Request Timeout
        timeout = Argument("timeout")
        timeout.title = "Timeout"
        timeout.description = "Request timeout in seconds (default: 60)"
        timeout.data_type = Argument.data_type_number
        timeout.required_on_create = False
        timeout.required_on_edit = False
        scheme.add_argument(timeout)

        return scheme

    def validate_input(self, validation_definition):
        """Validate the input configuration"""
        api_token = validation_definition.parameters.get("api_token", "")
        endpoint = validation_definition.parameters.get("endpoint", "")
        
        if not api_token:
            raise ValueError("API token is required")
        
        if endpoint not in self.ENDPOINTS:
            raise ValueError(f"Invalid endpoint: {endpoint}. Valid endpoints: {', '.join(self.ENDPOINTS.keys())}")
        
        # Validate proxy URL if enabled
        proxy_enabled = validation_definition.parameters.get("proxy_enabled", False)
        if proxy_enabled:
            proxy_url = validation_definition.parameters.get("proxy_url", "")
            if not proxy_url:
                raise ValueError("Proxy URL is required when proxy is enabled")

    def stream_events(self, inputs, ew):
        """Stream events to Splunk"""
        for input_name, input_item in inputs.inputs.items():
            # Required parameters
            api_token = input_item["api_token"]
            endpoint = input_item["endpoint"]
            
            # Optional parameters with defaults
            index = input_item.get("index", "main")
            company_guid = input_item.get("company_guid", "")
            user_guid = input_item.get("user_guid", "")
            risk_vectors = input_item.get("risk_vectors", "")
            days_back = int(input_item.get("days_back", 365))
            
            # Proxy configuration
            proxy_config = {
                "enabled": str(input_item.get("proxy_enabled", "false")).lower() == "true",
                "url": input_item.get("proxy_url", ""),
                "username": input_item.get("proxy_username", ""),
                "password": input_item.get("proxy_password", "")
            }
            
            # SSL and timeout
            verify_ssl = str(input_item.get("verify_ssl", "true")).lower() != "false"
            timeout = int(input_item.get("timeout", 60))
            
            try:
                ew.log(EventWriter.INFO, f"Starting Bitsight data collection for endpoint: {endpoint}")
                
                data = self.fetch_bitsight_data(
                    api_token, endpoint, company_guid, 
                    user_guid, risk_vectors, days_back,
                    proxy_config, verify_ssl, timeout
                )
                
                self.write_events(ew, input_name, endpoint, data, index)
                
                ew.log(EventWriter.INFO, f"Successfully collected {len(data) if isinstance(data, list) else 1} events for endpoint: {endpoint}")
                
            except Exception as e:
                ew.log(EventWriter.ERROR, f"Error fetching Bitsight data for {endpoint}: {str(e)}")

    def _setup_proxy(self, proxy_config):
        """Configure proxy handler"""
        if not proxy_config.get("enabled") or not proxy_config.get("url"):
            return None
        
        proxy_url = proxy_config["url"]
        
        # Add authentication if provided
        if proxy_config.get("username") and proxy_config.get("password"):
            # Parse proxy URL and add credentials
            if "://" in proxy_url:
                protocol, rest = proxy_url.split("://", 1)
                proxy_url = f"{protocol}://{proxy_config['username']}:{proxy_config['password']}@{rest}"
            else:
                proxy_url = f"http://{proxy_config['username']}:{proxy_config['password']}@{proxy_url}"
        
        # Create proxy handler
        proxy_handler = urllib.request.ProxyHandler({
            'http': proxy_url,
            'https': proxy_url
        })
        
        return proxy_handler

    def fetch_bitsight_data(self, api_token, endpoint, company_guid="", 
                           user_guid="", risk_vectors="", days_back=365,
                           proxy_config=None, verify_ssl=True, timeout=60):
        """Fetch data from Bitsight API"""
        endpoint_path = self.ENDPOINTS.get(endpoint, endpoint)
        
        # Handle user-specific endpoints
        if "{user_guid}" in endpoint_path:
            if user_guid:
                endpoint_path = endpoint_path.replace("{user_guid}", user_guid)
            else:
                # Fetch all users first
                users = self.fetch_all_users(api_token, proxy_config, verify_ssl, timeout)
                all_data = []
                for user in users:
                    guid = user.get("guid")
                    if guid:
                        path = endpoint_path.replace("{user_guid}", guid)
                        data = self._make_request(api_token, path, proxy_config, verify_ssl, timeout)
                        if data:
                            if isinstance(data, list):
                                for item in data:
                                    item["user_guid"] = guid
                                    item["user_email"] = user.get("email", "")
                            else:
                                data["user_guid"] = guid
                                data["user_email"] = user.get("email", "")
                            all_data.extend(data if isinstance(data, list) else [data])
                return all_data
        
        # Handle company-specific endpoints
        if "{guid}" in endpoint_path and company_guid:
            endpoint_path = endpoint_path.replace("{guid}", company_guid)
            
            # Add risk vector filter for findings
            if "findings" in endpoint and risk_vectors:
                endpoint_path += f"?risk_vector={risk_vectors}"
                
        elif "{guid}" in endpoint_path:
            # Need to fetch all companies first
            companies = self.fetch_all_companies(api_token, proxy_config, verify_ssl, timeout)
            all_data = []
            for company in companies:
                guid = company.get("guid")
                if guid:
                    path = endpoint_path.replace("{guid}", guid)
                    
                    # Add risk vector filter for findings
                    if "findings" in endpoint and risk_vectors:
                        path += f"?risk_vector={risk_vectors}"
                    
                    # Add date range for history endpoints
                    if "history" in endpoint:
                        end_date = datetime.date.today()
                        start_date = end_date - datetime.timedelta(days=days_back)
                        separator = "&" if "?" in path else "?"
                        path += f"{separator}start={start_date.isoformat()}&end={end_date.isoformat()}"
                    
                    data = self._make_request(api_token, path, proxy_config, verify_ssl, timeout)
                    if data:
                        # Add company context
                        if isinstance(data, list):
                            for item in data:
                                item["company_guid"] = guid
                                item["company_name"] = company.get("name", "")
                        else:
                            data["company_guid"] = guid
                            data["company_name"] = company.get("name", "")
                        all_data.extend(data if isinstance(data, list) else [data])
            return all_data
        
        return self._make_request(api_token, endpoint_path, proxy_config, verify_ssl, timeout)

    def fetch_all_companies(self, api_token, proxy_config=None, verify_ssl=True, timeout=60):
        """Fetch all companies from portfolio"""
        portfolio_data = self._make_request(api_token, "/portfolio", proxy_config, verify_ssl, timeout)
        companies = []
        
        if isinstance(portfolio_data, dict):
            companies = portfolio_data.get("companies", [])
        elif isinstance(portfolio_data, list):
            companies = portfolio_data
            
        return companies
    
    def fetch_all_users(self, api_token, proxy_config=None, verify_ssl=True, timeout=60):
        """Fetch all users from the account"""
        users_data = self._make_request(api_token, "/users", proxy_config, verify_ssl, timeout)
        users = []
        
        if isinstance(users_data, dict):
            users = users_data.get("results", users_data.get("users", []))
        elif isinstance(users_data, list):
            users = users_data
            
        return users

    def _make_request(self, api_token, endpoint_path, proxy_config=None, verify_ssl=True, timeout=60):
        """Make HTTP request to Bitsight API"""
        url = f"{self.BITSIGHT_API_BASE}{endpoint_path}"
        
        # Create SSL context
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        
        # Create request with Basic Auth
        auth_string = base64.b64encode(f"{api_token}:".encode()).decode()
        
        request = urllib.request.Request(url)
        request.add_header("Authorization", f"Basic {auth_string}")
        request.add_header("Accept", "application/json")
        request.add_header("Content-Type", "application/json")
        request.add_header("User-Agent", "Splunk-Bitsight-App/1.0.0")
        
        # Setup opener with proxy if configured
        handlers = []
        proxy_handler = self._setup_proxy(proxy_config) if proxy_config else None
        if proxy_handler:
            handlers.append(proxy_handler)
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
        
        opener = urllib.request.build_opener(*handlers)
        
        try:
            response = opener.open(request, timeout=timeout)
            data = json.loads(response.read().decode('utf-8'))
            return self._handle_pagination(api_token, data, proxy_config, verify_ssl, timeout)
        except urllib.error.HTTPError as e:
            raise Exception(f"HTTP Error {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            raise Exception(f"URL Error: {e.reason}")

    def _handle_pagination(self, api_token, data, proxy_config=None, verify_ssl=True, timeout=60):
        """Handle paginated API responses"""
        if not isinstance(data, dict):
            return data
            
        results = data.get("results", data.get("companies", data.get("alerts", data.get("users", []))))
        
        # Check for next page
        links = data.get("links", {})
        next_url = links.get("next")
        
        while next_url:
            auth_string = base64.b64encode(f"{api_token}:".encode()).decode()
            
            request = urllib.request.Request(next_url)
            request.add_header("Authorization", f"Basic {auth_string}")
            request.add_header("Accept", "application/json")
            request.add_header("User-Agent", "Splunk-Bitsight-App/1.0.0")
            
            # Setup SSL context
            ctx = ssl.create_default_context()
            if not verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            
            # Setup opener with proxy if configured
            handlers = []
            proxy_handler = self._setup_proxy(proxy_config) if proxy_config else None
            if proxy_handler:
                handlers.append(proxy_handler)
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
            
            opener = urllib.request.build_opener(*handlers)
            response = opener.open(request, timeout=timeout)
            page_data = json.loads(response.read().decode('utf-8'))
            
            page_results = page_data.get("results", page_data.get("companies", 
                          page_data.get("alerts", page_data.get("users", []))))
            results.extend(page_results)
            
            links = page_data.get("links", {})
            next_url = links.get("next")
        
        return results

    def write_events(self, ew, input_name, endpoint, data, index="main"):
        """Write events to Splunk"""
        sourcetype = f"bitsight:{endpoint.replace('-', '_')}"
        
        # Add collection timestamp for trending analysis
        collection_time = time.time()
        collection_date = datetime.datetime.now().isoformat()
        
        if isinstance(data, list):
            for item in data:
                # Add metadata for trending
                item["_collection_time"] = collection_time
                item["_collection_date"] = collection_date
                
                event = Event()
                event.stanza = input_name
                event.data = json.dumps(item)
                event.sourcetype = sourcetype
                event.index = index
                event.time = collection_time
                ew.write_event(event)
        elif isinstance(data, dict):
            data["_collection_time"] = collection_time
            data["_collection_date"] = collection_date
            
            event = Event()
            event.stanza = input_name
            event.data = json.dumps(data)
            event.sourcetype = sourcetype
            event.index = index
            event.time = collection_time
            ew.write_event(event)


if __name__ == "__main__":
    sys.exit(BitsightInput().run(sys.argv))
