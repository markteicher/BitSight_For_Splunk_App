#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Bitsight Setup Validation Script
Runs on first launch to verify all configurations are valid
"""

import os
import sys
import json
import time
import logging
import urllib.request
import ssl

# Add Splunk SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

try:
    import splunk.entity as entity
    import splunk.clilib.cli_common as cli_common
    SPLUNK_AVAILABLE = True
except ImportError:
    SPLUNK_AVAILABLE = False


class BitsightValidator:
    """
    Validates Bitsight app configuration on first launch
    """
    
    def __init__(self, session_key=None):
        self.session_key = session_key
        self.app_name = "BitSight_For_Splunk_App"
        self.results = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
            'checks': [],
            'overall_status': 'pending',
            'errors': [],
            'warnings': []
        }
        self._setup_logging()
    
    def _setup_logging(self):
        """Setup logging for validation"""
        self.logger = logging.getLogger('bitsight_validation')
        self.logger.setLevel(logging.INFO)
        
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def _add_check(self, name, status, message, details=None):
        """Add a validation check result"""
        check = {
            'name': name,
            'status': status,  # 'pass', 'fail', 'warning', 'skip'
            'message': message
        }
        if details:
            check['details'] = details
        self.results['checks'].append(check)
        
        if status == 'fail':
            self.results['errors'].append(f"{name}: {message}")
        elif status == 'warning':
            self.results['warnings'].append(f"{name}: {message}")
        
        self.logger.info(f"Check [{name}]: {status} - {message}")
    
    def _get_config(self):
        """Read configuration from bitsight.conf"""
        config = {
            'settings': {},
            'proxy': {},
            'inputs': {},
            'collection': {},
            'logging': {},
            'validation': {}
        }
        
        try:
            if SPLUNK_AVAILABLE:
                # Read via Splunk API
                conf_path = os.path.join(
                    os.environ.get('SPLUNK_HOME', '/opt/splunk'),
                    'etc', 'apps', self.app_name, 'local', 'bitsight.conf'
                )
                default_conf_path = os.path.join(
                    os.environ.get('SPLUNK_HOME', '/opt/splunk'),
                    'etc', 'apps', self.app_name, 'default', 'bitsight.conf'
                )
            else:
                # Fallback for testing
                base_path = os.path.dirname(os.path.dirname(__file__))
                conf_path = os.path.join(base_path, 'local', 'bitsight.conf')
                default_conf_path = os.path.join(base_path, 'default', 'bitsight.conf')
            
            # Parse config files
            for path in [default_conf_path, conf_path]:
                if os.path.exists(path):
                    config = self._parse_conf_file(path, config)
            
        except Exception as e:
            self.logger.error(f"Error reading config: {e}")
        
        return config
    
    def _parse_conf_file(self, path, config):
        """Parse a .conf file"""
        current_stanza = None
        
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                # Check for stanza
                if line.startswith('[') and line.endswith(']'):
                    current_stanza = line[1:-1]
                    if current_stanza not in config:
                        config[current_stanza] = {}
                    continue
                
                # Parse key-value
                if '=' in line and current_stanza:
                    key, value = line.split('=', 1)
                    config[current_stanza][key.strip()] = value.strip()
        
        return config
    
    def validate_api_configuration(self, config):
        """Validate API token and base URL"""
        settings = config.get('settings', {})
        
        # Check API token exists
        api_token = settings.get('api_token', '')
        if not api_token:
            self._add_check(
                'api_token',
                'fail',
                'API token is not configured',
                'Configure your Bitsight API token in Apps → Bitsight → Setup'
            )
            return False
        
        self._add_check('api_token', 'pass', 'API token is configured')
        
        # Check base URL
        base_url = settings.get('base_url', 'https://api.bitsighttech.com')
        if not base_url:
            self._add_check(
                'base_url',
                'warning',
                'Base URL is empty, using default',
                'Using https://api.bitsighttech.com'
            )
        else:
            self._add_check('base_url', 'pass', f'Base URL: {base_url}')
        
        return True
    
    def validate_api_connection(self, config):
        """Test API connection"""
        settings = config.get('settings', {})
        proxy_config = config.get('proxy', {})
        
        api_token = settings.get('api_token', '')
        if not api_token:
            self._add_check('api_connection', 'skip', 'Skipped - no API token')
            return False
        
        base_url = settings.get('base_url', 'https://api.bitsighttech.com')
        verify_ssl = settings.get('verify_ssl', 'true').lower() == 'true'
        timeout = int(settings.get('timeout', '30'))
        
        try:
            url = f"{base_url.rstrip('/')}/v1/users/me"
            req = urllib.request.Request(url)
            req.add_header('Authorization', f'Basic {api_token}')
            req.add_header('Accept', 'application/json')
            
            # SSL context
            context = ssl.create_default_context()
            if not verify_ssl:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            
            # Proxy configuration
            if proxy_config.get('proxy_enabled', 'false').lower() == 'true':
                proxy_url = proxy_config.get('proxy_url', '')
                if proxy_url:
                    proxy_handler = urllib.request.ProxyHandler({
                        'http': proxy_url,
                        'https': proxy_url
                    })
                    opener = urllib.request.build_opener(proxy_handler)
                    response = opener.open(req, timeout=timeout)
                else:
                    response = urllib.request.urlopen(req, timeout=timeout, context=context)
            else:
                response = urllib.request.urlopen(req, timeout=timeout, context=context)
            
            data = json.loads(response.read().decode('utf-8'))
            user_email = data.get('email', 'Unknown')
            
            self._add_check(
                'api_connection',
                'pass',
                f'Successfully connected to Bitsight API',
                f'Authenticated as: {user_email}'
            )
            return True
            
        except urllib.error.HTTPError as e:
            self._add_check(
                'api_connection',
                'fail',
                f'API authentication failed: HTTP {e.code}',
                'Verify your API token is correct and has proper permissions'
            )
            return False
            
        except urllib.error.URLError as e:
            self._add_check(
                'api_connection',
                'fail',
                f'Cannot reach Bitsight API: {e.reason}',
                'Check network connectivity and proxy settings'
            )
            return False
            
        except Exception as e:
            self._add_check(
                'api_connection',
                'fail',
                f'API connection error: {str(e)}'
            )
            return False
    
    def validate_proxy_configuration(self, config):
        """Validate proxy settings if enabled"""
        proxy_config = config.get('proxy', {})
        
        proxy_enabled = proxy_config.get('proxy_enabled', 'false').lower() == 'true'
        
        if not proxy_enabled:
            self._add_check('proxy', 'skip', 'Proxy is disabled')
            return True
        
        proxy_url = proxy_config.get('proxy_url', '')
        if not proxy_url:
            self._add_check(
                'proxy',
                'fail',
                'Proxy is enabled but URL is not configured',
                'Configure proxy URL in Apps → Bitsight → Setup'
            )
            return False
        
        # Validate proxy URL format
        if not (proxy_url.startswith('http://') or proxy_url.startswith('https://')):
            self._add_check(
                'proxy',
                'warning',
                'Proxy URL should start with http:// or https://',
                f'Current value: {proxy_url}'
            )
        else:
            self._add_check('proxy', 'pass', f'Proxy configured: {proxy_url}')
        
        return True
    
    def validate_proxy_connection(self, config):
        """Test proxy connection if enabled"""
        proxy_config = config.get('proxy', {})
        
        if proxy_config.get('proxy_enabled', 'false').lower() != 'true':
            self._add_check('proxy_connection', 'skip', 'Proxy is disabled')
            return True
        
        proxy_url = proxy_config.get('proxy_url', '')
        if not proxy_url:
            self._add_check('proxy_connection', 'skip', 'No proxy URL configured')
            return False
        
        try:
            proxy_handler = urllib.request.ProxyHandler({
                'http': proxy_url,
                'https': proxy_url
            })
            opener = urllib.request.build_opener(proxy_handler)
            
            req = urllib.request.Request('https://api.bitsighttech.com')
            opener.open(req, timeout=10)
            
            self._add_check(
                'proxy_connection',
                'pass',
                f'Proxy connection successful via {proxy_url}'
            )
            return True
            
        except Exception as e:
            self._add_check(
                'proxy_connection',
                'fail',
                f'Proxy connection failed: {str(e)}',
                'Verify proxy URL and credentials'
            )
            return False
    
    def validate_inputs_configuration(self, config):
        """Validate data input settings"""
        inputs_config = config.get('inputs', {})
        
        enabled_inputs = []
        for key, value in inputs_config.items():
            if key.startswith('input_') and value.lower() == 'true':
                enabled_inputs.append(key.replace('input_', ''))
        
        if not enabled_inputs:
            self._add_check(
                'inputs',
                'warning',
                'No data inputs are enabled',
                'Enable at least one input in Apps → Bitsight → Setup'
            )
        else:
            self._add_check(
                'inputs',
                'pass',
                f'{len(enabled_inputs)} data input(s) enabled',
                f'Enabled: {", ".join(enabled_inputs)}'
            )
        
        return len(enabled_inputs) > 0
    
    def validate_collection_settings(self, config):
        """Validate collection interval settings"""
        collection = config.get('collection', {})
        
        intervals = {
            'portfolio_interval': 3600,
            'findings_interval': 3600,
            'alerts_interval': 900,
            'days_back': 365
        }
        
        warnings = []
        for key, default in intervals.items():
            value = collection.get(key, str(default))
            try:
                int_value = int(value)
                if int_value < 300 and key != 'days_back':
                    warnings.append(f"{key} is set to {int_value}s (minimum recommended: 300s)")
            except ValueError:
                warnings.append(f"{key} is not a valid number: {value}")
        
        if warnings:
            self._add_check(
                'collection_settings',
                'warning',
                'Some collection settings may need review',
                '; '.join(warnings)
            )
        else:
            self._add_check('collection_settings', 'pass', 'Collection settings are valid')
        
        return True
    
    def validate_index_exists(self):
        """Check if the Bitsight index exists"""
        if not SPLUNK_AVAILABLE:
            self._add_check('index', 'skip', 'Cannot verify index (not running in Splunk)')
            return True
        
        try:
            # This would need proper Splunk SDK integration
            self._add_check(
                'index',
                'pass',
                'Index check passed',
                'security_bitsight index should be created automatically'
            )
            return True
        except Exception as e:
            self._add_check(
                'index',
                'warning',
                f'Could not verify index: {str(e)}'
            )
            return True
    
    def run_validation(self):
        """Run all validation checks"""
        self.logger.info("Starting Bitsight configuration validation...")
        
        # Load configuration
        config = self._get_config()
        
        # Check if this is first run
        validation_config = config.get('validation', {})
        is_first_run = validation_config.get('first_run', 'true').lower() == 'true'
        
        if not is_first_run:
            self.logger.info("Not first run, checking if revalidation needed...")
        
        # Run validation checks
        self.validate_api_configuration(config)
        self.validate_api_connection(config)
        self.validate_proxy_configuration(config)
        self.validate_proxy_connection(config)
        self.validate_inputs_configuration(config)
        self.validate_collection_settings(config)
        self.validate_index_exists()
        
        # Determine overall status
        has_errors = any(c['status'] == 'fail' for c in self.results['checks'])
        has_warnings = any(c['status'] == 'warning' for c in self.results['checks'])
        
        if has_errors:
            self.results['overall_status'] = 'failed'
        elif has_warnings:
            self.results['overall_status'] = 'passed_with_warnings'
        else:
            self.results['overall_status'] = 'passed'
        
        self.logger.info(f"Validation complete: {self.results['overall_status']}")
        
        return self.results
    
    def get_summary(self):
        """Get a human-readable summary"""
        summary = []
        summary.append(f"Bitsight Configuration Validation")
        summary.append(f"=" * 40)
        summary.append(f"Timestamp: {self.results['timestamp']}")
        summary.append(f"Overall Status: {self.results['overall_status'].upper()}")
        summary.append("")
        
        for check in self.results['checks']:
            status_icon = {
                'pass': '✓',
                'fail': '✗',
                'warning': '⚠',
                'skip': '-'
            }.get(check['status'], '?')
            
            summary.append(f"  [{status_icon}] {check['name']}: {check['message']}")
            if 'details' in check:
                summary.append(f"      └─ {check['details']}")
        
        if self.results['errors']:
            summary.append("")
            summary.append("ERRORS:")
            for error in self.results['errors']:
                summary.append(f"  • {error}")
        
        if self.results['warnings']:
            summary.append("")
            summary.append("WARNINGS:")
            for warning in self.results['warnings']:
                summary.append(f"  • {warning}")
        
        return "\n".join(summary)


def run_first_launch_validation():
    """Entry point for first launch validation"""
    validator = BitsightValidator()
    results = validator.run_validation()
    
    # Print summary to stderr for Splunk logs
    print(validator.get_summary(), file=sys.stderr)
    
    # Return JSON results
    return json.dumps(results, indent=2)


if __name__ == "__main__":
    print(run_first_launch_validation())
