#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Bitsight Setup Handler for Splunk
Handles configuration management via REST API
"""

import os
import sys
import json

# Add Splunk SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

try:
    import splunk.admin as admin
    import splunk.entity as entity
    import splunk.rest as rest
except ImportError:
    pass


class BitsightSetupHandler(admin.MConfigHandler):
    """
    Setup handler for Bitsight configuration
    """
    
    def setup(self):
        """Setup the handler with supported arguments"""
        if self.requestedAction == admin.ACTION_EDIT:
            # API Settings
            for arg in ['api_token', 'base_url', 'verify_ssl', 'timeout']:
                self.supportedArgs.addOptArg(arg)
            
            # Proxy settings
            for arg in ['proxy_enabled', 'proxy_url', 'proxy_username', 'proxy_password']:
                self.supportedArgs.addOptArg(arg)
            
            # Data input toggles
            for arg in ['input_portfolio', 'input_ratings', 'input_ratings_history',
                        'input_findings', 'input_findings_summary', 'input_alerts',
                        'input_exposed_credentials', 'input_threats', 'input_users']:
                self.supportedArgs.addOptArg(arg)
            
            # Collection settings
            for arg in ['portfolio_interval', 'findings_interval', 
                        'alerts_interval', 'days_back']:
                self.supportedArgs.addOptArg(arg)
            
            # Logging
            self.supportedArgs.addOptArg('log_level')
    
    def handleList(self, confInfo):
        """List current configuration"""
        conf_dict = self.readConf("bitsight")
        
        if conf_dict is not None:
            for stanza, settings in conf_dict.items():
                for key, val in settings.items():
                    # Mask sensitive fields
                    if key in ['api_token', 'proxy_password'] and val:
                        confInfo[stanza].append(key, '********')
                    else:
                        confInfo[stanza].append(key, val)
    
    def handleEdit(self, confInfo):
        """Update configuration"""
        name = self.callerArgs.id
        args = self.callerArgs
        
        # API Settings
        if name == 'settings':
            if 'api_token' in args.data:
                api_token = args.data['api_token'][0]
                if api_token and api_token != '********':
                    self.writeConf('bitsight', 'settings', {'api_token': api_token})
            
            for field in ['base_url', 'verify_ssl', 'timeout']:
                if field in args.data:
                    self.writeConf('bitsight', 'settings', 
                                  {field: args.data[field][0]})
        
        # Proxy settings
        elif name == 'proxy':
            if 'proxy_password' in args.data:
                proxy_pass = args.data['proxy_password'][0]
                if proxy_pass and proxy_pass != '********':
                    self.writeConf('bitsight', 'proxy', {'proxy_password': proxy_pass})
            
            for field in ['proxy_enabled', 'proxy_url', 'proxy_username']:
                if field in args.data:
                    self.writeConf('bitsight', 'proxy', 
                                  {field: args.data[field][0]})
        
        # Data input toggles
        elif name == 'inputs':
            for field in ['input_portfolio', 'input_ratings', 'input_ratings_history',
                          'input_findings', 'input_findings_summary', 'input_alerts',
                          'input_exposed_credentials', 'input_threats', 'input_users']:
                if field in args.data:
                    self.writeConf('bitsight', 'inputs', 
                                  {field: args.data[field][0]})
        
        # Collection settings
        elif name == 'collection':
            for field in ['portfolio_interval', 'findings_interval', 
                         'alerts_interval', 'days_back']:
                if field in args.data:
                    self.writeConf('bitsight', 'collection', 
                                  {field: args.data[field][0]})
        
        # Logging
        elif name == 'logging':
            if 'log_level' in args.data:
                self.writeConf('bitsight', 'logging', 
                              {'log_level': args.data['log_level'][0]})


class BitsightTestHandler(admin.MConfigHandler):
    """
    Handler for testing API and Proxy connections
    """
    
    def setup(self):
        """Setup the handler"""
        if self.requestedAction == admin.ACTION_EDIT:
            self.supportedArgs.addOptArg('test_api')
            self.supportedArgs.addOptArg('test_proxy')
    
    def handleList(self, confInfo):
        """Return test status"""
        confInfo['test'].append('status', 'ready')
    
    def handleEdit(self, confInfo):
        """Execute connection tests"""
        args = self.callerArgs
        
        if 'test_api' in args.data:
            result = self._test_api_connection()
            confInfo['test'].append('api_result', result)
        
        if 'test_proxy' in args.data:
            result = self._test_proxy_connection()
            confInfo['test'].append('proxy_result', result)
    
    def _test_api_connection(self):
        """Test Bitsight API connection"""
        try:
            import urllib.request
            import ssl
            
            # Read configuration
            conf = self.readConf("bitsight")
            settings = conf.get('settings', {})
            
            api_token = settings.get('api_token', '')
            base_url = settings.get('base_url', 'https://api.bitsighttech.com')
            verify_ssl = settings.get('verify_ssl', 'true').lower() == 'true'
            timeout = int(settings.get('timeout', '30'))
            
            if not api_token or api_token == '********':
                return json.dumps({'success': False, 'message': 'API token not configured'})
            
            # Create request
            url = f"{base_url.rstrip('/')}/v1/users/me"
            req = urllib.request.Request(url)
            req.add_header('Authorization', f'Basic {api_token}')
            req.add_header('Accept', 'application/json')
            
            # SSL context
            context = ssl.create_default_context()
            if not verify_ssl:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            
            # Make request
            response = urllib.request.urlopen(req, timeout=timeout, context=context)
            data = json.loads(response.read().decode('utf-8'))
            
            return json.dumps({
                'success': True, 
                'message': f"Connected successfully. User: {data.get('email', 'Unknown')}"
            })
            
        except Exception as e:
            return json.dumps({'success': False, 'message': str(e)})
    
    def _test_proxy_connection(self):
        """Test proxy connection"""
        try:
            import urllib.request
            
            # Read configuration
            conf = self.readConf("bitsight")
            proxy_conf = conf.get('proxy', {})
            
            proxy_enabled = proxy_conf.get('proxy_enabled', 'false').lower() == 'true'
            proxy_url = proxy_conf.get('proxy_url', '')
            
            if not proxy_enabled:
                return json.dumps({'success': False, 'message': 'Proxy is not enabled'})
            
            if not proxy_url:
                return json.dumps({'success': False, 'message': 'Proxy URL not configured'})
            
            # Test proxy by making a simple request
            proxy_handler = urllib.request.ProxyHandler({
                'http': proxy_url,
                'https': proxy_url
            })
            opener = urllib.request.build_opener(proxy_handler)
            
            req = urllib.request.Request('https://api.bitsighttech.com')
            response = opener.open(req, timeout=10)
            
            return json.dumps({
                'success': True, 
                'message': f"Proxy connection successful via {proxy_url}"
            })
            
        except Exception as e:
            return json.dumps({'success': False, 'message': str(e)})


# Initialize the handler
if __name__ == "__main__":
    admin.init(BitsightSetupHandler, admin.CONTEXT_NONE)
