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
except ImportError:
    pass


class BitsightSetupHandler(admin.MConfigHandler):
    """
    Setup handler for Bitsight configuration
    """
    
    def setup(self):
        """Setup the handler with supported arguments"""
        if self.requestedAction == admin.ACTION_EDIT:
            # Settings
            for arg in ['api_token', 'base_url', 'verify_ssl', 'timeout', 
                        'proxy_enabled', 'proxy_url']:
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
                    # Mask API token
                    if key == 'api_token' and val:
                        confInfo[stanza].append(key, '********')
                    else:
                        confInfo[stanza].append(key, val)
    
    def handleEdit(self, confInfo):
        """Update configuration"""
        name = self.callerArgs.id
        args = self.callerArgs
        
        # Validate required fields
        if name == 'settings':
            if 'api_token' in args.data:
                api_token = args.data['api_token'][0]
                if api_token and api_token != '********':
                    self.writeConf('bitsight', 'settings', {'api_token': api_token})
            
            if 'base_url' in args.data:
                self.writeConf('bitsight', 'settings', 
                              {'base_url': args.data['base_url'][0]})
            
            if 'verify_ssl' in args.data:
                self.writeConf('bitsight', 'settings', 
                              {'verify_ssl': args.data['verify_ssl'][0]})
            
            if 'timeout' in args.data:
                self.writeConf('bitsight', 'settings', 
                              {'timeout': args.data['timeout'][0]})
            
            if 'proxy_enabled' in args.data:
                self.writeConf('bitsight', 'settings', 
                              {'proxy_enabled': args.data['proxy_enabled'][0]})
            
            if 'proxy_url' in args.data:
                self.writeConf('bitsight', 'settings', 
                              {'proxy_url': args.data['proxy_url'][0]})
        
        elif name == 'collection':
            for field in ['portfolio_interval', 'findings_interval', 
                         'alerts_interval', 'days_back']:
                if field in args.data:
                    self.writeConf('bitsight', 'collection', 
                                  {field: args.data[field][0]})
        
        elif name == 'logging':
            if 'log_level' in args.data:
                self.writeConf('bitsight', 'logging', 
                              {'log_level': args.data['log_level'][0]})


# Initialize the handler
if __name__ == "__main__":
    admin.init(BitsightSetupHandler, admin.CONTEXT_NONE)
