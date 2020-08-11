# Farsight DNSDB

This integration uses Farsight Security’s DNSDB solution to interactively lookup rich, historical DNS information – either as playbook tasks or through API calls in the War Room – to access rdata and rrset records.

1. Go to 'Settings > Integrations > Servers & Services'
1. Locate the DNSDB integration by searching for 'Farsight DNSDB' using the search box on the top of the page.
1. Click 'Add instance' to create and configure a new integration. You should configure the following DNSDB and Demisto specific settings:

    Name
    :    A textual name for the integration instance.
    
    API Key
    :    The API key that user gets from Farsight Security.
    
    DNSDB Service URL
    :    The service URL for Farsight DNSDB.
    
    Use system proxy settings
    :    Select whether or not to communicate via the system proxy server.
    
    Demisto engine
    :    If relevant, select the engine that acts as a proxy to the server. [Engines](https://support.demisto.com/hc/en-us/articles/226274727-Settings-Integrations-Engines) are used when you need to access a remote network segments and there are network devices such as proxies, firewalls, etc. that prevent the Demisto server from accessing the remote networks.
    
1. Press the 'Test' button to validate connection. If you are experiencing issues with the service configuration, please contact [Farsight Security support](support@farsightsecurity.com)
1. After completing the test successfully, press the 'Done' button.
