<!-- HTML_DOC -->
<p>This integration uses Farsight Security’s DNSDB solution to interactively lookup rich, historical DNS information – either as playbook tasks or through API calls in the War Room – to access rdata and rrset records.</p>
<h2><strong>To set up Farsight Security DNSDB to work with Demisto:</strong></h2>
<p>User will need DNSDB’s API key and service URL for connecting to the Demisto server.</p>
<h2><strong>To set up the integration on Demisto:</strong></h2>
<ol>
<li>Go to ‘Settings &gt; Integrations &gt; Servers &amp; Services’</li>
<li>Locate the DNSDB integration by searching for ‘Farsight DNSDB’ using the search box on the top of the page.</li>
<li>Click ‘Add instance’ to create and configure a new integration. You should configure the following DNSDB and Demisto specific settings:<br> <strong>Name</strong>: A textual name for the integration instance.<br> <strong>API Key</strong>: The API key that user gets from Farsight Security.<br> <strong>DNSDB Service URL</strong>: The service URL for Farsight DNSDB.<br> <strong>Use system proxy settings</strong>: Select whether or not to communicate via the system proxy server.<br> <strong>Demisto engine</strong>: If relevant, select the engine that acts as a proxy to the server.<br> Engines are used when you need to access a remote network segments and there are network devices such as proxies, firewalls, etc. that prevent the Demisto server from accessing the remote networks.<br> For more information on Demisto engines see:<br> <a href="https://support.demisto.com/hc/en-us/articles/226274727-Settings-Integrations-Engines">https://demisto.zendesk.com/hc/en-us/articles/226274727-Settings-Integrations-Engines</a>
</li>
<li>Press the ‘Test’ button to validate connection.<br> If you are experiencing issues with the service configuration, please contact Demisto support at <a href="mailto:support@demisto.com">support@demisto.com</a>.</li>
<li>After completing the test successfully, press the ‘Done’ button.</li>
</ol>
<p> </p>