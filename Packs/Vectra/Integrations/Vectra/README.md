<!-- HTML_DOC -->
<p>Vectra is a detection product that alerts on suspicious network behavior. It can recognize certain known attacks and suspicious interactions on the network level (e.g. Reverse Shell, Port Scans, etc)</p>
<p>Cortex XSOAR supports fetching detections directly from Vectra. These are set to trigger incidents in Cortex XSOAR.</p>
<p>Commands start with !Vectra and can be viewed by clicking <strong>Show commands </strong>in the Settings/Integrations page.</p>
<p>For additional information check out also the solution brief at <a href="https://content.vectra.ai/rs/748-MCE-447/images/ProductIntegration_2017_Integrating_Cognito_with_Demisto_English.pdf">Integrating_Cognito_with_Demisto_English.pdf</a></p>
<h3>To set up the integration on Cortex XSOAR:</h3>
<ol>
<li>Go to ‘Settings &gt; Integrations &gt; Servers &amp; Services’</li>
<li>Locate the Vectra integration by searching for ‘Vectra’ using the search box on the top of the page.</li>
<li>Click ‘Add instance’ to create and configure a new integration. You should configure the following Vectra and Cortex XSOAR-specific settings:<br> <strong>Name</strong>: A textual name for the integration instance.<br> <strong>Server URL</strong>: The hostname or IP address of the Vectra application. Make sure the URL is reachable with respect to IP address and port.<br> <strong>Credentials and Password</strong>: The username and password, or toggle to Credentials.<br> <strong>Fetch incidents</strong>: Select whether to automatically create Cortex XSOAR incidents from Vectra offenses. <br> If this option is checked, the first batch of offenses pulled as incidents will be the one raised in last 10 minutes of adding the instance.<br><strong>Do not validate server certificate</strong>: Select to avoid server certification validation. You may want to do this in case Cortex XSOAR cannot validate the integration server certificate (due to missing CA certificate)<br> <strong>Incident type</strong>: Select to which incident type you want to map Vectra offenses.   <br> <strong>Cortex XSOAR engine</strong>: If relevant, select the engine that acts as a proxy to the server.<br> Engines are used when you need to access a remote network segments and there are network devices such as proxies, firewalls, etc. that prevent the Cortex XSOAR server from accessing the remote networks.</li>
</ol>
<p class="wysiwyg-indent4">For more information on Cortex XSOAR engines see:<br><a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Engines">Cortex XSOAR 6.13 - Engines</a><br> <a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Engines">Cortex XSOAR 8 Cloud- Engines</a><br> <a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Engines">Cortex XSOAR 8.7 On-prem - Engines</a><br> Require users to enter additional password: Select whether you’d like an additional step where users are required to authenticate themselves with a password.</p>
<ol start="4">
<li>Press the ‘Test’ button to validate connection.<br>
</li>
<li>After completing the test successfully, press the ‘Done’ button.</li>
</ol>
<h3>Commands:</h3>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>vectra-detections</strong> - Detection objects contain all the information related to security events detected on the network.</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>vectra-health - </strong>The health configuration retrieves system health statistics such as subnet counts, traffic bandwidth, headend and sensor information.</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>vectra-hosts - </strong>Host information includes data that correlates the host data to detected security events.</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>vectra-sensors - </strong>The sensors branch retrieves a list of sensors that collect and feed data to the X-series.</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>vectra-settings - </strong>The settings information includes S-series sensor and X-series configurations input by the administrator.</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>vectra-triage - </strong>The rules branch can be used to retrieve a listing of configured Triage rules</div>
</div>