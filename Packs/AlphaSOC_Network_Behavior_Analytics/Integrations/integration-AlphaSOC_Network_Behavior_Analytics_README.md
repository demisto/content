<!-- HTML_DOC -->
<h2>Overview</h2>
<hr>
<p>Use the AlphaSOC Network Behavior Analysis integration to instantly retrieve alerts from the AlphaSOC Analytics Engine (either from the cloud or an on-premise instance).</p>
<p>Network telemetry is sent to AlphaSOC (primarily DNS and IP events) from Network Behavior Analytics for Splunk, Network Flight Recorder, or direct API integrations, processed, and alerts generated. AlphaSOC is able to flag infected hosts, policy violations, anomalies, and threats requiring attention.</p>
<p> <img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/integration-AlphaSOC_Network_Behavior_Analytics_mceclip0.png"></p>
<p>The AlphaSOC Analytics Engine is free to evaluate without restriction for 30 days and you can instantly create an API key within Network Flight Recorder or our Splunk apps to evaluate and use the service.</p>
<p> </p>
<h2>Configure the AlphaSOC Network Behavior Analysis Integration on Cortex XSOAR</h2>
<hr>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for AlphaSOC Network Behavior Analysis.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li>
<strong>AlphaSOC Analysis Engine URL</strong>: efaults to <em>cloud</em>.</li>
<li>
<strong>AlphaSOC Analysis API Key</strong>:your AlphaSOC API key.</li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the API key and connection.</li>
</ol>
<p> </p>
<h2>Tune the Integration</h2>
<hr>
<p>Within the settings, the Ignore events below severity field defaults to 3 and is used to filter the content that you are loading into Cortex XSOAR from AlphaSOC. The severity values we use are as follows:</p>
<ul>
<li>5 (critical)</li>
<li>4 (high)</li>
<li>3 (medium)</li>
<li>2 (low)</li>
<li>1 (informational).</li>
</ul>
<p>Critical and high severity alerts include C2 callbacks, ransomware, cryptomining, DNS tunneling, port scanning, DGA traffic, and phishing traffic.</p>
<p>Medium severity alerts have lower fidelity and include beaconing to a suspicious domain, ICMP tunneling, and policy violations, for example, P2P activity, third-party VPN use, potentially unwanted programs or browser extensions present. We recommend leaving this field set to 3, but if you only want to load high-fidelity / high-confidence details of infected hosts into Cortex XSOAR, you can set this to 4.</p>
<p>The Include policy violations field defaults to true and can be set to false if you wish to suppress alerting of items that indicate poor hygiene within the environment, such as potentially unwanted programs (PUPs), unwanted browser extensions, P2P applications (such as BitTorrent), third-party VPN utilities, and remote access software, for example TeamViewer and GoToMyPC.</p>
<p> </p>
<h2>Test the Integration</h2>
<hr>
<p>When you have telemetry flowing into the AlphaSOC Analytics Engine and the Cortex XSOAR integration configured, you can synthesize malicious traffic and generate alerts for threats including C2 callbacks, DNS tunneling, DGA traffic, and port scanning using our open source Network Flight Simulator utility.</p>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/integration-AlphaSOC_Network_Behavior_Analytics_mceclip1.png"></p>
<p>The utility is available for both Windows and Linux, and will generate malicious traffic that in-turn will create incidents within Cortex XSOAR. If you click into the <em>Incidents</em> view, you can review the list.</p>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/integration-AlphaSOC_Network_Behavior_Analytics_mceclip2.png"></p>
