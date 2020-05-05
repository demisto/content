<!-- HTML_DOC -->
<p>When integrating Protectwise with Demisto, event data is received in a continues stream of data which can be handled by Demisto.</p>
<h3>To set up the integration on Demisto:</h3>
<ol>
<li>Go to ‘Settings &gt; Integrations &gt; Servers &amp; Services’</li>
<li>Locate the Protectwise integration by searching for ‘Protectwise’ using the search box on the top of the page.
<ol>
<li>Click ‘Add instance’ to create and configure a new integration. You should configure the following Protectwise and Demisto-specific settings:  <br>                             <br><strong>Name</strong>: A textual name for the integration instance.</li>
</ol>
</li>
</ol>
<p class="wysiwyg-indent8"><strong>URL</strong>: The hostname or IP address of the application. Make sure it is reachable with respect to IP address and port.</p>
<p class="wysiwyg-indent8"><strong>Email &amp; Password:</strong> the credentials for accessing the API.  </p>
<p class="wysiwyg-indent8"><strong>Do not validate certificate (insecure): </strong>Select to avoid server certification validation. You may want to do this in case Demisto cannot validate the integration server certificate (due to missing CA certificate).</p>
<p class="wysiwyg-indent8"><strong>Only fetch events with this text in the name:</strong> To only pull events with a specific name, specify it here. Demisto will look for one of the filter values in the Event name (comparison is case insensitive). <br>Separate multiple names with a comma. For example: Progression,Lateral Movement</p>
<p class="wysiwyg-indent8"><strong>Filter by threat category</strong>: To pull threats according to threat category.</p>
<p class="wysiwyg-indent8"><strong>Filter by killchain stage</strong>: To pull threats according to threat killchain stage.</p>
<p class="wysiwyg-indent8"><strong>Filter by LOW , MEDIUM , or HIGH threatLevel</strong>: To pull threats according to Threat Level.</p>
<p class="wysiwyg-indent8"><strong>Fetch incidents: </strong>Select whether to automatically create Demisto incidents from the integration's events. <br>If this option is checked, the first fetch will search for events 10 minutes back from the moment you turn on Fetching. Subsequently, new offences will be fetched as soon as they are generated. Use the "Query to fetch offences" option to pull older offences as incidents.<br>The next fetch interval depends on the systemwide interval (default 1 min).<strong><br></strong></p>
<p class="wysiwyg-indent8"><strong>Incident type:</strong> Specify the Demisto incident type that will be set for incidents from this integration.</p>
<p class="wysiwyg-indent8"><strong>Use system proxy settings</strong>: Select whether to communicate via the system proxy server or not.</p>
<p class="wysiwyg-indent8"><strong>Demisto engine:</strong> If relevant, select the engine that acts as a proxy to the server.  </p>
<p class="wysiwyg-indent8">Engines are used when you need to access a remote network segments and there are network devices such as proxies, firewalls, etc. that prevent the Demisto server from accessing the remote networks.<br><br>For more information on Demisto engines see:<br><a href="https://support.demisto.com/hc/en-us/articles/226274727-Settings-Integrations-Engines">https://demisto.zendesk.com/hc/en-us/articles/226274727-Settings-Integrations-Engines</a></p>
<ol start="4">
<li>Press the ‘Test’ button to validate connection.<br>If you are experiencing issues with the service configuration, please contact Demisto support at support@demisto.com</li>
<li>After completing the test successfully, press the ‘Done’ button.</li>
</ol>
<h3>Commands:</h3>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>protectwise-event-info - </strong>Lookup a single event and its associated observations for ProtectWise.</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>protectwise-event-pcap-download - </strong>Event Pcap Download.</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>protectwise-event-pcap-info - </strong>Get ProtectWise Event Pcap info.</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>protectwise-observation-info - </strong>Lookup a single observation for ProtectWise.</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>protectwise-observation-pcap-download - </strong>Observation Pcap Download.</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>protectwise-observation-pcap-info - </strong>Get ProtectWise Observation Pcap info.</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>protectwise-search-events - </strong>search Events ,Events are resources that describe a threat and contains a collection of observations.</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>protectwise-search-observations - </strong>search observations in ProtectWise.</div>
</div>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<strong>protectwise-show-sensors - </strong>Collection of all available sensors.</div>
<div class="ten wide break-word column integration-command-description"> </div>
</div>
<h3>Example:</h3>
<p>The following shows how fields provided by the API are mapped as labels in fetched Events.</p>
<pre><code>[killChainStage] Fortification
[observedAt] 2017-08-04T13:00:03.436Z
[isUpdate] true
[type] MaliciousFlow
[threatLevel] High
[category] Suspicious
[observationCount] 2
[sensorId] 1849
[cid] 1820
[message] Critical Lateral Movement Activity on Hosts: 192.168.2.81,192.168.2.170
[confidence] 100
[endedAt] 2017-08-04T12:59:49.156Z
[threatScore] 70
[id] 000555ed127a1ca0b771fc0e4270cfcc24510b32d7ff9b9d66dfedcf
[startedAt] 2017-08-04T12:59:49.156Z
[threatSubCategory] None
[priority] false
[agentId] 1849
[observedStage] Realtime
[netflowCount] 1
[sensorIds] 1849
[Brand] ProtectWise
[Instance] ProtectWise_instance_1
</code></pre>
<p><a href="https://user-images.githubusercontent.com/3792355/29264877-6cc04a82-80e7-11e7-8494-7c4860763995.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/3792355/29264877-6cc04a82-80e7-11e7-8494-7c4860763995.png" alt="image" width="751" height="269"></a></p>
<p><a href="https://user-images.githubusercontent.com/3792355/29264909-98cc9644-80e7-11e7-97ec-abb5c5b55f98.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/3792355/29264909-98cc9644-80e7-11e7-97ec-abb5c5b55f98.png" alt="image" width="752" height="180"></a></p>
<p><a href="https://user-images.githubusercontent.com/3792355/29264939-bd54d472-80e7-11e7-95de-22bd3990ea52.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/3792355/29264939-bd54d472-80e7-11e7-95de-22bd3990ea52.png" alt="image" width="751" height="404"></a><br><a href="https://user-images.githubusercontent.com/3792355/29264957-c4ba11be-80e7-11e7-818d-e5fda28ff83c.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/3792355/29264957-c4ba11be-80e7-11e7-818d-e5fda28ff83c.png" alt="image" width="751" height="277"></a></p>
<p> <a href="https://user-images.githubusercontent.com/3792355/29265449-b8e6d618-80e9-11e7-8547-f81014ce3630.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/3792355/29265449-b8e6d618-80e9-11e7-8547-f81014ce3630.png" alt="image" width="750" height="275"></a></p>
<p> </p>
<p> </p>