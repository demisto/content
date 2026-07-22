<!-- HTML_DOC -->
<h2>Overview</h2>
<p>Use the SafeBreach integration to run simulations in your SafeBreach environment and send the results to Cortex XSOAR.</p>
<p>This integration was integrated and tested with SafeBreach v2018Q2.2</p>
<hr>
<h2>Integrate Cortex XSOAR on SafeBreach</h2>
<ol>
<li>Log in to the SafeBreach Management platform.</li>
<li>Type <em>console</em> to access the SafeBreach CLI.</li>
<li>In the SafeBreach CLI window, type <code>plugins add demisto --url &lt;<em>demistoServerUrl</em>&gt; --apiKey &lt;<em>apiKey</em>&gt;</code>.<br>
<table border="2" width="655" cellpadding="6">
<tbody>
<tr>
<td style="width: 324px;"><strong>Argument</strong></td>
<td style="width: 324px;"><strong>Description</strong></td>
<td style="width: 324px;"><strong>Required</strong></td>
</tr>
<tr>
<td style="width: 324px;">url</td>
<td style="width: 324px;">Cortex XSOAR server address, for example https://192.168.2.178</td>
<td style="width: 324px;">required</td>
</tr>
<tr>
<td style="width: 324px;">apiKey</td>
<td style="width: 324px;">Cortex XSOAR API key / authentication token</td>
<td style="width: 324px;">required</td>
</tr>
<tr>
<td style="width: 324px;">help</td>
<td style="width: 324px;">Displays all options for adding Cortex XSOAR, for example [plugin add demisto -help]</td>
<td style="width: 324px;">optional</td>
</tr>
<tr>
<td style="width: 324px;">isAutomated</td>
<td style="width: 324px;">Simulation results can be sent to Cortex XSOAR as incidents. </td>
<td style="width: 324px;">optional</td>
</tr>
<tr>
<td style="width: 324px;">isAutomated true</td>
<td style="width: 324px;"> An automated incident (conatiner) is opened for each simulation that is either not-blocked, or when a blocked simulation result changes to not-blocked. For adding Cortex XSOAR with automation, use: [plugins add demisto --url &lt;demistoServerUrl&gt; --default &lt;apiKey&gt; --isAutomated true]. For changing Cortex XSOAR to become automated, use this command [plugins update demisto --isAutomated true]</td>
<td style="width: 324px;"> optional</td>
</tr>
<tr>
<td style="width: 324px;"> isAutomated false</td>
<td style="width: 324px;">The user can send a simulation result to Cortex XSOAR as an incident on demand, by clicking on Send to from the required simulation incident in Breach Methods.</td>
<td style="width: 324px;"> optional</td>
</tr>
</tbody>
</table>
</li>
</ol>
<h3> </h3>
<p>After you integrate Cortex XSOAR, SafeBreach Management users can drill down in a simulation and use the <strong>Send To</strong> button to send the simulation results to Cortex XSOAR. For more information see the Drilling Down for More about a Simulation article on the <a href="https://support.safebreach.com/hc/en-us">SafeBreach support site</a>.</p>
<p><strong>NOTE</strong>: You can also use the <em>update</em> and <em>show</em> commands to change and view details about Demisto plugins.</p>
<hr>
<h2>Generate a SafeBreach API Key</h2>
<ol>
<li>Log in to the SafeBreach Management platform.</li>
<li>Type <em>console</em> to access the SafeBreach CLI.</li>
<li>In the SafeBreach CLI window, type config apikeys add --name &lt;<em>apiKeyName</em>&gt;<br> Type a meaningful name for the API key.<br> <strong>Example output</strong><br>
<table border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 201px;"><strong>id</strong></td>
<td style="width: 501px;"><strong>key</strong></td>
<td style="width: 270px;"><strong>name</strong></td>
<td style="width: 324px;"><strong>accountID</strong></td>
</tr>
<tr>
<td style="width: 201px;">2</td>
<td style="width: 501px;">74963a8f-a3b3-4d6c-b3d4-715996cf4a31</td>
<td style="width: 270px;">apiKeyName</td>
<td style="width: 324px;">12345</td>
</tr>
</tbody>
</table>
</li>
</ol>
<hr>
<h2>Configure the SafeBreach Integration on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for the SafeBreach integration.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration.</li>
</ol><ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li>
<strong>Account ID</strong>: SafeBreach Account (see example output above) </li>
<li>
<strong>API Key</strong>: SafeBreach API key</li>
<li>
<strong>SafeBreach Platform URL</strong>: URL of your SafeBreach Management environment</li>
<li>
<strong>API Version</strong>: 1 (do not change the default value)</li>
<li>
<strong>Cortex XSOAR engine</strong>: If relevant, select the engine that acts as a proxy to the server.</li>
</ul>
<li>Click <strong>Test</strong> to validate the URLs and connection.</li>

<hr>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, in a playbook, or from your SafeBreach environment. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ul>
<li><a href="#h_176763804101526383549368">Send simulation results to Cortex XSOAR: Send To button in SafeBreach</a></li>
<li><a href="#h_441071342251526383556458">Rerun a simulation in SafeBreach: safebreach-rerun</a></li>
<li><a href="#h_718307413401526383562362">Retrieve results of a rerun simulation: safebreach-get-simulation</a></li>
</ul>
<hr>
<h3 id="h_176763804101526383549368">Send simulation results to Cortex XSOAR: Send To button in SafeBreach</h3>
<p>You execute this command in the SafeBreach Management platform. After you run a simulation, you can click the <strong>Send To</strong> button to send simulation results to Cortex XSOAR.</p>
<p><img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/integration-SafeBreach_mceclip0.png" width="592" height="271"></p>
<h4>Output</h4>
<p>The new incident is added to the Incidents list in Cortex XSOAR.</p>
<p><img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/integration-SafeBreach_mceclip1.png" width="589" height="294"></p>
<hr>
<h3 id="h_441071342251526383556458">Rerun a simulation in SafeBreach: safebreach-rerun</h3>
<p>Rerun a previously run simulation in SafeBreach. You execute this command from the Cortex XSOAR CLI or a playbook. You can only run this command inside an incident that was fetched from SafeBreach.</p>
<h4>Inputs</h4>
<p><code>!safebreach-rerun</code></p>
<p><img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/integration-SafeBreach_mceclip2.png"><code></code></p>
<h4>Outputs</h4>
<p><code>ok</code></p>
<p><img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/integration-SafeBreach_mceclip3.png"></p>
<hr>
<h3 id="h_718307413401526383562362">Retrieve results of a rerun simulation: safebreach-get-simulation</h3>
<p>After you rerun a simulation, retrieve the results of that simulation. You execute this command from the Cortex XSOAR CLI or a playbook. You can only run this command inside an incident that was fetched from SafeBreach.</p>
<h4>Inputs</h4>
<p><code>!safebreach-get-simulation</code></p>
<p><img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/integration-SafeBreach_mceclip4.png"></p>
<h4>Outputs</h4>
<p><img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/integration-SafeBreach_mceclip5.png"></p>
<hr>
<h2>XSOAR-SafeBreach Demo</h2>
<p><iframe src="https://www.youtube.com/watch?v=Wb7q5Gbd2qo&feature=youtu.be" width="560" height="315" frameborder="0" allowfullscreen=""></iframe></p>
