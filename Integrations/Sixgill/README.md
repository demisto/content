<p>
Sixgill’s cyber threat intelligence solution focuses on customers’ intelligence needs, helping them mitigate risk to their organizations more effectively and more efficiently. Using an agile and automatic collection methodology, Sixgill provides broad coverage of exclusive-access deep and dark web sources, as well as relevant surface web sources. Sixgill utilizes artificial intelligence and machine learning to automate the production cycle of cyber intelligence from monitoring through extraction to production. 

Automatic monitoring of cybercrime, providing actionable intelligence from exclusive clear, deep and dark web forums and markets. Detect, analyze and mitigate financial fraud in near real-time.

Integration:
Retrieving Sixgill's DarkFeed Threat Intelligence indicators (IOC)
Retrieving Sixgill's Actionable Alerts as incidents

This integration was integrated and tested with version 0.0.4 of Sixgill

</p>
<h2>Sixgill Playbook</h2>
<p>playbook-Sixgill-Test</p>
<h2>Use Cases</h2>
<ul>
<li>Fetching Sixgill's DarkFeed Threat Intelligence indicators.</li>
<li>Fetching Sixgill's Alerts & Events as incidents.</li>
</ul>
<h2>Detailed Description</h2>
<p>Configure an API account:</p>
<p>To configure an instance of Sixgill's integration in Demisto, you need to supply your API key and client Secret. Please contact support at cybersixgill.com to receive these.</p>
<h2>Fetch Incidents</h2>
<p>Sixgill's alerts are pushed as incidents to Demisto platform. </p>
<h2>Configure Sixgill on Demisto</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for Sixgill.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>Sixgill API client ID</strong></li>
   <li><strong>Sixgill API client secret</strong></li>
    </ul>
  </li>
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>
<h2>Commands</h2>
<p>
  You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li>fetch-incidents: fetch-incidents</li>
  <li>get-indicators: get-indicators</li>
</ol>
<h3>1. fetch-incidents</h3>
<hr>
<p>Get Sixgill's alerts as incidents</p>
<h5>Base Command</h5>
<p>
  <code>fetch-incidents</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Sixgill's API client id and client secret.</li>
    <li>Organization is registered to consume data using Demisto platform</li>
</ul>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>include_delivered_items</td>
      <td>Should previously-delivered items be included in the response</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!fetch-incidents</code>
</p>

<h5>Human Readable Output</h5>
<p>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>2. get-indicators</h3>
<hr>
<p>Fetching Sixgill's DarkFeed Threat Intelligence indicators</p>
<h5>Base Command</h5>
<p>
  <code>get-indicators</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>include_delivered_items</td>
      <td>Should previously-delivered items be included in the response</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>IP.Address</td>
      <td>Unknown</td>
      <td>IP address indicator.</td>
    </tr>
    <tr>
      <td>Domain.Name</td>
      <td>Unknown</td>
      <td>Domain name indicator</td>
    </tr>
    <tr>
      <td>File.MD5</td>
      <td>Unknown</td>
      <td>File hash indicator</td>
    </tr>
    <tr>
      <td>Sixgill.Indicator.Cryptocurrency.Address</td>
      <td>Unknown</td>
      <td>Cryptocurrency address indicator </td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!fetch-incidents</code>
</p>

<h5>Human Readable Output</h5>
<pre>Successfully extracted 1000 IOCs of the following types: ["suspicious_ip", "proxy_ip", "crypto_wallet", "mal_md5", "mal_domain"]}</pre>
<p>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
<h2>Additional Information</h2><h2>Known Limitations</h2><h2>Troubleshooting</h2><p>Contact us: support at cybersixgill.com</p>