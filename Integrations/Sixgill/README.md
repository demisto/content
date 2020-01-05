<p>
Fetching Sixgill alerts as incidents

This integration was integrated and tested with version 0.0.3 of Sixgill
</p>
<h2>Sixgill Playbook</h2>
<p>Populate this section with relevant playbook names.</p>
<h2>Use Cases</h2>
<ul>
<li>Consume sixgill alerts through demisto\s platform</li>
</ul><h2>Detailed Description</h2>
<p>Populate this section with the .md file contents for detailed description.</p>
<h2>Fetch Incidents</h2>
<p>Retrive all incidents related to an organization</p>
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
</ol>
<h3>1. fetch-incidents</h3>
<hr>
<p>Get bulk of Sixgill alerts</p>
<h5>Base Command</h5>
<p>
  <code>fetch-incidents</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Organization should be registered to Sixgill Actionable alerts</li>
    <li>Organization should be registered to consume Actionable alerts through demisto platform</li>
    <li>A valid client-id & client-secret to sixgill's API</li>
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
      <td>Should delivered items be included</td>
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
<h2>Additional Information</h2><h2>Known Limitations</h2><h2>Troubleshooting</h2>