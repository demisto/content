
<p>
BPA Integration

Used to run Best Practice Assessment checks for Panorama. 

This integration was integrated and tested with version 1.0 of BPA
</p>
<h2>BPA Playbook</h2>
<p>You can use the <strong>"Run Panorama Best Practice Assessment"</strong> playbook to run a BPA job on the configured instance. </p>

<h2>Configure BPA on Demisto</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for BPA.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>Panorama Server URL (e.g., https://192.168.0.1)</strong></li>
   <li><strong>Panorama Server Port (e.g 443)</strong></li>
   <li><strong>Panorama API Key</strong></li>
   <li><strong>BPA Access Token</strong></li>
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
  <li><a href="#pan-os-get-documentation" target="_self">Get documentaion: pan-os-get-documentation</a></li>
  <li><a href="#pan-os-bpa-submit-job" target="_self">Submits a BPA job: pan-os-bpa-submit-job</a></li>
  <li><a href="#pan-os-bpa-get-job-results" target="_self">Returns results of BPA job: pan-os-bpa-get-job-results</a></li>
</ol>
<h3 id="pan-os-get-documentation">1. pan-os-get-documentation</h3>
<hr>
<p>Get documentaion</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-get-documentation</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>
<h5>Input</h5>
There are no input arguments for this command.
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
      <td>PAN-OS-BPA.Documentation</td>
      <td>string</td>
      <td>Gets the documentation of all BPA checks</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!pan-os-get-documentation</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "PAN-OS-BPA.Documentation": [
        {
            "active": true,
            "created_time": "2019-08-14T23:10:09.935024Z",
            "description": "GRE Tunnel Keep-Alive",
            "doc_id": 246,
            "doc_type": "Warning",
            "id": 246,
            "last_updated_time": "2019-08-14T23:10:09.935040Z",
            "left_nav": "GRE Tunnels",
            "rationale": "Configure Keep-alive on GRE Tunnel to ensure stability and monitoring of tunnel activity.",
            "references": "https://docs.paloaltonetworks.com/pan-os/9-0/pan-os-admin/networking/gre-tunnels/create-a-gre-tunnel.html",
            "title": "GRE Tunnel Keep-Alive",
            "top_nav": "Network"
        },
        ...
       ]

<h5>Human Readable Output</h5>
<p>
<h3>BPA documentation</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>active</strong></th>
      <th><strong>created_time</strong></th>
      <th><strong>description</strong></th>
      <th><strong>doc_id</strong></th>
      <th><strong>doc_type</strong></th>
      <th><strong>id</strong></th>
      <th><strong>last_updated_time</strong></th>
      <th><strong>left_nav</strong></th>
      <th><strong>rationale</strong></th>
      <th><strong>references</strong></th>
      <th><strong>title</strong></th>
      <th><strong>top_nav</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> true </td>
      <td> 2019-08-14T23:10:09.935024Z </td>
      <td> GRE Tunnel Keep-Alive </td>
      <td> 246 </td>
      <td> Warning </td>
      <td> 246 </td>
      <td> 2019-08-14T23:10:09.935040Z </td>
      <td> GRE Tunnels </td>
      <td> Configure Keep-alive on GRE Tunnel to ensure stability and monitoring of tunnel activity. </td>
      <td> https://docs.paloaltonetworks.com/pan-os/9-0/pan-os-admin/networking/gre-tunnels/create-a-gre-tunnel.html </td>
      <td> GRE Tunnel Keep-Alive </td>
      <td> Network </td>
    </tr>
    </tbody>
    </table>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="pan-os-bpa-submit-job">2. pan-os-bpa-submit-job</h3>
<hr>
<p>Submits a BPA job.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-bpa-submit-job</code>
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
      <td>generate_zip_bundle</td>
      <td>Whether to download the Panorama report. Can be "true" or "false". Default is "false".</td>
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
      <td>PAN-OS-BPA.SubmittedJob.JobID</td>
      <td>string</td>
      <td>Submitted job ID</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!pan-os-bpa-submit-job</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "PAN-OS-BPA.SubmittedJob": {
        "JobID": "2b0c40d6-73a8-4d23-9bd8-27548b28beb5"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
Submitted BPA job ID: 2b0c40d6-73a8-4d23-9bd8-27548b28beb5
</p>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="pan-os-bpa-get-job-results">3. pan-os-bpa-get-job-results</h3>
<hr>
<p>Returns results of BPA job.</p>
<h5>Base Command</h5>
<p>
  <code>pan-os-bpa-get-job-results</code>
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
      <th>
        <strong>Default Value</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>task_id</td>
      <td>The job id to get results from</td>
      <td>Required</td>
      <td>-</td>
    </tr>
    <tr>
      <td>exclude_passed_checks</td>
      <td>Whether to exclude passed checks or not.</td>
      <td>Not Required</td>
      <td>false</td>
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
      <td>PAN-OS-BPA.JobResults.JobID</td>
      <td>string</td>
      <td>Submitted job ID</td>
    </tr>
    <tr>
      <td>PAN-OS-BPA.JobResults.Status</td>
      <td>string</td>
      <td>Job status</td>
    </tr>
    <tr>
      <td>PAN-OS-BPA.JobResults.Checks</td>
      <td>Unknown</td>
      <td>List of checks</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!pan-os-bpa-get-job-results task_id=32bc2c82-5b8b-471d-aed1-cccb36a6d6f7</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "PAN-OS-BPA.JobResults": {
        "Checks": [
            {
                "check_category": "device",
                "check_feature": "admin_role",
                "check_id": 154,
                "check_message": "It is recommended to create and use custom admin roles",
                "check_name": "Custom Admin Roles",
                "check_severity": "Info",
                "check_type": "Note"
            },
            ..
           ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
Checks received.
</p>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
