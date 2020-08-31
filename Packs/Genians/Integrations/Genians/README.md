<<<<<<< HEAD
<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Use the Genians integration to block IP using assign tag and unassign tag.</p>
</div>

<div class="cl-preview-section">
<p>Genians’ network sensing technology powered by Device Platform Intelligence (DPI) discovers and presents all detected devices’ business contextual and risk-related information along with their technical information without disturbing existing network infrastructure. The resulting intelligence enhances visibility and allows operators to detect and respond to any non-compliant or compromised devices in real time.</p>
<p>With the result of comprehensive network visibility, Genians can ensure compliance from all connected devices by leveraging Virtual In-Line Packet Inspection which operates at Layer 2. This technology has complete control over endpoint device traffic over TCP and UDP by eliminating the need for complex configurations and network changes.</p>
</div>

<div class="cl-preview-section">
<h2>Genians Genian NAC Module Requirements</h2>
<p>Before you can use this integration in Demisto, you need to enable certain modules in your Genian NAC environment.</p>
<p><strong>Genian NAC Web Console</strong></p>
<ol>
<li>This is the network address of the Genian NAC Enterprise or standalone Appliance. (The host on which the the Genian NAC is hosted.) For example, if the Genian NAC is hosted at the IP address<span> </span><em>192.168.100.100</em><span></span>, then you enter<span> </span><em>https://192.168.10.100:8443/mc2</em></li>
</ol>
<p><strong>Enforcement Mode</strong></p>
<ol>
<li>Go to<span> </span><em>System &gt; System &gt; Click IP of Sensor &gt; Click Sensor Tab &gt; Click Sensor on the right</em></li>
<li>Go to<span> </span><em>Sensor Operation &gt; Sensor Mode</em><span> </span>and change the<span> </span><em>Sensor Mode</em><span> </span>to '<span></span><strong>host</strong>'</li>
<li>Change<span> </span><em>Sensor Operationg Mode</em><span> </span>to '<span></span><strong>Enforcement</strong>'</li>
<ul>
<li>Monitoring: (Default) Monitoring mode. No blocking.</li>
<li>Enforcement: Blocking mode</li>
</ul>
</ol>
<p><strong>Specifying the Tag to be assigned to the node under control.</strong></p>
<ol>
<li>Go to<span> </span><em>Preferences &gt; Properties &gt; Tag</em></li>
<li>Create new Tag or use existing Tag (e.g. THREAT)</li>
</ol>
<p><strong>Create Enforcement Policy</strong></p>
<ol>
<li>Reference the Enforcement Policy section in the<span> </span><a href="https://docs.genians.com/release/en/controlling/understanding-policy.html#enforcement-policy" rel="nofollow">Genians Docs</a></li>
</ol>
</div>

<div class="cl-preview-section">
<h2>Configuration Parameters</h2>
<p><strong>Server IP</strong></p>
<ol>
<li>Input Genian NAC IP Address (e.g. 192.168.100.100)</li>
</ol>
<p><strong>API Key</strong></p>
<ol>
<li>You can generate an API Key in the Genian NAC Web Console.</li>
<ul>
<li>Go to<span> </span><em>Management &gt; User &gt; Administrator tab &gt; API Key</em><span> </span>to generate a key and save it.</li>
</ul>
<li>Input API Key (e.g. 912fae69-b454-4608-bf4b-fa142353b463)</li>
</ol>
<p><strong>Tag Name</strong></p>
<ol>
<li>Input Tag Name for IP Block (e.g. THREAT, GUEST)</li>
</ol>
</div>

<div class="cl-preview-section">
<h2>Configure Genians on Demisto</h2>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for Genians</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.</li>
<ul>
<li><strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server IP</strong></li>
<li><strong>API Key</strong></li>
<li><strong>Tag Name</strong></li>
</ul>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the token.</li>
</ol>
</div>

<div class="cl-preview-section">
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#Post IP address to a tag" target="_self">Post IP address to a tag: genians-assign-ip-tag</a></li>
<li><a href="#Delete IP address from a tag" target="_self">Delete IP address from a tag: genians-unassign-ip-tag</a></li>
</ol>
</div>

<div class="cl-preview-section">
<h3 id="Post IP address to a tag">1. Post IP address to a tag</h3>
<p>Assigns a tag to the Node specified.</p>
<h5>Base Command</h5>
<p><code>genians-assign-ip-tag</code></p>
<h5>Input</h5>
<table style="width: 745px;">
<thead>
<tr>
<th style="width: 150px;"><strong>Argument Name</strong></th>
<th style="width: 520px;"><strong>Description</strong></th>
<th style="width: 70px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 150px;">ip</td>
<td style="width: 520px;">IP Address (e.g. 192.168.100.87)</td>
<td style="width: 70px;">Mandatory</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 745px;">
<thead>
<tr>
<th style="width: 325px;"><strong>Path</strong></th>
<th style="width: 105px;"><strong>Type</strong></th>
<th style="width: 310px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 325px;">genians.tag.nodeId</td>
<td style="width: 105px;">String</td>
<td style="width: 310px;">nodeid of IP</td>
</tr>
<tr>
<td style="width: 325px;">genians.tag.Name</td>
<td style="width: 105px;">String</td>
<td style="width: 310px;">Tag name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>
[
    {
        "Type": "node",
        "Description": "Threat",
        "IDX": 9,
        "nodeId": "dd9394cc-4495-103a-8010-2cf05d0cf498-537696fb",
        "Name": "THREAT"
    }
]
</pre>
</div>

<div class="cl-preview-section">
<h3 id="Delete IP address from a tag">2. Delete IP address from a tag</h3>
<p>Removes the tag(s) from the Node specified.</p>
<h5>Base Command</h5>
<p><code>genians-unassign-ip-tag</code></p>
<h5>Input</h5>
<table style="width: 745px;">
<thead>
<tr>
<th style="width: 150px;"><strong>Argument Name</strong></th>
<th style="width: 520px;"><strong>Description</strong></th>
<th style="width: 70px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 150px;">ip</td>
<td style="width: 520px;">IP Address (e.g. 192.168.100.87)</td>
<td style="width: 70px;">Mandatory</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 745px;">
<thead>
<tr>
<th style="width: 325px;"><strong>Path</strong></th>
<th style="width: 105px;"><strong>Type</strong></th>
<th style="width: 310px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 325px;">genians.tag.nodeId</td>
<td style="width: 105px;">String</td>
<td style="width: 310px;">nodeid of IP</td>
</tr>
<tr>
<td style="width: 325px;">genians.tag.Name</td>
<td style="width: 105px;">String</td>
<td style="width: 310px;">Tag name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>
[]
</pre>
</div>
=======
Use the Genians integration to block IP using assign tag and unassign tag.

Genians’ network sensing technology powered by Device Platform Intelligence (DPI) discovers and presents all detected devices’ business contextual and risk-related information along with their technical information without disturbing existing network infrastructure. The resulting intelligence enhances visibility and allows operators to detect and respond to any non-compliant or compromised devices in real time.

With the result of comprehensive network visibility, Genians can ensure compliance from all connected devices by leveraging Virtual In-Line Packet Inspection which operates at Layer 2. This technology has complete control over endpoint device traffic over TCP and UDP by eliminating the need for complex configurations and network changes.

## Genians Genian NAC Module Requirements

Before you can use this integration in Demisto, you need to enable certain modules in your Genian NAC environment.

#### Genian NAC Web Console

1. This is the network address of the Genian NAC Enterprise or standalone Appliance. (The host on which the the Genian NAC is hosted.) For example, if the Genian NAC is hosted at the IP address *192.168.100.100*, then you enter *https://192.168.10.100:8443/mc2*

#### Enforcement Mode

1. Go to *System > System > Click IP of Sensor > Click Sensor Tab > Click Sensor on the right*
2. Go to *Sensor Operation > Sensor Mode* and change the *Sensor Mode* to '**host**'
3. Change *Sensor Operationg Mode* to '**Enforcement**'
    - Monitoring: (Default) Monitoring mode. No blocking.
    - Enforcement: Blocking mode

#### Specifying the Tag to be assigned to the node under control.

1. Go to *Preferences > Properties > Tag*
2. Create new Tag or use existing Tag (e.g. THREAT)

#### Create Enforcement Policy

1. Reference the Enforcement Policy section in the [Genians Docs](https://docs.genians.com/release/en/controlling/understanding-policy.html#enforcement-policy)


## Configuration Parameters

#### Server IP

1. Input Genian NAC IP Address (e.g. 192.168.100.100)

#### API Key

1. You can generate an API Key in the Genian NAC Web Console.
    - Go to *Management > User > Administrator tab > API Key* to generate a key and save it.
2. Input API Key (e.g. 912fae69-b454-4608-bf4b-fa142353b463)

#### Tag Name

1. Input Tag Name for IP Block (e.g. THREAT, GUEST)


## Configure Genians on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Genians.
3. Click **Add instance** to create and configure a new integration instance.
    - Name: a textual name for the integration instance.
    - Server IP
    - API Key
    - Tag Name
4. Click **Test** to validate the URLs, token, and connection.


## Commands

You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

1. [Post IP address to a tag: genians-assign-ip-tag](###Post IP address to a tag)
2. [Delete IP address from a tag: genians-unassign-ip-tag](###Delete IP address from a tag)

### Post IP address to a tag
***
Assigns a tag to the Node specified.

#### Base Command

`genians-assign-ip-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP Address (e.g. 192.168.100.87) | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| genians.tag.nodeId | string | nodeid of IP | 
| genians.tag.Name | string | Tag name | 

#### Raw Output

```
[
    {
        "Type": "node",
        "Description": "Threat",
        "IDX": 9,
        "nodeId": "dd9394cc-4495-103a-8010-2cf05d0cf498-537696fb",
        "Name": "THREAT"
    }
]
```

### Delete IP address from a tag
***
Removes the tag(s) from the Node specified.

#### Base Command

`genians-unassign-ip-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP Address (e.g. 192.168.100.87) | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| genians.tag.nodeId | string | nodeid of IP | 
| genians.tag.Name | string | Tag name | 

#### Raw Output

```[]```
>>>>>>> upstream/master
