<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Forescout is Unified device visibility and control platform for IT and OT security.</p>
</div>
<div class="cl-preview-section">
<h2 id="detailed-information">Detailed Information</h2>
</div>
<div class="cl-preview-section">
<p>Read this section and perform all necessary steps before you configure an integration instance.</p>
</div>
<div class="cl-preview-section">
<h3>Forescout Module Requirements</h3>
<p>Before you can use this integration in Cortex XSOAR, you need to enable certain modules in your Forescout environment.</p>
<ol>
<li>In the Forescout console, from the navigation bar select<span> </span><em>Tools &gt; Options</em>.</li>
<li>In the dialog that appears, from the categories section on the left, click<span> </span><em>Modules</em>.</li>
<li>In the main area of the dialog, from the drop-down menu, select<span> </span><em>Open Integration Module</em>. Make sure that the integration module and the following submodules are installed and enabled:<span> </span><em>Data Exchange (DEX)</em><span> </span>and<span> </span><em>Web API</em><span> </span>are all installed and enabled. If they aren't, install and enable them.</li>
</ol>
<h3>
<a id="user-content-configuration-parameters" class="anchor" href="https://github.com/demisto/content/blob/284b80afd53fdc12ff18a6953a888f5a0abed67d/Integrations/Forescout/Forescout_description.md#configuration-parameters" aria-hidden="true"></a>Configuration Parameters</h3>
<p><strong>url</strong><br> This is the network address of the Forescout Enterprise Manager or standalone Appliance. (The host on which the the Forescout Appliance is hosted.) For example, if the Forescout Appliance is hosted at the IP address<span> </span><em>192.168.10.23</em>, then you enter<span> </span><em><a href="https://192.168.10.23/" rel="nofollow">https://192.168.10.23</a></em>.</p>
<p><strong>Web API Username</strong><span> </span>and<span> </span><strong>Password</strong><br> The credentials entered here should be those created in the Forescout console for the<span> </span><em>Web API</em>.</p>
<ol>
<li>In the Forescout console, from the top navigation bar, click<span> </span><em>Tools &gt; Options</em>.</li>
<li>From the dialog that appears, in the categories section on the left, click<span> </span><em>Web API</em>, and select<span> </span><em>User Settings</em>.</li>
<li>Create a username and password by clicking the<span> </span><em>Add</em><span> </span>button, and completing the fields. These are the credentials that you will enter when configuring the Cortex XSOAR-Forescout integration:<span> </span><em>Web API Username</em><span> </span>and<span> </span><em>Password</em>.</li>
<li>Select<span> </span><em>Client IPs</em><span> </span>towards the top of the main area of the dialog, next to<span> </span><em>User Settings</em>.</li>
<li>Add the IP address where your Cortex XSOAR instance is hosted or allow requests from all IP addresses to make sure that requests made by the Cortex XSOAR-Forescout integration will be permitted.</li>
<li>Click the<span> </span><em>Apply</em><span> </span>button to save the changes you made.</li>
</ol>
<p><strong>Data Exchange (DEX) Username</strong><span> </span>and<span> </span><strong>Password</strong><br> The credentials entered here should be those created in the Forescout console for<span> </span><em>Data Exchange (DEX)</em>.</p>
<ol>
<li>In the Forescout console, from the top navigation bar, click<span> </span><em>Tools &gt; Options</em>.</li>
<li>From the dialog that appears, in the categories section on the left, click<span> </span><em>Data Exchange (DEX)</em>.</li>
<li>Select<span> </span><em>CounterACT Web Service &gt; Accounts</em>.</li>
<li>Create a username and password by clicking the<span> </span><em>Add</em><span> </span>button, and completing the fields.<span> </span><strong>Note</strong>: The value you entered for the<span> </span><em>Name</em><span> </span>field in the account-creation pop-up window is the value that you should enter for the<span> </span><em>Data Exchange (DEX) Account</em><span> </span>configuration parameter.</li>
<li>Click the<span> </span><em>Apply</em><span> </span>button to save the changes you made.</li>
</ol>
<p>The username and password entered in the account-creation dialog are the credentials that you will enter when configuring the Cortex XSOAR-Forescout integration:<span> </span><em>Data Exchange (DEX) Username</em><span> </span>and<span> </span><em>Password</em>.</p>
<p><strong>Data Exchange (DEX) Account</strong><br> The<span> </span><strong>Data Exchange (DEX)</strong><span> </span>credentials<span> </span><strong><em>Name</em></strong><span> </span>field. This can be found by navigating to<span> </span><strong>Tools &gt; Options &gt; Data Exchange (DEX) &gt; CounterACT Web Service &gt; Accounts</strong>.</p>
<h3>
<a id="user-content-important-usage-notes" class="anchor" href="https://github.com/demisto/content/blob/284b80afd53fdc12ff18a6953a888f5a0abed67d/Integrations/Forescout/Forescout_description.md#important-usage-notes" aria-hidden="true"></a>Important Usage Notes</h3>
<p>This integration allows the user to update host properties and Forescout Lists. To create Forescout properties, which can then be updated using the Cortex XSOAR-Forescout integration, from the Forescout console, navigate to<span> </span><strong>Tools &gt; Options &gt; Data Exchange (DEX) &gt; CounterACT Web Console &gt; Properties</strong>. This is where you create new properties. Make sure to associate the properties with the account you created, and which you used in the configuration parameters of the Forescout integration in Cortex XSOAR. Lists must also be defined and created in the Forescout console before you can update them using the Cortex XSOAR-Forescout integration. For more information, reference the<span> </span><em>Defining and Managing Lists</em><span> </span>section in the<span> </span><a href="https://www.forescout.com/wp-content/uploads/2018/04/CounterACT_Administration_Guide_8.0.pdf" rel="nofollow">Forescout Administration Guide</a>.</p>
</div>
<div class="cl-preview-section">
<h2 id="configure-forescout-on-demisto">Configure Forescout on Cortex XSOAR</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for Forescout.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>The network address of the Forescout Enterprise Manager or<br>standalone Appliance, e.g. ‘<a href="https://10.0.0.8/">https://10.0.0.8</a>’. #disable-secrets-detection</strong></li>
<li><strong>Web API Username (see Detailed Instructions (?))</strong></li>
<li><strong>Data Exchange (DEX) Username (see Detailed Instructions (?))</strong></li>
<li><strong>Data Exchange (DEX) Account (see Detailed Instructions (?))</strong></li>
<li><strong>HTTP Timeout (default is 60 seconds)</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
</div>
<div class="cl-preview-section"></div>
<div class="cl-preview-section"></div>
<div class="cl-preview-section">
<h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section">
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li><a href="#get-a-list-of-active-endpoints" target="_self">Get a list of active endpoints: forescout-get-hosts</a></li>
<li><a href="#get-an-index-of-host-fields" target="_self">Get an index of host fields: forescout-get-host-fields</a></li>
<li><a href="#get-details-for-a-host" target="_self">Get details for a host: forescout-get-host</a></li>
<li><a href="#get-a-list-of-policies" target="_self">Get a list of policies: forescout-get-policies</a></li>
<li><a href="#update-host-fields" target="_self">Update host fields: forescout-update-host-fields</a></li>
<li><a href="#update-lists" target="_self">Update lists: forescout-update-lists</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="get-a-list-of-active-endpoints">1. Get a list of active endpoints</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves a list of active endpoints.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>forescout-get-hosts</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 153.333px;"><strong>Argument Name</strong></th>
<th style="width: 515.667px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 153.333px;">rule_ids</td>
<td style="width: 515.667px;">Filter hosts by those selected by policies or policy sub-rules. Policies and/or rules should be specified by their IDs. To find policy and rule IDs by which you can filter, run the <a href="#get-a-list-of-policies" target="_self">forescout-get-policies</a> command. If multiple policy and/or rule IDs are entered, only hosts that are selected by all of the policies and/or rules specified will be returned. Multiple policy or rule IDs should be separated by a comma.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 153.333px;">fields</td>
<td style="width: 515.667px;">Filter hosts based on host field values. Enter fields with their associated values in the following format, ‘{field_1}={val_1}&amp;{field_2}={val_2} … &amp;{field_n}={val_n}’ where ‘{field_1}’ through ‘{field_n}’ are replaced by actual field names and ‘{val_1}’ through ‘{val_n}’ are replaced by the desired matching values. Note that a list field may be specified with the values separated by commas. Only hosts whose properties match all the specified values will be returned. For a list of potential host fields that may be specified, try executing the ‘forescout-get-hostfields’ command. A composite property may also be specified. If entered in the format where all the field-value pairs are in a single set of square brackets, for example, ‘{composite_prop}=[{field_1},{val_1},…,{field_n},{val_n}]’ then only hosts for which the specified composite property’s fields all match the values entered will be returned. If entered in the format, ‘{composite_prop}=[{field_1},{val}_1],…,[{field_n},{val_n}]’ where each field-value pair is enclosed in its own set of brackets, then hosts for which the composite property contains any of the field-values specified will be returned. Note that for composite properties, sub-fields should be entered as their internal representation in Forescout. To find internal representation for a composite property’s sub-fields try executing ‘forescout-get-host’ command with the host specified in the ‘identifier’ argument and the name of the composite property entered in the ‘fields’ argument of the command.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 327px;"><strong>Path</strong></th>
<th style="width: 104px;"><strong>Type</strong></th>
<th style="width: 310px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 327px;">Forescout.Host.ID</td>
<td style="width: 104px;">Number</td>
<td style="width: 310px;">Forescout ID for the host.</td>
</tr>
<tr>
<td style="width: 327px;">Forescout.Host.IPAddress</td>
<td style="width: 104px;">String</td>
<td style="width: 310px;">IP Address of the host.</td>
</tr>
<tr>
<td style="width: 327px;">Forescout.Host.MACAddress</td>
<td style="width: 104px;">String</td>
<td style="width: 310px;">MAC Address of the host.</td>
</tr>
<tr>
<td style="width: 327px;">Endpoint.IPAddress</td>
<td style="width: 104px;">String</td>
<td style="width: 310px;">IP Address of the host.</td>
</tr>
<tr>
<td style="width: 327px;">Endpoint.MACAddress</td>
<td style="width: 104px;">String</td>
<td style="width: 310px;">MAC Address of the host.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>forescout-get-hosts fields=online=true</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Forescout.Host": [
        {
            "MACAddress": "000c29e9e452",
            "IPAddress": "192.168.1.44",
            "ID": "3232235820"
        },
        {
            "MACAddress": "000c297cc5ae",
            "IPAddress": "192.168.1.125",
            "ID": "3232235901"
        },
        {
            "MACAddress": "005056a1ad60",
            "IPAddress": "192.168.1.52",
            "ID": "3232235828"
        },
        {
            "MACAddress": "000c29497e4e",
            "IPAddress": "192.168.1.119",
            "ID": "3232235895"
        },
        {
            "MACAddress": "000000000000",
            "IPAddress": "192.168.1.8",
            "ID": "3232235784"
        },
        {
            "MACAddress": null,
            "IPAddress": "192.168.1.1",
            "ID": "3232235777"
        },
        {
            "MACAddress": "005056b1488d",
            "IPAddress": "192.168.1.31",
            "ID": "3232235807"
        },
        {
            "MACAddress": "005056b1a93f",
            "IPAddress": "192.168.1.17",
            "ID": "3232235793"
        },
        {
            "MACAddress": null,
            "IPAddress": "192.168.1.212",
            "ID": "3232235988"
        }
    ],
    "Endpoint": [
        {
            "MACAddress": "000c29e9e452",
            "IPAddress": "192.168.1.44"
        },
        {
            "MACAddress": "000c297cc5ae",
            "IPAddress": "192.168.1.125"
        },
        {
            "MACAddress": "005056a1ad60",
            "IPAddress": "192.168.1.52"
        },
        {
            "MACAddress": "000c29497e4e",
            "IPAddress": "192.168.1.119"
        },
        {
            "MACAddress": "000000000000",
            "IPAddress": "192.168.1.8"
        },
        {
            "MACAddress": null,
            "IPAddress": "192.168.1.1"
        },
        {
            "MACAddress": "005056b1488d",
            "IPAddress": "192.168.1.31"
        },
        {
            "MACAddress": "005056b1a93f",
            "IPAddress": "192.168.1.17"
        },
        {
            "MACAddress": null,
            "IPAddress": "192.168.1.212"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="active-endpoints">Active Endpoints</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>ID</th>
<th>IPAddress</th>
<th>MACAddress</th>
</tr>
</thead>
<tbody>
<tr>
<td>3232235820</td>
<td>192.168.1.44</td>
<td>000c29e9e452</td>
</tr>
<tr>
<td>3232235901</td>
<td>192.168.1.125</td>
<td>000c297cc5ae</td>
</tr>
<tr>
<td>3232235828</td>
<td>192.168.1.52</td>
<td>005056a1ad60</td>
</tr>
<tr>
<td>3232235895</td>
<td>192.168.1.119</td>
<td>000c29497e4e</td>
</tr>
<tr>
<td>3232235784</td>
<td>192.168.1.8</td>
<td>000000000000</td>
</tr>
<tr>
<td>3232235777</td>
<td>192.168.1.1</td>
<td> </td>
</tr>
<tr>
<td>3232235807</td>
<td>192.168.1.31</td>
<td>005056b1488d</td>
</tr>
<tr>
<td>3232235793</td>
<td>192.168.1.17</td>
<td>005056b1a93f</td>
</tr>
<tr>
<td>3232235988</td>
<td>192.168.1.212</td>
<td> </td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-an-index-of-host-fields">2. Get an index of host fields</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves an index of Forescout host fields that match the specified criteria.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>forescout-get-host-fields</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 162.333px;"><strong>Argument Name</strong></th>
<th style="width: 506.667px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 162.333px;">search_in</td>
<td style="width: 506.667px;">Each host field has three searchable parts, the ‘name’, ‘label’, and ‘description’. By default only the ‘name’ will be searched. If you want to expand the search to include the description, you would enter ‘name,description’ for this argument.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 162.333px;">case_sensitive</td>
<td style="width: 506.667px;">Determines whether to match the case of the entered search term.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 162.333px;">match_exactly</td>
<td style="width: 506.667px;">Determines whether the search term is matched against the entirety of the potential host field instead of just seeing whether the host field contains the search term.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 162.333px;">search_term</td>
<td style="width: 506.667px;">The term to filter host fields by. By default, the search will be case insensitive and checked to see if a host field contains the search term unless otherwise specified in the ‘case_sensitive’ and ‘match_exactly’ arguments respectively.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 162.333px;">host_field_type</td>
<td style="width: 506.667px;">Limit the search to host fields whose values are of a certain type. For example, to limit the search to host properties whose values are either boolean, ip or a date enter ‘boolean,ip,date’.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-1">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 264px;"><strong>Path</strong></th>
<th style="width: 107px;"><strong>Type</strong></th>
<th style="width: 370px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 264px;">Forescout.HostField</td>
<td style="width: 107px;">Unknown</td>
<td style="width: 370px;">List index of host properties.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-1">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>forescout-get-host-fields search_term=hostname case_sensitive=false host_field_type=tree_path,string match_exactly=False search_in=name,label,description</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-1">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Forescout.HostField": [
        {
            "Name": "nbthost",
            "Type": "string",
            "Description": "Indicates the NetBIOS hostname of the host.",
            "Label": "NetBIOS Hostname"
        },
        {
            "Name": "hostname",
            "Type": "string",
            "Description": "Indicates the DNS name of the host.",
            "Label": "DNS Name"
        },
        {
            "Name": "aws_instance_public_dns",
            "Type": "string",
            "Description": "The public hostname of the EC2 instance, which resolves to the public IP address or Elastic IP address of the instance.",
            "Label": "EC2 Public DNS"
        },
        {
            "Name": "dhcp_hostname",
            "Type": "string",
            "Description": "The device Host Name as advertised by DHCP",
            "Label": "DHCP Hostname"
        },
        {
            "Name": "linux_hostname",
            "Type": "string",
            "Description": "Indicates a hostname. Use of this property requires that the host is managed by CounterACT via SecureConnector or remotely.",
            "Label": "Linux Hostname"
        },
        {
            "Name": "mac_hostname",
            "Type": "string",
            "Description": "Indicates a hostname. Use of this property requires that the host is managed by CounterACT via SecureConnector or remotely.",
            "Label": "Macintosh Hostname"
        },
        {
            "Name": "sw_hostname",
            "Type": "string",
            "Description": "The switch name as defined in the switch",
            "Label": "Switch Hostname"
        },
        {
            "Name": "wifi_end_point_host_name",
            "Type": "string",
            "Description": "",
            "Label": "WiFi End Point Hostname"
        },
        {
            "Name": "vmware_guest_host",
            "Type": "string",
            "Description": "Indicates the hostname of the guest operating system. VMware Tools must be running on the endpoint to resolve this property.",
            "Label": "Virtual Machine Guest Hostname"
        },
        {
            "Name": "vmware_esxi_hostname",
            "Type": "string",
            "Description": "Indicates the hostname of the ESXi server.",
            "Label": "VMware ESXi Server Name"
        },
        {
            "Name": "wifi_client_hostname",
            "Type": "string",
            "Description": "Indicates the user name of the client.",
            "Label": "WLAN Client Username"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="index-of-host-fields">Index of Host Fields</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Label</th>
<th>Name</th>
<th>Description</th>
<th>Type</th>
</tr>
</thead>
<tbody>
<tr>
<td>NetBIOS Hostname</td>
<td>nbthost</td>
<td>Indicates the NetBIOS hostname of the host.</td>
<td>string</td>
</tr>
<tr>
<td>DNS Name</td>
<td>hostname</td>
<td>Indicates the DNS name of the host.</td>
<td>string</td>
</tr>
<tr>
<td>EC2 Public DNS</td>
<td>aws_instance_public_dns</td>
<td>The public hostname of the EC2 instance, which resolves to the public IP address or Elastic IP address of the instance.</td>
<td>string</td>
</tr>
<tr>
<td>DHCP Hostname</td>
<td>dhcp_hostname</td>
<td>The device Host Name as advertised by DHCP</td>
<td>string</td>
</tr>
<tr>
<td>Linux Hostname</td>
<td>linux_hostname</td>
<td>Indicates a hostname. Use of this property requires that the host is managed by CounterACT via SecureConnector or remotely.</td>
<td>string</td>
</tr>
<tr>
<td>Macintosh Hostname</td>
<td>mac_hostname</td>
<td>Indicates a hostname. Use of this property requires that the host is managed by CounterACT via SecureConnector or remotely.</td>
<td>string</td>
</tr>
<tr>
<td>Switch Hostname</td>
<td>sw_hostname</td>
<td>The switch name as defined in the switch</td>
<td>string</td>
</tr>
<tr>
<td>WiFi End Point Hostname</td>
<td>wifi_end_point_host_name</td>
<td> </td>
<td>string</td>
</tr>
<tr>
<td>Virtual Machine Guest Hostname</td>
<td>vmware_guest_host</td>
<td>Indicates the hostname of the guest operating system. VMware Tools must be running on the endpoint to resolve this property.</td>
<td>string</td>
</tr>
<tr>
<td>VMware ESXi Server Name</td>
<td>vmware_esxi_hostname</td>
<td>Indicates the hostname of the ESXi server.</td>
<td>string</td>
</tr>
<tr>
<td>WLAN Client Username</td>
<td>wifi_client_hostname</td>
<td>Indicates the user name of the client.</td>
<td>string</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-details-for-a-host">3. Get details for a host</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves details of specified host.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>forescout-get-host</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 158.667px;"><strong>Argument Name</strong></th>
<th style="width: 509.333px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 158.667px;">fields</td>
<td style="width: 509.333px;">List of host properties to include in the output for the targeted endpoint. If a specified host property is not found, the property is omitted from the outputs. For a list of potential host properties that may be specified, try executing the ‘forescout-get-host-fields’ command. Requested fields should be comma separated.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 158.667px;">ip</td>
<td style="width: 509.333px;">IP (ipv4) of the desired endpoint. Endpoint identifiers - IPs, MAC addresses and object IDs - can be found in the returned outputs when<span> </span><code>forescout-get-hosts</code><span> </span>is executed.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 158.667px;">mac</td>
<td style="width: 509.333px;">MAC address of the desired endpoint. Endpoint identifiers - IPs, MAC addresses and object IDs - can be found in the returned outputs when<span> </span><code>forescout-get-hosts</code><span> </span>is executed.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 158.667px;">id</td>
<td style="width: 509.333px;">Forescout ID of the desired endpoint. Endpoint identifiers - IPs, MAC addresses and object IDs - can be found in the returned outputs when<span> </span><code>forescout-get-hosts</code><span> </span>is executed.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-2">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 287px;"><strong>Path</strong></th>
<th style="width: 61px;"><strong>Type</strong></th>
<th style="width: 392px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 287px;">Forescout.Host.MatchedFingerprint</td>
<td style="width: 61px;">Unknown</td>
<td style="width: 392px;">An endpoint may match multiple profiles. This property indicates all the classification profiles that this endpoint matches.</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.EngineSeenPacket</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Indicates the host was seen by CounterACT.</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.Online</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Host is online.</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.PrimClassification</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Indicates the most specific endpoint function detected. If CounterACT detects multiple endpoint functions, the property is resolved as the most specific value that is common to all the detected functions. If there is no common value, the property is resolved as ‘Multiple Suggestions’.</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.MacVendorString</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Indicates a value associated with the NIC Vendor</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.SambaOpenPort</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">NetBIOS ports are open</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.UserDefFp</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Indicates the operating system of the endpoint, as determined by classification tools.</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.Vendor</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Network Device Vendor, Type and Model</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.AgentVersion</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Indicates the SecureConnector version installed on a Windows host.</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.Fingerprint</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Passive OS detection based on Syn packets</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.AccessIP</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Indicates the last IP that was investigated for this host</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.VendorClassification</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Indicates the most specific vendor and model detected.</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.ManageAgent</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Indicates if the host is running SecureConnector.</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.Onsite</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Indicates that a host is connected to the organizational network</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.MacPrefix32</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">MAC prefix</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.VaNetfunc</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Reported CDP VoIP device description for VA netfunc</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.NmapDefFp7</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Nmap-OS Fingerprint(Ver. 7.01)</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.NmapDefFp5</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Nmap-OS Fingerprint(Ver. 5.3)</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.AgentInstallMode</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Indicates the SecureConnector deployment mode installed on the host.</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.NmapFp7</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Nmap-OS Class(Ver. 7.01) (Obsolete)</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.ClType</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Indicates how CounterACT determines the Network Function property of the endpoint.</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.ClRule</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Indicates the rule responsible for classifying the host</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.AgentVisibleMode</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Indicates the SecureConnector visible mode installed on the host.</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.OSClassification</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Operating System</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.ClassificationSourceOS</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Indicates how the Operating System classification property was determined for this endpoint.</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.LastNbtReportTime</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Last time when NBT name was reported</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.Misc</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Miscellaneous</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.ClassificationSourceFunc</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Indicates how the Function classification property was determined for this endpoint.</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.NmapNetfunc7</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Nmap-Network Function(Ver. 7.01)</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.MAC</td>
<td style="width: 61px;">Unknown</td>
<td style="width: 392px;">ARP Spoofing (Obsolete)</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.OpenPort</td>
<td style="width: 61px;">Unknown</td>
<td style="width: 392px;">Open Ports</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.GstSignedInStat</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Logged In Status</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.DhcpClass</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">The device class according to the DHCP fingerprint</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.ADM</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Admission Events.</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.DhcpReqFingerprint</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">The host DHCP request fingerprint</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.DhcpOptFingerprint</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">The host DHCP options fingerprint</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.Ipv4ReportTime</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Indicates the last time that IPv4 reported to the infrastructure</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.DhcpOS</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">The device OS according to the DHCP fingerprint</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.DhcpHostname</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">The device Host Name as advertised by DHCP</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.IPAddress</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Host IP address</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.MACAddress</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Host MAC address</td>
</tr>
<tr>
<td style="width: 287px;">Forescout.Host.ID</td>
<td style="width: 61px;">Number</td>
<td style="width: 392px;">Forescout ID number for the host</td>
</tr>
<tr>
<td style="width: 287px;">Endpoint.IPAddress</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">IP Address of the host.</td>
</tr>
<tr>
<td style="width: 287px;">Endpoint.MACAddress</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">MAC Address of the host.</td>
</tr>
<tr>
<td style="width: 287px;">Endpoint.DHCPServer</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Endpoint DHCP Server.</td>
</tr>
<tr>
<td style="width: 287px;">Endpoint.Hostname</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Hostname of the endpoint.</td>
</tr>
<tr>
<td style="width: 287px;">Endpoint.OS</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Endpoint Operating System.</td>
</tr>
<tr>
<td style="width: 287px;">Endpoint.Model</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Vendor and Model of the endpoint.</td>
</tr>
<tr>
<td style="width: 287px;">Endpoint.Domain</td>
<td style="width: 61px;">String</td>
<td style="width: 392px;">Domain of the endpoint.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-2">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>forescout-get-host ip=192.168.1.212 fields=fsapi_DemistoTest,fsapi_demisto_composite,fsapi_demisto_list,fsapi_composite_1</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-2">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Forescout.Host": {
        "MACAddress": null,
        "IPAddress": "192.168.1.212",
        "ID": "3232235988"
    },
    "Endpoint": {
        "MACAddress": null,
        "IPAddress": "192.168.1.212"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="endpoint-details-for-ip192.168.1.212">Endpoint Details for IP=192.168.1.212</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>ID</th>
<th>IPAddress</th>
</tr>
</thead>
<tbody>
<tr>
<td>3232235988</td>
<td>192.168.1.212</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-a-list-of-policies">4. Get a list of policies</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves a list of all policies defined in the Forescout platform and<br> their sub-rules.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>forescout-get-policies</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
<p>There are no input arguments for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="context-output-3">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 281.333px;"><strong>Path</strong></th>
<th style="width: 89.6667px;"><strong>Type</strong></th>
<th style="width: 369px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 281.333px;">Forescout.Policy.ID</td>
<td style="width: 89.6667px;">String</td>
<td style="width: 369px;">Forescout ID for the policy.</td>
</tr>
<tr>
<td style="width: 281.333px;">Forescout.Policy.Name</td>
<td style="width: 89.6667px;">String</td>
<td style="width: 369px;">Forescout name of the policy.</td>
</tr>
<tr>
<td style="width: 281.333px;">Forescout.Policy.Description</td>
<td style="width: 89.6667px;">String</td>
<td style="width: 369px;">Description of the policy.</td>
</tr>
<tr>
<td style="width: 281.333px;">Forescout.Policy.Rule</td>
<td style="width: 89.6667px;">Unknown</td>
<td style="width: 369px;">List of rules that make up the policy.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-3">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>forescout-get-policies</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-3">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Forescout.Policy": [
        {
            "Name": "Primary Classification",
            "Description": "",
            "Rule": [
                {
                    "Name": "CounterACT Devices",
                    "Description": "",
                    "ID": "-1203369125012565008"
                },
                {
                    "Name": "NAT Devices",
                    "Description": "When a device is NAT, its other classifications may be inaccurate. Therefore, we put the NAT detection first.",
                    "ID": "-5021668745466479821"
                },
                {
                    "Name": "Printers",
                    "Description": "",
                    "ID": "-275357014618763061"
                },
                {
                    "Name": "VoIP Devices",
                    "Description": "",
                    "ID": "4202614624411873493"
                },
                {
                    "Name": "Networking Equipment",
                    "Description": "",
                    "ID": "195929949297431248"
                },
                {
                    "Name": "Storage",
                    "Description": "",
                    "ID": "-6750955562195414496"
                },
                {
                    "Name": "Windows",
                    "Description": "",
                    "ID": "-6030907744367556977"
                },
                {
                    "Name": "Macintosh",
                    "Description": "",
                    "ID": "2278199708439440583"
                },
                {
                    "Name": "Linux\\Unix",
                    "Description": "",
                    "ID": "-7562731206926229799"
                },
                {
                    "Name": "Mobile Devices",
                    "Description": "",
                    "ID": "4030118542035508409"
                },
                {
                    "Name": "Approved Misc Devices",
                    "Description": "",
                    "ID": "168049340370707647"
                },
                {
                    "Name": "Multiple Profile Matches",
                    "Description": "Endpoints matching this sub-rule could not have either their Function or Operating System determined due to conflicting profile matches.\n\nInvestigate the devices in this sub-rule and either manually classify them or build additional sub-rules to classify them based on patterns you observe. View the values Suggested Function and Suggested Operating System properties to discover the conflicting profile matches.",
                    "ID": "8701509617393717735"
                },
                {
                    "Name": "Other Known Function",
                    "Description": "",
                    "ID": "-642863379250182254"
                },
                {
                    "Name": "Other Known Operating System",
                    "Description": "",
                    "ID": "-4200038946418694277"
                },
                {
                    "Name": "Other Known Vendor",
                    "Description": "",
                    "ID": "150826048313755731"
                },
                {
                    "Name": "Unclassified",
                    "Description": "",
                    "ID": "-8959326502596556700"
                }
            ],
            "ID": "2101168655015691125"
        },
        {
            "Name": "Corporate/Guest Control",
            "Description": "",
            "Rule": [
                {
                    "Name": "Corporate Hosts",
                    "Description": "",
                    "ID": "2240420499151482925"
                },
                {
                    "Name": "Signed-in Guests",
                    "Description": "",
                    "ID": "1248354759835029874"
                },
                {
                    "Name": "Guest Hosts",
                    "Description": "",
                    "ID": "9151906460028315616"
                }
            ],
            "ID": "-7733328397206852516"
        },
        {
            "Name": "Antivirus Compliance",
            "Description": "",
            "Rule": [
                {
                    "Name": "Not Manageable",
                    "Description": "Optional step: Make Windows machines managable by installing the Secure Connector",
                    "ID": "7661917523791823306"
                },
                {
                    "Name": "AV Not Installed",
                    "Description": "Antivirus is not installed.",
                    "ID": "-2012169476997908764"
                },
                {
                    "Name": "AV Not Running",
                    "Description": "Antivirus is not running.",
                    "ID": "8013197435392890209"
                },
                {
                    "Name": "AV Not Updated",
                    "Description": "Antivirus is not updated.",
                    "ID": "6048295467368903309"
                },
                {
                    "Name": "Compliant",
                    "Description": "",
                    "ID": "-7389372863827790785"
                }
            ],
            "ID": "-4928940807449738209"
        },
        {
            "Name": "sadfsafg",
            "Description": "asdf",
            "Rule": [],
            "ID": "267720461254861999"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-3">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="forescout-policies">Forescout Policies</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>ID</th>
<th>Name</th>
<th>Description</th>
<th>Rule</th>
</tr>
</thead>
<tbody>
<tr>
<td>2101168655015691125</td>
<td>Primary Classification</td>
<td> </td>
<td>ID: -1203369125012565008, Name: CounterACT Devices, Description: ,<br> ID: -5021668745466479821, Name: NAT Devices, Description: When a device is NAT, its other classifications may be inaccurate. Therefore, we put the NAT detection first.,<br> ID: -275357014618763061, Name: Printers, Description: ,<br> ID: 4202614624411873493, Name: VoIP Devices, Description: ,<br> ID: 195929949297431248, Name: Networking Equipment, Description: ,<br> ID: -6750955562195414496, Name: Storage, Description: ,<br> ID: -6030907744367556977, Name: Windows, Description: ,<br> ID: 2278199708439440583, Name: Macintosh, Description: ,<br> ID: -7562731206926229799, Name: Linux\Unix, Description: ,<br> ID: 4030118542035508409, Name: Mobile Devices, Description: ,<br> ID: 168049340370707647, Name: Approved Misc Devices, Description: ,<br> ID: 8701509617393717735, Name: Multiple Profile Matches, Description: Endpoints matching this sub-rule could not have either their Function or Operating System determined due to conflicting profile matches.\n\nInvestigate the devices in this sub-rule and either manually classify them or build additional sub-rules to classify them based on patterns you observe. View the values Suggested Function and Suggested Operating System properties to discover the conflicting profile matches.,<br> ID: -642863379250182254, Name: Other Known Function, Description: ,<br> ID: -4200038946418694277, Name: Other Known Operating System, Description: ,<br> ID: 150826048313755731, Name: Other Known Vendor, Description: ,<br> ID: -8959326502596556700, Name: Unclassified, Description:</td>
</tr>
<tr>
<td>-7733328397206852516</td>
<td>Corporate/Guest Control</td>
<td> </td>
<td>ID: 2240420499151482925, Name: Corporate Hosts, Description: ,<br> ID: 1248354759835029874, Name: Signed-in Guests, Description: ,<br> ID: 9151906460028315616, Name: Guest Hosts, Description:</td>
</tr>
<tr>
<td>-4928940807449738209</td>
<td>Antivirus Compliance</td>
<td> </td>
<td>ID: 7661917523791823306, Name: Not Manageable, Description: Optional step: Make Windows machines managable by installing the Secure Connector,<br> ID: -2012169476997908764, Name: AV Not Installed, Description: Antivirus is not installed.,<br> ID: 8013197435392890209, Name: AV Not Running, Description: Antivirus is not running.,<br> ID: 6048295467368903309, Name: AV Not Updated, Description: Antivirus is not updated.,<br> ID: -7389372863827790785, Name: Compliant, Description:</td>
</tr>
<tr>
<td>267720461254861999</td>
<td>sadfsafg</td>
<td>asdf</td>
<td> </td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="update-host-fields">5. Update host fields</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Update a host’s field. Note that if a List field or Composite field has not been defined in Forescout to ‘Aggregate new values from each update’ that performing an update operation on a field will overwrite previous data written to that field.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-4">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>forescout-update-host-fields</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-4">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 154.667px;"><strong>Argument Name</strong></th>
<th style="width: 513.333px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 154.667px;">update_type</td>
<td style="width: 513.333px;">The type of update to perform on a host field.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154.667px;">host_ip</td>
<td style="width: 513.333px;">The IP address of the target host. Required if ‘updated_type’ is ‘update’ or ‘delete’.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 154.667px;">field</td>
<td style="width: 513.333px;">Enter the the name of the field to update. Composite fields should be updated using the ‘fields_json’ command argument.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154.667px;">value</td>
<td style="width: 513.333px;">Value to be assigned to the field specified in the ‘field’ argument. If the value is a list of items, then items should be separated using a comma.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 154.667px;">fields_json</td>
<td style="width: 513.333px;">One may perform multiple field-value assignments using this command argument. The argument should be entered in valid JSON format. This argument is useful for setting composite fields although other fields may be entered as well. For example, ‘{“Example_Composite”: [{“Shape”: “Triangle”, “Color”: “Beige”}, {“Shape”: “Square”, “Color”: “Violet”}], “String_Field”: “Example”}’ where ‘Example_Composite’ is the name of the Composite field in Forescout and ‘Shape’ and ‘Color’ are sub fields. In the example, ‘String_Field’ is a regular host field of type string whose value will be assigned ‘Example’. If the composite field was defined in Forescout as an aggregate property then additional records will be appended, otherwise they will be overwritten.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-4">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-4">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>forescout-update-host-fields host_ip=192.168.1.212 field=fsapi_DemistoTest value="Testing new Arguments" fields_json={“fsapi_demisto_composite”:
    {“age”: “900”, “name”: “Ignatio Permutti”, “alive”: “false”}, “fsapi_demisto_list”:
    [“Hey1”, “Hey2”, “Hey3”], “fsapi_composite_1”: [{“animal”: “mongoose”, “sound”:
    “squeak”, “lifespan”: “10”, “region”: “North America”}, {“animal”: “squirrel”,
    “sound”: “pip”, “lifespan”: “5”, “region”: “Everywher”}]}<em>update_type=update</em>
  </pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-4">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Successfully updated 4 properties for host ip=192.168.1.212</p>
</div>
<div class="cl-preview-section">
<h3 id="update-lists">6. Update lists</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Updates Forescout lists.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-5">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>forescout-update-lists</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-5">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 138.333px;"><strong>Argument Name</strong></th>
<th style="width: 530.667px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 138.333px;">update_type</td>
<td style="width: 530.667px;">The type of update to perform on a Forescout list.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138.333px;">list_names</td>
<td style="width: 530.667px;">Names of lists defined in the Forescout platform that you wish to update. If the ‘update_type’ is set to ‘delete_all_list_values’ then it is unnecessary to fill in the ‘values’ command argument. Multiple list names should be separated by a comma. To find names of lists that may be updated, navigate to<span> </span><em>Tools</em><span> </span>&gt;<span> </span><em>Options</em><span> </span>&gt;<span> </span><em>Lists</em><span> </span>in the Forescout platform.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 138.333px;">values</td>
<td style="width: 530.667px;">The values to add or delete from the lists entered in the ‘list_names’ command argument. Multiple values should separated by a comma. Note that the values entered here will be updated for all of the lists entered in the ‘list_names’ command argument.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-5">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-5">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>forescout-update-lists list_names=disallowed_names,creatures update_type=add_list_values values="ignatius,devon"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-5">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Successfully added values to the 2 lists.</p>
</div>