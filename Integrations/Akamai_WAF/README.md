<p>
    manage a common set of lists for use in various Akamai security products such as Kona Site Defender, Web App
    Protector, and Bot Manager.
    This integration was integrated and tested with <a
        href="https://developer.akamai.com/api/cloud_security/network_lists/v2.html"> Network Lists API v2.0 </a>
</p>

<h2>Use Cases</h2>
<ul>
    <li>Get network list details - activations status, elements etc</li>
    <li>Network create or remove.</li>
    <li>Network list editing - add/remove elements.</li>
    <li>Network list activation.</li>
</ul>
<h2>Detailed Description</h2>
<p>
    The Akamai WAF integration allows you to manage a common set of lists for use in various Akamai security products
    such as
    Kona Site Defender, Web App Protector, and Bot Manager. Network lists are shared sets of IP addresses, CIDR blocks,
    or broad geographic areas. Along with managing your own lists, you can also access read-only lists that Akamai
    dynamically updates for you.
</p>

<h2>API keys generating steps</h2>
<ol>
    <li>Go to `WEB & DATA CENTER SECURITY`>`Security Configuration`>choose you configuration>`Advanced settings`> Enable
        SIEM integration.
    </li>
    <li><a href="https://control.akamai.com/">Open Control panel</a> and login with admin account.</li>
    <li>Open <code>identity and access management</code> menu.</li>
    <li>Create user with assign roles <code>Network List</code> or make sure the admin has rights for manage SIEM.</li>
    <li>Log in to new account you created in the last step.</li>
    <li>Open <code>identity and access management</code> menu.</li>
    <li>Create <code>new api client for me</code></li>
    <li>Assign API key to the relevant users group, and assign on next page <code>Read/Write</code> access for <code>SIEM</code>.
    </li>
    <li>Save configuration and go to API detail you created.</li>
    <li>Press <code>new credentials</code> and download or copy it.</li>
    <li>Now use the credentials for configure Akamai WAF in Demisto</li>
</ol>
<h2>Configure Akamai WAF on Demisto</h2>
<ol>
    <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
        &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.
    </li>
    <li>Search for Akamai WAF.</li>
    <li>
        Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
        <ul>
            <li><strong>Name</strong>: a textual name for the integration instance.</li>
            <li><strong>Server URL (e.g., https://example.net)</strong></li>
            <li><strong>Client token</strong></li>
            <li><strong>Access token</strong></li>
            <li><strong>Client secret</strong></li>
            <li><strong>Trust any certificate (not secure)</strong></li>
            <li><strong>Use system proxy settings</strong></li>
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
    <li>List all network lists available:
        <a href="#akamai-get-network-lists" target="_self"> akamai-get-network-lists</a></li>
    <li>Get network list by ID:
        <a href="#akamai-get-network-list-by-id" target="_self"> akamai-get-network-list-by-id</a>
    </li>
    <li>Create new network list (Support txt file upload for elements):
        <a href="#akamai-create-network-list" target="_self"> akamai-create-network-list</a></li>
    <li>Delete network list:<a href="#akamai-delete-network-list" target="_self"> akamai-delete-network-list</a></li>
    <li>Activate network list on Staging or Production: <a href="#akamai-activate-network-list" target="_self">
        akamai-activate-network-list</a></li>
    <li>Add elements to network list: <a href="#akamai-add-elements-to-network-list" target="_self">
        akamai-add-elements-to-network-list</a></li>
    <li>Remove element from network list:<a href="#akamai-remove-element-from-network-list" target="_self">
        akamai-remove-element-from-network-list</a></li>
    <li>Production or staging:<a href="#akamai-get-network-list-activation-status" target="_self">Get network list
        activation status in akamai-get-network-list-activation-status</a></li>
</ol>
<h3 id="akamai-get-network-lists">1. akamai-get-network-lists</h3>
<hr>
<p>List all network lists available for an authenticated user who belongs to a group.</p>
<h5>Base Command</h5>
<p>
    <code>akamai-get-network-lists</code>
</p>
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
        <td>list_type</td>
        <td>Filters the output to lists of only the given type of network lists if provided, either IP or GEO.</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>search</td>
        <td>Only list items that match the specified substring in any network list’s name or list of items.</td>
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
        <td>Akamai.NetworkLists.Name</td>
        <td>String</td>
        <td>Network list name</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.Type</td>
        <td>String</td>
        <td>Network list type GEO/IP</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.UniqueID</td>
        <td>String</td>
        <td>Network list unique ID</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.ElementCount</td>
        <td>String</td>
        <td>Network list elements count</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.CreateDate</td>
        <td>Date</td>
        <td>Network list creation date</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.CreatedBy</td>
        <td>String</td>
        <td>Network list creator</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.ExpeditedProductionActivationStatus</td>
        <td>String</td>
        <td>Expedited production activation status</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.ExpeditedStagingActivationStatus</td>
        <td>String</td>
        <td>Expedited staging activation status</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.ProductionActivationStatus</td>
        <td>String</td>
        <td>Production activation status</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.StagingActivationStatus</td>
        <td>String</td>
        <td>Staging activation status</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.UpdateDate</td>
        <td>String</td>
        <td>Network list update date</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.UpdatedBy</td>
        <td>String</td>
        <td>Last user updated the network list</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.Elements</td>
        <td>String</td>
        <td>Elemnts in the network list</td>
    </tr>
    </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
    <code>!akamai-get-network-lists</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Akamai":{
        "NetworkLists":[
            {
                "CreatedBy": "user",
                "ElementCount": 2,
                "Elements": [
                    "8.8.8.8",
                    "8.8.8.8"
                ],
                "ExpeditedProductionActivationStatus": "INACTIVE",
                "ExpeditedStagingActivationStatus": "INACTIVE",
                "Name": "Test",
                "ProductionActivationStatus": "PENDING_ACTIVATION",
                "StagingActivationStatus": "INACTIVE",
                "Type": "IP",
                "UniqueID": "uniq_id",
                "UpdateDate": "2020-01-13T18:57:05.99Z",
                "UpdatedBy": "user"
            },
            {
                "CreatedBy": "akamai",
                "ElementCount": 18,
                "Elements": [
                    "iq",
                    "mm",
                    "ir",
                    "ye",
                    "so",
                    "sd"
                ],
                "ExpeditedProductionActivationStatus": "INACTIVE",
                "ExpeditedStagingActivationStatus": "INACTIVE",
                "Name": "Test",
                "ProductionActivationStatus": "PENDING_ACTIVATION",
                "StagingActivationStatus": "INACTIVE",
                "Type": "IP",
                "UniqueID": "uniq_id",
                "UpdateDate": "2020-01-13T18:57:05.99Z",
                "UpdatedBy": "user"
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Akamai WAF - network lists</h3>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th><strong>Element count</strong></th>
        <th><strong>Name</strong></th>
        <th><strong>Production Activation Status</strong></th>
        <th><strong>Staging Activation Status</strong></th>
        <th><strong>Type</strong></th>
        <th><strong>Unique ID</strong></th>
        <th><strong>Updated by</strong></th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td> 2</td>
        <td> Test</td>
        <td> PENDING_ACTIVATION</td>
        <td> INACTIVE</td>
        <td> IP</td>
        <td> uniqe_id</td>
        <td> user</td>
    </tr>
    <tr>
        <td> 1</td>
        <td> test</td>
        <td> INACTIVE</td>
        <td> INACTIVE</td>
        <td> IP</td>
        <td> uniqe_id</td>
        <td> user</td>
    </tr>
    </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->

<h3 id="akamai-get-network-list-by-id">2. akamai-get-network-list-by-id</h3>
<hr>
<p>Get network list by ID</p>
<h5>Base Command</h5>
<p>
    <code>akamai-get-network-list-by-id</code>
</p>


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
        <td>network_list_id</td>
        <td>Network list ID</td>
        <td>Required</td>
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
        <td>Akamai.NetworkLists.Name</td>
        <td>String</td>
        <td>Network list name</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.Type</td>
        <td>String</td>
        <td>Network list type GEO/IP</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.UniqueID</td>
        <td>String</td>
        <td>Network list unique ID</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.ElementCount</td>
        <td>String</td>
        <td>Network list elements count</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.CreateDate</td>
        <td>Date</td>
        <td>Network list creation date</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.CreatedBy</td>
        <td>String</td>
        <td>Network list creator</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.ExpeditedProductionActivationStatus</td>
        <td>String</td>
        <td>Expedited production activation status</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.ExpeditedStagingActivationStatus</td>
        <td>String</td>
        <td>Expedited staging activation status</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.ProductionActivationStatus</td>
        <td>String</td>
        <td>Production activation status</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.StagingActivationStatus</td>
        <td>String</td>
        <td>Staging activation status</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.UpdateDate</td>
        <td>String</td>
        <td>Network list update date</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.UpdatedBy</td>
        <td>String</td>
        <td>Last user updated the network list</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.Elements</td>
        <td>String</td>
        <td>Elemnts in the network list</td>
    </tr>
    </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
    <code>!akamai-get-network-list-by-id network_list_id=69988_TEST</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Akamai": {
        "NetworkLists": [
            {
                "CreatedBy": "user",
                "ElementCount": 2,
                "Elements": [
                    "8.8.8.8",
                    "8.8.8.8"
                ],
                "ExpeditedProductionActivationStatus": "INACTIVE",
                "ExpeditedStagingActivationStatus": "INACTIVE",
                "Name": "Test",
                "ProductionActivationStatus": "PENDING_ACTIVATION",
                "StagingActivationStatus": "INACTIVE",
                "Type": "IP",
                "UniqueID": "unique_id",
                "UpdateDate": "2020-01-13T18:57:05.99Z",
                "UpdatedBy": "user"
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Akamai WAF - network list 69988_TEST</h3>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th><strong>Element count</strong></th>
        <th><strong>Name</strong></th>
        <th><strong>Production Activation Status</strong></th>
        <th><strong>Staging Activation Status</strong></th>
        <th><strong>Type</strong></th>
        <th><strong>Unique ID</strong></th>
        <th><strong>Updated by</strong></th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td> 2</td>
        <td> Test</td>
        <td> PENDING_ACTIVATION</td>
        <td> INACTIVE</td>
        <td> IP</td>
        <td> uique_id</td>
        <td> user</td>
    </tr>
    </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->

<h3 id="akamai-create-network-list">3. akamai-create-network-list</h3>
<hr>
<p>Create new network list (Support txt file upload for elements)</p>
<h5>Base Command</h5>
<p>
    <code>akamai-create-network-list</code>
</p>

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
        <td>list_name</td>
        <td>Network list name</td>
        <td>Required</td>
    </tr>
    <tr>
        <td>list_type</td>
        <td>Network list type</td>
        <td>Required</td>
    </tr>
    <tr>
        <td>elements</td>
        <td>Network list elements</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>entry_id</td>
        <td>War-room entry ID of sample file</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>description</td>
        <td>Network list description</td>
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
        <td>Akamai.NetworkLists.Name</td>
        <td>String</td>
        <td>Network list ID</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.UniqueID</td>
        <td>String</td>
        <td>Network list ID - Get it from akamai-get-network-lists</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.Type</td>
        <td>String</td>
        <td>Network list type</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.ElementCount</td>
        <td>Number</td>
        <td>Number of element in the list</td>
    </tr>
    <tr>
        <td>Akamai.NetworkLists.Elements</td>
        <td>String</td>
        <td>Elements in the lisy</td>
    </tr>
    </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
    <code>!akamai-create-network-list list_name=test list_type=IP description=test elements=8.8.8.8</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Akamai": {
        "NetworkLists": [
            {
                "Elements": [
                    "8.8.8.8"
                ],
                "Name": "test",
                "Type": "IP",
                "UniqueID": "70548_TEST"
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Akamai WAF - network list test created successfully</h3>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th><strong>Name</strong></th>
        <th><strong>Type</strong></th>
        <th><strong>Unique ID</strong></th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td> test</td>
        <td> IP</td>
        <td> 70548_TEST</td>
    </tr>
    </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="akamai-delete-network-list">4. akamai-delete-network-list</h3>
<hr>
<p>Delete network list</p>
<h5>Base Command</h5>
<p>
    <code>akamai-delete-network-list</code>
</p>

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
        <td>network_list_id</td>
        <td>Network list ID</td>
        <td>Required</td>
    </tr>
    </tbody>
</table>

<h5>Context Output</h5>
There are no context output for this command.

<h5>Command Example</h5>
<p>
    <code>!akamai-delete-network-list network_list_id=69856_NEW</code>
</p>
<h5>Context Example</h5>
<pre>
{}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
    Akamai WAF - network list <strong>69856_NEW</strong> deleted.
</p>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="akamai-activate-network-list">5. akamai-activate-network-list</h3>
<hr>
<p>Activate network list on Staging or Production</p>
<h5>Base Command</h5>
<p>
    <code>akamai-activate-network-list</code>
</p>


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
        <td>network_list_id</td>
        <td>Network list ID</td>
        <td>Required</td>
    </tr>
    <tr>
        <td>env</td>
        <td>Enviorment to activate the network list</td>
        <td>Required</td>
    </tr>
    <tr>
        <td>comment</td>
        <td>Comment to be logged</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>notify</td>
        <td>List of emails seprated with commas</td>
        <td>Optional</td>
    </tr>
    </tbody>
</table>

<h5>Context Output</h5>
There are no context output for this command.

<h5>Command Example</h5>
<p>
    <code>!akamai-activate-network-list network_list_id=69988_TEST env=PRODUCTION comment=test</code>
</p>
<h5>Context Example</h5>
<pre>
{}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
    <strong>Akamai WAF - network list 69988_TEST activated on PRODUCTION successfully</strong>
</p>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="akamai-add-elements-to-network-list">6. akamai-add-elements-to-network-list</h3>
<hr>
<p>Add elements to network list</p>
<h5>Base Command</h5>
<p>
    <code>akamai-add-elements-to-network-list</code>
</p>


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
        <td>network_list_id</td>
        <td>Network list ID</td>
        <td>Required</td>
    </tr>
    <tr>
        <td>entry_id</td>
        <td>War-room entry ID of sample file</td>
        <td>Optional</td>
    </tr>
    <tr>
        <td>elements</td>
        <td>Elements to be added, comma seprated</td>
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
    <code>!akamai-add-elements-to-network-list network_list_id=69988_TEST elements="8.8.8.8, 9.9.9.9"</code>
</p>
<h5>Context Example</h5>
<pre>
{}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Akamai WAF - elements added to network list 69988_TEST successfully</h3>
<table style="width:750px" border="2" cellpadding="6">
    <thead>
    <tr>
        <th><strong>elements</strong></th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td> 8.8.8.8,<br>9.9.9.9</td>
    </tr>
    </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="akamai-remove-element-from-network-list">7. akamai-remove-element-from-network-list</h3>
<hr>
<p>Remove element from network list</p>
<h5>Base Command</h5>
<p>
    <code>akamai-remove-element-from-network-list</code>
</p>


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
        <td>network_list_id</td>
        <td>Network list ID</td>
        <td>Required</td>
    </tr>
    <tr>
        <td>element</td>
        <td>Element to be removed</td>
        <td>Required</td>
    </tr>
    </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.

<h5>Command Example</h5>
<p>
    <code>!akamai-remove-element-from-network-list network_list_id=69988_TEST element=8.8.8.8</code>
</p>
<h5>Context Example</h5>
<pre>
{}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
    Akamai WAF - element <strong>8.8.8.8</strong> removed from network list <strong>69988_TEST</strong> successfully
</p>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="akamai-get-network-list-activation-status">8. akamai-get-network-list-activation-status</h3>
<hr>
<p>Get network list activation status in Production or staging</p>
<h5>Base Command</h5>
<p>
    <code>akamai-get-network-list-activation-status</code>
</p>


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
        <td>network_list_id</td>
        <td>Network list ID</td>
        <td>Required</td>
    </tr>
    <tr>
        <td>env</td>
        <td>Enviorment Produciton or Staginf</td>
        <td>Required</td>
    </tr>
    </tbody>
</table>


<h5>Context Output</h5>
There are no context output for this command.

<h5>Command Example</h5>
<p>
    <code>!akamai-get-network-list-activation-status network_list_id=69988_TEST env=PRODUCTION</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Akamai.NetworkLists.ActivationStatus": {
        "Status": "PENDING_ACTIVATION",
        "UniqueID": "69988_TEST"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
    Akamai WAF - network list <strong>69988_TEST</strong> is <strong>PENDING_ACTIVATION</strong> in <strong>PRODUCTION</strong>
</p>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
