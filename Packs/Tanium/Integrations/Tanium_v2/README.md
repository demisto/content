<p>
  Tanium endpoint security and systems management

  This integration was integrated and tested with version 7.3.0 of Tanium server
</p>
<h2>Tanium v2 Playbooks</h2>
<ul>
  <li>Tanium - Ask Question</li>
  <li>Tanium - Get Saved Question Result</li>
</ul>
<h2>Use Cases</h2>
<ul>
  <li>Create questions, groups, packages, etc on the Tanium Server.</li>
  <li>Deploy packages to machines groups.</li>
  <li>Get information about sensors, packages, actions, hosts etc.</li>
</ul>
<h2>Detailed Description</h2>
Integration with Tanium REST API. Available from Tanium version 7.3.0. You can manage questions, actions, saved
    questions, packages and sensor information.

  ## Configuration Parameters
  <ul>
  <li><i>Hostname</i>
   - The network address of the Tanium server host.
  <li><i>Domain </i>
   - The Tanium user domain. Relevant when there is more than one domain inside Tanium.</li>
  <li><i>Credentials </i>
   - The credentials should be the same as the Tanium client.</li>
</ul>

<h2>Configure Tanium v2 on Cortex XSOAR</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
    &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for Tanium v2.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
      <li><strong>Hostname, IP address, or server URL.</strong></li>
      <li><strong>Domain</strong></li>
      <li><strong>Credentials OR API Token</strong></li>
      <li><strong>Trust any certificate (not secure)</strong></li>
      <li><strong>Use system proxy settings</strong></li>
    </ul>
  </li>
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>
<h2>Authentication Options</h2>
<ol>
    <li><strong>Basic Authentication -</strong> to authenticate using basic authentication fill in the username and
     password
     into the corresponding fields and leave the API Token field empty. The username and password should be the same
      as the Tanium client.</li>
    <li>
    <strong>OAuth 2.0 Authentication -</strong> To use OAuth 2.0 follow the next steps:
    <ol>
    <li>Follow the instructions <a href= https://docs.tanium.com/platform_user/platform_user/console_api_tokens.html#add_API_tokens ><strong>here</strong></a>  to create an API token.
    <li>Paste the generated API Token into the <strong>API Token</strong> parameter in the instance configuration, and leave the username
        and password fields empty.</li>
    <li>Click the <strong>Test</strong> button to validate the instance configuration.</li>
    </ol>
    </li>
</ol>
<strong>Notes:</strong>
<ol>
    <li><strong>Trusted IP Addresses:</strong> by default, the Tanium Server blocks API tokens from all addresses except
     registered Tanium Module Servers. To add allowed IP addresses for any API token, add the IP addresses to the api_token_trusted_ip_address_list global setting. To add allowed IP addresses for an individual API token, specify the IP addresses in the trusted_ip_addresses field of the api_token object.</li>
    <li><strong>Expiration Time:</strong> by default, an api_token is valid for seven days. To change the expiration timeframe, edit
     the api_token_expiration_in_days global setting (minimum value is 1), or include a value with the expire_in_days field when you create the token.</li>
    <li>To edit a global setting in the Tanium platform, go to <i>Administration</i> -> <i>Global
     Settings</i> and search for the setting you would like to edit.</li>
     <li>For more information see the <a href=https://docs.tanium.com/platform_user/platform_user/console_api_tokens.html><strong>Tanium documentation</strong></a>.</li>
</ol>
<h2>Commands</h2>
<p>
  You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li><a href="#tn-get-package" target="_self">Returns a package object based on name or ID: tn-get-package</a></li>
  <li><a href="#tn-ask-question" target="_self">Asks the server to parse the question text and choose the first parsed
      result as the question to run: tn-ask-question</a></li>
  <li><a href="#tn-get-question-result" target="_self">Returns the question result based on question ID:
      tn-get-question-result</a></li>
  <li><a href="#tn-list-sensors" target="_self">Returns a list of all sensors: tn-list-sensors</a></li>
  <li><a href="#tn-get-sensor" target="_self">Returns detailed information about a sensor object based on name or ID:
      tn-get-sensor</a></li>
  <li><a href="#tn-create-saved-question" target="_self">Creates a saved question object: tn-create-saved-question</a>
  </li>
  <li><a href="#tn-list-saved-questions" target="_self">Returns all saved questions: tn-list-saved-questions</a></li>
  <li><a href="#tn-get-saved-question-result" target="_self">Returns the saved question result based on the saved
      question ID: tn-get-saved-question-result</a></li>
  <li><a href="#tn-get-system-status" target="_self">Returns all client details: tn-get-system-status</a></li>
  <li><a href="#tn-create-package" target="_self">Creates a package object: tn-create-package</a></li>
  <li><a href="#tn-list-packages" target="_self">Returns all package information: tn-list-packages</a></li>
  <li><a href="#tn-get-question-metadata" target="_self">Returns a question object based on question ID:
      tn-get-question-metadata</a></li>
  <li><a href="#tn-list-saved-actions" target="_self">Returns all saved actions: tn-list-saved-actions</a></li>
  <li><a href="#tn-get-saved-action" target="_self">Returns a saved action object based on name or ID:
      tn-get-saved-action</a></li>
  <li><a href="#tn-get-saved-question-metadata" target="_self">Returns a saved question object based on name or ID:
      tn-get-saved-question-metadata</a></li>
  <li><a href="#tn-create-saved-action" target="_self">Creates a saved action object: tn-create-saved-action</a></li>
  <li><a href="#tn-create-action" target="_self">Creates an action object based on the package name or the package ID:
      tn-create-action</a></li>
  <li><a href="#tn-list-actions" target="_self">Returns all actions: tn-list-actions</a></li>
  <li><a href="#tn-get-action" target="_self">Returns an action object based on ID: tn-get-action</a></li>
  <li><a href="#tn-list-saved-actions-pending-approval" target="_self">Retrieves all saved action approval definitions
      on the server: tn-list-saved-actions-pending-approval</a></li>
  <li><a href="#tn-get-group" target="_self">Returns a group object based on ID or name: tn-get-group</a></li>
  <li><a href="#tn-create-manual-group" target="_self">Creates a group object based on computers or IP addresses list:
      tn-create-manual-group</a></li>
  <li><a href="#tn-create-filter-based-group" target="_self">Creates a group object based on text filter:
      tn-create-filter-based-group</a></li>
  <li><a href="#tn-list-groups" target="_self">Returns all groups: tn-list-groups</a></li>
  <li><a href="#tn-delete-group" target="_self">Deletes a group object: tn-delete-group</a></li>
  <li><a href="#tn-create-action-by-host" target="_self">Creates an action object, based on a package name or package
      ID: tn-create-action-by-host</a></li>
</ol>
<h3 id="tn-get-package">1. tn-get-package</h3>
<hr>
<p>Returns a package object based on name or ID.</p>
<h5>Base Command</h5>
<p>
  <code>tn-get-package</code>
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
      <td>name</td>
      <td>The name of the package.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>id</td>
      <td>The package ID. Package ID or package name is required. When both exist, ID is used.</td>
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
      <td>TaniumPackage.Command</td>
      <td>String</td>
      <td>The command to run.</td>
    </tr>
    <tr>
      <td>TaniumPackage.CommandTimeout</td>
      <td>Number</td>
      <td>Timeout in seconds for the command execution.</td>
    </tr>
    <tr>
      <td>TaniumPackage.ContentSet.Id</td>
      <td>Number</td>
      <td>The ID of the content set to associate with the package.</td>
    </tr>
    <tr>
      <td>TaniumPackage.ContentSet.Name</td>
      <td>String</td>
      <td>The name of the content set to associate with the package.</td>
    </tr>
    <tr>
      <td>TaniumPackage.CreationTime</td>
      <td>String</td>
      <td>The time and date when this object was created in the database.</td>
    </tr>
    <tr>
      <td>TaniumPackage.DisplayName</td>
      <td>String</td>
      <td>The name of the package that displays in the user interface.</td>
    </tr>
    <tr>
      <td>TaniumPackage.ExpireSeconds</td>
      <td>Number</td>
      <td>Timeout in seconds for the action.</td>
    </tr>
    <tr>
      <td>TaniumPackage.Files.Hash</td>
      <td>String</td>
      <td>The SHA-256 hash of the contents of the file.</td>
    </tr>
    <tr>
      <td>TaniumPackage.Files.Id</td>
      <td>Number</td>
      <td>The unique ID of the package_file object.</td>
    </tr>
    <tr>
      <td>TaniumPackage.Files.Name</td>
      <td>String</td>
      <td>The unique name of the package_file object.</td>
    </tr>
    <tr>
      <td>TaniumPackage.ID</td>
      <td>Number</td>
      <td>The unique ID of the package_spec object.</td>
    </tr>
    <tr>
      <td>TaniumPackage.LastModifiedBy</td>
      <td>String</td>
      <td>The user who most recently modified this object.</td>
    </tr>
    <tr>
      <td>TaniumPackage.LastUpdate</td>
      <td>String</td>
      <td>The most recent time and date when this object was modified.</td>
    </tr>
    <tr>
      <td>TaniumPackage.ModUser.Domain</td>
      <td>String</td>
      <td>The domain of the user who most recently modified this object</td>
    </tr>
    <tr>
      <td>TaniumPackage.ModUser.Id</td>
      <td>Number</td>
      <td>The ID of the user who most recently modified this object</td>
    </tr>
    <tr>
      <td>TaniumPackage.ModUser.Name</td>
      <td>String</td>
      <td>The name of the user who most recently modified this object</td>
    </tr>
    <tr>
      <td>TaniumPackage.ModificationTime</td>
      <td>String</td>
      <td>The most recent time and date when this object was modified.</td>
    </tr>
    <tr>
      <td>TaniumPackage.Name</td>
      <td>String</td>
      <td>The unique name of the package_spec object.</td>
    </tr>
    <tr>
      <td>TaniumPackage.Parameters.Values</td>
      <td>String</td>
      <td>The parameter values.</td>
    </tr>
    <tr>
      <td>TaniumPackage.Parameters.Label</td>
      <td>String</td>
      <td>Parameter description.</td>
    </tr>
    <tr>
      <td>TaniumPackage.Parameters.Key</td>
      <td>String</td>
      <td>The attribute name of the parameter.</td>
    </tr>
    <tr>
      <td>TaniumPackage.Parameters.ParameterType</td>
      <td>String</td>
      <td>The type of parameter.</td>
    </tr>
    <tr>
      <td>TaniumPackage.SourceId</td>
      <td>Number</td>
      <td>The ID of the package into which the parameters are substituted.</td>
    </tr>
    <tr>
      <td>TaniumPackage.VerifyExpireSeconds</td>
      <td>Number</td>
      <td>A verification failure timeout. The time begins with the start of the action. If the action cannot be verified
        by the timeout, the action status is reported as failed.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-get-package id=225</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "TaniumPackage": {
        "Command": "cmd /c cscript ApplyWindowsQuarantine.vbs \"$1\" \"$2\" \"$3\" \"$4\" \"$5\" \"$6\" \"$7\" \"$8\" \"$9\"",
        "CommandTimeout": 180,
        "ContentSet": {
            "Id": 32,
            "Name": "Incident Response"
        },
        "CreationTime": "2019-09-19T13:57:35Z",
        "DisplayName": "Apply Windows IPsec Quarantine",
        "ExpireSeconds": 780,
        "Files": [
            {
                "Hash": "26cab9aaddf7d0e1ecf4113dee1ee976f6df9070a1f9edf3fa9e10bc63eb6a94",
                "ID": 699,
                "Name": "PortTester.exe"
            },
            {
                "Hash": "7a2aaaf742831abf22918e4726181f25aa8b32c1dcb6b500824fe5e5ffec25fb",
                "ID": 700,
                "Name": "taniumquarantine.dat"
            },
            {
                "Hash": "b2dfeab931f5938c52df84b8e6b157e698c508c7723b23505659e5ae659fcf6f",
                "ID": 701,
                "Name": "ApplyWindowsQuarantine.vbs"
            }
        ],
        "ID": 225,
        "LastModifiedBy": "administrator",
        "LastUpdate": "2019-09-19T13:57:35Z",
        "ModificationTime": "2019-09-19T13:57:35Z",
        "Name": "Apply Windows IPsec Quarantine",
        "Parameters": [
            {
                "Key": "$1",
                "Label": "Apply Custom Config (below)",
                "ParameterType": "com.tanium.components.parameters::CheckBoxParameter",
                "Values": null
            },
            {
                "Key": null,
                "Label": null,
                "ParameterType": "com.tanium.components.parameters::SeparatorParameter",
                "Values": null
            },
            {
                "Key": "$2",
                "Label": "Allow All DHCP",
                "ParameterType": "com.tanium.components.parameters::CheckBoxParameter",
                "Values": null
            },
            {
                "Key": "$3",
                "Label": "Allow All DNS",
                "ParameterType": "com.tanium.components.parameters::CheckBoxParameter",
                "Values": null
            },
            {
                "Key": "$4",
                "Label": "Allow All Tanium Servers",
                "ParameterType": "com.tanium.components.parameters::CheckBoxParameter",
                "Values": null
            },
            {
                "Key": "$5",
                "Label": "Validate Tanium Server Availability",
                "ParameterType": "com.tanium.components.parameters::CheckBoxParameter",
                "Values": null
            },
            {
                "Key": "$6",
                "Label": "Notification Message",
                "ParameterType": "com.tanium.components.parameters::TextAreaParameter",
                "Values": null
            },
            {
                "Key": "$7",
                "Label": "Custom Quarantine Rules",
                "ParameterType": "com.tanium.components.parameters::TextAreaParameter",
                "Values": null
            },
            {
                "Key": "$8",
                "Label": "Alternate Tanium Servers",
                "ParameterType": "com.tanium.components.parameters::TextInputParameter",
                "Values": null
            },
            {
                "Key": "$9",
                "Label": "VPN Servers",
                "ParameterType": "com.tanium.components.parameters::TextInputParameter",
                "Values": null
            }
        ],
        "SourceId": 0,
        "VerifyExpireSeconds": 600
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>Package information</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>Command</strong></th>
        <th><strong>CommandTimeout</strong></th>
        <th><strong>ContentSet</strong></th>
        <th><strong>CreationTime</strong></th>
        <th><strong>DisplayName</strong></th>
        <th><strong>ExpireSeconds</strong></th>
        <th><strong>ID</strong></th>
        <th><strong>LastModifiedBy</strong></th>
        <th><strong>LastUpdate</strong></th>
        <th><strong>ModUser</strong></th>
        <th><strong>ModificationTime</strong></th>
        <th><strong>Name</strong></th>
        <th><strong>SourceId</strong></th>
        <th><strong>VerifyExpireSeconds</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> cmd /c cscript ApplyWindowsQuarantine.vbs "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" </td>
        <td> 180 </td>
        <td> Id: 32<br>Name: Incident Response </td>
        <td> 2019-09-19T13:57:35Z </td>
        <td> Apply Windows IPsec Quarantine </td>
        <td> 780 </td>
        <td> 225 </td>
        <td> administrator </td>
        <td> 2019-09-19T13:57:35Z </td>
        <td> </td>
        <td> 2019-09-19T13:57:35Z </td>
        <td> Apply Windows IPsec Quarantine </td>
        <td> 0 </td>
        <td> 600 </td>
      </tr>
    </tbody>
  </table>

  <h3>Parameters information</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>Key</strong></th>
        <th><strong>Label</strong></th>
        <th><strong>ParameterType</strong></th>
        <th><strong>Values</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> $1 </td>
        <td> Apply Custom Config (below) </td>
        <td> com.tanium.components.parameters::CheckBoxParameter </td>
        <td> </td>
      </tr>
      <tr>
        <td> </td>
        <td> </td>
        <td> com.tanium.components.parameters::SeparatorParameter </td>
        <td> </td>
      </tr>
      <tr>
        <td> $2 </td>
        <td> Allow All DHCP </td>
        <td> com.tanium.components.parameters::CheckBoxParameter </td>
        <td> </td>
      </tr>
      <tr>
        <td> $3 </td>
        <td> Allow All DNS </td>
        <td> com.tanium.components.parameters::CheckBoxParameter </td>
        <td> </td>
      </tr>
      <tr>
        <td> $4 </td>
        <td> Allow All Tanium Servers </td>
        <td> com.tanium.components.parameters::CheckBoxParameter </td>
        <td> </td>
      </tr>
      <tr>
        <td> $5 </td>
        <td> Validate Tanium Server Availability </td>
        <td> com.tanium.components.parameters::CheckBoxParameter </td>
        <td> </td>
      </tr>
      <tr>
        <td> $6 </td>
        <td> Notification Message </td>
        <td> com.tanium.components.parameters::TextAreaParameter </td>
        <td> </td>
      </tr>
      <tr>
        <td> $7 </td>
        <td> Custom Quarantine Rules </td>
        <td> com.tanium.components.parameters::TextAreaParameter </td>
        <td> </td>
      </tr>
      <tr>
        <td> $8 </td>
        <td> Alternate Tanium Servers </td>
        <td> com.tanium.components.parameters::TextInputParameter </td>
        <td> </td>
      </tr>
      <tr>
        <td> $9 </td>
        <td> VPN Servers </td>
        <td> com.tanium.components.parameters::TextInputParameter </td>
        <td> </td>
      </tr>
    </tbody>
  </table>

  <h3>Files information</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>Hash</strong></th>
        <th><strong>ID</strong></th>
        <th><strong>Name</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> 26cab9aaddf7d0e1ecf4113dee1ee976f6df9070a1f9edf3fa9e10bc63eb6a94 </td>
        <td> 699 </td>
        <td> PortTester.exe </td>
      </tr>
      <tr>
        <td> 7a2aaaf742831abf22918e4726181f25aa8b32c1dcb6b500824fe5e5ffec25fb </td>
        <td> 700 </td>
        <td> taniumquarantine.dat </td>
      </tr>
      <tr>
        <td> b2dfeab931f5938c52df84b8e6b157e698c508c7723b23505659e5ae659fcf6f </td>
        <td> 701 </td>
        <td> ApplyWindowsQuarantine.vbs </td>
      </tr>
    </tbody>
  </table>
</p>

<h3 id="tn-ask-question">2. tn-ask-question</h3>
<hr>
<p>Asks the server to parse the question text and choose the first parsed result as the question to run.</p>
<h5>Base Command</h5>
<p>
  <code>tn-ask-question</code>
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
      <td>question-text</td>
      <td>The question text.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>parameters</td>
      <td>The question parameters. For example, sensor1{key1=val1;key2=val2};sensor2{key1=val1}.</td>
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
      <td>Tanium.Question.ID</td>
      <td>Number</td>
      <td>The unique ID of the question object.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-ask-question question-text=`Get IP Address from all machines`</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.Question": {
        "ID": 50500
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <p>
    New question created. ID = 50500
  </p>
</p>

<h3 id="tn-get-question-result">3. tn-get-question-result</h3>
<hr>
<p>Returns the question result based on question ID.</p>
<h5>Base Command</h5>
<p>
  <code>tn-get-question-result</code>
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
      <td>question-id</td>
      <td>The question ID.</td>
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
      <td>Tanium.QuestionResult.QuestionID</td>
      <td>Number</td>
      <td>The unique ID of the question object.</td>
    </tr>
    <tr>
      <td>Tanium.QuestionResult.Results</td>
      <td>Unknown</td>
      <td>The question results.</td>
    </tr>
    <tr>
      <td>Tanium.QuestionResult.Status</td>
      <td>String</td>
      <td>The status of the question request. Can be: "Completed" or "Pending".</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-get-question-result question-id=50477</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.QuestionResult": {
        "QuestionID": "50477",
        "Status": "Pending"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <p>
    Question is still executing, Question id: 50477
  </p>
</p>

<h3 id="tn-list-sensors">4. tn-list-sensors</h3>
<hr>
<p>Returns a list of all sensors.</p>
<h5>Base Command</h5>
<p>
  <code>tn-list-sensors</code>
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
      <td>limit</td>
      <td>The maximum number of sensors to return.</td>
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
      <td>TaniumSensor.Category</td>
      <td>String</td>
      <td>The category that includes this sensor.</td>
    </tr>
    <tr>
      <td>TaniumSensor.ContentSetId</td>
      <td>Number</td>
      <td>The ID of the content set to associate with the sensor.</td>
    </tr>
    <tr>
      <td>TaniumSensor.ContentSetName</td>
      <td>String</td>
      <td>The name of the content set to associate with the sensor.</td>
    </tr>
    <tr>
      <td>TaniumSensor.CreationTime</td>
      <td>String</td>
      <td>The time and date when this object was created in the database.</td>
    </tr>
    <tr>
      <td>TaniumSensor.Description</td>
      <td>String</td>
      <td>A description for the sensor.</td>
    </tr>
    <tr>
      <td>TaniumSensor.Hash</td>
      <td>String</td>
      <td>The hash ID of the sensor.</td>
    </tr>
    <tr>
      <td>TaniumSensor.ID</td>
      <td>Number</td>
      <td>The unique ID of the sensor object.</td>
    </tr>
    <tr>
      <td>TaniumSensor.IgnoreCaseFlag</td>
      <td>Boolean</td>
      <td>Whether to ignore the case flag of the sensor. Default is 1, which means the case flag is ignored.</td>
    </tr>
    <tr>
      <td>TaniumSensor.KeepDuplicatesFlag</td>
      <td>Boolean</td>
      <td>Whether to keep duplicate values in the sensor results. Default is 1 which keeps duplicate values instead of
        returning each unique value once.</td>
    </tr>
    <tr>
      <td>TaniumSensor.LastModifiedBy</td>
      <td>String</td>
      <td>The name of the user who last modified this object.</td>
    </tr>
    <tr>
      <td>TaniumSensor.MaxAgeSeconds</td>
      <td>Number</td>
      <td>The maximum age in seconds a sensor result is invalid. When results are half this value, the sensor is
        re-evaluated.</td>
    </tr>
    <tr>
      <td>TaniumSensor.ModUserDomain</td>
      <td>String</td>
      <td>The domain of the user who most recently modified this object.</td>
    </tr>
    <tr>
      <td>TaniumSensor.ModUserId</td>
      <td>Number</td>
      <td>The ID of the user who most recently modified this object.</td>
    </tr>
    <tr>
      <td>TaniumSensor.ModUserName</td>
      <td>String</td>
      <td>The name of user who most recently modified this object.</td>
    </tr>
    <tr>
      <td>TaniumSensor.ModificationTime</td>
      <td>String</td>
      <td>The most recent time and date when this object was modified.</td>
    </tr>
    <tr>
      <td>TaniumSensor.Name</td>
      <td>String</td>
      <td>The name of the sensor.</td>
    </tr>
    <tr>
      <td>TaniumSensor.SourceId</td>
      <td>Number</td>
      <td>The ID of the sensor into which the parameters are substituted. If specified, source_hash may be omitted.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-list-sensors limit=1</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "TaniumSensor": [
        {
            "Category": "Network",
            "ContentSetId": 10,
            "ContentSetName": "Network",
            "CreationTime": "2019-07-17T20:13:49Z",
            "Description": "Returns the SSID (name) of a wireless network a machine is connected to.\nExample: linksys",
            "Hash": "1466668831",
            "ID": 232,
            "IgnoreCaseFlag": true,
            "KeepDuplicatesFlag": false,
            "LastModifiedBy": "administrator",
            "MaxAgeSeconds": 900,
            "ModUserDomain": "EC2AMAZ-N5ETQVT",
            "ModUserId": 1,
            "ModUserName": "administrator",
            "ModificationTime": "2019-07-17T20:13:49Z",
            "Name": "Wireless Network Connected SSID",
            "SourceId": 0
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>Sensors</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>Category</strong></th>
        <th><strong>ContentSetId</strong></th>
        <th><strong>ContentSetName</strong></th>
        <th><strong>CreationTime</strong></th>
        <th><strong>Description</strong></th>
        <th><strong>Hash</strong></th>
        <th><strong>ID</strong></th>
        <th><strong>IgnoreCaseFlag</strong></th>
        <th><strong>KeepDuplicatesFlag</strong></th>
        <th><strong>LastModifiedBy</strong></th>
        <th><strong>MaxAgeSeconds</strong></th>
        <th><strong>ModUserDomain</strong></th>
        <th><strong>ModUserId</strong></th>
        <th><strong>ModUserName</strong></th>
        <th><strong>ModificationTime</strong></th>
        <th><strong>Name</strong></th>
        <th><strong>SourceId</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> Network </td>
        <td> 10 </td>
        <td> Network </td>
        <td> 2019-07-17T20:13:49Z </td>
        <td> Returns the SSID (name) of a wireless network a machine is connected to.<br>Example: linksys </td>
        <td> 1466668831 </td>
        <td> 232 </td>
        <td> true </td>
        <td> false </td>
        <td> administrator </td>
        <td> 900 </td>
        <td> EC2AMAZ-N5ETQVT </td>
        <td> 1 </td>
        <td> administrator </td>
        <td> 2019-07-17T20:13:49Z </td>
        <td> Wireless Network Connected SSID </td>
        <td> 0 </td>
      </tr>
    </tbody>
  </table>
</p>

<h3 id="tn-get-sensor">5. tn-get-sensor</h3>
<hr>
<p>Returns detailed information about a sensor object based on name or ID.</p>
<h5>Base Command</h5>
<p>
  <code>tn-get-sensor</code>
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
      <td>id</td>
      <td>The sensor ID.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>name</td>
      <td>The name of the sensor.</td>
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
      <td>TaniumSensor.Category</td>
      <td>String</td>
      <td>The category that includes this sensor.</td>
    </tr>
    <tr>
      <td>TaniumSensor.ContentSetId</td>
      <td>Number</td>
      <td>The ID of the content_set to associate with the sensor.</td>
    </tr>
    <tr>
      <td>TaniumSensor.ContentSetName</td>
      <td>String</td>
      <td>The name of the content_set to associate with the sensor.</td>
    </tr>
    <tr>
      <td>TaniumSensor.CreationTime</td>
      <td>String</td>
      <td>The date and time when this object was created in the database.</td>
    </tr>
    <tr>
      <td>TaniumSensor.Description</td>
      <td>String</td>
      <td>A description for the sensor.</td>
    </tr>
    <tr>
      <td>TaniumSensor.Hash</td>
      <td>String</td>
      <td>The hash id of the sensor</td>
    </tr>
    <tr>
      <td>TaniumSensor.ID</td>
      <td>Number</td>
      <td>The unique ID of the sensor object.</td>
    </tr>
    <tr>
      <td>TaniumSensor.IgnoreCaseFlag</td>
      <td>Boolean</td>
      <td>Ignore the case flag. Default is 1, which means the case flag is ignored.</td>
    </tr>
    <tr>
      <td>TaniumSensor.KeepDuplicatesFlag</td>
      <td>Boolean</td>
      <td>Keep duplicates flag in the sensor results. Default is 1, which preserves duplicate values in sensor results
        instead of only returning each unique value once.</td>
    </tr>
    <tr>
      <td>TaniumSensor.LastModifiedBy</td>
      <td>String</td>
      <td>The name of the user who last modified this object.</td>
    </tr>
    <tr>
      <td>TaniumSensor.MaxAgeSeconds</td>
      <td>Number</td>
      <td>The maximum age in seconds of a sensor result before it is invalid. When results are half this value, the
        sensor is re-evaluated.</td>
    </tr>
    <tr>
      <td>TaniumSensor.ModUserDomain</td>
      <td>String</td>
      <td>The domain of the user who most recently modified this object.</td>
    </tr>
    <tr>
      <td>TaniumSensor.ModUserId</td>
      <td>Number</td>
      <td>The ID of the user who most recently modified this object.</td>
    </tr>
    <tr>
      <td>TaniumSensor.ModUserName</td>
      <td>String</td>
      <td>The name of the user who most recently modified this object.</td>
    </tr>
    <tr>
      <td>TaniumSensor.ModificationTime</td>
      <td>String</td>
      <td>The most recent time and date when this object was modified.</td>
    </tr>
    <tr>
      <td>TaniumSensor.Name</td>
      <td>String</td>
      <td>The name of the sensor.</td>
    </tr>
    <tr>
      <td>TaniumSensor.Parameters.Key</td>
      <td>String</td>
      <td>The attribute name of the parameter.</td>
    </tr>
    <tr>
      <td>TaniumSensor.Parameters.Label</td>
      <td>String</td>
      <td>The description of the parameter.</td>
    </tr>
    <tr>
      <td>TaniumSensor.Parameters.Values</td>
      <td>String</td>
      <td>The values of the parameter.</td>
    </tr>
    <tr>
      <td>TaniumSensor.Parameters.ParameterType</td>
      <td>String</td>
      <td>The type of parameter.</td>
    </tr>
    <tr>
      <td>TaniumSensor.SourceId</td>
      <td>Number</td>
      <td>The ID of the sensor into which the parameters are substituted. If specified, source_hash may be omitted.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-get-sensor id=204</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "TaniumSensor": {
        "Category": "Applications",
        "ContentSetId": 11,
        "ContentSetName": "Software",
        "CreationTime": "2019-07-17T20:13:49Z",
        "Description": "The version string of applications which match the parameter given.\nExample:  11.5.502.146",
        "Hash": "2387001299",
        "ID": 204,
        "IgnoreCaseFlag": true,
        "KeepDuplicatesFlag": false,
        "LastModifiedBy": "administrator",
        "MaxAgeSeconds": 900,
        "ModUserDomain": "EC2AMAZ-N5ETQVT",
        "ModUserId": 1,
        "ModUserName": "administrator",
        "ModificationTime": "2019-07-17T20:13:49Z",
        "Name": "Installed Application Version",
        "Parameters": [
            {
                "Key": "application",
                "Label": "Application Name",
                "ParameterType": "com.tanium.components.parameters::TextInputParameter",
                "Values": null
            }
        ],
        "SourceId": 0
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>Sensor information</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>Category</strong></th>
        <th><strong>ContentSetId</strong></th>
        <th><strong>ContentSetName</strong></th>
        <th><strong>CreationTime</strong></th>
        <th><strong>Description</strong></th>
        <th><strong>Hash</strong></th>
        <th><strong>ID</strong></th>
        <th><strong>IgnoreCaseFlag</strong></th>
        <th><strong>KeepDuplicatesFlag</strong></th>
        <th><strong>LastModifiedBy</strong></th>
        <th><strong>MaxAgeSeconds</strong></th>
        <th><strong>ModUserDomain</strong></th>
        <th><strong>ModUserId</strong></th>
        <th><strong>ModUserName</strong></th>
        <th><strong>ModificationTime</strong></th>
        <th><strong>Name</strong></th>
        <th><strong>SourceId</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> Applications </td>
        <td> 11 </td>
        <td> Software </td>
        <td> 2019-07-17T20:13:49Z </td>
        <td> The version string of applications which match the parameter given.<br>Example: 11.5.502.146 </td>
        <td> 2387001299 </td>
        <td> 204 </td>
        <td> true </td>
        <td> false </td>
        <td> administrator </td>
        <td> 900 </td>
        <td> EC2AMAZ-N5ETQVT </td>
        <td> 1 </td>
        <td> administrator </td>
        <td> 2019-07-17T20:13:49Z </td>
        <td> Installed Application Version </td>
        <td> 0 </td>
      </tr>
    </tbody>
  </table>

  <h3>Parameter information</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>Key</strong></th>
        <th><strong>Label</strong></th>
        <th><strong>ParameterType</strong></th>
        <th><strong>Values</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> application </td>
        <td> Application Name </td>
        <td> com.tanium.components.parameters::TextInputParameter </td>
        <td> </td>
      </tr>
    </tbody>
  </table>
</p>

<h3 id="tn-create-saved-question">6. tn-create-saved-question</h3>
<hr>
<p>Creates a saved question object.</p>
<h5>Base Command</h5>
<p>
  <code>tn-create-saved-question</code>
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
      <td>question-id</td>
      <td>The question ID.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>name</td>
      <td>Name of the saved question to create.</td>
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
      <td>Tanium.SavedQuestion.ID</td>
      <td>Number</td>
      <td>The ID of the saved question.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.Name</td>
      <td>String</td>
      <td>The name of the saved question.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-create-saved-question name=ip_all_machines question-id=50477</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.SavedQuestion": {
        "ID": 450,
        "name": "ip_all_machines"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <p>
    Question saved. ID = 450
  </p>
</p>

<h3 id="tn-list-saved-questions">7. tn-list-saved-questions</h3>
<hr>
<p>Returns all saved questions.</p>
<h5>Base Command</h5>
<p>
  <code>tn-list-saved-questions</code>
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
      <td>limit</td>
      <td>The maximum number of saved questions to return.</td>
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
      <td>Tanium.SavedQuestion.ArchiveEnabledFlag</td>
      <td>Boolean</td>
      <td>Whether archiving is enabled for the saved question.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.ArchiveOwner</td>
      <td>String</td>
      <td>The name of the user that owns the archive. Archives can be shared between users with identical management
        rights groups.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.ExpireSeconds</td>
      <td>Number</td>
      <td>The duration in seconds before each question expires. Default value is 600.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.ID</td>
      <td>Number</td>
      <td>The unique ID of the question object.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.IssueSeconds</td>
      <td>Number</td>
      <td>The time in seconds to reissue the question when active. Default value is 120.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.IssueSecondsNeverFlag</td>
      <td>Boolean</td>
      <td>Whether the question is not reissued automatically. Default is 1 (not reissued).</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.KeepSeconds</td>
      <td>Number</td>
      <td>The number of seconds to save the data results in the archive.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.ModTime</td>
      <td>String</td>
      <td>The most recent time and date when this object was modified.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.ModUserDomain</td>
      <td>String</td>
      <td>The domain of the user who most recently modified this object.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.ModUserId</td>
      <td>Number</td>
      <td>The ID of the user who most recently modified this object.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.ModUserName</td>
      <td>String</td>
      <td>The name of user who most recently modified this object.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.MostRecentQuestionId</td>
      <td>Number</td>
      <td>The ID of the most recently issued question object generated by the saved question.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.Name</td>
      <td>String</td>
      <td>The name of the saved question object.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.QueryText</td>
      <td>String</td>
      <td>The textual representation of the question.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.QuestionId</td>
      <td>Number</td>
      <td>The ID of the question from which to create the saved question.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.RowCountFlag</td>
      <td>Boolean</td>
      <td>If the value is true, only the row count data is saved when archiving this question.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.SortColumn</td>
      <td>Number</td>
      <td>The default sort column, if no sort order is specified.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.UserId</td>
      <td>Number</td>
      <td>The ID of the user who owns this object.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.UserName</td>
      <td>String</td>
      <td>The name of the user who owns this object.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-list-saved-questions limit=1</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.SavedQuestion": [
        {
            "ArchiveEnabledFlag": false,
            "ExpireSeconds": 600,
            "ID": 130,
            "IssueSeconds": 120,
            "IssueSecondsNeverFlag": false,
            "KeepSeconds": 0,
            "ModTime": "2019-07-17T20:43:06Z",
            "MostRecentQuestionId": 19563,
            "Name": "SCCM - Client Cache Size",
            "QueryText": "Get SCCM Cache Size from all machines",
            "QuestionId": 19563,
            "RowCountFlag": false,
            "SortColumn": 0,
            "UserId": 1,
            "UserName": "administrator"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>Saved questions</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>ArchiveEnabledFlag</strong></th>
        <th><strong>ArchiveOwner</strong></th>
        <th><strong>ExpireSeconds</strong></th>
        <th><strong>ID</strong></th>
        <th><strong>IssueSeconds</strong></th>
        <th><strong>IssueSecondsNeverFlag</strong></th>
        <th><strong>KeepSeconds</strong></th>
        <th><strong>ModTime</strong></th>
        <th><strong>MostRecentQuestionId</strong></th>
        <th><strong>Name</strong></th>
        <th><strong>QueryText</strong></th>
        <th><strong>QuestionId</strong></th>
        <th><strong>RowCountFlag</strong></th>
        <th><strong>SortColumn</strong></th>
        <th><strong>UserId</strong></th>
        <th><strong>UserName</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> false </td>
        <td> </td>
        <td> 600 </td>
        <td> 130 </td>
        <td> 120 </td>
        <td> false </td>
        <td> 0 </td>
        <td> 2019-07-17T20:43:06Z </td>
        <td> 19563 </td>
        <td> SCCM - Client Cache Size </td>
        <td> Get SCCM Cache Size from all machines </td>
        <td> 19563 </td>
        <td> false </td>
        <td> 0 </td>
        <td> 1 </td>
        <td> administrator </td>
      </tr>
    </tbody>
  </table>
</p>

<h3 id="tn-get-saved-question-result">8. tn-get-saved-question-result</h3>
<hr>
<p>Returns the saved question result based on the saved question ID.</p>
<h5>Base Command</h5>
<p>
  <code>tn-get-saved-question-result</code>
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
      <td>question-id</td>
      <td>The saved question ID.</td>
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
      <td>Tanium.SavedQuestionResult.SavedQuestionID</td>
      <td>Number</td>
      <td>The ID of the saved question.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestionResult.Results</td>
      <td>Unknown</td>
      <td>The saved question results.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestionResult.Status</td>
      <td>String</td>
      <td>Status of the question request. Can be: "Completed" or "Pending".</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-get-saved-question-result question-id=130</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.SavedQuestionResult": {
        "SavedQuestionID": "130",
        "Status": "Completed"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>question results:</h3>
  <p>
    **No entries.**
  </p>
</p>

<h3 id="tn-get-system-status">9. tn-get-system-status</h3>
<hr>
<p>Returns all client details.</p>
<h5>Base Command</h5>
<p>
  <code>tn-get-system-status</code>
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
      <td>Tanium.Client.ComputerId</td>
      <td>Number</td>
      <td>The computer ID of the client.</td>
    </tr>
    <tr>
      <td>Tanium.Client.FullVersion</td>
      <td>String</td>
      <td>The Tanium Client version.</td>
    </tr>
    <tr>
      <td>Tanium.Client.HostName</td>
      <td>String</td>
      <td>The computer hostname.</td>
    </tr>
    <tr>
      <td>Tanium.Client.IpAddressClient</td>
      <td>String</td>
      <td>The IP address of the client returned from a sensor on the client.</td>
    </tr>
    <tr>
      <td>Tanium.Client.IpAddressServer</td>
      <td>String</td>
      <td>The IP address of the client that was recorded on the server during the last registration.</td>
    </tr>
    <tr>
      <td>Tanium.Client.LastRegistration</td>
      <td>Date</td>
      <td>The most recent time that the client registered with the server.</td>
    </tr>
    <tr>
      <td>Tanium.Client.Status</td>
      <td>String</td>
      <td>The status of the client. Can be: "Blocked", "Leader" "Normal", "Slow link".</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-get-system-status</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.Client": [
        {
            "ComputerId": 9065264,
            "FullVersion": "7.2.314.3476",
            "HostName": "ec2amaz-kgmro60",
            "IpAddressClient": "127.0.0.1",
            "IpAddressServer": "127.0.0.1",
            "LastRegistration": "2019-11-27T15:06:08Z",
            "Status": "Leader"
        },
        {
            "ComputerId": 2232836718,
            "FullVersion": "7.2.314.3476",
            "HostName": "HOSTNAME",
            "IpAddressClient": "127.0.0.1",
            "IpAddressServer": "127.0.0.1",
            "LastRegistration": "2019-11-27T15:06:09Z",
            "Status": "Leader"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>System status</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>ComputerId</strong></th>
        <th><strong>FullVersion</strong></th>
        <th><strong>HostName</strong></th>
        <th><strong>IpAddressClient</strong></th>
        <th><strong>IpAddressServer</strong></th>
        <th><strong>LastRegistration</strong></th>
        <th><strong>Status</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> 9065264 </td>
        <td> 7.2.314.3476 </td>
        <td> ec2amaz-kgmro60 </td>
        <td> 127.0.0.1 </td>
        <td> 127.0.0.1 </td>
        <td> 2019-11-27T15:06:08Z </td>
        <td> Leader </td>
      </tr>
      <tr>
        <td> 2232836718 </td>
        <td> 7.2.314.3476 </td>
        <td> HOSTNAME </td>
        <td> 127.0.0.1 </td>
        <td> 127.0.0.1 </td>
        <td> 2019-11-27T15:06:09Z </td>
        <td> Leader </td>
      </tr>
    </tbody>
  </table>
</p>

<h3 id="tn-create-package">10. tn-create-package</h3>
<hr>
<p>Creates a package object.</p>
<h5>Base Command</h5>
<p>
  <code>tn-create-package</code>
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
      <td>command</td>
      <td>The command to execute.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>name</td>
      <td>The name of the package to create.</td>
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
      <td>TaniumPackage.Command</td>
      <td>String</td>
      <td>The command to run.</td>
    </tr>
    <tr>
      <td>TaniumPackage.CommandTimeout</td>
      <td>Number</td>
      <td>Timeout in seconds for the command execution.</td>
    </tr>
    <tr>
      <td>TaniumPackage.ContentSet.Id</td>
      <td>Number</td>
      <td>The ID of the content set to associate with the package.</td>
    </tr>
    <tr>
      <td>TaniumPackage.ContentSet.Name</td>
      <td>String</td>
      <td>The name of the content set to associate with the package.</td>
    </tr>
    <tr>
      <td>TaniumPackage.CreationTime</td>
      <td>String</td>
      <td>The time and date when this object was created in the database.</td>
    </tr>
    <tr>
      <td>TaniumPackage.DisplayName</td>
      <td>String</td>
      <td>The name of the package that displays in the user interface.</td>
    </tr>
    <tr>
      <td>TaniumPackage.ExpireSeconds</td>
      <td>Number</td>
      <td>Timeout in seconds for the action expiry.</td>
    </tr>
    <tr>
      <td>TaniumPackage.ID</td>
      <td>Number</td>
      <td>The unique ID of the package_spec object.</td>
    </tr>
    <tr>
      <td>TaniumPackage.LastModifiedBy</td>
      <td>String</td>
      <td>The user who most recently modified this object.</td>
    </tr>
    <tr>
      <td>TaniumPackage.LastUpdate</td>
      <td>String</td>
      <td>The most recent time and date when this object was modified.</td>
    </tr>
    <tr>
      <td>TaniumPackage.ModUser.Domain</td>
      <td>String</td>
      <td>The domain of the user who most recently modified this object.</td>
    </tr>
    <tr>
      <td>TaniumPackage.ModUser.Id</td>
      <td>Number</td>
      <td>The ID of the user who most recently modified this object</td>
    </tr>
    <tr>
      <td>TaniumPackage.ModUser.Name</td>
      <td>String</td>
      <td>The name of the user who most recently modified this object</td>
    </tr>
    <tr>
      <td>TaniumPackage.ModificationTime</td>
      <td>String</td>
      <td>The most recent time and date when this object was modified.</td>
    </tr>
    <tr>
      <td>TaniumPackage.Name</td>
      <td>String</td>
      <td>The unique name of the package_spec object.</td>
    </tr>
    <tr>
      <td>TaniumPackage.SourceId</td>
      <td>Number</td>
      <td>The ID of the package into which the parameters are substituted.</td>
    </tr>
    <tr>
      <td>TaniumPackage.VerifyExpireSeconds</td>
      <td>Number</td>
      <td>A verification failure timeout. The time begins with the start of the action. If the action cannot be verified
        by the timeout, the action status is reported as failed.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-create-package command=cls name=clear_screen</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "TaniumPackage": {
        "Command": "cls",
        "CommandTimeout": 600,
        "ContentSet": {
            "Id": 2,
            "Name": ""
        },
        "CreationTime": "2019-11-27T15:06:14Z",
        "DisplayName": "clear_screen",
        "ExpireSeconds": 3600,
        "ID": 1220,
        "LastModifiedBy": "administrator",
        "LastUpdate": "2019-11-27T15:06:14Z",
        "ModificationTime": "2019-11-27T15:06:14Z",
        "Name": "clear_screen",
        "SourceId": 0,
        "VerifyExpireSeconds": 3600
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>Package information</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>Command</strong></th>
        <th><strong>CommandTimeout</strong></th>
        <th><strong>ContentSet</strong></th>
        <th><strong>CreationTime</strong></th>
        <th><strong>DisplayName</strong></th>
        <th><strong>ExpireSeconds</strong></th>
        <th><strong>Files</strong></th>
        <th><strong>ID</strong></th>
        <th><strong>LastModifiedBy</strong></th>
        <th><strong>LastUpdate</strong></th>
        <th><strong>ModUser</strong></th>
        <th><strong>ModificationTime</strong></th>
        <th><strong>Name</strong></th>
        <th><strong>Parameters</strong></th>
        <th><strong>SourceId</strong></th>
        <th><strong>VerifyExpireSeconds</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> cls </td>
        <td> 600 </td>
        <td> Id: 2<br>Name: </td>
        <td> 2019-11-27T15:06:14Z </td>
        <td> clear_screen </td>
        <td> 3600 </td>
        <td> </td>
        <td> 1220 </td>
        <td> administrator </td>
        <td> 2019-11-27T15:06:14Z </td>
        <td> </td>
        <td> 2019-11-27T15:06:14Z </td>
        <td> clear_screen </td>
        <td> </td>
        <td> 0 </td>
        <td> 3600 </td>
      </tr>
    </tbody>
  </table>

  <h3>Parameters information</h3>
  <p>
    **No entries.**
  </p>
  <h3>Files information</h3>
  <p>
    **No entries.**
  </p>
</p>

<h3 id="tn-list-packages">11. tn-list-packages</h3>
<hr>
<p>Returns all package information.</p>
<h5>Base Command</h5>
<p>
  <code>tn-list-packages</code>
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
      <td>limit</td>
      <td>The maximum number of packages to return.</td>
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
      <td>TaniumPackage.Command</td>
      <td>String</td>
      <td>The command to run.</td>
    </tr>
    <tr>
      <td>TaniumPackage.CommandTimeout</td>
      <td>Number</td>
      <td>Timeout in seconds for the command execution.</td>
    </tr>
    <tr>
      <td>TaniumPackage.ContentSet.Id</td>
      <td>Number</td>
      <td>The ID of the content set to associate with the package.</td>
    </tr>
    <tr>
      <td>TaniumPackage.ContentSet.Name</td>
      <td>String</td>
      <td>The name of the content set to associate with the package.</td>
    </tr>
    <tr>
      <td>TaniumPackage.CreationTime</td>
      <td>String</td>
      <td>The time and date when this object was created in the database.</td>
    </tr>
    <tr>
      <td>TaniumPackage.DisplayName</td>
      <td>String</td>
      <td>The name of the package that displays in the user interface.</td>
    </tr>
    <tr>
      <td>TaniumPackage.ExpireSeconds</td>
      <td>Number</td>
      <td>Timeout in seconds for the action expiry.</td>
    </tr>
    <tr>
      <td>TaniumPackage.ID</td>
      <td>Number</td>
      <td>The unique ID of the package_spec object.</td>
    </tr>
    <tr>
      <td>TaniumPackage.LastModifiedBy</td>
      <td>String</td>
      <td>The user who most recently modified this object.</td>
    </tr>
    <tr>
      <td>TaniumPackage.LastUpdate</td>
      <td>String</td>
      <td>The most recent time and date when this object was modified.</td>
    </tr>
    <tr>
      <td>TaniumPackage.ModUser.Domain</td>
      <td>String</td>
      <td>The domain of the user who most recently modified this object.</td>
    </tr>
    <tr>
      <td>TaniumPackage.ModUser.Id</td>
      <td>Number</td>
      <td>The ID of the user who most recently modified this object.</td>
    </tr>
    <tr>
      <td>TaniumPackage.ModUser.Name</td>
      <td>String</td>
      <td>The name of the user who most recently modified this object.</td>
    </tr>
    <tr>
      <td>TaniumPackage.ModificationTime</td>
      <td>String</td>
      <td>The most recent time and date when this object was modified.</td>
    </tr>
    <tr>
      <td>TaniumPackage.Name</td>
      <td>String</td>
      <td>The unique name of the package_spec object.</td>
    </tr>
    <tr>
      <td>TaniumPackage.SourceId</td>
      <td>Number</td>
      <td>The ID of the package into which the parameters are substituted.</td>
    </tr>
    <tr>
      <td>TaniumPackage.VerifyExpireSeconds</td>
      <td>Number</td>
      <td>A verification failure timeout. The time begins with the start of the action. If the action cannot be verified
        by the timeout, the action status is reported as failed.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-list-packages limit=1</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "TaniumPackage": [
        {
            "Command": "/bin/bash run-add-intel-package.sh 2>&1",
            "CommandTimeout": 600,
            "ContentSet": {
                "Id": 8,
                "Name": "Detect Service"
            },
            "CreationTime": "2019-07-23T20:40:17Z",
            "DisplayName": "Detect Intel for Unix Revision 4 Delta",
            "ExpireSeconds": 2400,
            "ID": 132,
            "LastModifiedBy": "administrator",
            "LastUpdate": "2019-07-23T20:40:17Z",
            "ModificationTime": "2019-07-23T20:40:17Z",
            "Name": "Detect Intel for Unix Revision 4 Delta",
            "SourceId": 0,
            "VerifyExpireSeconds": 3600
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>Packages</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>Command</strong></th>
        <th><strong>CommandTimeout</strong></th>
        <th><strong>ContentSet</strong></th>
        <th><strong>CreationTime</strong></th>
        <th><strong>DisplayName</strong></th>
        <th><strong>ExpireSeconds</strong></th>
        <th><strong>ID</strong></th>
        <th><strong>LastModifiedBy</strong></th>
        <th><strong>LastUpdate</strong></th>
        <th><strong>ModUser</strong></th>
        <th><strong>ModificationTime</strong></th>
        <th><strong>Name</strong></th>
        <th><strong>SourceId</strong></th>
        <th><strong>VerifyExpireSeconds</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> /bin/bash run-add-intel-package.sh 2>&1 </td>
        <td> 600 </td>
        <td> Id: 8<br>Name: Detect Service </td>
        <td> 2019-07-23T20:40:17Z </td>
        <td> Detect Intel for Unix Revision 4 Delta </td>
        <td> 2400 </td>
        <td> 132 </td>
        <td> administrator </td>
        <td> 2019-07-23T20:40:17Z </td>
        <td> </td>
        <td> 2019-07-23T20:40:17Z </td>
        <td> Detect Intel for Unix Revision 4 Delta </td>
        <td> 0 </td>
        <td> 3600 </td>
      </tr>
    </tbody>
  </table>
</p>

<h3 id="tn-get-question-metadata">12. tn-get-question-metadata</h3>
<hr>
<p>Returns a question object based on question ID.</p>
<h5>Base Command</h5>
<p>
  <code>tn-get-question-metadata</code>
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
      <td>question-id</td>
      <td>The question ID.</td>
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
      <td>Tanium.Question.ID</td>
      <td>Number</td>
      <td>The unique ID of the question object.</td>
    </tr>
    <tr>
      <td>Tanium.Question.Expiration</td>
      <td>Date</td>
      <td>The date the question expires.</td>
    </tr>
    <tr>
      <td>Tanium.Question.ExpireSeconds</td>
      <td>Number</td>
      <td>The number of seconds before the question expires. Default is 600.</td>
    </tr>
    <tr>
      <td>Tanium.Question.ForceComputerIdFlag</td>
      <td>Boolean</td>
      <td>Whether to force the question to be a counting question if only one selection is present. Default is not to
        force. If the question object is an instance of a saved question, this field is derived from the saved question
      </td>
    </tr>
    <tr>
      <td>Tanium.Question.IsExpired</td>
      <td>Boolean</td>
      <td>Whether the question has expired.</td>
    </tr>
    <tr>
      <td>Tanium.Question.QueryText</td>
      <td>String</td>
      <td>The textual representation of the question.</td>
    </tr>
    <tr>
      <td>Tanium.Question.SavedQuestionId</td>
      <td>Number</td>
      <td>The ID of the saved question derived from this question.</td>
    </tr>
    <tr>
      <td>Tanium.Question.UserId</td>
      <td>Number</td>
      <td>The ID of the user who created / issued this question.</td>
    </tr>
    <tr>
      <td>Tanium.Question.UserName</td>
      <td>String</td>
      <td>The name of the user who created / issued this question.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-get-question-metadata question-id=50477</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.Question": {
        "Expiration": "2019-11-27T14:16:24Z",
        "ExpireSeconds": 0,
        "ForceComputerIdFlag": false,
        "ID": 50477,
        "IsExpired": true,
        "QueryText": "Get IP Address from all machines",
        "SavedQuestionId": 450,
        "UserId": 1,
        "UserName": "administrator"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>Question results</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>Expiration</strong></th>
        <th><strong>ExpireSeconds</strong></th>
        <th><strong>ForceComputerIdFlag</strong></th>
        <th><strong>ID</strong></th>
        <th><strong>IsExpired</strong></th>
        <th><strong>QueryText</strong></th>
        <th><strong>SavedQuestionId</strong></th>
        <th><strong>UserId</strong></th>
        <th><strong>UserName</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> 2019-11-27T14:16:24Z </td>
        <td> 0 </td>
        <td> false </td>
        <td> 50477 </td>
        <td> true </td>
        <td> Get IP Address from all machines </td>
        <td> 450 </td>
        <td> 1 </td>
        <td> administrator </td>
      </tr>
    </tbody>
  </table>
</p>

<h3 id="tn-list-saved-actions">13. tn-list-saved-actions</h3>
<hr>
<p>Returns all saved actions.</p>
<h5>Base Command</h5>
<p>
  <code>tn-list-saved-actions</code>
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
      <td>limit</td>
      <td>The maximin number of saved actions to return.</td>
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
      <td>Tanium.SavedAction.ActionGroupId</td>
      <td>Number</td>
      <td>The ID of the group of clients to target.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.ApprovedFlag</td>
      <td>Boolean</td>
      <td>Whether the saved action is approved. True is approved.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.ApproverId</td>
      <td>Number</td>
      <td>The ID of the user to approve the saved action.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.ApproverName</td>
      <td>String</td>
      <td>The name of the user to approve the saved action.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.CreationTime</td>
      <td>Date</td>
      <td>The time and date when this object was created in the database.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.EndTime</td>
      <td>Date</td>
      <td>The time and date to stop issuing actions.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.ExpireSeconds</td>
      <td>Number</td>
      <td>The duration from the start time before the action expires.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.ID</td>
      <td>Number</td>
      <td>The unique ID of the saved action object.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.LastActionId</td>
      <td>Number</td>
      <td>The ID of the action object that was issued last.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.LastActionStartTime</td>
      <td>Date</td>
      <td>The start time and date of the action object that was issued last.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.LastAaction.TargetGroupId</td>
      <td>Number</td>
      <td>The target group of the action object that was issued last.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.LastStartTime</td>
      <td>Date</td>
      <td>The most recent date and time that the action started.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.Name</td>
      <td>String</td>
      <td>The name of the saved_action object.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.NextStartTime</td>
      <td>Date</td>
      <td>The next time and date when the action will start.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.PackageId</td>
      <td>Number</td>
      <td>The ID of the package deployed by the saved action.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.PackageName</td>
      <td>String</td>
      <td>The name of the package deployed by the saved action.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.PackageSourceHash</td>
      <td>String</td>
      <td>The source hash of the package deployed by the saved action.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.StartTime</td>
      <td>Date</td>
      <td>The time and date when the action became active. An empty string or null starts immediately.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.Status</td>
      <td>Number</td>
      <td>The status of the saved action. Can be: "0" for Enabled, "1" for Disabled, or "2" for Deleted.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.TargetGroupId</td>
      <td>Number</td>
      <td>The group of machines to target.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.UserId</td>
      <td>Number</td>
      <td>The ID of the user who created the saved action.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.UserName</td>
      <td>String</td>
      <td>The ID of the user who created the saved action.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-list-saved-actions limit=1</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.SavedAction": [
        {
            "ActionGroupId": 432,
            "ApprovedFlag": false,
            "ApproverId": 0,
            "CreationTime": "2019-09-25T16:56:59Z",
            "EndTime": "Never",
            "ExpireSeconds": 600,
            "ID": 353,
            "LastActionId": 7206,
            "LastActionStartTime": "Never",
            "LastStartTime": "Never",
            "Name": "Trace - Start Session [Linux]",
            "NextStartTime": "Never",
            "PackageId": 728,
            "PackageName": "Trace - Start Session [Linux]",
            "PackageSourceHash": "f3931b6451967b74b522887e1f00f4a59b2fae730a5c277577bb804c7f484c61",
            "StartTime": "2019-09-25T16:57:31Z",
            "Status": 0,
            "TargetGroupId": 14652,
            "UserId": 1,
            "UserName": "administrator"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>Saved actions</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>ActionGroupId</strong></th>
        <th><strong>ApprovedFlag</strong></th>
        <th><strong>ApproverId</strong></th>
        <th><strong>ApproverName</strong></th>
        <th><strong>CreationTime</strong></th>
        <th><strong>EndTime</strong></th>
        <th><strong>ExpireSeconds</strong></th>
        <th><strong>ID</strong></th>
        <th><strong>LastActionId</strong></th>
        <th><strong>LastActionStartTime</strong></th>
        <th><strong>LastStartTime</strong></th>
        <th><strong>Name</strong></th>
        <th><strong>NextStartTime</strong></th>
        <th><strong>PackageId</strong></th>
        <th><strong>PackageName</strong></th>
        <th><strong>PackageSourceHash</strong></th>
        <th><strong>StartTime</strong></th>
        <th><strong>Status</strong></th>
        <th><strong>TargetGroupId</strong></th>
        <th><strong>UserId</strong></th>
        <th><strong>UserName</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> 432 </td>
        <td> false </td>
        <td> 0 </td>
        <td> </td>
        <td> 2019-09-25T16:56:59Z </td>
        <td> Never </td>
        <td> 600 </td>
        <td> 353 </td>
        <td> 7206 </td>
        <td> Never </td>
        <td> Never </td>
        <td> Trace - Start Session [Linux] </td>
        <td> Never </td>
        <td> 728 </td>
        <td> Trace - Start Session [Linux] </td>
        <td> f3931b6451967b74b522887e1f00f4a59b2fae730a5c277577bb804c7f484c61 </td>
        <td> 2019-09-25T16:57:31Z </td>
        <td> 0 </td>
        <td> 14652 </td>
        <td> 1 </td>
        <td> administrator </td>
      </tr>
    </tbody>
  </table>
</p>

<h3 id="tn-get-saved-action">14. tn-get-saved-action</h3>
<hr>
<p>Returns a saved action object based on name or ID.</p>
<h5>Base Command</h5>
<p>
  <code>tn-get-saved-action</code>
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
      <td>id</td>
      <td>The saved action ID.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>name</td>
      <td>The saved action name.</td>
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
      <td>Tanium.SavedAction.ActionGroupId</td>
      <td>Number</td>
      <td>The ID of the group of clients to target.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.ApprovedFlag</td>
      <td>Boolean</td>
      <td>Whether the saved action is approved. True is approved.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.ApproverId</td>
      <td>Number</td>
      <td>The ID of the user to approve the saved action.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.ApproverName</td>
      <td>String</td>
      <td>The name of the user to approve the saved action.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.CreationTime</td>
      <td>Date</td>
      <td>The time and date when this object was created in the database.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.EndTime</td>
      <td>Date</td>
      <td>The time and date to stop issuing actions.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.ExpireSeconds</td>
      <td>Number</td>
      <td>The duration from the start time before the action expires.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.ID</td>
      <td>Number</td>
      <td>The unique ID of the saved_action object.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.LastActionId</td>
      <td>Number</td>
      <td>The ID of the action object that was issued last.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.LastActionStartTime</td>
      <td>Date</td>
      <td>The start time and date of the action object that was issued last.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.LastAaction.TargetGroupId</td>
      <td>Number</td>
      <td>The target group of the action object that was issued last.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.LastStartTime</td>
      <td>Date</td>
      <td>The most recent date and time that the action started.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.Name</td>
      <td>String</td>
      <td>The name of the saved action object.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.NextStartTime</td>
      <td>Date</td>
      <td>The next time and date when the action will start.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.PackageId</td>
      <td>Number</td>
      <td>The ID of the package deployed by the saved action.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.PackageName</td>
      <td>String</td>
      <td>The name of the package deployed by the saved action.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.PackageSourceHash</td>
      <td>String</td>
      <td>The source hash of the package deployed by the saved action.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.StartTime</td>
      <td>Date</td>
      <td>The time amd date when the action became active. An empty string or null starts immediately.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.Status</td>
      <td>Number</td>
      <td>The status of the saved action. Can be: "0" for Enabled, "1" for Disabled, or "2" for Deleted.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.TargetGroupId</td>
      <td>Number</td>
      <td>The group of machines to target.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.UserId</td>
      <td>Number</td>
      <td>The ID of the user who created the saved action.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.UserName</td>
      <td>String</td>
      <td>The ID of the user who created the saved action.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-get-saved-action id=5</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.SavedAction": {
        "ActionGroupId": 315,
        "ApprovedFlag": true,
        "ApproverId": 1,
        "ApproverName": "administrator",
        "CreationTime": "2019-07-17T20:14:36Z",
        "EndTime": "Never",
        "ExpireSeconds": 4500,
        "ID": 5,
        "LastActionId": 5,
        "LastActionStartTime": "Never",
        "LastStartTime": "Never",
        "Name": "Distribute Python - Tools [Linux]",
        "NextStartTime": "2019-11-27T16:14:38",
        "PackageId": 56,
        "PackageName": "Python - Tools [Linux]",
        "PackageSourceHash": "package-hash",
        "StartTime": "2019-07-17T20:14:38Z",
        "Status": 1,
        "TargetGroupId": 243,
        "UserId": 1,
        "UserName": "administrator"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>Saved action information</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>ActionGroupId</strong></th>
        <th><strong>ApprovedFlag</strong></th>
        <th><strong>ApproverId</strong></th>
        <th><strong>ApproverName</strong></th>
        <th><strong>CreationTime</strong></th>
        <th><strong>EndTime</strong></th>
        <th><strong>ExpireSeconds</strong></th>
        <th><strong>ID</strong></th>
        <th><strong>LastActionId</strong></th>
        <th><strong>LastActionStartTime</strong></th>
        <th><strong>LastStartTime</strong></th>
        <th><strong>Name</strong></th>
        <th><strong>NextStartTime</strong></th>
        <th><strong>PackageId</strong></th>
        <th><strong>PackageName</strong></th>
        <th><strong>PackageSourceHash</strong></th>
        <th><strong>StartTime</strong></th>
        <th><strong>Status</strong></th>
        <th><strong>TargetGroupId</strong></th>
        <th><strong>UserId</strong></th>
        <th><strong>UserName</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> 315 </td>
        <td> true </td>
        <td> 1 </td>
        <td> administrator </td>
        <td> 2019-07-17T20:14:36Z </td>
        <td> Never </td>
        <td> 4500 </td>
        <td> 5 </td>
        <td> 5 </td>
        <td> Never </td>
        <td> Never </td>
        <td> Distribute Python - Tools [Linux] </td>
        <td> 2019-11-27T16:14:38 </td>
        <td> 56 </td>
        <td> Python - Tools [Linux] </td>
        <td> 10d2ca59b744491a80af4f4df7e19698b86cc779c34984aa56ece55250f1b659 </td>
        <td> 2019-07-17T20:14:38Z </td>
        <td> 1 </td>
        <td> 243 </td>
        <td> 1 </td>
        <td> administrator </td>
      </tr>
    </tbody>
  </table>
</p>

<h3 id="tn-get-saved-question-metadata">15. tn-get-saved-question-metadata</h3>
<hr>
<p>Returns a saved question object based on name or ID.</p>
<h5>Base Command</h5>
<p>
  <code>tn-get-saved-question-metadata</code>
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
      <td>question-id</td>
      <td>The saved question ID.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>question-name</td>
      <td>The saved question name.</td>
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
      <td>Tanium.SavedQuestion.ArchiveEnabledFlag</td>
      <td>Boolean</td>
      <td>Whether to enable archiving.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.ArchiveOwner</td>
      <td>String</td>
      <td>The name of the user that owns the archive. Archives can be shared between users with identical management
        rights groups.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.ExpireSeconds</td>
      <td>Number</td>
      <td>The duration in seconds before each question expires. Default value is 600.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.ID</td>
      <td>Number</td>
      <td>The unique ID of the saved_question object.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.IssueSeconds</td>
      <td>Number</td>
      <td>The number of seconds to reissue the question when active. Default value is 120.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.IssueSecondsNeverFlag</td>
      <td>Boolean</td>
      <td>Whether the question is reissued automatically. If value is 1, the question is not reissued automatically.
      </td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.KeepSeconds</td>
      <td>Number</td>
      <td>The number of seconds to save the data results in the archive.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.ModTime</td>
      <td>String</td>
      <td>The most recent time and date when the object was modified.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.ModUserDomain</td>
      <td>String</td>
      <td>The domain of the user who most recently modified this object.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.ModUserId</td>
      <td>Number</td>
      <td>The ID of the user who most recently modified this object.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.ModUserName</td>
      <td>String</td>
      <td>The name of user who most recently modified this object.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.MostRecentQuestionId</td>
      <td>Number</td>
      <td>The ID of the most recently issued question object generated by this saved_question.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.Name</td>
      <td>String</td>
      <td>The name of the saved_question object.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.QueryText</td>
      <td>String</td>
      <td>The textual representation of the question.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.QuestionId</td>
      <td>Number</td>
      <td>The ID of the question from which to create the saved question.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.RowCountFlag</td>
      <td>Boolean</td>
      <td>Whether the row count data is saved when archiving this question.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.SortColumn</td>
      <td>Number</td>
      <td>The column to use as the default sort column, if no sort order is specified.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.UserId</td>
      <td>Number</td>
      <td>The ID of the user who owns this object.</td>
    </tr>
    <tr>
      <td>Tanium.SavedQuestion.UserName</td>
      <td>String</td>
      <td>The name of the user who owns this object.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-get-saved-question-metadata question-id=130</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.SavedQuestion": {
        "ArchiveEnabledFlag": false,
        "ExpireSeconds": 600,
        "ID": 130,
        "IssueSeconds": 120,
        "IssueSecondsNeverFlag": false,
        "KeepSeconds": 0,
        "ModTime": "2019-07-17T20:43:06Z",
        "MostRecentQuestionId": 50501,
        "Name": "SCCM - Client Cache Size",
        "QueryText": "Get SCCM Cache Size from all machines",
        "QuestionId": 50501,
        "RowCountFlag": false,
        "SortColumn": 0,
        "UserId": 1,
        "UserName": "administrator"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>Saved question information</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>ArchiveEnabledFlag</strong></th>
        <th><strong>ExpireSeconds</strong></th>
        <th><strong>ID</strong></th>
        <th><strong>IssueSeconds</strong></th>
        <th><strong>IssueSecondsNeverFlag</strong></th>
        <th><strong>KeepSeconds</strong></th>
        <th><strong>ModTime</strong></th>
        <th><strong>MostRecentQuestionId</strong></th>
        <th><strong>Name</strong></th>
        <th><strong>QueryText</strong></th>
        <th><strong>QuestionId</strong></th>
        <th><strong>RowCountFlag</strong></th>
        <th><strong>SortColumn</strong></th>
        <th><strong>UserId</strong></th>
        <th><strong>UserName</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> false </td>
        <td> 600 </td>
        <td> 130 </td>
        <td> 120 </td>
        <td> false </td>
        <td> 0 </td>
        <td> 2019-07-17T20:43:06Z </td>
        <td> 50501 </td>
        <td> SCCM - Client Cache Size </td>
        <td> Get SCCM Cache Size from all machines </td>
        <td> 50501 </td>
        <td> false </td>
        <td> 0 </td>
        <td> 1 </td>
        <td> administrator </td>
      </tr>
    </tbody>
  </table>
</p>

<h3 id="tn-create-saved-action">16. tn-create-saved-action</h3>
<hr>
<p>Creates a saved action object.</p>
<h5>Base Command</h5>
<p>
  <code>tn-create-saved-action</code>
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
      <td>action-group-id</td>
      <td>The action group ID.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>package-id</td>
      <td>The package ID.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>name</td>
      <td>The name of the action.</td>
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
      <td>Tanium.SavedAction.ActionGroupId</td>
      <td>Number</td>
      <td>The ID of the group of clients to target.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.ApprovedFlag</td>
      <td>Boolean</td>
      <td>Whether the saved action is approved. True is approved.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.ApproverId</td>
      <td>Number</td>
      <td>The ID of the user to approve the saved action.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.ApproverName</td>
      <td>String</td>
      <td>The name of the user to approve the saved action.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.CreationTime</td>
      <td>Date</td>
      <td>The date and time when this object was created in the database.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.EndTime</td>
      <td>Date</td>
      <td>The date and time to stop issuing actions.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.ExpireSeconds</td>
      <td>Number</td>
      <td>The duration from the start time before the action expires.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.ID</td>
      <td>Number</td>
      <td>The unique ID of the saved_action object.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.LastActionId</td>
      <td>Number</td>
      <td>The ID of the action object that was issued last.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.LastActionStartTime</td>
      <td>Date</td>
      <td>The start time of the action object that was issued last.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.LastAaction.TargetGroupId</td>
      <td>Number</td>
      <td>The target group of the action object that was issued last.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.LastStartTime</td>
      <td>Date</td>
      <td>The most recent date and time that the action started.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.Name</td>
      <td>String</td>
      <td>The name of the saved action object.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.NextStartTime</td>
      <td>Date</td>
      <td>The next date and time when the action will start.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.PackageId</td>
      <td>Number</td>
      <td>The ID of the package deployed by the saved action.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.PackageName</td>
      <td>String</td>
      <td>The name of the package deployed by the saved action.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.PackageSourceHash</td>
      <td>String</td>
      <td>The source hash of the package deployed by the saved action.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.StartTime</td>
      <td>Date</td>
      <td>The date and time when the action became active. An empty string or null starts immediately.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.Status</td>
      <td>Number</td>
      <td>The status of the saved action. Can be: "0" for Enabled, "1" for Disabled, or "2" for Deleted.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.TargetGroupId</td>
      <td>Number</td>
      <td>The group of machines to target.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.UserId</td>
      <td>Number</td>
      <td>The ID of the user who created the saved action.</td>
    </tr>
    <tr>
      <td>Tanium.SavedAction.UserName</td>
      <td>String</td>
      <td>The ID of the user who created the saved action.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-create-saved-action package-id=102 action-group-id=1</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.SavedAction": {
        "ActionGroupId": 1,
        "ApprovedFlag": false,
        "ApproverId": 0,
        "CreationTime": "2019-11-27T15:06:18Z",
        "EndTime": "Never",
        "ExpireSeconds": 0,
        "ID": 641,
        "LastActionId": 19880,
        "LastActionStartTime": "Never",
        "LastStartTime": "Never",
        "NextStartTime": "Never",
        "PackageId": 1221,
        "PackageName": "SCCM - Force Software Update Compliance State Refresh",
        "PackageSourceHash": "package-hash",
        "StartTime": "2019-11-27T15:06:18Z",
        "Status": 0,
        "TargetGroupId": 0,
        "UserId": 1,
        "UserName": "administrator"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>Saved action created</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>ActionGroupId</strong></th>
        <th><strong>ApprovedFlag</strong></th>
        <th><strong>ApproverId</strong></th>
        <th><strong>CreationTime</strong></th>
        <th><strong>EndTime</strong></th>
        <th><strong>ExpireSeconds</strong></th>
        <th><strong>ID</strong></th>
        <th><strong>LastActionId</strong></th>
        <th><strong>LastActionStartTime</strong></th>
        <th><strong>LastStartTime</strong></th>
        <th><strong>NextStartTime</strong></th>
        <th><strong>PackageId</strong></th>
        <th><strong>PackageName</strong></th>
        <th><strong>PackageSourceHash</strong></th>
        <th><strong>StartTime</strong></th>
        <th><strong>Status</strong></th>
        <th><strong>TargetGroupId</strong></th>
        <th><strong>UserId</strong></th>
        <th><strong>UserName</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> 1 </td>
        <td> false </td>
        <td> 0 </td>
        <td> 2019-11-27T15:06:18Z </td>
        <td> Never </td>
        <td> 0 </td>
        <td> 641 </td>
        <td> 19880 </td>
        <td> Never </td>
        <td> Never </td>
        <td> Never </td>
        <td> 1221 </td>
        <td> SCCM - Force Software Update Compliance State Refresh </td>
        <td> edbf105f4648298e582015aaed927cbf3e8bbbc3666c5d52c7c5e5ad1910ae6a </td>
        <td> 2019-11-27T15:06:18Z </td>
        <td> 0 </td>
        <td> 0 </td>
        <td> 1 </td>
        <td> administrator </td>
      </tr>
    </tbody>
  </table>
</p>

<h3 id="tn-create-action">17. tn-create-action</h3>
<hr>
<p>Creates an action object based on the package name or the package ID.</p>
<h5>Base Command</h5>
<p>
  <code>tn-create-action</code>
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
      <td>package-id</td>
      <td>The package ID.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>package-name</td>
      <td>The package name.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>parameters</td>
      <td>The package parameters. For example, $1=Value1;$2=Value2;$3=Value3.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>target-group-id</td>
      <td>The target group ID to deploy the package.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>target-group-name</td>
      <td>The target group name to deploy the package. Target group and action group ID are required. Target group can
        passed by name or ID. Note - the target group should be different than "All Computers" or "Default".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>action-group-id</td>
      <td>The action group ID to deploy the package.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>action-name</td>
      <td>The action name.</td>
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
      <td>Tanium.Action.ActionGroupId</td>
      <td>Number</td>
      <td>The id of the parent group of machines to target.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ActionGroupName</td>
      <td>String</td>
      <td>The name of the parent group of machines to target.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ApproverId</td>
      <td>Number</td>
      <td>The id of the approver of this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ApproverName</td>
      <td>String</td>
      <td>The name of the approver of this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.CreationTime</td>
      <td>Date</td>
      <td>The date and time when this object was created in the database.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ExpirationTime</td>
      <td>Date</td>
      <td>The date and time when the action expires.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ExpireSeconds</td>
      <td>Number</td>
      <td>The timeout in seconds for the action expiry.</td>
    </tr>
    <tr>
      <td>Tanium.Action.HistorySavedQuestionId</td>
      <td>Number</td>
      <td>The ID of the saved question that tracks the results of the action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ID</td>
      <td>Number</td>
      <td>The unique ID of the action object.</td>
    </tr>
    <tr>
      <td>Tanium.Action.Name</td>
      <td>String</td>
      <td>The action name.</td>
    </tr>
    <tr>
      <td>Tanium.Action.PackageId</td>
      <td>Number</td>
      <td>The ID of the package deployed by this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.PackageName</td>
      <td>String</td>
      <td>The name of the package deployed by this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.SavedActionId</td>
      <td>Number</td>
      <td>The ID of the saved action that this action was issued from, if any.</td>
    </tr>
    <tr>
      <td>Tanium.Action.StartTime</td>
      <td>String</td>
      <td>The date and time when the action became active.</td>
    </tr>
    <tr>
      <td>Tanium.Action.Status</td>
      <td>String</td>
      <td>The status of the action. Can be: "Pending", "Active", "Stopped", or "Expired".</td>
    </tr>
    <tr>
      <td>Tanium.Action.StoppedFlag</td>
      <td>Boolean</td>
      <td>Whether an action stop has been issued for this action. A value of true indicates an action stop was issued.
      </td>
    </tr>
    <tr>
      <td>Tanium.Action.TargetGroupId</td>
      <td>Number</td>
      <td>The ID of the group of machines to target.</td>
    </tr>
    <tr>
      <td>Tanium.Action.TargetGroupName</td>
      <td>String</td>
      <td>The name of the group of machines to target.</td>
    </tr>
    <tr>
      <td>Tanium.Action.UserDomain</td>
      <td>String</td>
      <td>The domain of the user who issued this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.UserId</td>
      <td>Number</td>
      <td>The ID of the user who issued this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.UserName</td>
      <td>String</td>
      <td>The name of the user who issued this action.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-create-action action-group-id=1 action-name=`Trace - Install Endpoint Certificate [Windows]` package-id=225 target-group-name=`Windows machines`</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.Action": {
        "ActionGroupId": 1,
        "ActionGroupName": "All Computers",
        "ApproverId": 1,
        "CreationTime": "2019-11-27T15:06:19Z",
        "ExpirationTime": "2001-01-01T00:13:00Z",
        "ExpireSeconds": 780,
        "HistorySavedQuestionId": 0,
        "ID": 19886,
        "Name": "Trace - Install Endpoint Certificate [Windows] via Demisto API",
        "PackageId": 1222,
        "PackageName": "Apply Windows IPsec Quarantine",
        "SavedActionId": 642,
        "StartTime": "2001-01-01T00:00:00Z",
        "Status": "Pending",
        "StoppedFlag": false,
        "TargetGroupId": 11719,
        "TargetGroupName": "Windows machines",
        "UserDomain": "EC2AMAZ-N5ETQVT",
        "UserId": 1,
        "UserName": "administrator"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>Action created</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>ActionGroupId</strong></th>
        <th><strong>ActionGroupName</strong></th>
        <th><strong>ApproverId</strong></th>
        <th><strong>ApproverName</strong></th>
        <th><strong>CreationTime</strong></th>
        <th><strong>ExpirationTime</strong></th>
        <th><strong>ExpireSeconds</strong></th>
        <th><strong>HistorySavedQuestionId</strong></th>
        <th><strong>ID</strong></th>
        <th><strong>Name</strong></th>
        <th><strong>PackageId</strong></th>
        <th><strong>PackageName</strong></th>
        <th><strong>SavedActionId</strong></th>
        <th><strong>StartTime</strong></th>
        <th><strong>Status</strong></th>
        <th><strong>StoppedFlag</strong></th>
        <th><strong>TargetGroupId</strong></th>
        <th><strong>TargetGroupName</strong></th>
        <th><strong>UserDomain</strong></th>
        <th><strong>UserId</strong></th>
        <th><strong>UserName</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> 1 </td>
        <td> All Computers </td>
        <td> 1 </td>
        <td> </td>
        <td> 2019-11-27T15:06:19Z </td>
        <td> 2001-01-01T00:13:00Z </td>
        <td> 780 </td>
        <td> 0 </td>
        <td> 19886 </td>
        <td> Trace - Install Endpoint Certificate [Windows] via Demisto API </td>
        <td> 1222 </td>
        <td> Apply Windows IPsec Quarantine </td>
        <td> 642 </td>
        <td> 2001-01-01T00:00:00Z </td>
        <td> Pending </td>
        <td> false </td>
        <td> 11719 </td>
        <td> Windows machines </td>
        <td> EC2AMAZ-N5ETQVT </td>
        <td> 1 </td>
        <td> administrator </td>
      </tr>
    </tbody>
  </table>
</p>

<h3 id="tn-list-actions">18. tn-list-actions</h3>
<hr>
<p>Returns all actions.</p>
<h5>Base Command</h5>
<p>
  <code>tn-list-actions</code>
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
      <td>limit</td>
      <td>The maximum number of actions to return.</td>
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
      <td>Tanium.Action.ActionGroupId</td>
      <td>Number</td>
      <td>The ID of the parent group of machines to target.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ActionGroupName</td>
      <td>String</td>
      <td>The name of the parent group of machines to target.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ApproverId</td>
      <td>Number</td>
      <td>The ID of the approver of this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ApproverName</td>
      <td>String</td>
      <td>The name of the approver of this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.CreationTime</td>
      <td>Date</td>
      <td>The date and time when this object was created in the database.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ExpirationTime</td>
      <td>Date</td>
      <td>The date and time when the action expires.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ExpireSeconds</td>
      <td>Number</td>
      <td>The timeout in seconds for the action expiry.</td>
    </tr>
    <tr>
      <td>Tanium.Action.HistorySavedQuestionId</td>
      <td>Number</td>
      <td>The ID of the saved question that tracks the results of the action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ID</td>
      <td>Number</td>
      <td>The unique ID of the action object.</td>
    </tr>
    <tr>
      <td>Tanium.Action.Name</td>
      <td>String</td>
      <td>The action name.</td>
    </tr>
    <tr>
      <td>Tanium.Action.PackageId</td>
      <td>Number</td>
      <td>The ID of the package deployed by this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.PackageName</td>
      <td>String</td>
      <td>The name of the package deployed by this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.SavedActionId</td>
      <td>Number</td>
      <td>The ID of the saved action that this action was issued from, if any.</td>
    </tr>
    <tr>
      <td>Tanium.Action.StartTime</td>
      <td>String</td>
      <td>The date and time when the action became active.</td>
    </tr>
    <tr>
      <td>Tanium.Action.Status</td>
      <td>String</td>
      <td>The status of the action. Can be: "Pending", "Active", "Stopped", or "Expired".</td>
    </tr>
    <tr>
      <td>Tanium.Action.StoppedFlag</td>
      <td>Boolean</td>
      <td>Whether an action stop has been issued for this action. A value of true indicates an action stop was issued.
      </td>
    </tr>
    <tr>
      <td>Tanium.Action.TargetGroupId</td>
      <td>Number</td>
      <td>The ID of the group of machines to target.</td>
    </tr>
    <tr>
      <td>Tanium.Action.TargetGroupName</td>
      <td>String</td>
      <td>The name of the group of machines to target.</td>
    </tr>
    <tr>
      <td>Tanium.Action.UserDomain</td>
      <td>String</td>
      <td>The domain of the user who issued this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.UserId</td>
      <td>Number</td>
      <td>The ID of the user who issued this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.UserName</td>
      <td>String</td>
      <td>The name of the user who issued this action.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-list-actions limit=1</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.Action": [
        {
            "ActionGroupId": 432,
            "ActionGroupName": "Tanium Threat Response",
            "ApproverId": 1,
            "ApproverName": "administrator",
            "CreationTime": "2019-08-15T10:39:03Z",
            "ExpirationTime": "2019-08-15T10:50:03Z",
            "ExpireSeconds": 660,
            "HistorySavedQuestionId": 239,
            "ID": 1144,
            "Name": "Trace - Install Endpoint Certificate [Windows]",
            "PackageId": 220,
            "PackageName": "Trace - Install Endpoint Certificate [Windows]",
            "SavedActionId": 31,
            "StartTime": "2019-08-15T10:39:03Z",
            "Status": "Closed",
            "StoppedFlag": false,
            "TargetGroupId": 423,
            "TargetGroupName": "Default",
            "UserDomain": "EC2AMAZ-N5ETQVT",
            "UserId": 1,
            "UserName": "administrator"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>Actions</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>ActionGroupId</strong></th>
        <th><strong>ActionGroupName</strong></th>
        <th><strong>ApproverId</strong></th>
        <th><strong>ApproverName</strong></th>
        <th><strong>CreationTime</strong></th>
        <th><strong>ExpirationTime</strong></th>
        <th><strong>ExpireSeconds</strong></th>
        <th><strong>HistorySavedQuestionId</strong></th>
        <th><strong>ID</strong></th>
        <th><strong>Name</strong></th>
        <th><strong>PackageId</strong></th>
        <th><strong>PackageName</strong></th>
        <th><strong>SavedActionId</strong></th>
        <th><strong>StartTime</strong></th>
        <th><strong>Status</strong></th>
        <th><strong>StoppedFlag</strong></th>
        <th><strong>TargetGroupId</strong></th>
        <th><strong>TargetGroupName</strong></th>
        <th><strong>UserDomain</strong></th>
        <th><strong>UserId</strong></th>
        <th><strong>UserName</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> 432 </td>
        <td> Tanium Threat Response </td>
        <td> 1 </td>
        <td> administrator </td>
        <td> 2019-08-15T10:39:03Z </td>
        <td> 2019-08-15T10:50:03Z </td>
        <td> 660 </td>
        <td> 239 </td>
        <td> 1144 </td>
        <td> Trace - Install Endpoint Certificate [Windows] </td>
        <td> 220 </td>
        <td> Trace - Install Endpoint Certificate [Windows] </td>
        <td> 31 </td>
        <td> 2019-08-15T10:39:03Z </td>
        <td> Closed </td>
        <td> false </td>
        <td> 423 </td>
        <td> Default </td>
        <td> EC2AMAZ-N5ETQVT </td>
        <td> 1 </td>
        <td> administrator </td>
      </tr>
    </tbody>
  </table>
</p>

<h3 id="tn-get-action">19. tn-get-action</h3>
<hr>
<p>Returns an action object based on ID.</p>
<h5>Base Command</h5>
<p>
  <code>tn-get-action</code>
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
      <td>id</td>
      <td>The action ID.</td>
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
      <td>Tanium.Action.ActionGroupId</td>
      <td>Number</td>
      <td>The ID of the parent group of machines to target.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ActionGroupName</td>
      <td>String</td>
      <td>The name of the parent group of machines to target.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ApproverId</td>
      <td>Number</td>
      <td>The ID of the approver of this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ApproverName</td>
      <td>String</td>
      <td>The name of the approver of this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.CreationTime</td>
      <td>Date</td>
      <td>The date and time when this object was created in the database.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ExpirationTime</td>
      <td>Date</td>
      <td>The date and time when the action expires.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ExpireSeconds</td>
      <td>Number</td>
      <td>The timeout in seconds for the action expiry.</td>
    </tr>
    <tr>
      <td>Tanium.Action.HistorySavedQuestionId</td>
      <td>Number</td>
      <td>The ID of the saved question that tracks the results of the action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ID</td>
      <td>Number</td>
      <td>The unique ID of the action object.</td>
    </tr>
    <tr>
      <td>Tanium.Action.Name</td>
      <td>String</td>
      <td>The action name.</td>
    </tr>
    <tr>
      <td>Tanium.Action.PackageId</td>
      <td>Number</td>
      <td>The ID of the package deployed by this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.PackageName</td>
      <td>String</td>
      <td>The name of the package deployed by this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.SavedActionId</td>
      <td>Number</td>
      <td>The ID of the saved action that this action was issued from, if any.</td>
    </tr>
    <tr>
      <td>Tanium.Action.StartTime</td>
      <td>String</td>
      <td>The date and time when the action became active.</td>
    </tr>
    <tr>
      <td>Tanium.Action.Status</td>
      <td>String</td>
      <td>The status of the action. Can be: "Pending", "Active", "Stopped", or "Expired".</td>
    </tr>
    <tr>
      <td>Tanium.Action.StoppedFlag</td>
      <td>Boolean</td>
      <td>Whether an action stop has been issued for this action. A value of true indicates an action stop was issued.
      </td>
    </tr>
    <tr>
      <td>Tanium.Action.TargetGroupId</td>
      <td>Number</td>
      <td>The ID of the group of machines to target.</td>
    </tr>
    <tr>
      <td>Tanium.Action.TargetGroupName</td>
      <td>String</td>
      <td>The name of the group of machines to target.</td>
    </tr>
    <tr>
      <td>Tanium.Action.UserDomain</td>
      <td>String</td>
      <td>The domain of the user who issued this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.UserId</td>
      <td>Number</td>
      <td>The ID of the user who issued this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.UserName</td>
      <td>String</td>
      <td>The name of the user who issued this action.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-get-action id=2</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.Action": {
        "ActionGroupId": 3,
        "ActionGroupName": "Default",
        "ApproverId": 1,
        "ApproverName": "administrator",
        "CreationTime": "2018-12-10T13:21:01Z",
        "ExpirationTime": "2018-12-10T14:26:57Z",
        "ExpireSeconds": 3900,
        "HistorySavedQuestionId": 19,
        "ID": 2,
        "Name": "Distribute Tanium Standard Utilities (Linux)",
        "PackageId": 21,
        "PackageName": "Distribute Tanium Standard Utilities (Linux)",
        "SavedActionId": 2,
        "StartTime": "2018-12-10T13:21:57Z",
        "Status": "Closed",
        "StoppedFlag": false,
        "TargetGroupId": 15,
        "TargetGroupName": "Default",
        "UserDomain": "EC2AMAZ-N5ETQVT",
        "UserId": 1,
        "UserName": "administrator"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>Action information</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>ActionGroupId</strong></th>
        <th><strong>ActionGroupName</strong></th>
        <th><strong>ApproverId</strong></th>
        <th><strong>ApproverName</strong></th>
        <th><strong>CreationTime</strong></th>
        <th><strong>ExpirationTime</strong></th>
        <th><strong>ExpireSeconds</strong></th>
        <th><strong>HistorySavedQuestionId</strong></th>
        <th><strong>ID</strong></th>
        <th><strong>Name</strong></th>
        <th><strong>PackageId</strong></th>
        <th><strong>PackageName</strong></th>
        <th><strong>SavedActionId</strong></th>
        <th><strong>StartTime</strong></th>
        <th><strong>Status</strong></th>
        <th><strong>StoppedFlag</strong></th>
        <th><strong>TargetGroupId</strong></th>
        <th><strong>TargetGroupName</strong></th>
        <th><strong>UserDomain</strong></th>
        <th><strong>UserId</strong></th>
        <th><strong>UserName</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> 3 </td>
        <td> Default </td>
        <td> 1 </td>
        <td> administrator </td>
        <td> 2018-12-10T13:21:01Z </td>
        <td> 2018-12-10T14:26:57Z </td>
        <td> 3900 </td>
        <td> 19 </td>
        <td> 2 </td>
        <td> Distribute Tanium Standard Utilities (Linux) </td>
        <td> 21 </td>
        <td> Distribute Tanium Standard Utilities (Linux) </td>
        <td> 2 </td>
        <td> 2018-12-10T13:21:57Z </td>
        <td> Closed </td>
        <td> false </td>
        <td> 15 </td>
        <td> Default </td>
        <td> EC2AMAZ-N5ETQVT </td>
        <td> 1 </td>
        <td> administrator </td>
      </tr>
    </tbody>
  </table>
</p>

<h3 id="tn-list-saved-actions-pending-approval">20. tn-list-saved-actions-pending-approval</h3>
<hr>
<p>Retrieves all saved action approval definitions on the server.</p>
<h5>Base Command</h5>
<p>
  <code>tn-list-saved-actions-pending-approval</code>
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
      <td>limit</td>
      <td>The maximum number of saved actions to return.</td>
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
      <td>Tanium.PendingSavedAction.ApprovedFlag</td>
      <td>Boolean</td>
      <td>Whether the saved action is approved. True is approved.</td>
    </tr>
    <tr>
      <td>Tanium.PendingSavedAction.ID</td>
      <td>Number</td>
      <td>The unique ID of the saved action object.</td>
    </tr>
    <tr>
      <td>Tanium.PendingSavedAction.Name</td>
      <td>String</td>
      <td>The name of the saved action object.</td>
    </tr>
    <tr>
      <td>Tanium.PendingSavedAction.OwnerUserId</td>
      <td>Number</td>
      <td>The ID of the user who owns this object.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-list-saved-actions-pending-approval limit=1</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.PendingSavedAction": [
        {
            "ApprovedFlag": false,
            "ID": 164,
            "Name": "Deploy Kill Process",
            "OwnerUserId": 1
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>Saved actions pending approval</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>ApprovedFlag</strong></th>
        <th><strong>ID</strong></th>
        <th><strong>Name</strong></th>
        <th><strong>OwnerUserId</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> false </td>
        <td> 164 </td>
        <td> Deploy Kill Process </td>
        <td> 1 </td>
      </tr>
    </tbody>
  </table>
</p>

<h3 id="tn-get-group">21. tn-get-group</h3>
<hr>
<p>Returns a group object based on ID or name.</p>
<h5>Base Command</h5>
<p>
  <code>tn-get-group</code>
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
      <td>id</td>
      <td>The group ID.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>name</td>
      <td>Name of group.</td>
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
      <td>Tanium.Group.ID</td>
      <td>Unknown</td>
      <td>The unique ID of the group object.</td>
    </tr>
    <tr>
      <td>Tanium.Group.Name</td>
      <td>String</td>
      <td>The name of the group.</td>
    </tr>
    <tr>
      <td>Tanium.Group.Text</td>
      <td>String</td>
      <td>A description of the clients that this group represents.</td>
    </tr>
    <tr>
      <td>Tanium.Group.Type</td>
      <td>String</td>
      <td>The type of the group.</td>
    </tr>
    <tr>
      <td>Tanium.Group.Deleted</td>
      <td>Boolean</td>
      <td>Whether the group is deleted. True if deleted.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-get-group name=`linux machines`</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.Group": {
        "Deleted": false,
        "ID": 11721,
        "Name": "linux machines",
        "Text": " OS Platform equals linux",
        "Type": "Manual group"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>Group information</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>Deleted</strong></th>
        <th><strong>ID</strong></th>
        <th><strong>Name</strong></th>
        <th><strong>Text</strong></th>
        <th><strong>Type</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> false </td>
        <td> 11721 </td>
        <td> linux machines </td>
        <td> OS Platform equals linux </td>
        <td> Manual group </td>
      </tr>
    </tbody>
  </table>
</p>

<h3 id="tn-create-manual-group">22. tn-create-manual-group</h3>
<hr>
<p>Creates a group object based on computers or IP addresses list.</p>
<h5>Base Command</h5>
<p>
  <code>tn-create-manual-group</code>
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
      <td>group-name</td>
      <td>The name of the group to create.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>computer-names</td>
      <td>Comma separated list of hosts. For example, Host1,Host2.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>ip-addresses</td>
      <td>Comma separated list of IP addresses. For example, 12.12.12.12,10.1.1.1.</td>
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
      <td>Tanium.Group.ID</td>
      <td>Number</td>
      <td>The unique ID of the group object.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-create-manual-group group-name=group11 computer-names=host1,host2</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.Group": {
        "Deleted": false,
        "ID": 31825,
        "Name": "group11",
        "Type": "Manual group"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>Group created</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>Deleted</strong></th>
        <th><strong>ID</strong></th>
        <th><strong>Name</strong></th>
        <th><strong>Type</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> false </td>
        <td> 31825 </td>
        <td> group11 </td>
        <td> Manual group </td>
      </tr>
    </tbody>
  </table>
</p>

<h3 id="tn-create-filter-based-group">23. tn-create-filter-based-group</h3>
<hr>
<p>Creates a group object based on text filter.</p>
<h5>Base Command</h5>
<p>
  <code>tn-create-filter-based-group</code>
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
      <td>text-filter</td>
      <td>The text filter-based computer group. For example, operating system contains windows.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>group-name</td>
      <td>Name of the group to create.</td>
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
      <td>Tanium.Group.ID</td>
      <td>Number</td>
      <td>The unique ID of the group object.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-create-filter-based-group group-name=linux_machines text-filter=`operating system contains linux`</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.Group": {
        "ID": 31826,
        "Type": "Manual group"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>Group created</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>ID</strong></th>
        <th><strong>Type</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> 31826 </td>
        <td> Manual group </td>
      </tr>
    </tbody>
  </table>
</p>

<h3 id="tn-list-groups">24. tn-list-groups</h3>
<hr>
<p>Returns all groups.</p>
<h5>Base Command</h5>
<p>
  <code>tn-list-groups</code>
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
      <td>limit</td>
      <td>The maximum number of groups to return.</td>
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
      <td>Tanium.Group.ID</td>
      <td>Number</td>
      <td>The unique ID of the group object.</td>
    </tr>
    <tr>
      <td>Tanium.Group.Name</td>
      <td>String</td>
      <td>The name of the group.</td>
    </tr>
    <tr>
      <td>Tanium.Group.Text</td>
      <td>String</td>
      <td>A description of the clients that this group represents.</td>
    </tr>
    <tr>
      <td>Tanium.Group.Type</td>
      <td>String</td>
      <td>The type of the group.</td>
    </tr>
    <tr>
      <td>Tanium.Group.Deleted</td>
      <td>Boolean</td>
      <td>whether the group is deleted. True if deleted.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-list-groups limit=1</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.Group": [
        {
            "Deleted": false,
            "ID": 315,
            "Name": "Default",
            "Type": "Action group"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>Groups</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>Deleted</strong></th>
        <th><strong>ID</strong></th>
        <th><strong>Name</strong></th>
        <th><strong>Text</strong></th>
        <th><strong>Type</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> false </td>
        <td> 315 </td>
        <td> Default </td>
        <td> </td>
        <td> Action group </td>
      </tr>
    </tbody>
  </table>
</p>

<h3 id="tn-delete-group">25. tn-delete-group</h3>
<hr>
<p>Deletes a group object.</p>
<h5>Base Command</h5>
<p>
  <code>tn-delete-group</code>
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
      <td>id</td>
      <td>The group ID.</td>
      <td>Required</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-delete-group id=31822</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.Group": {
        "Deleted": true,
        "ID": 31822
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <p>
    Group has been deleted. ID = 31822
  </p>
</p>

<h3 id="tn-create-action-by-host">26. tn-create-action-by-host</h3>
<hr>
<p>Creates an action object, based on a package name or package ID.</p>
<h5>Base Command</h5>
<p>
  <code>tn-create-action-by-host</code>
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
      <td>package-id</td>
      <td>The package ID.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>package-name</td>
      <td>The package name. Target group is required and can passed by name or ID. When both exist, the ID is used. Note
        the target group should be different than "All Computers" or "Default".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>parameters</td>
      <td>Package parameters. For example, $1=Value1;$2=Value2;$3=Value3.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>action-group-id</td>
      <td>The action group ID to deploy the package.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>hostname</td>
      <td>The hostname to deploy the package. Hostname or IP address is required.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>ip-address</td>
      <td>The IP address of the host to deploy the package.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>action-name</td>
      <td>The action name.</td>
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
      <td>Tanium.Action.ActionGroupId</td>
      <td>Number</td>
      <td>The id of the parent group of machines to target.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ActionGroupName</td>
      <td>String</td>
      <td>The name of the parent group of machines to target.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ApproverId</td>
      <td>Number</td>
      <td>The id of the approver of this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ApproverName</td>
      <td>String</td>
      <td>The name of the approver of this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.CreationTime</td>
      <td>Date</td>
      <td>The date and time when this object was created in the database.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ExpirationTime</td>
      <td>Date</td>
      <td>The date and time when the action expires.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ExpireSeconds</td>
      <td>Number</td>
      <td>The timeout in seconds for the action expiry.</td>
    </tr>
    <tr>
      <td>Tanium.Action.HistorySavedQuestionId</td>
      <td>Number</td>
      <td>The ID of the saved question that tracks the results of the action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.ID</td>
      <td>Number</td>
      <td>The unique ID of the action object.</td>
    </tr>
    <tr>
      <td>Tanium.Action.Name</td>
      <td>String</td>
      <td>The action name.</td>
    </tr>
    <tr>
      <td>Tanium.Action.PackageId</td>
      <td>Number</td>
      <td>The ID of the package deployed by this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.PackageName</td>
      <td>String</td>
      <td>The name of the package deployed by this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.SavedActionId</td>
      <td>Number</td>
      <td>The ID of the saved action that this action was issued from, if any.</td>
    </tr>
    <tr>
      <td>Tanium.Action.StartTime</td>
      <td>String</td>
      <td>The date and time when the action became active.</td>
    </tr>
    <tr>
      <td>Tanium.Action.Status</td>
      <td>String</td>
      <td>The status of the action. Can be: "Pending", "Active", "Stopped", or "Expired".</td>
    </tr>
    <tr>
      <td>Tanium.Action.StoppedFlag</td>
      <td>Boolean</td>
      <td>Whether an action stop has been issued for this action. A value of true indicates an action stop was issued.
      </td>
    </tr>
    <tr>
      <td>Tanium.Action.TargetGroupId</td>
      <td>Number</td>
      <td>The ID of the group of machines to target.</td>
    </tr>
    <tr>
      <td>Tanium.Action.TargetGroupName</td>
      <td>String</td>
      <td>The name of the group of machines to target.</td>
    </tr>
    <tr>
      <td>Tanium.Action.UserDomain</td>
      <td>String</td>
      <td>The domain of the user who issued this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.UserId</td>
      <td>Number</td>
      <td>The ID of the user who issued this action.</td>
    </tr>
    <tr>
      <td>Tanium.Action.UserName</td>
      <td>String</td>
      <td>The name of the user who issued this action.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!tn-create-action-by-host action-group-id=1 action-name=`Trace - Install Endpoint Certificate [Windows]` package-id=225 ip-address=127.0.0.1</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Tanium.Action": {
        "ActionGroupId": 1,
        "ActionGroupName": "All Computers",
        "ApproverId": 1,
        "CreationTime": "2019-11-27T15:06:19Z",
        "ExpirationTime": "2001-01-01T00:13:00Z",
        "ExpireSeconds": 780,
        "HistorySavedQuestionId": 0,
        "ID": 19881,
        "Name": "Trace - Install Endpoint Certificate [Windows] via Demisto API",
        "PackageId": 1222,
        "PackageName": "Apply Windows IPsec Quarantine",
        "SavedActionId": 642,
        "StartTime": "2001-01-01T00:00:00Z",
        "Status": "Pending",
        "StoppedFlag": false,
        "TargetGroupId": 31823,
        "TargetGroupName": "Default",
        "UserDomain": "EC2AMAZ-N5ETQVT",
        "UserId": 1,
        "UserName": "administrator"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
  <h3>Action created</h3>
  <table style="width:750px" border="2" cellpadding="6">
    <thead>
      <tr>
        <th><strong>ActionGroupId</strong></th>
        <th><strong>ActionGroupName</strong></th>
        <th><strong>ApproverId</strong></th>
        <th><strong>ApproverName</strong></th>
        <th><strong>CreationTime</strong></th>
        <th><strong>ExpirationTime</strong></th>
        <th><strong>ExpireSeconds</strong></th>
        <th><strong>HistorySavedQuestionId</strong></th>
        <th><strong>ID</strong></th>
        <th><strong>Name</strong></th>
        <th><strong>PackageId</strong></th>
        <th><strong>PackageName</strong></th>
        <th><strong>SavedActionId</strong></th>
        <th><strong>StartTime</strong></th>
        <th><strong>Status</strong></th>
        <th><strong>StoppedFlag</strong></th>
        <th><strong>TargetGroupId</strong></th>
        <th><strong>TargetGroupName</strong></th>
        <th><strong>UserDomain</strong></th>
        <th><strong>UserId</strong></th>
        <th><strong>UserName</strong></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td> 1 </td>
        <td> All Computers </td>
        <td> 1 </td>
        <td> </td>
        <td> 2019-11-27T15:06:19Z </td>
        <td> 2001-01-01T00:13:00Z </td>
        <td> 780 </td>
        <td> 0 </td>
        <td> 19881 </td>
        <td> Trace - Install Endpoint Certificate [Windows] via Demisto API </td>
        <td> 1222 </td>
        <td> Apply Windows IPsec Quarantine </td>
        <td> 642 </td>
        <td> 2001-01-01T00:00:00Z </td>
        <td> Pending </td>
        <td> false </td>
        <td> 31823 </td>
        <td> Default </td>
        <td> EC2AMAZ-N5ETQVT </td>
        <td> 1 </td>
        <td> administrator </td>
      </tr>
    </tbody>
  </table>
</p>
<h2>Additional Information</h2>
<h2>Known Limitations</h2>
<h2>Troubleshooting</h2>
