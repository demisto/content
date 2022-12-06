<!-- HTML_DOC -->
<p>Use the Tanium integration to manage questions, packages, and actions.</p>
<p>This integration was integrated and tested with version 7.0.314 of Tanium v7.0.314 and Pytan v2.2.2.</p>
<h2>Configure Tanium on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Tanium.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Host URL (e.g. 1.2.3.4)</strong></li>
<li><strong>Port</strong></li>
<li><strong>Credentials</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ul>
</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.<br> After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<h3>Action Commands</h3>
<ol>
<li><a href="#h_68592942981536234345847">Parse question text: tn-ask-question</a></li>
<li><a href="#h_4702385721801536234352417">Ask a question about an endpoint: tn-ask-system</a></li>
<li><a href="#h_821282513511536234358842">Create and ask a manual question: tn-ask-manual-question</a></li>
<li><a href="#h_4182715695201536234365360">Deploy a package: tn-deploy-package</a></li>
<li><a href="#h_4505936596871536234377786">Approve pending (saved) actions: tn-approve-pending-action</a></li>
<li><a href="#h_3428607248541536234384276">Create a package object: tn-create-package</a></li>
</ol>
<h3>Information Commands</h3>
<ol>
<li><a href="#h_79985657810211536234394171">Get sensor information: tn-get-sensor</a></li>
<li><a href="#h_37447380411881536234401296">Get a package object: tn-get-package</a></li>
<li><a href="#h_84591255713541536234412259">Get a saved question: tn-get-saved-question</a></li>
<li><a href="#h_31108262815171536234424514">Get an object: tn-get-object</a></li>
<li><a href="#h_58516095916761536234433283">Get all packages: tn-get-all-packages</a></li>
<li><a href="#h_27709808918361536234459040">Get all saved questions: tn-get-all-saved-questions</a></li>
<li><a href="#h_47056289319951536234471851">Get all saved actions: tn-get-all-saved-actions</a></li>
<li><a href="#h_85977583321531536234503900">Get all pending actions: tn-get-all-pending-actions</a></li>
<li><a href="#h_95458532023101536234512462">Get all objects: tn-get-all-objects</a></li>
</ol>
<h3> Debug Commands</h3>
<ol>
<li><a href="#h_95205013124651536234522127">Request the server to parse question text: tn-parse-query</a></li>
</ol>
<h2>Action Commands</h2>
<h3 id="h_68592942981536234345847">1. Parse question text</h3>
<hr>
<p>Ask the server to parse the question text and select one of the parsed results as the question to run.</p>
<h5>Base Command</h5>
<p><code>tn-ask-question</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 153px;"><strong>Argument Name</strong></th>
<th style="width: 484px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 153px;">question</td>
<td style="width: 484px;">The question text</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 153px;">index</td>
<td style="width: 484px;">The index of the parsed question to be asked (as returned by the <em>tn-parse-query </em>command)</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 185px;"><strong>Path</strong></th>
<th style="width: 51px;"><strong>Type</strong></th>
<th style="width: 472px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 185px;">Tanium.QuestionResults</td>
<td style="width: 51px;">object</td>
<td style="width: 472px;">Results of the requested question. Can be a complex object.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>  !tn-ask-question question="Get Computer Name from all machines"
</pre>
<h5>Context Example</h5>
<pre>{
	Tanium: {
   		QuestionResults:[{
      		Computer Name: Demisto-Computer,
      		Count:1
   		}]
	}
}
</pre>
<h5>Human Readable Output</h5>
<h3>Result for parsed query - Get Computer Name from all machines</h3>
<table border="2">
<thead>
<tr>
<th>Count</th>
<th>Computer Name</th>
</tr>
</thead>
<tbody>
<tr>
<td>1</td>
<td>Demisto-Computer</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_4702385721801536234352417">2. Ask a question about an endpoint</h3>
<hr>
<p>Ask a question about a specific endpoint.</p>
<h5>Base Command</h5>
<p><code>tn-ask-system</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 297px;"><strong>Argument Name</strong></th>
<th style="width: 235px;"><strong>Description</strong></th>
<th style="width: 176px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 297px;">hostname</td>
<td style="width: 235px;">Name of host</td>
<td style="width: 176px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 175px;"><strong>Path</strong></th>
<th style="width: 52px;"><strong>Type</strong></th>
<th style="width: 481px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 175px;">Tanium.QuestionResults</td>
<td style="width: 52px;">object</td>
<td style="width: 481px;">Results of requested computer name. Can be a complex object.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tn-ask-system hostname="Demisto-Computer"</pre>
<h5>Context Example</h5>
<pre>{
	Tanium: {
   		QuestionResults:[{
      		Computer Name: Demisto-Computer,
      		Count:1
   		}]
	}
}
</pre>
<h5>Human Readable Output</h5>
<h3>Result for parsed query - Get Computer Name from all machines</h3>
<table style="width: 186px;" border="2">
<thead>
<tr>
<th style="width: 48px;">Count</th>
<th style="width: 133px;">Computer Name</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 48px;">1</td>
<td style="width: 133px;">Demisto-Computer</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_821282513511536234358842">3. Create and ask a manual question</h3>
<hr>
<p>Ask a manual question using human strings, and get the question results. Use the <em>help</em> argument for full details.</p>
<h5>Base Command</h5>
<p><code>tn-ask-manual-question</code></p>
<h5>Input</h5>
<table style="width: 742px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 155px;"><strong>Argument Name</strong></th>
<th style="width: 482px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 155px;">sensors</td>
<td style="width: 482px;">A semicolon-separated list of sensors (columns) to include in a question. For detailed information use  the <em>tn-get-sensor</em> command.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">question_filters</td>
<td style="width: 482px;">A semicolon-separated list of filters that apply to the entire question</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">question_options</td>
<td style="width: 482px;">
<p>A semicolon-separated list of options that apply to the entire question. Options are</p>
<ul>
<li>ignore_case</li>
<li>match_case</li>
<li>match_any_value</li>
<li>match_all_values</li>
<li>max_data_age</li>
<li>value_type</li>
<li>and</li>
<li>or</li>
</ul>
</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">filters_help</td>
<td style="width: 482px;">Print the help string for filters and exit</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">sensors_help</td>
<td style="width: 482px;">Print the help string for sensors and exit</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">options_help</td>
<td style="width: 482px;">Print the help string for options and exit</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">polling_secs</td>
<td style="width: 482px;">Number of seconds to wait between result fetching attempts</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">complete_pct</td>
<td style="width: 482px;">Percentage of <em>mr_tested</em> out of <em>estimated_total</em> to consider the question</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 189px;"><strong>Path</strong></th>
<th style="width: 60px;"><strong>Type</strong></th>
<th style="width: 459px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 189px;">Tanium.QuestionResults</td>
<td style="width: 60px;">object</td>
<td style="width: 459px;">Results of requested question. May be a complex object</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tn-ask-manual-question sensors="Computer Name, opt:max_data_age:60" question_filters="Index Query File Exists{fileMagicNumber=10}, that contains:No;Computer Name, that contains:WIN"</pre>
<h5>Context Example</h5>
<pre>{
	Tanium: {
   		QuestionResults:[{
      		Computer Name: Demisto-Computer,
      		Count:1
   		}]
	}
}
</pre>
<h5>Human Readable Output</h5>
<h3>Result for parsed query - Get Computer Name from all machines</h3>
<table border="2">
<thead>
<tr>
<th>Count</th>
<th>Computer Name</th>
</tr>
</thead>
<tbody>
<tr>
<td>1</td>
<td>Demisto-Computer</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_4182715695201536234365360">4. Deploy a package</h3>
<hr>
<p>Deploy a package and get the results.</p>
<h5>Base Command</h5>
<p><code>tn-deploy-package</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 151px;"><strong>Argument Name</strong></th>
<th style="width: 486px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 151px;">package</td>
<td style="width: 486px;">Name of package to deploy with this action</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 151px;">action_filters</td>
<td style="width: 486px;">A semicolon-separated list of strings. Each string must describe a sensor and a filter, which limits which computers the action will deploy package to, (e.g., <em>Operating System, that contains:Windows; Computer Name, that contains:WIN</em>)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">action_options</td>
<td style="width: 486px;">A comma-separated list of options to apply to action_filters (e.g. <em>"max_data_age:3600,and"</em>). Default is <em>or</em>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">get_results</td>
<td style="width: 486px;">Specifies whether to wait for result completion after deploying action</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">package_args</td>
<td style="width: 486px;">A comma-separated list of arguments needed to execute the package command. Run the <em>tn-get-package</em> command to view a detailed list of arguments.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">action_filters_groups</td>
<td style="width: 486px;">A comma-separated list of computer group names to filter by</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">action_group</td>
<td style="width: 486px;">Name of action group</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 361px;"><strong>Path</strong></th>
<th style="width: 90px;"><strong>Type</strong></th>
<th style="width: 257px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 361px;">Tanium.SavedActions.Id</td>
<td style="width: 90px;">string</td>
<td style="width: 257px;">Saved action ID</td>
</tr>
<tr>
<td style="width: 361px;">Tanium.SavedActions.Name</td>
<td style="width: 90px;">string</td>
<td style="width: 257px;">Saved action name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tn-deploy-package package="Comply - Remove Selected Hashes - Unix" package_args=hash1</pre>
<h5>Context Example</h5>
<pre>Tanium:{
	SavedActions:[{
		Id:1050
		Name:API Deploy Comply - Remove Selected Hashes - Unix
	}]
}
</pre>
<h5>Human Readable Output</h5>
<p><code>Id of saved action is 1050</code></p>
<p> </p>
<h3 id="h_4505936596871536234377786">5. Approve pending (saved) actions</h3>
<hr>
<p>Approve saved actions.</p>
<h5>Base Command</h5>
<p><code>tn-approve-pending-action</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 204px;"><strong>Argument Name</strong></th>
<th style="width: 384px;"><strong>Description</strong></th>
<th style="width: 120px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 204px;">action_id</td>
<td style="width: 384px;">ID of the saved action to approve</td>
<td style="width: 120px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 401px;"><strong>Path</strong></th>
<th style="width: 94px;"><strong>Type</strong></th>
<th style="width: 213px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 401px;">Tanium.ActionApproval.ApprovedFlag</td>
<td style="width: 94px;">boolean</td>
<td style="width: 213px;">Approval status</td>
</tr>
<tr>
<td style="width: 401px;">Tanium.ActionApproval.Id</td>
<td style="width: 94px;">string</td>
<td style="width: 213px;">Saved action ID</td>
</tr>
<tr>
<td style="width: 401px;">Tanium.ActionApproval.Name</td>
<td style="width: 94px;">string</td>
<td style="width: 213px;">Saved action name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tn-approve-pending-action id=1050</pre>
<h5>Context Example</h5>
<pre>Tanium:{
	ActionApproval:[{
		ApprovedFlag:1
		Id:1050
		Name:API Deploy Comply - Remove Selected Hashes - Unix
	}]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Action Approval</h3>
<table style="width: 527px;" border="2">
<thead>
<tr>
<th style="width: 100px;">ApprovedFlag</th>
<th style="width: 45px;">Id</th>
<th style="width: 376px;">Name</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 100px;">1</td>
<td style="width: 45px;">1050</td>
<td style="width: 376px;">API Deploy Comply - Remove Selected Hashes - Unix</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_3428607248541536234384276">6. Create a package object</h3>
<hr>
<p>Create a package object.</p>
<h5>Base Command</h5>
<p><code>tn-create-package</code></p>
<h5>Input</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 185px;"><strong>Argument Name</strong></th>
<th style="width: 451px;"><strong>Description</strong></th>
<th style="width: 72px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 185px;">name</td>
<td style="width: 451px;">Name of package to create</td>
<td style="width: 72px;">Required</td>
</tr>
<tr>
<td style="width: 185px;">command</td>
<td style="width: 451px;">Command to execute</td>
<td style="width: 72px;">Required</td>
</tr>
<tr>
<td style="width: 185px;">display_name</td>
<td style="width: 451px;">Display name of package</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 185px;">file_urls</td>
<td style="width: 451px;">A comma-separated list of URLs of files to add to the package</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 185px;">command_timeout_seconds</td>
<td style="width: 451px;">Timeout for command execution (in seconds)</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 185px;">expire_seconds</td>
<td style="width: 451px;">Timeout for action expiry (in seconds)</td>
<td style="width: 72px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 287px;"><strong>Path</strong></th>
<th style="width: 54px;"><strong>Type</strong></th>
<th style="width: 367px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 287px;">Tanium.Packages.verify_expire_seconds</td>
<td style="width: 54px;">string</td>
<td style="width: 367px;">Timeout for verifying the action expiry (in seconds)</td>
</tr>
<tr>
<td style="width: 287px;">Tanium.Packages.display_name</td>
<td style="width: 54px;">string</td>
<td style="width: 367px;">Display name of package</td>
</tr>
<tr>
<td style="width: 287px;">Tanium.Packages.name</td>
<td style="width: 54px;">string</td>
<td style="width: 367px;">Name of created package</td>
</tr>
<tr>
<td style="width: 287px;">Tanium.Packages.command</td>
<td style="width: 54px;">string</td>
<td style="width: 367px;">Command to execute</td>
</tr>
<tr>
<td style="width: 287px;">Tanium.Packages.creation_time</td>
<td style="width: 54px;">date</td>
<td style="width: 367px;">Package creation time</td>
</tr>
<tr>
<td style="width: 287px;">Tanium.Packages.command_timeout</td>
<td style="width: 54px;">number</td>
<td style="width: 367px;">Timeout for command execution (in seconds)</td>
</tr>
<tr>
<td style="width: 287px;">Tanium.Packages.modification_time</td>
<td style="width: 54px;">date</td>
<td style="width: 367px;">Package modification time</td>
</tr>
<tr>
<td style="width: 287px;">Tanium.Packages.last_update</td>
<td style="width: 54px;">date</td>
<td style="width: 367px;">Time when package was last updated</td>
</tr>
<tr>
<td style="width: 287px;">Tanium.Packages.deleted_flag</td>
<td style="width: 54px;">boolean</td>
<td style="width: 367px;">Was the package deleted</td>
</tr>
<tr>
<td style="width: 287px;">Tanium.Packages.id</td>
<td style="width: 54px;">string</td>
<td style="width: 367px;">Tanium unique package ID</td>
</tr>
<tr>
<td style="width: 287px;">Tanium.Packages.expire_seconds</td>
<td style="width: 54px;">number</td>
<td style="width: 367px;">Timeout for action expiry (in seconds)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tn-create-package command="cmd /c echo $1" name=ExamplePackage display_name="Example Package"</pre>
<h5>Context Example</h5>
<pre>Tanium:{
	Packages:[{
		skip_lock_flag:0
		hidden_flag:0
		verify_group_id:0
		available_time:2001-01-01T00:00:00
		last_modified_by:Shani
		verify_expire_seconds:3600
		display_name:Echo
		name:EchoPackage
		command:cmd /c echo $1
		creation_time:2018-08-23T15:22:54
		command_timeout:600
		modification_time:2018-08-23T15:22:54
		last_update:2018-08-23T15:22:54
		deleted_flag:0
		_type:package_spec
		verify_group:{}
		_type:group
		id:0
		id:771
		expire_seconds:600
		source_id:0
	}]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Tanium Package</h3>
<table style="width: 398px;" border="2">
<thead>
<tr>
<th style="width: 34px;">id</th>
<th style="width: 85px;">name</th>
<th style="width: 159px;">creation_time</th>
<th style="width: 109px;">command</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 34px;">772</td>
<td style="width: 85px;">EchoPackage</td>
<td style="width: 159px;">2018-08-23T15:22:54</td>
<td style="width: 109px;">cmd /c echo $1</td>
</tr>
</tbody>
</table>
<p> </p>
<h2>Information Commands</h2>
<h3 id="h_79985657810211536234394171">1. Get sensor information</h3>
<hr>
<p>Get detailed information about a specified sensor.</p>
<h5>Base Command</h5>
<p><code>tn-get-sensor</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 265px;"><strong>Argument Name</strong></th>
<th style="width: 288px;"><strong>Description</strong></th>
<th style="width: 155px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 265px;">name</td>
<td style="width: 288px;">Name of the sensor</td>
<td style="width: 155px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 312px;"><strong>Path</strong></th>
<th style="width: 78px;"><strong>Type</strong></th>
<th style="width: 318px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 312px;">Tanium.Sensors.max_age_seconds</td>
<td style="width: 78px;">number</td>
<td style="width: 318px;">Sensor maximum age (in seconds)</td>
</tr>
<tr>
<td style="width: 312px;">Tanium.Sensors.description</td>
<td style="width: 78px;">string</td>
<td style="width: 318px;">Description of the sensor</td>
</tr>
<tr>
<td style="width: 312px;">Tanium.Sensors.name</td>
<td style="width: 78px;">string</td>
<td style="width: 318px;">Name of the sensor</td>
</tr>
<tr>
<td style="width: 312px;">Tanium.Sensors.id</td>
<td style="width: 78px;">string</td>
<td style="width: 318px;">ID of the sensor</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tn-get-sensor name="Index Query File Exists"</pre>
<h5>Context Example</h5>
<pre>Tanium:{
	Sensors:[{
		hidden_flag:0
		string_count:6
		max_age_seconds:86400
		queries:{
			_type:queries
			query:[{
				_type:query
				platform:Windows
				script:select CSName from win32_operatingsystem
				script_type:WMIQuery
			}]
		}
		exclude_from_parse_flag:0
		value_type:String
		name:Computer Name
		ignore_case_flag:1
		_type:sensor
		id:3
		description:The assigned name of the client machine. Example: workstation-1.company.com
		category:Reserved
		source_id:0
	}]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Tanium Sensor - Index Query File Exists</h3>
<table style="width: 648px;" border="2">
<thead>
<tr>
<th style="width: 30px;">id</th>
<th style="width: 76px;">name</th>
<th style="width: 69px;">category</th>
<th style="width: 311px;">description</th>
<th style="width: 146px;">max_age_seconds</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 30px;">706</td>
<td style="width: 76px;">Index Query File Exists</td>
<td style="width: 69px;">Index</td>
<td style="width: 311px;">Returns Yes or No, using Index to determine whether specified file exists based on the supplied input</td>
<td style="width: 146px;">900</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>Sensor Parameters Details</h3>
<table style="width: 648px;" border="2">
<thead>
<tr>
<th style="width: 97px;">Key</th>
<th style="width: 70px;">Name</th>
<th style="width: 53px;">Values</th>
<th style="width: 272px;">Description</th>
<th style="width: 140px;">Type</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 97px;">directoryPath</td>
<td style="width: 70px;">Directory Path</td>
<td style="width: 53px;">Any value</td>
<td style="width: 272px;">Glob of directory name used for searching,e.g. <em>Windows</em>
</td>
<td style="width: 140px;">TextInputParameter</td>
</tr>
<tr>
<td style="width: 97px;">fileName</td>
<td style="width: 70px;">File Name</td>
<td style="width: 53px;">Any value</td>
<td style="width: 272px;">Glob of file name used for searching, e.g. *exe</td>
<td style="width: 140px;">TextInputParameter</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_37447380411881536234401296">2. Get a package object</h3>
<hr>
<p>Get a package object by name or ID.</p>
<h5>Base Command</h5>
<p><code>tn-get-package</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 183px;"><strong>Argument Name</strong></th>
<th style="width: 424px;"><strong>Description</strong></th>
<th style="width: 101px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 183px;">name</td>
<td style="width: 424px;">Name of package</td>
<td style="width: 101px;">Optional</td>
</tr>
<tr>
<td style="width: 183px;">id</td>
<td style="width: 424px;">Tanium ID of package (use instead of name)</td>
<td style="width: 101px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 299px;"><strong>Path</strong></th>
<th style="width: 64px;"><strong>Type</strong></th>
<th style="width: 345px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 299px;">Tanium.Packages.verify_expire_seconds</td>
<td style="width: 64px;">number</td>
<td style="width: 345px;">Timeout for verifying action (in seconds)</td>
</tr>
<tr>
<td style="width: 299px;">Tanium.Packages.display_name</td>
<td style="width: 64px;">string</td>
<td style="width: 345px;">Display name of package</td>
</tr>
<tr>
<td style="width: 299px;">Tanium.Packages.name</td>
<td style="width: 64px;">string</td>
<td style="width: 345px;">Name of created package</td>
</tr>
<tr>
<td style="width: 299px;">Tanium.Packages.command</td>
<td style="width: 64px;">string</td>
<td style="width: 345px;">Command to execute</td>
</tr>
<tr>
<td style="width: 299px;">Tanium.Packages.creation_time</td>
<td style="width: 64px;">date</td>
<td style="width: 345px;">Package creation time</td>
</tr>
<tr>
<td style="width: 299px;">Tanium.Packages.command_timeout</td>
<td style="width: 64px;">number</td>
<td style="width: 345px;">Timeout for command execution (in seconds)</td>
</tr>
<tr>
<td style="width: 299px;">Tanium.Packages.modification_time</td>
<td style="width: 64px;">date</td>
<td style="width: 345px;">Package modification time</td>
</tr>
<tr>
<td style="width: 299px;">Tanium.Packages.last_modified_by</td>
<td style="width: 64px;">string</td>
<td style="width: 345px;">User who last modified packge</td>
</tr>
<tr>
<td style="width: 299px;">Tanium.Packages.last_update</td>
<td style="width: 64px;">date</td>
<td style="width: 345px;">Time when package was last updated</td>
</tr>
<tr>
<td style="width: 299px;">Tanium.Packages.deleted_flag</td>
<td style="width: 64px;">boolean</td>
<td style="width: 345px;">Was the package deleted</td>
</tr>
<tr>
<td style="width: 299px;">Tanium.Packages.id</td>
<td style="width: 64px;">string</td>
<td style="width: 345px;">Tanium unique package ID</td>
</tr>
<tr>
<td style="width: 299px;">Tanium.Packages.expire_seconds</td>
<td style="width: 64px;">number</td>
<td style="width: 345px;">Timeout for action (in seconds)</td>
</tr>
<tr>
<td style="width: 299px;">Tanium.Packages.files</td>
<td style="width: 64px;">object</td>
<td style="width: 345px;">Package files</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tn-get-package name="Set Mac Tanium Client Logging Level"</pre>
<h5>Context Example</h5>
<pre>Tanium:{
	Packages:[{
		skip_lock_flag:0
		hidden_flag:0
		verify_group_id:0
		available_time:2016-04-06T13:03:12
		last_modified_by:Administrator
		verify_expire_seconds:600
		display_name:Set Mac Tanium Client Logging Level
		parameter_definition:{"parameters":[{"maximum":99,"key":"$1","stepSize":1,"label":"Log Level (0-99)","helpString":"Enter a logging level, 0=no logging, 99=verbose logging","snapInterval":1,"defaultValue":"1","minimum":0,"value":"1","parameterType":"com.tanium.components.parameters::NumericParameter","model":"com.tanium.components.parameters::NumericParameter"}],"parameterType":"com.tanium.components.parameters::ParametersArray","model":"com.tanium.components.parameters::ParametersArray"}
		name:Set Mac Tanium Client Logging Level
		command:/bin/sh set-log-level-parameterized.sh $1
		creation_time:2018-01-10T18:37:56
		command_timeout:900
		modification_time:2018-01-10T18:37:56
		last_update:2018-01-10T18:37:56
		deleted_flag:0
		files:{}
		_type:package_spec
		verify_group:{}
		_type:group
		id:0
		id:50
		expire_seconds:1500
		source_id:0
	}]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Tanium Package</h3>
<table style="width: 648px;" border="2">
<thead>
<tr>
<th style="width: 20px;">id</th>
<th style="width: 162px;">name</th>
<th style="width: 114px;">creation_time</th>
<th style="width: 199px;">command</th>
<th style="width: 137px;">last_modified_by</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 20px;">50</td>
<td style="width: 162px;">Set Mac Tanium Client Logging Level</td>
<td style="width: 114px;">2018-01-10T18:37:56</td>
<td style="width: 199px;">/bin/sh set-log-level-parameterized.sh $1</td>
<td style="width: 137px;">Administrator</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>Package Arguments Details</h3>
<table style="width: 648px;" border="2">
<thead>
<tr>
<th style="width: 36px;">Key</th>
<th style="width: 88px;">Name</th>
<th style="width: 57px;">Values</th>
<th style="width: 320px;">Description</th>
<th style="width: 131px;">Type</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 36px;">$1</td>
<td style="width: 88px;">Log Level (0-99)</td>
<td style="width: 57px;">Any value</td>
<td style="width: 320px;">Enter a logging level, 0=no logging, 99=verbose logging</td>
<td style="width: 131px;">NumericParameter</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_84591255713541536234412259">3. Get a saved question</h3>
<hr>
<p>Get a saved question by name or ID.</p>
<h5>Base Command</h5>
<p><code>tn-get-saved-question</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 143px;"><strong>Argument Name</strong></th>
<th style="width: 486px;"><strong>Description</strong></th>
<th style="width: 79px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 143px;">name</td>
<td style="width: 486px;">Name of saved question</td>
<td style="width: 79px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">id</td>
<td style="width: 486px;">Tanium unique id of saved question to be used instead of name</td>
<td style="width: 79px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 328px;"><strong>Path</strong></th>
<th style="width: 69px;"><strong>Type</strong></th>
<th style="width: 311px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 328px;">Tanium.SavedQuestions.query_text</td>
<td style="width: 69px;">string</td>
<td style="width: 311px;">Question query text</td>
</tr>
<tr>
<td style="width: 328px;">Tanium.SavedQuestions.mod_time</td>
<td style="width: 69px;">date</td>
<td style="width: 311px;">Question modification time</td>
</tr>
<tr>
<td style="width: 328px;">Tanium.SavedQuestions.user.id</td>
<td style="width: 69px;">string</td>
<td style="width: 311px;">Unique ID of user who saved question</td>
</tr>
<tr>
<td style="width: 328px;">Tanium.SavedQuestions.user.name</td>
<td style="width: 69px;">string</td>
<td style="width: 311px;">Name of user who saved question</td>
</tr>
<tr>
<td style="width: 328px;">Tanium.SavedQuestions.name</td>
<td style="width: 69px;">string</td>
<td style="width: 311px;">Name of saved question</td>
</tr>
<tr>
<td style="width: 328px;">Tanium.SavedQuestions.expire_seconds</td>
<td style="width: 69px;">number</td>
<td style="width: 311px;">Question expiration time (in seconds)</td>
</tr>
<tr>
<td style="width: 328px;">Tanium.SavedQuestions.id</td>
<td style="width: 69px;">string</td>
<td style="width: 311px;">Unique ID of the saved question</td>
</tr>
<tr>
<td style="width: 328px;">Tanium.SavedQuestions.issue_seconds</td>
<td style="width: 69px;">number</td>
<td style="width: 311px;">Issue time (in seconds)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tn-get-saved-question id=132</pre>
<h5>Context Example</h5>
<pre>Tanium:{
	SavedQuestions:[{
		row_count_flag:0
		hidden_flag:0
		public_flag:1
		query_text:Get Is Virtual and Chassis Type from all machines
		issue_seconds_never_flag:0
		keep_seconds:0
		question:{}
		archive_enabled_flag:0
		mod_user:{}
		mod_time:2018-01-10T18:38:00
		action_tracking_flag:0
		name:Virtualized / Physical Chassis
		user: {}
		most_recent_question_id:519303
		packages:{}
		archive_owner:{}
		sort_column:0
		_type:saved_question
		issue_seconds:120
		id:182
		cache_row_id:68
		expire_seconds:600
	}]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Tanium Saved Question</h3>
<table style="width: 648px;" border="2">
<thead>
<tr>
<th style="width: 421px;">query_text</th>
<th style="width: 190px;">name</th>
<th style="width: 27px;">id</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 421px;">Get Computer Name and Operating System from all machines with Action Lock Status containing "Action Lock On"</td>
<td style="width: 190px;">Clients That Cannot Take Actions - Action Lock On</td>
<td style="width: 27px;">132</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_31108262815171536234424514">4. Get an object</h3>
<hr>
<p>Send a generic get object request.</p>
<h5>Base Command</h5>
<p><code>tn-get-object</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 173px;"><strong>Argument Name</strong></th>
<th style="width: 436px;"><strong>Description</strong></th>
<th style="width: 99px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 173px;">name</td>
<td style="width: 436px;">Name of object</td>
<td style="width: 99px;">Optional</td>
</tr>
<tr>
<td style="width: 173px;">id</td>
<td style="width: 436px;">Tanium ID of the object (use instead of name)</td>
<td style="width: 99px;">Optional</td>
</tr>
<tr>
<td style="width: 173px;">object_type</td>
<td style="width: 436px;">Type of object to get</td>
<td style="width: 99px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!tn-get-object object_type=sensor name="Computer Name"</pre>
<h5>Human Readable Output</h5>
<pre>{
    "_type": "sensors",
    "sensor": [
        {
            "_type": "sensor",
            "category": "Reserved",
            "description": "The assigned name of the client machine.\nExample: workstation-1.company.com",
            "exclude_from_parse_flag": 0,
            "hash": 3409330187,
            "hidden_flag": 0,
            "id": 3,
            "ignore_case_flag": 1,
            "max_age_seconds": 86400,
            "name": "Computer Name",
            "queries": {},
            "source_id": 0,
            "string_count": 6,
            "value_type": "String"
        }
    ]
}</pre>
<p> </p>
<h3 id="h_58516095916761536234433283">5. Get all packages</h3>
<hr>
<p>Get all Tanium package objects</p>
<h5>Base Command</h5>
<p><code>tn-get-all-packages</code></p>
<h5>Input</h5>
<p>There is no input for this command.</p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 298px;"><strong>Path</strong></th>
<th style="width: 70px;"><strong>Type</strong></th>
<th style="width: 340px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 298px;">Tanium.Packages.verify_expire_seconds</td>
<td style="width: 70px;">number</td>
<td style="width: 340px;">Timeout for verifying the action (in seconds)</td>
</tr>
<tr>
<td style="width: 298px;">Tanium.Packages.display_name</td>
<td style="width: 70px;">string</td>
<td style="width: 340px;">Display name of package</td>
</tr>
<tr>
<td style="width: 298px;">Tanium.Packages.name</td>
<td style="width: 70px;">string</td>
<td style="width: 340px;">Name of created package</td>
</tr>
<tr>
<td style="width: 298px;">Tanium.Packages.command</td>
<td style="width: 70px;">string</td>
<td style="width: 340px;">Command to execute</td>
</tr>
<tr>
<td style="width: 298px;">Tanium.Packages.creation_time</td>
<td style="width: 70px;">date</td>
<td style="width: 340px;">Package creation time</td>
</tr>
<tr>
<td style="width: 298px;">Tanium.Packages.command_timeout</td>
<td style="width: 70px;">number</td>
<td style="width: 340px;">Timeout for command execution (in seconds)</td>
</tr>
<tr>
<td style="width: 298px;">Tanium.Packages.modification_time</td>
<td style="width: 70px;">date</td>
<td style="width: 340px;">Package modification time</td>
</tr>
<tr>
<td style="width: 298px;">Tanium.Packages.last_modified_by</td>
<td style="width: 70px;">string</td>
<td style="width: 340px;">User who last modified packge</td>
</tr>
<tr>
<td style="width: 298px;">Tanium.Packages.last_update</td>
<td style="width: 70px;">date</td>
<td style="width: 340px;">Time when package was last updated</td>
</tr>
<tr>
<td style="width: 298px;">Tanium.Packages.deleted_flag</td>
<td style="width: 70px;">boolean</td>
<td style="width: 340px;">Is the package deleted</td>
</tr>
<tr>
<td style="width: 298px;">Tanium.Packages.id</td>
<td style="width: 70px;">string</td>
<td style="width: 340px;">Tanium unique package ID</td>
</tr>
<tr>
<td style="width: 298px;">Tanium.Packages.expire_seconds</td>
<td style="width: 70px;">number</td>
<td style="width: 340px;">Timeout for the action (in seconds)</td>
</tr>
<tr>
<td style="width: 298px;">Tanium.Packages.files</td>
<td style="width: 70px;">unknown</td>
<td style="width: 340px;">Package files</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tn-get-all-packages</pre>
<h5>Context Example</h5>
<pre>Tanium:{
	Packages:[{
		skip_lock_flag:0
		hidden_flag:0
		verify_group_id:0
		available_time:2016-04-06T13:03:12
		last_modified_by:Administrator
		verify_expire_seconds:600
		display_name:Set Mac Tanium Client Logging Level
		parameter_definition:{"parameters":[{"maximum":99,"key":"$1","stepSize":1,"label":"Log Level (0-99)","helpString":"Enter a logging level, 0=no logging, 99=verbose logging","snapInterval":1,"defaultValue":"1","minimum":0,"value":"1","parameterType":"com.tanium.components.parameters::NumericParameter","model":"com.tanium.components.parameters::NumericParameter"}],"parameterType":"com.tanium.components.parameters::ParametersArray","model":"com.tanium.components.parameters::ParametersArray"}
		name:Set Mac Tanium Client Logging Level
		command:/bin/sh set-log-level-parameterized.sh $1
		creation_time:2018-01-10T18:37:56
		command_timeout:900
		modification_time:2018-01-10T18:37:56
		last_update:2018-01-10T18:37:56
		deleted_flag:0
		files:{}
		_type:package_spec
		verify_group:{}
		_type:group
		id:0
		id:50
		expire_seconds:1500
		source_id:0
	}]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Tanium Packages</h3>
<table style="width: 648px;" border="2">
<thead>
<tr>
<th style="width: 27px;">id</th>
<th style="width: 127px;">name</th>
<th style="width: 111px;">creation_time</th>
<th style="width: 230px;">command</th>
<th style="width: 137px;">last_modified_by</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 27px;">734</td>
<td style="width: 127px;">Detect Intel for Windows</td>
<td style="width: 111px;">2001-01-01T00:00:00</td>
<td style="width: 230px;">cmd /c cscript /nologo run-add-intel-package.vbs 2&gt;&amp;1</td>
<td style="width: 137px;"> </td>
</tr>
<tr>
<td style="width: 27px;">672</td>
<td style="width: 127px;">Remove Tanium Trace Tools [Mac-Linux]</td>
<td style="width: 111px;">2018-08-21T10:57:13</td>
<td style="width: 230px;">/bin/bash remove_tanium_trace_tools.sh</td>
<td style="width: 137px;">Administrator</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_27709808918361536234459040">6. Get all saved questions</h3>
<hr>
<p>Gets all saved questions.</p>
<h5>Base Command</h5>
<p><code>tn-get-all-saved-questions</code></p>
<h5>Input</h5>
<p>There are no inputs for this command.</p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 310px;"><strong>Path</strong></th>
<th style="width: 67px;"><strong>Type</strong></th>
<th style="width: 331px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 310px;">Tanium.SavedQuestions.query_text</td>
<td style="width: 67px;">string</td>
<td style="width: 331px;">Question query text</td>
</tr>
<tr>
<td style="width: 310px;">Tanium.SavedQuestions.mod_time</td>
<td style="width: 67px;">date</td>
<td style="width: 331px;">Question modification time</td>
</tr>
<tr>
<td style="width: 310px;">Tanium.SavedQuestions.user.id</td>
<td style="width: 67px;">string</td>
<td style="width: 331px;">Unique ID of the user who saved question</td>
</tr>
<tr>
<td style="width: 310px;">Tanium.SavedQuestions.user.name</td>
<td style="width: 67px;">string</td>
<td style="width: 331px;">Name of the user who saved question</td>
</tr>
<tr>
<td style="width: 310px;">Tanium.SavedQuestions.name</td>
<td style="width: 67px;">string</td>
<td style="width: 331px;">Name of saved question</td>
</tr>
<tr>
<td style="width: 310px;">Tanium.SavedQuestions.expire_seconds</td>
<td style="width: 67px;">number</td>
<td style="width: 331px;">Question expiration time (in seconds)</td>
</tr>
<tr>
<td style="width: 310px;">Tanium.SavedQuestions.id</td>
<td style="width: 67px;">string</td>
<td style="width: 331px;">Unique ID of the saved question</td>
</tr>
<tr>
<td style="width: 310px;">Tanium.SavedQuestions.issue_seconds</td>
<td style="width: 67px;">number</td>
<td style="width: 331px;">Issue time (in seconds)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tn-get-all-saved-questions</pre>
<h5>Context Example</h5>
<pre>Tanium:{
	SavedQuestions:[{
		row_count_flag:0
		hidden_flag:0
		public_flag:1
		query_text:Get Is Virtual and Chassis Type from all machines
		issue_seconds_never_flag:0
		keep_seconds:0
		question:{}
		archive_enabled_flag:0
		mod_user:{}
		mod_time:2018-01-10T18:38:00
		action_tracking_flag:0
		name:Virtualized / Physical Chassis
		user: {}
		most_recent_question_id:519303
		packages:{}
		archive_owner:{}
		sort_column:0
		_type:saved_question
		issue_seconds:120
		id:182
		cache_row_id:68
		expire_seconds:600
	}]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Tanium Saved Questions</h3>
<table style="width: 648px;" border="2">
<thead>
<tr>
<th style="width: 431px;">query_text</th>
<th style="width: 180px;">name</th>
<th style="width: 27px;">id</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 431px;">Get Is Virtual and Chassis Type from all machines</td>
<td style="width: 180px;">Virtualized / Physical Chassis</td>
<td style="width: 27px;">182</td>
</tr>
<tr>
<td style="width: 431px;">Get Installed Applications starting with "adobe reader" from all machines</td>
<td style="width: 180px;">Adobe Reader Versions</td>
<td style="width: 27px;">197</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_47056289319951536234471851">7. Get all saved actions</h3>
<hr>
<p>Gets all saved actions.</p>
<h5>Base Command</h5>
<p><code>tn-get-all-saved-actions</code></p>
<h5>Input</h5>
<p>There is no input for this command.</p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 320px;"><strong>Path</strong></th>
<th style="width: 71px;"><strong>Type</strong></th>
<th style="width: 317px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 320px;">Tanium.SavedActions.distribute_seconds</td>
<td style="width: 71px;">number</td>
<td style="width: 317px;">Distribute seconds of action</td>
</tr>
<tr>
<td style="width: 320px;">Tanium.SavedActions.public_flag</td>
<td style="width: 71px;">boolean</td>
<td style="width: 317px;">Whether action is public or not</td>
</tr>
<tr>
<td style="width: 320px;">Tanium.SavedActions.action_group_id</td>
<td style="width: 71px;">string</td>
<td style="width: 317px;">Group ID of action</td>
</tr>
<tr>
<td style="width: 320px;">Tanium.SavedActions.approver.id</td>
<td style="width: 71px;">string</td>
<td style="width: 317px;">ID of the user who approved the action</td>
</tr>
<tr>
<td style="width: 320px;">Tanium.SavedActions.start_time</td>
<td style="width: 71px;">date</td>
<td style="width: 317px;">Action start time</td>
</tr>
<tr>
<td style="width: 320px;">Tanium.SavedActions.name</td>
<td style="width: 71px;">string</td>
<td style="width: 317px;">Action name</td>
</tr>
<tr>
<td style="width: 320px;">Tanium.SavedActions.user.id</td>
<td style="width: 71px;">string</td>
<td style="width: 317px;">ID of the user who created the action</td>
</tr>
<tr>
<td style="width: 320px;">Tanium.SavedActions.creation_time</td>
<td style="width: 71px;">date</td>
<td style="width: 317px;">Time the action was created</td>
</tr>
<tr>
<td style="width: 320px;">Tanium.SavedActions.end_time</td>
<td style="width: 71px;">date</td>
<td style="width: 317px;">Time the action ended</td>
</tr>
<tr>
<td style="width: 320px;">Tanium.SavedActions.status</td>
<td style="width: 71px;">string</td>
<td style="width: 317px;">Action status</td>
</tr>
<tr>
<td style="width: 320px;">Tanium.SavedActions.last_start_time</td>
<td style="width: 71px;">date</td>
<td style="width: 317px;">Last time action started</td>
</tr>
<tr>
<td style="width: 320px;">Tanium.SavedActions.id</td>
<td style="width: 71px;">string</td>
<td style="width: 317px;">ID of action</td>
</tr>
<tr>
<td style="width: 320px;">Tanium.SavedActions.package_spec.id</td>
<td style="width: 71px;">string</td>
<td style="width: 317px;">The package associated with the action</td>
</tr>
<tr>
<td style="width: 320px;">Tanium.SavedActions.approved_flag</td>
<td style="width: 71px;">boolean</td>
<td style="width: 317px;">Whether action was approved or not</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tn-get-all-saved-actions</pre>
<h5>Context Example</h5>
<pre>Tanium:{
	SavedActions:[{
		distribute_seconds:0
		public_flag:0
		action_group_id:0
		approver:{}
		issue_count:0
		start_time:2001-01-01T00:00:00
		name:Unscheduled - Clean Stale Tanium Client Data
		user:{}
		creation_time:2016-08-10T07:12:58
		metadata:{}
		target_group:{}
		end_time:Never
		status:1
		last_start_time:Never
		package_spec:{}
		approved_flag:1
		next_start_time:Never
		_type:saved_action
		issue_seconds:0
		policy_flag:0
		id:94
		cache_row_id:1
		user_start_time:2016-08-10T07:13:00
		expire_seconds:1800
		last_action:{} 
	}]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Tanium Saved Actions</h3>
<table border="2">
<thead>
<tr>
<th>id</th>
<th>name</th>
<th>creation_time</th>
<th>action_group_id</th>
<th>approved_flag</th>
</tr>
</thead>
<tbody>
<tr>
<td>914</td>
<td>API Deploy USB Write Protect - Set to On</td>
<td>2018-08-17T01:59:31</td>
<td>0</td>
<td>0</td>
</tr>
<tr>
<td>939</td>
<td>Start Tanium Trace Session</td>
<td>2018-08-21T07:00:52</td>
<td>2334</td>
<td>0</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_85977583321531536234503900">8. Get all pending actions</h3>
<hr>
<p>Gets all pending actions.</p>
<h5>Base Command</h5>
<p><code>tn-get-all-pending-actions</code></p>
<h5>Input</h5>
<p>There is no input for this command.</p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 331px;"><strong>Path</strong></th>
<th style="width: 65px;"><strong>Type</strong></th>
<th style="width: 312px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 331px;">Tanium.PendingActions.distribute_seconds</td>
<td style="width: 65px;">number</td>
<td style="width: 312px;">Distribute seconds of action</td>
</tr>
<tr>
<td style="width: 331px;">Tanium.PendingActions.public_flag</td>
<td style="width: 65px;">boolean</td>
<td style="width: 312px;">Whether action is public or not</td>
</tr>
<tr>
<td style="width: 331px;">Tanium.PendingActions.action_group_id</td>
<td style="width: 65px;">string</td>
<td style="width: 312px;">Group ID of action</td>
</tr>
<tr>
<td style="width: 331px;">Tanium.PendingActions.approver.id</td>
<td style="width: 65px;">string</td>
<td style="width: 312px;">ID of the user who approved the action</td>
</tr>
<tr>
<td style="width: 331px;">Tanium.PendingActions.start_time</td>
<td style="width: 65px;">date</td>
<td style="width: 312px;">Action start time</td>
</tr>
<tr>
<td style="width: 331px;">Tanium.PendingActions.name</td>
<td style="width: 65px;">string</td>
<td style="width: 312px;">Action name</td>
</tr>
<tr>
<td style="width: 331px;">Tanium.PendingActions.user.id</td>
<td style="width: 65px;">string</td>
<td style="width: 312px;">
<p>ID of the user who created the action</p>
</td>
</tr>
<tr>
<td style="width: 331px;">Tanium.PendingActions.creation_time</td>
<td style="width: 65px;">date</td>
<td style="width: 312px;">Time the action was created</td>
</tr>
<tr>
<td style="width: 331px;">Tanium.PendingActions.end_time</td>
<td style="width: 65px;">date</td>
<td style="width: 312px;">Time the action ended</td>
</tr>
<tr>
<td style="width: 331px;">Tanium.PendingActions.status</td>
<td style="width: 65px;">string</td>
<td style="width: 312px;">Action status</td>
</tr>
<tr>
<td style="width: 331px;">Tanium.PendingActions.last_start_time</td>
<td style="width: 65px;">date</td>
<td style="width: 312px;">Last time action started</td>
</tr>
<tr>
<td style="width: 331px;">Tanium.PendingActions.id</td>
<td style="width: 65px;">string</td>
<td style="width: 312px;">ID of the action</td>
</tr>
<tr>
<td style="width: 331px;">Tanium.PendingActions.package_spec.id</td>
<td style="width: 65px;">string</td>
<td style="width: 312px;">The package associated with the action</td>
</tr>
<tr>
<td style="width: 331px;">Tanium.PendingActions.approved_flag</td>
<td style="width: 65px;">boolean</td>
<td style="width: 312px;">Whether the action was approved</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!tn-get-all-pending-actions</pre>
<h5>Context Example</h5>
<pre>Tanium:{
	PendingActions:[{
		distribute_seconds:0
		public_flag:0
		action_group_id:0
		approver:{}
		issue_count:0
		start_time:2001-01-01T00:00:00
		name:Unscheduled - Clean Stale Tanium Client Data
		user:{}
		creation_time:2016-08-10T07:12:58
		metadata:{}
		target_group:{}
		end_time:Never
		status:1
		last_start_time:Never
		package_spec:{}
		approved_flag:1
		next_start_time:Never
		_type:saved_action
		issue_seconds:0
		policy_flag:0
		id:94
		cache_row_id:1
		user_start_time:2016-08-10T07:13:00
		expire_seconds:1800
		last_action:{} 
	}]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Tanium Pending Actions</h3>
<table style="width: 648px;" border="2">
<thead>
<tr>
<th style="width: 27px;">id</th>
<th style="width: 231px;">name</th>
<th style="width: 131px;">creation_time</th>
<th style="width: 129px;">action_group_id</th>
<th style="width: 114px;">approved_flag</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 27px;">914</td>
<td style="width: 231px;">API Deploy USB Write Protect - Set to On</td>
<td style="width: 131px;">2018-08-17T01:59:31</td>
<td style="width: 129px;">0</td>
<td style="width: 114px;">0</td>
</tr>
<tr>
<td style="width: 27px;">939</td>
<td style="width: 231px;">Start Tanium Trace Session</td>
<td style="width: 131px;">2018-08-21T07:00:52</td>
<td style="width: 129px;">2334</td>
<td style="width: 114px;">0</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_95458532023101536234512462">9. Get all objects</h3>
<hr>
<p>Gets all objects of the specified type.</p>
<h5>Base Command</h5>
<p><code>tn-get-all-objects</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 259px;"><strong>Argument Name</strong></th>
<th style="width: 298px;"><strong>Description</strong></th>
<th style="width: 151px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 259px;">object_type</td>
<td style="width: 298px;">Type of object to get</td>
<td style="width: 151px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!tn-get-all-objects object_type=package</pre>
<h5>Human Readable Output</h5>
<pre>{
    "_type": "sensors",
    "sensor": [
        {
            "_type": "sensor",
            "category": "Reserved",
            "description": "The assigned name of the client machine.\nExample: workstation-1.company.com",
            "exclude_from_parse_flag": 0,
            "hash": 3409330187,
            "hidden_flag": 0,
            "id": 3,
            "ignore_case_flag": 1,
            "max_age_seconds": 86400,
            "name": "Computer Name",
            "queries": {},
            "source_id": 0,
            "string_count": 6,
            "value_type": "String"
        }
    ]
}</pre>
<p> </p>


### tn-get-all-sensors
***
Gets all sensors


#### Base Command

`tn-get-all-sensors`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### tn-get-action
***
Get detailed information about a given action.


#### Base Command

`tn-get-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of action of retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tanium.Actions.name | string | Name of the actions | 
| Tanium.Actions.id | number | ID of the action | 
| Tanium.Actions.status | string | Status of the action - Closed, Pending, etc. | 
| Tanium.Actions.start_time | date | Time when the action started running | 
| Tanium.Actions.approver.name | string | Name of Tanium user who approved the action | 
| Tanium.Actions.creation_time | date | Time when the action was created | 
| Tanium.Actions.package_spec.command | string | The command that is issued by the action | 
| Tanium.Actions.package_spec.name | string | Name of the package that was deployed | 

<h2>Debug Commands</h2>
<h3 id="h_95205013124651536234522127">1. Request the server to parse question text</h3>
<hr>
<p>Ask the server to parse the question text and return all parsing options.</p>
<h5>Base Command</h5>
<p><code>tn-parse-query</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 216px;"><strong>Argument Name</strong></th>
<th style="width: 366px;"><strong>Description</strong></th>
<th style="width: 126px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 216px;">question</td>
<td style="width: 366px;">The question text to be parsed</td>
<td style="width: 126px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!tn-parse-query question="get computer name"</pre>
<h5>Human Readable Output</h5>
<h3>Tanium Questions</h3>
<table style="width: 452px;" border="2">
<thead>
<tr>
<th style="width: 47px;">index</th>
<th style="width: 400px;">question</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 47px;">1</td>
<td style="width: 400px;">Get Computer Name from all machines</td>
</tr>
<tr>
<td style="width: 47px;">2</td>
<td style="width: 400px;">Get Computer ID from all machines</td>
</tr>
<tr>
<td style="width: 47px;">3</td>
<td style="width: 400px;">Get Computer ID containing "name" from all machines</td>
</tr>
</tbody>
</table>