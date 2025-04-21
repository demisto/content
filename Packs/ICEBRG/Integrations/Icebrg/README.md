<!-- HTML_DOC -->
<p>ICEBRG is a network security product which is used in conjunction with Cortex XSOAR to get events and reports produced in ICEBRG for queries.</p>
<p>The following data is fetched :</p>
<ul>
<li>Fetching reports which contain more than one asset.</li>
<li>Events cannot be fetched.</li>
<li>Flittering by published date.</li>
<li>Fetching every 10 minutes.</li>
</ul>
<h3>To set up ICEBRG to work with Cortex XSOAR:</h3>
<p>To obtain API token (on ICEBRG):</p>
<ol>
<li>Go to ‘Settings &gt; Profile Settings &gt; Tokens’.</li>
<li>Click ‘Create new token’.</li>
<li>Enter description.</li>
<li>Click ‘Create’</li>
<li>Record this token to use in the next steps.</li>
</ol>
<h3>To set up the integration on Cortex XSOAR:</h3>
<ol>
<li>Go to ‘Settings &gt; Integrations &gt; Servers &amp; Services’</li>
<li>Locate ‘ICEBRG’ by searching for it using the search box on the top of the page.</li>
<li>Click ‘Add instance’ to create and configure a new integration. You should configure the following settings:<br><strong>Name</strong>: A textual name for the integration instance.<br><strong>Server URL for the search API</strong>: The URL appliance.<br><strong>API username</strong>: ICEBRG API token.<br><strong>Server URL for the reports API:</strong> The server used for the reports API.<br><strong>Password</strong>: ICEBRG API password.<br><strong>ICEBRG token:</strong> The token obtained in the steps above.<strong> <br></strong><strong>Fetch incidents</strong>: Select whether to automatically create Cortex XSOAR incidents from <strong>ICEBRG </strong>offenses. <br><strong>Cortex XSOAR engine</strong>: If relevant, select the engine that acts as a proxy to the server. Engines are used when you need to access a remote network segments and there are network devices such as proxies, firewalls, etc. that prevent the Cortex XSOAR server from accessing the remote networks.<br>For more information on Cortex XSOAR engines see:<br><a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Engines">Cortex XSOAR 6.13 - Engines</a><br> <a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Engines">Cortex XSOAR 8 Cloud- Engines</a><br> <a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Engines">Cortex XSOAR 8.7 On-prem - Engines</a>
</li>
<li>Press the ‘Test’ button to validate connection.
</li>
<li>After completing the test successfully, press the ‘Done’ button.</li>
</ol>
<p> Top Use-cases:</p>
<ul>
<li>Search events by query.</li>
<li>Get reports by UUID..</li>
</ul>
<h3>Commands:</h3>
<ul>
<li style="font-family: courier;"><strong>icebrg-search-events</strong></li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td style="width: 678.556px;">
<p><strong>Query (mandatory)</strong> - The query string or entity for which to search.<br><strong>Start date -</strong> The beginning of the temporal extent by which to restrict filter results, inclusive (in RFC3339 format).<br><strong>End date </strong>- The end of the temporal extent by which to restrict filter results, exclusive (in RFC3339 format). <br><strong>Order by </strong>- The event property by which to order results. Default: timestamp. <br><strong>Order </strong>- The order of results, either "asc" or "desc". Default: desc.<br><strong>Customer ID</strong> - The customer ID by which to restrict filter results. Default: user's account.<br><strong>History</strong> - When true, save this query in user's Query History and include up to the last 50 queries from user's Query History. Default: false.<br><strong>Service traffic</strong> - When true, the service will include the service_traffic aggregation. Default: false.</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<strong>Icebrg.Events.QueryType</strong> - Query type<br><strong>Icebrg.Events.Total</strong> - Total events <br><strong>Icebrg.Events.OrderBy</strong> - Key to order events by<br><strong>Icebrg.Events.Order</strong> - Order of the events <br><strong>Icebrg.Events.Offset</strong> - Events offset<br> <strong>Icebrg.Events.History</strong> - History of events <br><strong>Icebrg.Events.Limit</strong> - Limit number of events to show</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td style="width: 678.556px;">
<pre>{
	"total": 135359505,
	"offset": 0,
	"limit": 100,
	"order_by": "timestamp",
	"query_type": "complex",
	"events": [ ... ]
}</pre>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;"><strong>icebrg-get-history</strong></li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>none</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p><strong>Icebrg.UserQueryHistory.Total</strong> - Total user queries<br><strong>Icebrg.UserQueryHistory.Timestamp</strong> - Timestamp of user query<br><strong>Icebrg.UserQueryHistory.Query</strong> - Called query<br><strong>Icebrg.UserQueryHistory.QueryId</strong> - ID of query<br><strong>Icebrg.UserQueryHistory.UserId</strong> - User ID</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<pre>{
 	"history": [{
    			"total": 3393897721,
    			"timestamp": "2017-03-30T20:56:11.556Z",
    			"query": "port = 80",
    			"id": "725be4f112f5b5ae9807b7130b2cea97"
	 },
		{
    			"total": 211313295,
    			"timestamp": "2017-03-30T17:44:35.748Z",
    			"query": "google.com",
 			"id": "655765009424c447765d06773e711dd3"
	}],
	"User_id": "f3259c9f-e54a-4e93-b71d-8e995a2cd96b"
 }</pre>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;"><strong>icebrg-saved-searches</strong></li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>none</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<strong>Icebrg.SavedSearches.Tags</strong> - Query tags<br> <strong>Icebrg.SavedSearches.Description</strong> - Query description<br> <strong>Icebrg.SavedSearches.Title</strong> - Query title <br><strong>Icebrg.SavedSearches.Timestamp</strong> - Query timestamp<br><strong>Icebrg.SavedSearches.Query</strong> - Called query <br><strong>Icebrg.SavedSearches.Id</strong> - Query ID</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<pre>{
	"saved_queries": [{
   			 "tags": [],
    			"description": "",
    			"title": "Test",
    			"timestamp": "2017-03-17T00:48:34.359Z",
    			"query": "ip='127.0.0.1'",
    			"id": "AVrZvNBGl0ZSNz2usg93"
		}]
}</pre>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;"><strong>icebrg-get-reports</strong></li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<strong>Limit</strong> - The maximum number of records to return. The default is no limit. <br><strong>Offset</strong> - The number of records to skip. The default is none. <br><strong>Sort by</strong> - The field to sort by (created, updated, or published). The default is unsorted. <br><strong>Sort order</strong> - The sort order asc or desc. The default is asc if sort_by is provided. <br><strong>Account UUID</strong> - UUID of account to filter by. <br><strong>Archived</strong> - Archived status to filter by. <br><strong>Confidence</strong> - Confidence to filter by (low, moderate, high). <br><strong>Risk</strong> - Risk to filter by (low, moderate, high). <br><strong>Search</strong> - Text string to search the title and summary. <br><strong>Status</strong> - Status to filter by. <br><strong>Published start</strong> - Published start date to filter by (inclusive), RFC3339 format. <br><strong>Published end</strong> - Published end date to filter by (exclusive), RFC3339 format.</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<strong>Icebrg.Reports.Publishes.UserUuid</strong> - User UUID that published the report <strong>Icebrg.Reports.Publishes.Publishe</strong> - Timestamp of published report <strong>Icebrg.Reports.AssetCount</strong> - Asset count of report <br><strong>Icebrg.Reports.IndicatorCount</strong> - Indicator count of report <br><strong>Icebrg.Reports.Archived</strong> - True if archived, else false <br><strong>Icebrg.Reports.Details</strong> - Report details <br><strong>Icebrg.Reports.Summary</strong> - Report summary <br><strong>Icebrg.Reports.Category</strong> - Category of the report <br><strong>Icebrg.Reports.Confidence</strong> - Indicator count of report <br><strong>Icebrg.Reports.Archived</strong> - Confidence of report <br><strong>Icebrg.Reports.Risk</strong> - Risk of report <br><strong>Icebrg.Reports.Title</strong> - Report title <br><strong>Icebrg.Reports.Status</strong> - Status of report <br><strong>Icebrg.Reports.AccountUuid</strong> - Account UUID of report<br> <strong>Icebrg.Reports.UpdatedUserUuid</strong> - User UUID that updated the report <strong>Icebrg.Reports.CreatedUserUuid</strong> - User UUID that created the report <strong>Icebrg.Reports.Updated</strong> - Timestamp of report update <br><strong>Icebrg.Reports.Created</strong> - Timestamp of report creation<br> <strong>Icebrg.Reports.Uuid</strong> - Report UUID<strong><br></strong>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<pre>{
    "reports": [{
		 "publishes": [{
   			     "user_uuid": "b3fc3df4-d3cf-4202-971c-0dcfe7cccf42",
     			     "published": "2017-01-24T10:13:13.418Z"
  		   }],
  		 "asset_count": 1,
 		 "indicator_count": 5,
  		"archived": false,
  		"details": "On 21 January, ...",
  		"summary": "A host was infected with Cerber ransomware after opening a<br>		           malicious Word document received via email.",
  		"category": "Ransomware",
  		"confidence": "high",
  		"risk": "moderate",
  		"title": "Cerber Malware Infection",
  		"status": "published",
  		"account_uuid": "6bc3d2f1-af77-4236-a9db-17dacd06e4d9",
  		"updated_user_uuid": "b3fc3df4-d3cf-4202-971c-0dcfe7cccf42",
  		"created_user_uuid": "b3fc3df4-d3cf-4202-971c-0dcfe7cccf42",
  		"updated": "2017-01-24T10:12:32.534Z",
  		"created": "2017-01-24T07:25:36.363Z",
  		"uuid": "2d35734f-5b16-41ff-a482-b08a7c74202a"
	}],
}</pre>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;"><strong>icebrg-get-report-assets</strong></li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<strong>Report UUID (mandatory)</strong> - Report UUID to get the indicator</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<strong>Icebrg.ReportAssets.Asset</strong> - Assets of Report UUID</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<pre>{
	"assets": [{
    			"asset" : "10.248.100.74"
		}]
}</pre>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>Troubleshooting</h3>
<p>This integration was integrated and tested with version 1.3 of ICEBRG.</p>