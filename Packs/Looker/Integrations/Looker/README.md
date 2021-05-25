<!-- HTML_DOC -->
<div class="cl-preview-section">
<div class="cl-preview-section">
<p>This integration was integrated and tested with Looker version 6.10.20.</p>
</div>
<div class="cl-preview-section">
<h2 id="use-cases">Use Cases</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Ingest query results as incidents.</li>
<li>Run a custom (inline) query as part of a playbook.</li>
<li>Automatically create and save a query as a look.</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="important-information">Important Information</h2>
<p>Make sure you read this information on how to obtain information required for configuring the integration.</p>
</div>
<div class="cl-preview-section">
<h4 id="generate-an-api3-key-for-a-looker-user">Generate an API3 key for a Looker user:</h4>
</div>
<div class="cl-preview-section">
<ol>
<li>Log in to the Looker web interface with an account that is permitted to manage users.</li>
<li>At the top of the page, click on the “Admin” drop down and select “Users”</li>
<li>Select the user you would like to generate the API3 key for.</li>
<li>Go to “API3 Keys” and select “Edit Keys”</li>
<li>Click on “New API3 Key”</li>
</ol>
</div>
<div class="cl-preview-section">
<h4 id="get-a-look-id">Get a Look ID:</h4>
</div>
<div class="cl-preview-section">
<p><strong>Usages:</strong></p>
</div>
<div class="cl-preview-section">
<ul>
<li>“Look name or ID to fetch incidents from” integration parameter.</li>
<li>Look ID command arguments.</li>
<li>Uniquely identify a Look (the name is not unique).</li>
</ul>
</div>
<div class="cl-preview-section">
<p><strong>Option A:</strong><span> </span>Looker Web Interface</p>
</div>
<div class="cl-preview-section">
<ol>
<li>Click on a look.</li>
<li>The number at the end of the URL is the ID of the look.</li>
</ol>
</div>
<div class="cl-preview-section">
<p><strong>Option B:</strong><span> </span>Cortex XSOAR commands</p>
</div>
<div class="cl-preview-section">
<ol>
<li>Configure the Looker integration without fetching incidents, or filling in the parameter.</li>
<li>Run the<span> </span><code>looker-search-queries</code><span> </span>or<span> </span><code>looker-search-looks</code><span> </span>command.</li>
<li>The ID will be part of the results (among other look details).</li>
</ol>
</div>
<div class="cl-preview-section">
<h4 id="get-model-and-view-names-from-an-explores-url">Get model and view names from an explore’s URL:</h4>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to the explore.</li>
<li>The URL will be formatted like this:<span> </span><code>https://&lt;looker server&gt;/explore/&lt;model&gt;/&lt;view&gt;</code>
</li>
</ol>
</div>
<div class="cl-preview-section">
<h4 id="get-a-fields-sql-name-for-command-arguments">Get a field’s SQL name (for command arguments):</h4>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to the explore.</li>
<li>Click a field.</li>
<li>In the<span> </span><strong>DATA</strong><span> </span>tab, click<span> </span><strong>SQL</strong>.</li>
</ol>
</div>
<div class="cl-preview-section">
<p>You will see the field name in the following format:<span> </span><code>object_name.field_name</code>.</p>
</div>
<div class="cl-preview-section">
<h2 id="configure-looker-on-demisto">Configure Looker on Cortex XSOAR</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for Looker.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>API URL and port (e.g.,<span> </span>https://example.looker.com:19999)</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>API3 Client ID</strong></li>
<li><strong>API3 Client Secret</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section">
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li><a href="#run-a-saved-look" target="_self">Run a saved look: looker-run-look</a></li>
<li><a href="#search-for-saved-looks" target="_self">Search for saved looks: looker-search-looks</a></li>
<li><a href="#run-an-inline-query" target="_self">Run an inline query: looker-run-inline-query</a></li>
<li><a href="#create-a-look" target="_self">Create a look: looker-create-look</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="run-a-saved-look">1. Run a saved look</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Runs a saved look and returns the results in the specified format.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>looker-run-look</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 136px;"><strong>Argument Name</strong></th>
<th style="width: 533px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 136px;">id</td>
<td style="width: 533px;">ID of the look. Can be found in the look’s URL, or by running the ‘looker-search-looks’ command.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">fields</td>
<td style="width: 533px;">Fields to return.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">name</td>
<td style="width: 533px;">Name of the look.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">limit</td>
<td style="width: 533px;">Maximum number of looks to return (0 for looker-determined limit).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">result_format</td>
<td style="width: 533px;">Format of the result.</td>
<td style="width: 71px;">Required</td>
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
<th style="width: 355px;"><strong>Path</strong></th>
<th style="width: 163px;"><strong>Type</strong></th>
<th style="width: 222px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 355px;">LookerResults.LookID</td>
<td style="width: 163px;">Number</td>
<td style="width: 222px;">Look ID.</td>
</tr>
<tr>
<td style="width: 355px;">LookerResults.Results</td>
<td style="width: 163px;">Unknown</td>
<td style="width: 222px;">Look Results.</td>
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
<pre>looker-run-look name="Look 1" limit="2" result_format="json"
</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>"LookerResults": {
    "LookID": 3,
    "Results": [
        {
            "OrderItems_Id": 160086,
            "OrderItems_OrderId": 153797, 
            "OrderItems_Status": "Complete", 
            "OrderItems_CreatedDate": "2019-04-02",
            "OrderItems_SalePrice": 54,
            "Products_Brand": "Alternative",
            "Products_ItemName": "Alternative Women's Alice Drop Shoulder V-Neck",
            "Users_Name": "Chelsea Mccormick",
            "Users_Email": "example@gmail.com"
        }, 
        {
            "OrderItems_Id": 63757,
            "OrderItems_OrderId": 58557, 
            "OrderItems_Status": "Cancelled", 
            "OrderItems_CreatedDate": "2019-04-19",
            "OrderItems_SalePrice": 49.5,
            "Products_Brand": "Lucky Brand",
            "Products_ItemName": "Lucky Brand Women's Plus-Size Moroccan Medallion Tee",
            "Users_Name": "Darrell Nelson",
            "Users_Email": "example@aol.com"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="results-for-look-look-1">Results for look Look 1</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>LookerResults.Results.OrderItems_Id</th>
<th>LookerResults.Results.OrderItems_OrderId</th>
<th>LookerResults.Results.OrderItems_Status</th>
<th>LookerResults.Results.OrderItems_CreatedDate</th>
<th>LookerResults.Results.OrderItems_SalePrice</th>
<th>LookerResults.Results.Products_Brand</th>
<th>LookerResults.Results.Products_ItemName</th>
<th>LookerResults.Results.Users_Name</th>
<th>LookerResults.Results.Users_Email</th>
</tr>
</thead>
<tbody>
<tr>
<td>160086</td>
<td>153797</td>
<td>Complete</td>
<td>2019-04-02</td>
<td>54</td>
<td>Alternative</td>
<td>Alternative Women’s Alice Drop Shoulder V-Neck</td>
<td>Chelsea Mccormick</td>
<td><a href="mailto:example.gmail.com">example.gmail.com</a></td>
</tr>
<tr>
<td>63757</td>
<td>58557</td>
<td>Cancelled</td>
<td>2019-04-19</td>
<td>49.5</td>
<td>Lucky Brand</td>
<td>Lucky Brand Women’s Plus-Size Moroccan Medallion Tee</td>
<td>Darrell Nelson</td>
<td><a href="mailto:example.gmail.com">example.gmail.com</a></td>
</tr>
</tbody>
</table>
</div>
</div>
<div class="cl-preview-section">
<p>This command has dynamic output keys.<br> To access them in the context, copy the key’s path from the column header in the results table.</p>
</div>
<div class="cl-preview-section">
<h3 id="search-for-saved-looks">2. Search for saved looks</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves saved looks that match the search criteria.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>looker-search-looks</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 149px;"><strong>Argument Name</strong></th>
<th style="width: 513px;"><strong>Description</strong></th>
<th style="width: 78px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 149px;">name</td>
<td style="width: 513px;">Match look name.</td>
<td style="width: 78px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">space_id</td>
<td style="width: 513px;">Filter results by a particular space.</td>
<td style="width: 78px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">user_id</td>
<td style="width: 513px;">Filter by dashboards created by a particular user.</td>
<td style="width: 78px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">limit</td>
<td style="width: 513px;">Maximum number of looks to return (0 for looker-determined limit).</td>
<td style="width: 78px;">Optional</td>
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
<th style="width: 249px;"><strong>Path</strong></th>
<th style="width: 77px;"><strong>Type</strong></th>
<th style="width: 414px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 249px;">Looker.Look.ID</td>
<td style="width: 77px;">Number</td>
<td style="width: 414px;">Look ID.</td>
</tr>
<tr>
<td style="width: 249px;">Looker.Look.Name</td>
<td style="width: 77px;">String</td>
<td style="width: 414px;">Look name.</td>
</tr>
<tr>
<td style="width: 249px;">Looker.Look.SpaceID</td>
<td style="width: 77px;">Number</td>
<td style="width: 414px;">ID of the space that contains the look.</td>
</tr>
<tr>
<td style="width: 249px;">Looker.Look.SpaceName</td>
<td style="width: 77px;">String</td>
<td style="width: 414px;">Name of the space that contains the look.</td>
</tr>
<tr>
<td style="width: 249px;">Looker.Look.LastUpdated</td>
<td style="width: 77px;">Date</td>
<td style="width: 414px;">The time that the look was last updated.</td>
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
<pre>!looker-search-looks limit="2"
</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-1">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>"Looker": {
    "Look": {
        [
            {
                "ID": 3,
                "LastUpdated": "2019-04-10T16:11:43.249Z",
                "Name": "Look 1",
                "SpaceID": 6,
                "SpaceName": "Space 1"
            },
            {
                "ID": 4,
                "LastUpdated": "2019-04-16T11:41:57.482Z",
                "Name": "Look 2",
                "SpaceID": 7,
                "SpaceName": "Space 2"
            }
        ]
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="look-search-results">Look search results</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>ID</th>
<th>Name</th>
<th>SpaceID</th>
<th>SpaceName</th>
<th>LastUpdated</th>
</tr>
</thead>
<tbody>
<tr>
<td>3</td>
<td>Look 1</td>
<td>6</td>
<td>Space 1</td>
<td>2019-04-10T16:11:43.249Z</td>
</tr>
<tr>
<td>4</td>
<td>Look 2</td>
<td>7</td>
<td>Space 2</td>
<td>2019-04-16T11:41:57.482Z</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="run-an-inline-query">3. Run an inline query</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Runs a query by defining it in the command arguments, rather than a saved query in looker.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>looker-run-inline-query</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 137px;"><strong>Argument Name</strong></th>
<th style="width: 532px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 137px;">model</td>
<td style="width: 532px;">Name of the model - can be found in the explore’s URL</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 137px;">view</td>
<td style="width: 532px;">Name of the view or explore. Can be found in the explore’s URL.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 137px;">fields</td>
<td style="width: 532px;">List of fields to display. (Field name format: “object_name.field_name”).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">filters</td>
<td style="width: 532px;">Filters for the query, passed as a comma-separated list with the format: “field name=filter value;…” (Field name format: “object_name.field_name”).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">pivots</td>
<td style="width: 532px;">List of pivots. (Field name format: “object_name.field_name”).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">sorts</td>
<td style="width: 532px;">Sorting for the query results. (Field name format: “object_name.field_name”).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">limit</td>
<td style="width: 532px;">Maximum number of looks to return (0 for looker-determined limit).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">result_format</td>
<td style="width: 532px;">Format of the result.</td>
<td style="width: 71px;">Required</td>
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
<th style="width: 344px;"><strong>Path</strong></th>
<th style="width: 128px;"><strong>Type</strong></th>
<th style="width: 268px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 344px;">LookerResults.InlineQuery</td>
<td style="width: 128px;">Unknown</td>
<td style="width: 268px;">Inline query results.</td>
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
<pre>looker-run-inline-query model="thelook" view="order_items" fields="order_items.status, order_items.order_id, products.brand" filters="products.brand=Ray-Ban, Calvin Klein" limit="2" result_format="json"
</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-2">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>"LookerResults": {
        "InlineQuery": [
            {
                "OrderItems_OrderId": 5704, 
                "OrderItems_Status": "Cancelled", 
                "Products_Brand": "Ray-Ban"
            }, 
            {
                "OrderItems_OrderId": 1535, 
                "OrderItems_Status": "Cancelled", 
                "Products_Brand": "Ray-Ban"
            }
        ]
    }
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="inline-query-results">Inline Query Results</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 2px;">
<thead>
<tr>
<th>LookerResults.InlineQuery.OrderItems_Status</th>
<th>LookerResults.InlineQuery.OrderItems_OrderId</th>
<th>LookerResults.InlineQuery.Products_Brand</th>
</tr>
</thead>
<tbody>
<tr>
<td>Cancelled</td>
<td>5704</td>
<td>Ray-Ban</td>
</tr>
<tr>
<td>Cancelled</td>
<td>1535</td>
<td>Ray-Ban</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="create-a-look">4. Create a look</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Creates a look from a query</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>looker-create-look</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 155px;"><strong>Argument Name</strong></th>
<th style="width: 514px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 155px;">model</td>
<td style="width: 514px;">Name of the model. Can be found in the explore’s URL.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 155px;">view</td>
<td style="width: 514px;">Name of the view or Explore. Can be found in the explore’s URL.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 155px;">fields</td>
<td style="width: 514px;">List of fields to display. (Field name format: “object_name.field_name”).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">filters</td>
<td style="width: 514px;">Filters for the query, passed as a comma-separated list with the format: “field name=filter value;…” (Field name format: “object_name.field_name”).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">pivots</td>
<td style="width: 514px;">List of pivots. (Field name format: “object_name.field_name”).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">sorts</td>
<td style="width: 514px;">Sorting for the query results. (Field name format: “object_name.field_name”).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">look_title</td>
<td style="width: 514px;">Title of the look.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 155px;">look_description</td>
<td style="width: 514px;">Description of the look.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">look_space_id</td>
<td style="width: 514px;">ID of the space that will contain the look.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-3">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 252px;"><strong>Path</strong></th>
<th style="width: 74px;"><strong>Type</strong></th>
<th style="width: 414px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 252px;">Looker.Look.ID</td>
<td style="width: 74px;">Number</td>
<td style="width: 414px;">Look ID.</td>
</tr>
<tr>
<td style="width: 252px;">Looker.Look.Name</td>
<td style="width: 74px;">String</td>
<td style="width: 414px;">Look name.</td>
</tr>
<tr>
<td style="width: 252px;">Looker.Look.SpaceID</td>
<td style="width: 74px;">Number</td>
<td style="width: 414px;">ID of the space that contains the look.</td>
</tr>
<tr>
<td style="width: 252px;">Looker.Look.SpaceName</td>
<td style="width: 74px;">String</td>
<td style="width: 414px;">Name of the space that contains the look.</td>
</tr>
<tr>
<td style="width: 252px;">Looker.Look.LastUpdated</td>
<td style="width: 74px;">Date</td>
<td style="width: 414px;">The time that the look was last updated.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<p>This command has dynamic output keys.<br> To access them in the context, copy the key’s path from the column header in the results table.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-3">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>looker-run-inline-query model="thelook" view="order_items" fields="order_items.status, order_items.order_id, products.brand" filters="products.brand=Ray-Ban, Calvin Klein" limit="2" result_format="json" look_space_id=6 look_title="Look 3" look_description="This is my third saved look"
</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-3">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>"Looker": {
    "Look": {
        "ID": 7,
        "LastUpdated": "2019-04-10T16:11:43.249Z",
        "Name": "Look 3",
        "SpaceID": 6,
        "SpaceName": "Space 1"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-3">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="look-look-3-created-successfully">Look “Look 3” created successfully</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>ID</th>
<th>Name</th>
<th>SpaceID</th>
<th>SpaceName</th>
<th>LastUpdated</th>
</tr>
</thead>
<tbody>
<tr>
<td>7</td>
<td>Look 3</td>
<td>6</td>
<td>Space 1</td>
<td>2019-04-10T16:11:43.249Z</td>
</tr>
</tbody>
</table>
</div>
</div>
</div>
