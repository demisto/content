<!-- HTML_DOC -->
<p><span>Use the Elasticsearch v2 integration to query and search indexes using the Lucene syntax.</span></p>
<h2>Use Cases</h2>
<ul>
<li>Query and search indexes.</li>
<li>Calculate query and search scores based on accuracy of results.</li>
</ul>
<h2>Additional Information</h2>
<p>The Elasticsearch v2 integration supports Elasticsearch 6.0.0 and later.</p>
<p>Strings are queried using the Lucene syntax. For more information about the Lucene syntax, see: <a href="https://www.elastic.co/guide/en/elasticsearch/reference/7.3/query-dsl-query-string-query.html#query-string-syntax">https://www.elastic.co/guide/en/elasticsearch/reference/7.3/query-dsl-query-string-query.html#query-string-syntax</a></p>
<p>For more information about request response fields, see: <a href="https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-body.html#request-body-search-explain">https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-body.html#request-body-search-explain</a></p>
<p>For more information about type mapping, see: <a href="https://www.elastic.co/guide/en/elasticsearch/reference/7.x/mapping.html#mapping-type">https://www.elastic.co/guide/en/elasticsearch/reference/7.x/mapping.html#mapping-type</a></p>
<p>Note: Not all fields can be sorted in Elasticsearch. The fields are used to sort the results table. The supported result types are boolean, numeric, date, and keyword fields. </p>
<h2>Configure Elasticsearch v2 on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong>  &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Elasticsearch v2.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li>
<strong>Server URL</strong>: the Elasticsearch server to which the integration connects. Ensure that the URL includes the correct Elasticsearch port. By default this is 9200.</li>
<li>
<strong>Username and password</strong>: to log in to the server.</li>
</ul>
</li>
<li>(Optional) Select the <strong>Fetch Incidents</strong> box and input the additional parameters.
<ul>
<li>A CSV list from which to fetch incidents.</li>
<li>The query by which to fetch incidents (Lucene syntax).</li>
<li>The index time field (for sorting sort and limiting data).</li>
<li>The time format as kept in Elasticsearch.</li>
<li>The first fetch timestamp.</li>
<li>The number of results returned in each fetch.
<p>Selecting the Fetch Incidents checkbox makes the additional parameters above mandatory.</p>
</li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the new instance.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_82e92c75-e6a8-4a9f-a94a-8ef38336a017" target="_self">Query an index: es-search</a></li>
<li><a href="#h_b54d5b7b-35d1-44f5-a347-e1079bf0bc98" target="_self">Searches an index: search</a></li>
</ol>
<h3 id="h_82e92c75-e6a8-4a9f-a94a-8ef38336a017">1. Query an index</h3>
<!-- <hr> -->
<p>Queries an index.</p>
<h5>Base Command</h5>
<p><code>es-search</code></p>
<h5>Input</h5>
<table style="width: 747px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 160.444px;"><strong>Argument Name</strong></th>
<th style="width: 474.556px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 160.444px;">index</td>
<td style="width: 474.556px;">The index in which to perform a search.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 160.444px;">query</td>
<td style="width: 474.556px;">The string to query. Strings are queried using the Lucene syntax.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 160.444px;">fields</td>
<td style="width: 474.556px;">A CSV list of the fields of a document to fetch. Leaving the fields empty fetches the entire document.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 160.444px;">explain</td>
<td style="width: 474.556px;">Calculates an explanation of a score for a query. Default is "false". For example, "value:1.6943597".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 160.444px;">page</td>
<td style="width: 474.556px;">The number of the page from which to start a search. The default is "0".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 160.444px;">size</td>
<td style="width: 474.556px;">The number of documents displayed per page. Can be "1" to "10,000". The default is "100".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 160.444px;">sort-field</td>
<td style="width: 474.556px;">The field by which to sort the results table. The supported result types are boolean, numeric, date, and keyword fields. Keyword fields require the doc_values parameter to be set to "true" from the Elasticsearch server.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 160.444px;">sort-order</td>
<td style="width: 474.556px;">The order by which to sort the results table. The results tables can only be sorted if a sort-field is defined.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 747px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 223.667px;"><strong>Path</strong></th>
<th style="width: 84.3333px;"><strong>Type</strong></th>
<th style="width: 398px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 223.667px;">Elasticsearch.Search.Results._index</td>
<td style="width: 84.3333px;">String</td>
<td style="width: 398px;">The index to which the document belongs.</td>
</tr>
<tr>
<td style="width: 223.667px;">Elasticsearch.Search.Results._id</td>
<td style="width: 84.3333px;">String</td>
<td style="width: 398px;">The ID of the document.</td>
</tr>
<tr>
<td style="width: 223.667px;">Elasticsearch.Search.Results._type</td>
<td style="width: 84.3333px;">String</td>
<td style="width: 398px;">The mapping type of the document.</td>
</tr>
<tr>
<td style="width: 223.667px;">Elasticsearch.Search.max_score</td>
<td style="width: 84.3333px;">Number</td>
<td style="width: 398px;">The maximum relevance score of a query.</td>
</tr>
<tr>
<td style="width: 223.667px;">Elasticsearch.Search.Query</td>
<td style="width: 84.3333px;">String</td>
<td style="width: 398px;">The query performed in the search.</td>
</tr>
<tr>
<td style="width: 223.667px;">Elasticsearch.Search.total.value</td>
<td style="width: 84.3333px;">Number</td>
<td style="width: 398px;">The number of search results.</td>
</tr>
<tr>
<td style="width: 223.667px;">Elasticsearch.Search.Results._score</td>
<td style="width: 84.3333px;">Number</td>
<td style="width: 398px;">The relevance score of the search result.</td>
</tr>
<tr>
<td style="width: 223.667px;">Elasticsearch.Search.Index</td>
<td style="width: 84.3333px;">String</td>
<td style="width: 398px;">The index in which the search was performed.</td>
</tr>
<tr>
<td style="width: 223.667px;">Elasticsearch.Search.Server</td>
<td style="width: 84.3333px;">String</td>
<td style="width: 398px;">The server on which the search was performed.</td>
</tr>
<tr>
<td style="width: 223.667px;">Elasticsearch.Search.timed_out</td>
<td style="width: 84.3333px;">Boolean</td>
<td style="width: 398px;">Whether the search stopped due to a time-out.</td>
</tr>
<tr>
<td style="width: 223.667px;">Elasticsearch.Search.took</td>
<td style="width: 84.3333px;">Number</td>
<td style="width: 398px;">The time in milliseconds taken for the search to complete.</td>
</tr>
<tr>
<td style="width: 223.667px;">Elasticsearch.Search.Page</td>
<td style="width: 84.3333px;">Number</td>
<td style="width: 398px;">The number of the page from which the search started</td>
</tr>
<tr>
<td style="width: 223.667px;">Elasticsearch.Search.Size</td>
<td style="width: 84.3333px;">Number</td>
<td style="width: 398px;">The maximum amount of scores that a search can return.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!es-search query="Date:* AND name:incident" index=users fields=name,nums sort-field=Date sort-order=desc size=2</pre>
<h5>Human Readable Output</h5>
<p> <img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/Elasticsearch_v2_1.png" alt="1.png"></p>
<h3 id="h_b54d5b7b-35d1-44f5-a347-e1079bf0bc98">2. Search an index</h3>
<!-- <hr> -->
<p>Searches an index.</p>
<h5>Base Command</h5>
<p><code>search</code></p>
<h5>Input</h5>
<table style="width: 747px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 198.444px;"><strong>Argument Name</strong></th>
<th style="width: 436.556px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 198.444px;">index</td>
<td style="width: 436.556px;">The index in which to perform a search.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 198.444px;">query</td>
<td style="width: 436.556px;">The string to query. Strings are queried using the Lucene syntax.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 198.444px;">fields</td>
<td style="width: 436.556px;">A CSV list of the fields of a document to fetch. Leaving the fields empty fetches the entire document.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 198.444px;">explain</td>
<td style="width: 436.556px;">Calculates an explanation of a score for a query. Default is "false". For example, "value:1.6943597".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 198.444px;">page</td>
<td style="width: 436.556px;">The number of the page from which to start a search. The default is "0".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 198.444px;">size</td>
<td style="width: 436.556px;">The number of documents displayed per page. Can be "1" to "10,000". The default is "100".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 198.444px;">sort-field</td>
<td style="width: 436.556px;">The field by which to sort the results table. The supported result types are boolean, numeric, date, and keyword fields. Keyword fields require the doc_values parameter to be set to "true" from the Elasticsearch server.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 198.444px;">sort-order</td>
<td style="width: 436.556px;">The order by which to sort the results table. The results tables can only be sorted if a sort-field is defined.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 747px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 216.667px;"><strong>Path</strong></th>
<th style="width: 91.3333px;"><strong>Type</strong></th>
<th style="width: 398px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 216.667px;">Elasticsearch.Search.Results._index</td>
<td style="width: 91.3333px;">String</td>
<td style="width: 398px;">The index to which the document belongs.</td>
</tr>
<tr>
<td style="width: 216.667px;">Elasticsearch.Search.Results._id</td>
<td style="width: 91.3333px;">String</td>
<td style="width: 398px;">The ID of the document.</td>
</tr>
<tr>
<td style="width: 216.667px;">Elasticsearch.Search.Results._type</td>
<td style="width: 91.3333px;">String</td>
<td style="width: 398px;">The mapping type of the document.</td>
</tr>
<tr>
<td style="width: 216.667px;">Elasticsearch.Search.max_score</td>
<td style="width: 91.3333px;">Number</td>
<td style="width: 398px;">The maximum relevance score of a query.</td>
</tr>
<tr>
<td style="width: 216.667px;">Elasticsearch.Search.Query</td>
<td style="width: 91.3333px;">String</td>
<td style="width: 398px;">The query performed in the search.</td>
</tr>
<tr>
<td style="width: 216.667px;">Elasticsearch.Search.total.value</td>
<td style="width: 91.3333px;">Number</td>
<td style="width: 398px;">The number of search results.</td>
</tr>
<tr>
<td style="width: 216.667px;">Elasticsearch.Search.Results._score</td>
<td style="width: 91.3333px;">Number</td>
<td style="width: 398px;">The relevance score of the search result.</td>
</tr>
<tr>
<td style="width: 216.667px;">Elasticsearch.Search.Index</td>
<td style="width: 91.3333px;">String</td>
<td style="width: 398px;">The index in which the search was performed.</td>
</tr>
<tr>
<td style="width: 216.667px;">Elasticsearch.Search.Server</td>
<td style="width: 91.3333px;">String</td>
<td style="width: 398px;">The server on which the search was performed.</td>
</tr>
<tr>
<td style="width: 216.667px;">Elasticsearch.Search.timed_out</td>
<td style="width: 91.3333px;">Boolean</td>
<td style="width: 398px;">Whether the search stopped due to a time-out.</td>
</tr>
<tr>
<td style="width: 216.667px;">Elasticsearch.Search.took</td>
<td style="width: 91.3333px;">Number</td>
<td style="width: 398px;">The time in milliseconds taken for the search to complete.</td>
</tr>
<tr>
<td style="width: 216.667px;">Elasticsearch.Search.Page</td>
<td style="width: 91.3333px;">Number</td>
<td style="width: 398px;">The number of the page from which the search started.</td>
</tr>
<tr>
<td style="width: 216.667px;">Elasticsearch.Search.Size</td>
<td style="width: 91.3333px;">Number</td>
<td style="width: 398px;">The maximum amount of scores that a search can return.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!search query="Date:* AND name:incident" index=users fields=name,nums sort-field=Date sort-order=desc size=2</pre>
<h5>Human Readable Output</h5>
<p> <img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/Elasticsearch_v2_1.png" alt="1.png"></p>
<h2>Troubleshooting</h2>
<p>For more information about the correct time format, see <a href="http://strftime.org/" target="_self">http://strftime.org/</a>.</p>
<h2>Schema Mapping</h2>
<p>Cortex XSOAR version 6.0 introduces an improved classification & mapping experience, which includes fetching schema data.</p>
<p>Elasticsearch v2 integration supports fetching the schema of indexes that are set in the <strong>Index from which to fetch incidents</strong> integration parameter, thereby enabling mapping fields per index.</p>
<h3>Setup schema mapping</h3> 
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong>  &gt; <strong>Classification &amp; Mapping</strong>.</li>
<li>Create a new mapper and edit an existing one</li>
<li>Set <strong>Get data</strong> to <strong>Select schema</strong> and <strong>Select instance</strong> to the Elasticsearch v2 integration instance to fetch from.</li>
<li>Map fields according to the fetched index schema.</li>
</ol>
