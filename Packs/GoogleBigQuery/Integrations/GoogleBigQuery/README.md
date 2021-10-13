<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Google BigQuery is a data warehouse for querying and analyzing large databases.</p>
</div>
<div class="cl-preview-section">
<h2 id="configure-google-bigquery-on-demisto">Configure Google BigQuery on Cortex XSOAR</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Google BigQuery.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Google service account JSON (a credentials JSON generated from Google API Manager or from GCP console)</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section">
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.<br> After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li><a href="#perform-a-query-in-bigquery" target="_self">Perform a query in BigQuery: bigquery-query</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="perform-a-query-in-bigquery">1. Perform a query in BigQuery</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Performs a query on BigQuery.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>bigquery-query</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 143px;"><strong>Argument Name</strong></th>
<th style="width: 526px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 143px;">query</td>
<td style="width: 526px;">A query string (in BigQuery query syntax). For more information about the standard syntax, see the <a href="https://cloud.google.com/bigquery/docs/reference/standard-sql/query-syntax" target="_blank" rel="noopener">BigQuery documentation</a>.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 143px;">location</td>
<td style="width: 526px;">The geographic location where the job should run. Required for locations other than US and EU.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">allow_large_results</td>
<td style="width: 526px;">Allow query results tables larger than 128 MB compressed (legacy SQL only)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">default_dataset</td>
<td style="width: 526px;">A string of the fully-qualified dataset ID in standard SQL format. The value must include a project ID and dataset ID, separated by periods.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">destination_table</td>
<td style="width: 526px;">The table to which the results are written. Default value is “None”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">kms_key_name</td>
<td style="width: 526px;">Custom encryption configuration for the destination table.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">dry_run</td>
<td style="width: 526px;">If “true,” BigQuery doesn’t run the job. Instead, if the query is valid, BigQuery returns statistics about the job, such as how many bytes would be processed. If the query is invalid, an error is returned. The default value is “false”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">priority</td>
<td style="width: 526px;">Priority of the query (“INTERACTIVE” or “BATCH”). A query set as INTERACTIVE will be run on-demand, at the next possible time. A query set as BATCH will start as soon as idle resources are available, and changed to INTERACTIVE priority if it wasn’t started within 24 hours. The default value is “INTERACTIVE”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">use_query_cache</td>
<td style="width: 526px;">Whether to look for the query results in the cache.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">use_legacy_sql</td>
<td style="width: 526px;">Whether to use legacy SQL syntax.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">job_id</td>
<td style="width: 526px;">The ID of the job. The ID must contain only letters (a-z, A-Z), numbers (0-9), underscores (_), or dashes (-). The maximum length is 1,024 characters.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">write_disposition</td>
<td style="width: 526px;">Specifies the action that occurs if the destination table already exists.</td>
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
<th style="width: 181px;"><strong>Path</strong></th>
<th style="width: 101px;"><strong>Type</strong></th>
<th style="width: 458px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 181px;">BigQuery.Query</td>
<td style="width: 101px;">String</td>
<td style="width: 458px;">The query performed.</td>
</tr>
<tr>
<td style="width: 181px;">BigQuery.Row</td>
<td style="width: 101px;">Unknown</td>
<td style="width: 458px;">The table rows the given query returned.</td>
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
<pre>!bigquery-query query="SELECT * FROMbigquery-public-data.usa_names.usa_1910_2013<code>WHERE state='TX' LIMIT 100"</code></pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "BigQuery": {
        "Query": "SELECT * FROM `bigquery-public-data.usa_names.usa_1910_2013` WHERE state='TX' LIMIT 100", 
        "Row": [
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Frances", 
                "Number": 197
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Alice", 
                "Number": 149
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Beatrice", 
                "Number": 123
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Ella", 
                "Number": 102
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Gertrude", 
                "Number": 97
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Josephine", 
                "Number": 86
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Lula", 
                "Number": 77
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Blanche", 
                "Number": 50
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Marjorie", 
                "Number": 40
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Christine", 
                "Number": 34
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Margarita", 
                "Number": 31
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Alta", 
                "Number": 29
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Sara", 
                "Number": 28
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Naomi", 
                "Number": 24
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Sofia", 
                "Number": 23
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Andrea", 
                "Number": 16
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Delfina", 
                "Number": 16
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Dominga", 
                "Number": 16
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Elnora", 
                "Number": 16
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Adele", 
                "Number": 15
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Rafaela", 
                "Number": 12
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Dixie", 
                "Number": 11
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Luisa", 
                "Number": 11
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Bess", 
                "Number": 10
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Ernestine", 
                "Number": 10
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Lorine", 
                "Number": 9
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Patsy", 
                "Number": 9
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Cecelia", 
                "Number": 8
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Enriqueta", 
                "Number": 8
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Lucinda", 
                "Number": 8
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Alyce", 
                "Number": 7
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Oneta", 
                "Number": 7
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Apolonia", 
                "Number": 6
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Gloria", 
                "Number": 6
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Rhoda", 
                "Number": 6
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Buna", 
                "Number": 5
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Maye", 
                "Number": 5
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Pansy", 
                "Number": 5
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Gladys", 
                "Number": 240
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Maria", 
                "Number": 223
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Helen", 
                "Number": 189
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Velma", 
                "Number": 133
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Clara", 
                "Number": 129
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Anna", 
                "Number": 117
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Evelyn", 
                "Number": 106
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Rosa", 
                "Number": 88
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Mae", 
                "Number": 83
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Bernice", 
                "Number": 77
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Stella", 
                "Number": 69
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Vivian", 
                "Number": 63
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Mable", 
                "Number": 62
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Maggie", 
                "Number": 54
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Betty", 
                "Number": 50
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Guadalupe", 
                "Number": 50
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Lorene", 
                "Number": 46
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Susie", 
                "Number": 44
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Sadie", 
                "Number": 42
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Erma", 
                "Number": 38
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Verna", 
                "Number": 37
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Amelia", 
                "Number": 33
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Estelle", 
                "Number": 31
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Nell", 
                "Number": 31
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Margie", 
                "Number": 28
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Celia", 
                "Number": 26
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Lessie", 
                "Number": 24
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Eloise", 
                "Number": 22
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Millie", 
                "Number": 22
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Olga", 
                "Number": 21
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Letha", 
                "Number": 20
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Rachel", 
                "Number": 19
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Luz", 
                "Number": 16
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Gussie", 
                "Number": 15
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Sylvia", 
                "Number": 14
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Aline", 
                "Number": 13
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Barbara", 
                "Number": 11
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Iris", 
                "Number": 11
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Leila", 
                "Number": 10
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Mozelle", 
                "Number": 10
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Simona", 
                "Number": 9
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Catalina", 
                "Number": 8
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Hester", 
                "Number": 8
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Willia", 
                "Number": 8
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Allene", 
                "Number": 7
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Avis", 
                "Number": 7
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "George", 
                "Number": 7
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Isabella", 
                "Number": 7
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Polly", 
                "Number": 7
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Syble", 
                "Number": 7
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Teodora", 
                "Number": 7
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Lennie", 
                "Number": 5
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Ricarda", 
                "Number": 5
            }, 
            {
                "Gender": "F", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Valerie", 
                "Number": 5
            }, 
            {
                "Gender": "M", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Robert", 
                "Number": 276
            }, 
            {
                "Gender": "M", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Willie", 
                "Number": 199
            }, 
            {
                "Gender": "M", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Fred", 
                "Number": 78
            }, 
            {
                "Gender": "M", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Raymond", 
                "Number": 78
            }, 
            {
                "Gender": "M", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Richard", 
                "Number": 75
            }, 
            {
                "Gender": "M", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Sam", 
                "Number": 56
            }, 
            {
                "Gender": "M", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Ernest", 
                "Number": 55
            }, 
            {
                "Gender": "M", 
                "State": "TX", 
                "Year": 1910, 
                "Name": "Leroy", 
                "Number": 29
            }
        ]
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="bigquery-query-results">BigQuery Query Results</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>State</th>
<th>Gender</th>
<th>Year</th>
<th>Name</th>
<th>Number</th>
</tr>
</thead>
<tbody>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Frances</td>
<td>197</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Alice</td>
<td>149</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Beatrice</td>
<td>123</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Ella</td>
<td>102</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Gertrude</td>
<td>97</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Josephine</td>
<td>86</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Lula</td>
<td>77</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Blanche</td>
<td>50</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Marjorie</td>
<td>40</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Christine</td>
<td>34</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Margarita</td>
<td>31</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Alta</td>
<td>29</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Sara</td>
<td>28</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Naomi</td>
<td>24</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Sofia</td>
<td>23</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Andrea</td>
<td>16</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Delfina</td>
<td>16</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Dominga</td>
<td>16</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Elnora</td>
<td>16</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Adele</td>
<td>15</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Rafaela</td>
<td>12</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Dixie</td>
<td>11</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Luisa</td>
<td>11</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Bess</td>
<td>10</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Ernestine</td>
<td>10</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Lorine</td>
<td>9</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Patsy</td>
<td>9</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Cecelia</td>
<td>8</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Enriqueta</td>
<td>8</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Lucinda</td>
<td>8</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Alyce</td>
<td>7</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Oneta</td>
<td>7</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Apolonia</td>
<td>6</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Gloria</td>
<td>6</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Rhoda</td>
<td>6</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Buna</td>
<td>5</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Maye</td>
<td>5</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Pansy</td>
<td>5</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Gladys</td>
<td>240</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Maria</td>
<td>223</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Helen</td>
<td>189</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Velma</td>
<td>133</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Clara</td>
<td>129</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Anna</td>
<td>117</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Evelyn</td>
<td>106</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Rosa</td>
<td>88</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Mae</td>
<td>83</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Bernice</td>
<td>77</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Stella</td>
<td>69</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Vivian</td>
<td>63</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Mable</td>
<td>62</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Maggie</td>
<td>54</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Betty</td>
<td>50</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Guadalupe</td>
<td>50</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Lorene</td>
<td>46</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Susie</td>
<td>44</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Sadie</td>
<td>42</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Erma</td>
<td>38</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Verna</td>
<td>37</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Amelia</td>
<td>33</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Estelle</td>
<td>31</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Nell</td>
<td>31</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Margie</td>
<td>28</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Celia</td>
<td>26</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Lessie</td>
<td>24</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Eloise</td>
<td>22</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Millie</td>
<td>22</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Olga</td>
<td>21</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Letha</td>
<td>20</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Rachel</td>
<td>19</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Luz</td>
<td>16</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Gussie</td>
<td>15</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Sylvia</td>
<td>14</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Aline</td>
<td>13</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Barbara</td>
<td>11</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Iris</td>
<td>11</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Leila</td>
<td>10</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Mozelle</td>
<td>10</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Simona</td>
<td>9</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Catalina</td>
<td>8</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Hester</td>
<td>8</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Willia</td>
<td>8</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Allene</td>
<td>7</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Avis</td>
<td>7</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>George</td>
<td>7</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Isabella</td>
<td>7</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Polly</td>
<td>7</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Syble</td>
<td>7</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Teodora</td>
<td>7</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Lennie</td>
<td>5</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Ricarda</td>
<td>5</td>
</tr>
<tr>
<td>TX</td>
<td>F</td>
<td>1910</td>
<td>Valerie</td>
<td>5</td>
</tr>
<tr>
<td>TX</td>
<td>M</td>
<td>1910</td>
<td>Robert</td>
<td>276</td>
</tr>
<tr>
<td>TX</td>
<td>M</td>
<td>1910</td>
<td>Willie</td>
<td>199</td>
</tr>
<tr>
<td>TX</td>
<td>M</td>
<td>1910</td>
<td>Fred</td>
<td>78</td>
</tr>
<tr>
<td>TX</td>
<td>M</td>
<td>1910</td>
<td>Raymond</td>
<td>78</td>
</tr>
<tr>
<td>TX</td>
<td>M</td>
<td>1910</td>
<td>Richard</td>
<td>75</td>
</tr>
<tr>
<td>TX</td>
<td>M</td>
<td>1910</td>
<td>Sam</td>
<td>56</td>
</tr>
<tr>
<td>TX</td>
<td>M</td>
<td>1910</td>
<td>Ernest</td>
<td>55</td>
</tr>
<tr>
<td>TX</td>
<td>M</td>
<td>1910</td>
<td>Leroy</td>
<td>29</td>
</tr>
</tbody>
</table>
</div>
</div>