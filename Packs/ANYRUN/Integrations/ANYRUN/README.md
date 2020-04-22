<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>ANY.RUN is a cloud-based sandbox with interactive access.</p>
</div>
<div class="cl-preview-section">
<h2 id="use-cases">Use Cases</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Submit a file, remote file, or URL to ANY.RUN for analysis.</li>
<li>Retrieve report details for a given analysis task ID.</li>
<li>View history of analysis tasks.</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="configure-anyrun-on-demisto">Configure ANYRUN on Demisto</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for ANYRUN.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL</strong></li>
<li><strong>Username</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section">
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.<br> After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li><a href="#get-analysis-history" target="_self">Get analysis history: anyrun-get-history</a></li>
<li><a href="#get-a-task-report-for-a-submission" target="_self">Get a task report for a submission: anyrun-get-report</a></li>
<li><a href="#anyrun-run-analysis" target="_self">Submit a file or URL for analysis: anyrun-run-analysis</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="get-analysis-history">1. Get analysis history</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Gets the analysis history.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>anyrun-get-history</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 135px;"><strong>Argument Name</strong></th>
<th style="width: 534px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 135px;">team</td>
<td style="width: 534px;">If true, gets team history. If empty, gets your submitted analyses history.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 135px;">skip</td>
<td style="width: 534px;">The number of analyses to skip.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 135px;">limit</td>
<td style="width: 534px;">Limits the history retrieved/searched to the specified number of executed analyses. The range is 1-100.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 135px;">filter</td>
<td style="width: 534px;">File name, hash, or task ID by which to filter the task history.</td>
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
<th style="width: 256px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 425px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 256px;">ANYRUN.Task.Name</td>
<td style="width: 59px;">String</td>
<td style="width: 425px;">Task name.</td>
</tr>
<tr>
<td style="width: 256px;">ANYRUN.Task.Verdict</td>
<td style="width: 59px;">String</td>
<td style="width: 425px;">ANY.RUN verdict for the submitted file’s status.</td>
</tr>
<tr>
<td style="width: 256px;">ANYRUN.Task.Related</td>
<td style="width: 59px;">String</td>
<td style="width: 425px;">ANY.RUN link to a related file.</td>
</tr>
<tr>
<td style="width: 256px;">ANYRUN.Task.File</td>
<td style="width: 59px;">String</td>
<td style="width: 425px;">ANY.RUN link to download the submitted file.</td>
</tr>
<tr>
<td style="width: 256px;">ANYRUN.Task.Date</td>
<td style="width: 59px;">Date</td>
<td style="width: 425px;">The date that the file was submitted for analysis.</td>
</tr>
<tr>
<td style="width: 256px;">ANYRUN.Task.Hash.MD5</td>
<td style="width: 59px;">String</td>
<td style="width: 425px;">MD5 hash of the submitted file.</td>
</tr>
<tr>
<td style="width: 256px;">ANYRUN.Task.Hash.SHA1</td>
<td style="width: 59px;">String</td>
<td style="width: 425px;">SHA1 hash of the submitted file.</td>
</tr>
<tr>
<td style="width: 256px;">ANYRUN.Task.Hash.SHA256</td>
<td style="width: 59px;">String</td>
<td style="width: 425px;">SHA256 hash of the submitted file.</td>
</tr>
<tr>
<td style="width: 256px;">ANYRUN.Task.Hash.HeadHash</td>
<td style="width: 59px;">String</td>
<td style="width: 425px;">Head hash of the submitted file.</td>
</tr>
<tr>
<td style="width: 256px;">ANYRUN.Task.Hash.SSDeep</td>
<td style="width: 59px;">String</td>
<td style="width: 425px;">SSDeep hash of the submitted file.</td>
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
<p><code>anyrun-get-history skip=0 team=false filter=scribbles2.txt.zip</code></p>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "ANYRUN.Task": [
        {
            "Hash": {
                "HeadHash": "e61fcc6a06420106fa6642ef833b9c38", 
                "SHA1": "475d7efc7983357e51ea780e350b0efe6a5ba2e2", 
                "SHA256": "1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1", 
                "SSDeep": "24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9", 
                "MD5": "e61fcc6a06420106fa6642ef833b9c38"
            }, 
            "Name": "scribbles2.txt.zip", 
            "Related": "[https://app.any.run/tasks/892455a2-8c96-45fb-9f2a-18ca4ef184f9](https://app.any.run/tasks/892455a2-8c96-45fb-9f2a-18ca4ef184f9)", 
            "Verdict": "No threats detected", 
            "File": "https://content.any.run/tasks/892455a2-8c96-45fb-9f2a-18ca4ef184f9/download/files/afca4a63-9fe0-461c-8e73-c8fd784cf90e", 
            "Date": "2019-04-24T07:13:06.087Z", 
            "ID": "892455a2-8c96-45fb-9f2a-18ca4ef184f9"
        }, 
        {
            "Hash": {
                "HeadHash": "e61fcc6a06420106fa6642ef833b9c38", 
                "SHA1": "475d7efc7983357e51ea780e350b0efe6a5ba2e2", 
                "SHA256": "1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1", 
                "SSDeep": "24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9", 
                "MD5": "e61fcc6a06420106fa6642ef833b9c38"
            }, 
            "Name": "scribbles2.txt.zip", 
            "Related": "[https://app.any.run/tasks/fe7c63ef-2b7f-4e70-b50c-996ae34b28ef](https://app.any.run/tasks/fe7c63ef-2b7f-4e70-b50c-996ae34b28ef)", 
            "Verdict": "No threats detected", 
            "File": "https://content.any.run/tasks/fe7c63ef-2b7f-4e70-b50c-996ae34b28ef/download/files/227a7bd4-5baa-477b-b319-58d7619b79ef", 
            "Date": "2019-04-24T07:02:38.747Z", 
            "ID": "fe7c63ef-2b7f-4e70-b50c-996ae34b28ef"
        }, 
        {
            "Hash": {
                "HeadHash": "e61fcc6a06420106fa6642ef833b9c38", 
                "SHA1": "475d7efc7983357e51ea780e350b0efe6a5ba2e2", 
                "SHA256": "1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1", 
                "SSDeep": "24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9", 
                "MD5": "e61fcc6a06420106fa6642ef833b9c38"
            }, 
            "Name": "scribbles2.txt.zip", 
            "Related": "[https://app.any.run/tasks/81bb80cd-3bcf-41b3-aac5-c3e35a39ba0d](https://app.any.run/tasks/81bb80cd-3bcf-41b3-aac5-c3e35a39ba0d)", 
            "Verdict": "No threats detected", 
            "File": "https://content.any.run/tasks/81bb80cd-3bcf-41b3-aac5-c3e35a39ba0d/download/files/0c5c1527-b50b-483e-84e1-7b4b8f82d26b", 
            "Date": "2019-04-23T13:46:47.372Z", 
            "ID": "81bb80cd-3bcf-41b3-aac5-c3e35a39ba0d"
        }, 
        {
            "Hash": {
                "HeadHash": "e61fcc6a06420106fa6642ef833b9c38", 
                "SHA1": "475d7efc7983357e51ea780e350b0efe6a5ba2e2", 
                "SHA256": "1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1", 
                "SSDeep": "24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9", 
                "MD5": "e61fcc6a06420106fa6642ef833b9c38"
            }, 
            "Name": "scribbles2.txt.zip", 
            "Related": "[https://app.any.run/tasks/07d4d230-9638-4f04-a226-c7b18a81c329](https://app.any.run/tasks/07d4d230-9638-4f04-a226-c7b18a81c329)", 
            "Verdict": "No threats detected", 
            "File": "https://content.any.run/tasks/07d4d230-9638-4f04-a226-c7b18a81c329/download/files/69dcf7f0-69c2-432e-8d30-3e2f630e0aae", 
            "Date": "2019-04-23T08:11:17.460Z", 
            "ID": "07d4d230-9638-4f04-a226-c7b18a81c329"
        }, 
        {
            "Hash": {
                "HeadHash": "e61fcc6a06420106fa6642ef833b9c38", 
                "SHA1": "475d7efc7983357e51ea780e350b0efe6a5ba2e2", 
                "SHA256": "1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1", 
                "SSDeep": "24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9", 
                "MD5": "e61fcc6a06420106fa6642ef833b9c38"
            }, 
            "Name": "scribbles2.txt.zip", 
            "Related": "[https://app.any.run/tasks/411fe6a6-ca36-4322-8f1d-f5ec67c6346d](https://app.any.run/tasks/411fe6a6-ca36-4322-8f1d-f5ec67c6346d)", 
            "Verdict": "No threats detected", 
            "File": "https://content.any.run/tasks/411fe6a6-ca36-4322-8f1d-f5ec67c6346d/download/files/a006642b-956b-4a9d-a72c-0affdd2dd6c8", 
            "Date": "2019-04-22T12:16:13.302Z", 
            "ID": "411fe6a6-ca36-4322-8f1d-f5ec67c6346d"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="task-history---filtered-by-scribbles2.txt.zip">Task History - Filtered By “scribbles2.txt.zip”</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Name</th>
<th>ID</th>
<th>File</th>
<th>Hash</th>
<th>Verdict</th>
<th>Related</th>
<th>Date</th>
</tr>
</thead>
<tbody>
<tr>
<td>scribbles2.txt.zip</td>
<td>892455a2-8c96-45fb-9f2a-18ca4ef184f9</td>
<td>https://content.any.run/tasks/892455a2-8c96-45fb-9f2a-18ca4ef184f9/download/files/afca4a63-9fe0-461c-8e73-c8fd784cf90e</td>
<td>MD5: e61fcc6a06420106fa6642ef833b9c38<br> SHA1: 475d7efc7983357e51ea780e350b0efe6a5ba2e2<br> SHA256: 1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1<br> HeadHash: e61fcc6a06420106fa6642ef833b9c38<br> SSDeep: 24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9</td>
<td>No threats detected</td>
<td><a href="https://app.any.run/tasks/892455a2-8c96-45fb-9f2a-18ca4ef184f9">https://app.any.run/tasks/892455a2-8c96-45fb-9f2a-18ca4ef184f9</a></td>
<td>2019-04-24T07:13:06.087Z</td>
</tr>
<tr>
<td>scribbles2.txt.zip</td>
<td>fe7c63ef-2b7f-4e70-b50c-996ae34b28ef</td>
<td>https://content.any.run/tasks/fe7c63ef-2b7f-4e70-b50c-996ae34b28ef/download/files/227a7bd4-5baa-477b-b319-58d7619b79ef</td>
<td>MD5: e61fcc6a06420106fa6642ef833b9c38<br> SHA1: 475d7efc7983357e51ea780e350b0efe6a5ba2e2<br> SHA256: 1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1<br> HeadHash: e61fcc6a06420106fa6642ef833b9c38<br> SSDeep: 24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9</td>
<td>No threats detected</td>
<td><a href="https://app.any.run/tasks/fe7c63ef-2b7f-4e70-b50c-996ae34b28ef">https://app.any.run/tasks/fe7c63ef-2b7f-4e70-b50c-996ae34b28ef</a></td>
<td>2019-04-24T07:02:38.747Z</td>
</tr>
<tr>
<td>scribbles2.txt.zip</td>
<td>81bb80cd-3bcf-41b3-aac5-c3e35a39ba0d</td>
<td>https://content.any.run/tasks/81bb80cd-3bcf-41b3-aac5-c3e35a39ba0d/download/files/0c5c1527-b50b-483e-84e1-7b4b8f82d26b</td>
<td>MD5: e61fcc6a06420106fa6642ef833b9c38<br> SHA1: 475d7efc7983357e51ea780e350b0efe6a5ba2e2<br> SHA256: 1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1<br> HeadHash: e61fcc6a06420106fa6642ef833b9c38<br> SSDeep: 24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9</td>
<td>No threats detected</td>
<td><a href="https://app.any.run/tasks/81bb80cd-3bcf-41b3-aac5-c3e35a39ba0d">https://app.any.run/tasks/81bb80cd-3bcf-41b3-aac5-c3e35a39ba0d</a></td>
<td>2019-04-23T13:46:47.372Z</td>
</tr>
<tr>
<td>scribbles2.txt.zip</td>
<td>07d4d230-9638-4f04-a226-c7b18a81c329</td>
<td>https://content.any.run/tasks/07d4d230-9638-4f04-a226-c7b18a81c329/download/files/69dcf7f0-69c2-432e-8d30-3e2f630e0aae</td>
<td>MD5: e61fcc6a06420106fa6642ef833b9c38<br> SHA1: 475d7efc7983357e51ea780e350b0efe6a5ba2e2<br> SHA256: 1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1<br> HeadHash: e61fcc6a06420106fa6642ef833b9c38<br> SSDeep: 24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9</td>
<td>No threats detected</td>
<td><a href="https://app.any.run/tasks/07d4d230-9638-4f04-a226-c7b18a81c329">https://app.any.run/tasks/07d4d230-9638-4f04-a226-c7b18a81c329</a></td>
<td>2019-04-23T08:11:17.460Z</td>
</tr>
<tr>
<td>scribbles2.txt.zip</td>
<td>411fe6a6-ca36-4322-8f1d-f5ec67c6346d</td>
<td>https://content.any.run/tasks/411fe6a6-ca36-4322-8f1d-f5ec67c6346d/download/files/a006642b-956b-4a9d-a72c-0affdd2dd6c8</td>
<td>MD5: e61fcc6a06420106fa6642ef833b9c38<br> SHA1: 475d7efc7983357e51ea780e350b0efe6a5ba2e2<br> SHA256: 1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1<br> HeadHash: e61fcc6a06420106fa6642ef833b9c38<br> SSDeep: 24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9</td>
<td>No threats detected</td>
<td><a href="https://app.any.run/tasks/411fe6a6-ca36-4322-8f1d-f5ec67c6346d">https://app.any.run/tasks/411fe6a6-ca36-4322-8f1d-f5ec67c6346d</a></td>
<td>2019-04-22T12:16:13.302Z</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-a-task-report-for-a-submission">2. Get a task report for a submission</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Gets the report of a task created for a submitted file or URL.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>anyrun-get-report</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>task</td>
<td>Unique task ID. A task ID is returned when submitting a file or URL for analysis using the <a href="#anyrun-run-analysis" target="_self"><code>anyrun-run-analysis</code></a> command. Task IDs can also be located in the <code>ID</code> field of the output of executing the <a href="#get-analysis-history" target="_self"><code>anyrun-get-history</code></a> command.</td>
<td>Required</td>
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
<th style="width: 293px;"><strong>Path</strong></th>
<th style="width: 70px;"><strong>Type</strong></th>
<th style="width: 377px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 293px;">ANYRUN.Task.AnalysisDate</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Date and time the analysis was executed.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Behavior.Category</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Category of a process behavior.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Behavior.Action</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Actions performed by a process.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Behavior.ThreatLevel</td>
<td style="width: 70px;">Number</td>
<td style="width: 377px;">Threat score associated with a process behavior.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Behavior.ProcessUUID</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Unique ID of the process whose behaviors are being profiled.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Connection.Reputation</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Connection reputation.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Connection.ProcessUUID</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">ID of the process that created the connection.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Connection.ASN</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Connection autonomous system network.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Connection.Country</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Connection country.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Connection.Protocol</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Connection protocol.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Connection.Port</td>
<td style="width: 70px;">Number</td>
<td style="width: 377px;">Connection port number.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Connection.IP</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Connection IP number.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.DnsRequest.Reputation</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Reputation of the DNS request.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.DnsRequest.IP</td>
<td style="width: 70px;">Unknown</td>
<td style="width: 377px;">IP addresses associated with a DNS request.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.DnsRequest.Domain</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Domain resolution of a DNS request.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Threat.ProcessUUID</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Unique process ID from where the threat originated.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Threat.Msg</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Threat message.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Threat.Class</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Class of the threat.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Threat.SrcPort</td>
<td style="width: 70px;">Number</td>
<td style="width: 377px;">Port on which the threat originated.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Threat.DstPort</td>
<td style="width: 70px;">Number</td>
<td style="width: 377px;">Destination port of the threat.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Threat.SrcIP</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Source IP address where the threat originated.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Threat.DstIP</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Destination IP address of the threat.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.HttpRequest.Reputation</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Reputation of the HTTP request.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.HttpRequest.Country</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">HTTP request country.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.HttpRequest.ProcessUUID</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">ID of the process making the HTTP request.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.HttpRequest.Body</td>
<td style="width: 70px;">Unknown</td>
<td style="width: 377px;">HTTP request body parameters and details.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.HttpRequest.HttpCode</td>
<td style="width: 70px;">Number</td>
<td style="width: 377px;">HTTP request response code.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.HttpRequest.Status</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Status of the HTTP request.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.HttpRequest.ProxyDetected</td>
<td style="width: 70px;">Boolean</td>
<td style="width: 377px;">Whether the HTTP request was made through a proxy.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.HttpRequest.Port</td>
<td style="width: 70px;">Number</td>
<td style="width: 377px;">HTTP request port.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.HttpRequest.IP</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">HTTP request IP address.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.HttpRequest.URL</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">HTTP request URL.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.HttpRequest.Host</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">HTTP request host.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.HttpRequest.Method</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">HTTP request method type.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.FileInfo</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Details of the submitted file.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.OS</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">OS of the sandbox in which the file was analyzed.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.ID</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">The unique ID of the task.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.MIME</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">The MIME of the file submitted for analysis.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.MD5</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">The MD5 hash of the file submitted for analysis.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.SHA1</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">The SHA1 hash of the file submitted for analysis.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.SHA256</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">The SHA256 hash of the file submitted for analysis.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.SSDeep</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">SSDeep hash of the file submitted for analysis.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Verdict</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">ANY.RUN verdict for the maliciousness of the submitted file or URL.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Process.FileName</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">File name of the process.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Process.PID</td>
<td style="width: 70px;">Number</td>
<td style="width: 377px;">Process identification number.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Process.PPID</td>
<td style="width: 70px;">Number</td>
<td style="width: 377px;">Parent process identification number.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Process.ProcessUUID</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Unique process ID (used by ANY.RUN).</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Process.CMD</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Process command.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Process.Path</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Path of the executed command.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Process.User</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">User who executed the command.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Process.IntegrityLevel</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">The process integrity level.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Process.ExitCode</td>
<td style="width: 70px;">Number</td>
<td style="width: 377px;">Process exit code.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Process.MainProcess</td>
<td style="width: 70px;">Boolean</td>
<td style="width: 377px;">Whether the process is the main process.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Process.Version.Company</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Company responsible for the program executed.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Process.Version.Description</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Description of the type of program.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Process.Version.Version</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Version of the program executed.</td>
</tr>
<tr>
<td style="width: 293px;">DBotScore.Indicator</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 293px;">DBotScore.Score</td>
<td style="width: 70px;">Number</td>
<td style="width: 377px;">The actual score.</td>
</tr>
<tr>
<td style="width: 293px;">DBotScore.Type</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Type of indicator.</td>
</tr>
<tr>
<td style="width: 293px;">DBotScore.Vendor</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 293px;">File.Extension</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Extension of the file submitted for analysis.</td>
</tr>
<tr>
<td style="width: 293px;">File.Name</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">The name of the file submitted for analysis.</td>
</tr>
<tr>
<td style="width: 293px;">File.MD5</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">MD5 hash of the file submitted for analysis.</td>
</tr>
<tr>
<td style="width: 293px;">File.SHA1</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">SHA1 hash of the file submitted for analysis.</td>
</tr>
<tr>
<td style="width: 293px;">File.SHA256</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">SHA256 hash of the file submitted for analysis.</td>
</tr>
<tr>
<td style="width: 293px;">File.SSDeep</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">SSDeep hash of the file submitted for analysis.</td>
</tr>
<tr>
<td style="width: 293px;">File.Malicious.Vendor</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 293px;">File.Malicious.Description</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">For malicious files, the reason that the vendor made the decision.</td>
</tr>
<tr>
<td style="width: 293px;">URL.Data</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">URL data.</td>
</tr>
<tr>
<td style="width: 293px;">URL.Malicious.Vendor</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">For malicious URLs, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 293px;">URL.Malicious.Description</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">For malicious URLs, the reason that the vendor made the decision.</td>
</tr>
<tr>
<td style="width: 293px;">ANYRUN.Task.Status</td>
<td style="width: 70px;">String</td>
<td style="width: 377px;">Task analysis status.</td>
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
<p><code>anyrun-get-report task=fe7c63ef-2b7f-4e70-b50c-996ae34b28ef</code></p>
</div>
<div class="cl-preview-section">
<h5 id="context-example-1">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "ANYRUN.Task": {
        "HttpRequest": [], 
        "SSDeep": "24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9", 
        "Status": "done", 
        "SHA1": "475d7efc7983357e51ea780e350b0efe6a5ba2e2", 
        "Threat": [], 
        "Process": [
            {
                "CMD": "\"C:\\Program Files\\WinRAR\\WinRAR.exe\" \"C:\\Users\\admin\\AppData\\Local\\Temp\\scribbles2.txt.zip\"", 
                "IntegrityLevel": "MEDIUM", 
                "PID": 916, 
                "MainProcess": true, 
                "FileName": "WinRAR.exe", 
                "Version": {
                    "Company": "Alexander Roshal", 
                    "Version": "5.60.0", 
                    "Description": "WinRAR archiver"
                }, 
                "ProcessUUID": "8834c75a-ceba-4ae3-83e6-87b8b460ff82", 
                "User": "admin", 
                "Path": "C:\\Program Files\\WinRAR\\WinRAR.exe", 
                "PPID": 2044, 
                "ExitCode": null
            }
        ], 
        "ID": "fe7c63ef-2b7f-4e70-b50c-996ae34b28ef", 
        "Connection": [], 
        "MIME": "application/zip", 
        "Behavior": [], 
        "Verdict": "No threats detected", 
        "FileInfo": "Zip archive data, at least v2.0 to extract", 
        "SHA256": "1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1", 
        "OS": "Windows 7 Professional Service Pack 1 (build: 7601, 32 bit)", 
        "DnsRequest": [], 
        "AnalysisDate": "2019-04-24T07:02:38.747Z", 
        "MD5": "e61fcc6a06420106fa6642ef833b9c38"
    }, 
    "DBotScore": {
        "Vendor": "ANYRUN", 
        "Indicator": "1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1", 
        "Score": 1, 
        "Type": "hash"
    }, 
    "File": {
        "SHA1": "475d7efc7983357e51ea780e350b0efe6a5ba2e2", 
        "Name": "scribbles2.txt.zip", 
        "Extension": "zip", 
        "SSDeep": "24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9", 
        "SHA256": "1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1", 
        "MD5": "e61fcc6a06420106fa6642ef833b9c38"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="report-for-task-fe7c63ef-2b7f-4e70-b50c-996ae34b28ef">Report for Task fe7c63ef-2b7f-4e70-b50c-996ae34b28ef</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>OS</th>
<th>AnalysisDate</th>
<th>Verdict</th>
<th>MIME</th>
<th>FileInfo</th>
<th>Process</th>
<th>Status</th>
<th>MD5</th>
<th>SHA1</th>
<th>SHA256</th>
<th>SSDeep</th>
</tr>
</thead>
<tbody>
<tr>
<td>Windows 7 Professional Service Pack 1 (build: 7601, 32 bit)</td>
<td>2019-04-24T07:02:38.747Z</td>
<td>No threats detected</td>
<td>application/zip</td>
<td>Zip archive data, at least v2.0 to extract</td>
<td>FileName: WinRAR.exe, PID: 916, PPID: 2044, ProcessUUID: 8834c75a-ceba-4ae3-83e6-87b8b460ff82, CMD: \C:\Program Files\WinRAR\WinRAR.exe\ \C:\Users\admin\AppData\Local\Temp\scribbles2.txt.zip, Path: C:\Program Files\WinRAR\WinRAR.exe, User: admin, IntegrityLevel: MEDIUM, ExitCode: null, MainProcess: true, Version: {Company: Alexander Roshal, Description: WinRAR archiver, Version: 5.60.0</td>
<td>done</td>
<td>e61fcc6a06420106fa6642ef833b9c38</td>
<td>475d7efc7983357e51ea780e350b0efe6a5ba2e2</td>
<td>1832caedd2f87b3c2d5c7dcc5c5f844a1479d3a7868570241656b1516607dbb1</td>
<td>24:9YQxEcNJQGgrtSuJDWDRzvu4H2ANvg0JvWH2Rb:9xNJKrtSuxOT9</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="anyrun-run-analysis">3. Submit a file or URL for analysis</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Submits a file or URL for analysis.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>anyrun-run-analysis</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 186px;"><strong>Argument Name</strong></th>
<th style="width: 483px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 186px;">obj_type</td>
<td style="width: 483px;">Type of new task.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">file</td>
<td style="width: 483px;">EntryID of the file to analyze.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">obj_url</td>
<td style="width: 483px;">URL, used only if ‘obj_type’ command argument is ‘url’ or ‘download’. Permitted size is 5-512 characters long.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">env_bitness</td>
<td style="width: 483px;">Bitness of OS.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">env_version</td>
<td style="width: 483px;">Version of Windows OS.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">env_type</td>
<td style="width: 483px;">Environment preset type.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">opt_network_connect</td>
<td style="width: 483px;">Network connection state.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">opt_kernel_heavyevasion</td>
<td style="width: 483px;">Heavy evasion option.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">opt_privacy_type</td>
<td style="width: 483px;">Privacy settings for generated task.</td>
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
<th style="width: 168px;"><strong>Path</strong></th>
<th style="width: 68px;"><strong>Type</strong></th>
<th style="width: 504px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 168px;">ANYRUN.Task.ID</td>
<td style="width: 68px;">String</td>
<td style="width: 504px;">ID of the task created to analyze the submission.</td>
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
<p><code>anyrun-run-analysis obj_type=file file=693@66884384-c643-4343-8cf7-26f59e62a88e env_bitness=64</code></p>
</div>
<div class="cl-preview-section">
<h5 id="context-example-2">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "ANYRUN.Task": {
        "ID": "e04b401f-9396-4183-ad00-b6ed34c023e3"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="submission-successful">Submission Successful</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Task</th>
</tr>
</thead>
<tbody>
<tr>
<td>e04b401f-9396-4183-ad00-b6ed34c023e3</td>
</tr>
</tbody>
</table>
</div>
</div>