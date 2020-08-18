## Query.AI
Query.AI is a decentralized data access and analysis technology that simplifies security investigations across disparate platforms, without data duplication.

In order to use this integration you need the following:
1. The URL of Query.AI Proxy component (see below)
2. An email registered with Query.AI belonging to your Organization
3. The API key associated with above email
4. Platform Connection Details of any platform integrated via Query.AI you wish to connect to (This can be overridden while executing commands)

#### BASE_URL
The base URL would be of the [Query.AI Proxy](https://proxy.query.ai:443) . Replace with hostname and port of the Query.AI Proxy component running in your environment.

<h2>Commands</h2>
<p>
  You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li><a href="#queryai-run-query" target="_self">Returns response for the query being run on Query.AI: queryai-run-query</a></li>
</ol>
<h3 id="queryai-run-query">1. queryai-run-query</h3>
<hr>
<p>Returns response for the query being run on Query.AI.</p>
<h5>Base Command</h5>
<p>
  <code>queryai-run-query</code>
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
      <td>query</td>
      <td>Search Query.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>alias</td>
      <td>Platform Alias.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>connection_params</td>
      <td>Connection params as JSON object. Eg- {"alias":{"username":"my_username","password":"my_password"}}.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>workflow_params</td>
      <td>Workflow params as JSON object. Eg- {"param1":"value1","param2":"value2"}.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>time_text</td>
      <td>Search time period.</td>
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
      <td>QueryAI.query.result</td>
      <td>Unknown</td>
      <td>Response after running query.</td>
    </tr>
    <tr>
      <td>QueryAI.query.markdown_string</td>
      <td>Unknown</td>
      <td>Readable Response after running query.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!queryai-run-query query="run workflow my_workflow" alias="my_alias" connection_params="{\"my_alias\":{\"username\":\"my_username\",\"password\":\"my_password\"}}" workflow_params="{\"param1\":\"value1\",\"param2\":\"value2\"}" time_text="search 1 year ago to now"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "QueryAI": {
        "query": {
            "markdown_string": "### Query.AI Result for the query: run workflow my_workflow\n|agegroupbin|agegroupdesc|\n|---|---|\n| 2 | 18-19 |\n| 3 | 20-21 |\n### Click here to [see details](https://ai.query.ai/login;questions=run%20workflow%20my_workflow;alias=my_alias;queryDuration=search%201%20year%20ago%20to%20now;params=%7B%22param1%22%3A%22value1%22%2C%22param2%22%3A%22value2%22%7D;)",
            "result": [
                {
                    "agegroupbin": 2,
                    "agegroupdesc": "18-19"
                },
                {
                    "agegroupbin": 3,
                    "agegroupdesc": "20-21"
                }
            ]
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<hr>

### Query.AI Result for the query: run workflow my_workflow
|agegroupbin|agegroupdesc|
|---|---|
| 2 | 18-19 |
| 3 | 20-21 |
### Click here to [see details](https://ai.query.ai/login;questions=run%20workflow%20my_workflow;alias=my_alias;queryDuration=search%201%20year%20ago%20to%20now;params=%7B%22param1%22%3A%22value1%22%2C%22param2%22%3A%22value2%22%7D;)
<hr>

## Support

For any other assistance or feedback, feel free to [contact us](mailto:support@query.ai).
