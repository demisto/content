<!-- HTML_DOC -->
<p>Use the Kafka integration to manage messages and partitions.</p>
<p>This integration was integrated and tested with version 2.6 of Kafka.</p>
<h2>Configure Kafka v2 on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Kafka v2.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a meaningful name for the integration instance.</li>
<li><strong>Use proxy</strong></li>
<li>
<strong>CSV list of Kafka brokers to connect to</strong>, e.g., <code>ip:port,ip2:port2</code>
</li>
<li><strong>Do not validate server certificate (insecure)</strong></li>
<li><strong>CA certificate of Kafka server (.cer)</strong></li>
<li><strong>Client certificate (.cer)</strong></li>
<li><strong>Client certificate key (.key)</strong></li>
<li><strong>Additional password (if required)</strong></li>
<li><strong>Topic to fetch incidents from</strong></li>
<li><strong>Offset to fetch incidents from</strong></li>
<li><strong>Max number of messages to fetch</strong></li>
<li><strong>Incident type</strong></li>
<li><strong>Enable debug (will post Kafka connection logs to the War Room)</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li>Print all partitions for a topic: kafka-print-topics</li>
<li>Publish a message to Kafka: kafka-publish-msg</li>
<li>Consume a single Kafka message: kafka-consume-msg</li>
<li>Print all partitions for a topic: kafka-fetch-partitions</li>
</ol>
<h3>1. Print all partitions for a topic</h3>
<hr>
<p>Prints all partitions of a topic.</p>
<h5>Base Command</h5>
<p><code>kafka-print-topics</code></p>
<h5>Input</h5>
<p>There is no input for this command.</p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<td style="width: 220px;">Path</td>
<td style="width: 106px;">Type</td>
<td style="width: 414px;">Description</td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 220px;">Kafka.Topic.Name</td>
<td style="width: 106px;">string</td>
<td style="width: 414px;">Topic name.</td>
</tr>
<tr>
<td style="width: 220px;"><span>Kafka.Topic.Partitions.ID</span></td>
<td style="width: 106px;">Number</td>
<td style="width: 414px;">Topic partition ID.</td>
</tr>
<tr>
<td style="width: 220px;"><span>Kafka.Topic.Partitions.EarliestOffset</span></td>
<td style="width: 106px;">Number</td>
<td style="width: 414px;"><span>Topic partition earliest offset.</span></td>
</tr>
<tr>
<td style="width: 220px;"><span>Kafka.Topic.Partitions.LatestOffset</span></td>
<td style="width: 106px;">Number</td>
<td style="width: 414px;"><span>Topic partition latest offset.</span></td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!kafka-print-topics</code></p>
<h5>Context Example</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/Kafka_V2_mceclip2.png"></p>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/Kafka_V2_mceclip3.png"></p>
<h3>2. Publish a message to Kafka</h3>
<hr>
<p>Publishes a message to Kafka. </p>
<h5>Base Command</h5>
<p><code>kafka-publish-msg</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<td style="width: 160px;">Argument Name</td>
<td style="width: 397px;">Description</td>
<td style="width: 183px;">Required</td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 160px;">topic</td>
<td style="width: 397px;">A topic to filter by.</td>
<td style="width: 183px;">Required</td>
</tr>
<tr>
<td style="width: 160px;">value</td>
<td style="width: 397px;">Message value (string)</td>
<td style="width: 183px;">Required</td>
</tr>
<tr>
<td style="width: 160px;">partitioning_key</td>
<td style="width: 397px;">Message partition key (number)</td>
<td style="width: 183px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code>!kafka-publish-msg topic=test value="test message"</code></p>
<p> </p>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/Kafka_V2_mceclip4.png"></p>
<h3>3. Consume a single Kafka message</h3>
<hr>
<p>Consumes a single Kafka message.</p>
<h5>Base Command</h5>
<p><code>kafka-consume-msg</code></p>
<p> </p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<td style="width: 160px;">Argument Name</td>
<td style="width: 397px;">Description</td>
<td style="width: 183px;">Required</td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 160px;">topic</td>
<td style="width: 397px;">A topic to filter by</td>
<td style="width: 183px;">Required</td>
</tr>
<tr>
<td style="width: 160px;">offset</td>
<td style="width: 397px;">Message offset to filter by ("Earliest", "Latest", or any other offset number)</td>
<td style="width: 183px;">Optional</td>
</tr>
<tr>
<td style="width: 160px;">partition</td>
<td style="width: 397px;">Partition (number)</td>
<td style="width: 183px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<td style="width: 220px;">Path</td>
<td style="width: 106px;">Type</td>
<td style="width: 414px;">Description</td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 220px;">Kafka.Topic.Name</td>
<td style="width: 106px;">string</td>
<td style="width: 414px;">Topic name</td>
</tr>
<tr>
<td style="width: 220px;">Kafka.Topic.Message.Value</td>
<td style="width: 106px;">string</td>
<td style="width: 414px;">Message value</td>
</tr>
<tr>
<td style="width: 220px;">Kafka.Topic.Message.Offset</td>
<td style="width: 106px;">number</td>
<td style="width: 414px;">Offset of the value in the topic</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!kafka-consume-msg topic=test offset=latest</code></p>
<h5>Context Example</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/Kafka_V2_mceclip5.png"></p>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/Kafka_V2_mceclip6.png"></p>
<h3>4. Print all partitions for a topic</h3>
<hr>
<p>Prints all partitions for a topic.</p>
<h5>Base Command</h5>
<p><code>kafka-fetch-partitions</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<td style="width: 160px;">Argument Name</td>
<td style="width: 397px;">Description</td>
<td style="width: 183px;">Required</td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 160px;">topic</td>
<td style="width: 397px;">A topic to filter by</td>
<td style="width: 183px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<td style="width: 220px;">Path</td>
<td style="width: 106px;">Type</td>
<td style="width: 414px;">Description</td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 220px;">Kafka.Topic.Name</td>
<td style="width: 106px;">string</td>
<td style="width: 414px;">Topic name</td>
</tr>
<tr>
<td style="width: 220px;">Kafka.Topic.Partition</td>
<td style="width: 106px;">number</td>
<td style="width: 414px;">Number of partitions for the topic</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!kafka-fetch-partitions topic=test</code></p>
<h5>Context Example</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/Kafka_V2_mceclip7.png"></p>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/Kafka_V2_mceclip8.png"></p>
