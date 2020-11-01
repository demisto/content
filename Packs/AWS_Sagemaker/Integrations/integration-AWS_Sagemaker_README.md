<!-- HTML_DOC -->
<p class="description">Use the API endpoint to get email text classification (subject and body), by leveraging a model trained on a vast amount of emails that were flagged by security experts as being malicious. The Phishing Email Classifier works best on English-language emails that contain at least 30 words in the email body. Other languages will be supported in the future.</p>
<div>
<div class="awsui-table-inner awsui-table-variant-default">
<div class="awsui-table-regions-container">
<div class="awsui-table-header"> </div>
</div>
</div>
</div>
<hr>
<h2>Configure the AWS SageMaker Integration on Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for AWS SageMaker.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>AWS access key</strong></li>
<li><strong>AWS secret key</strong></li>
<li><strong>AWS Region code</strong></li>
<li><strong>Endpoint Name</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<hr>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_10416044041544595909992">Predict the maliciousness of an email: predict-phishing</a></li>
</ol>
<h3 id="h_10416044041544595909992">1. Predict the maliciousness of an email</h3>
<hr>
<h5>Base Command</h5>
<p><code>predict-phishing</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 274.667px;"><strong>Argument</strong></td>
<td style="width: 445.333px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 274.667px;">inputText</td>
<td style="width: 445.333px;">The text to analyze and predict if it is malicious. Lists of text is supported.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Output</h5>
<p>The output is the predicted label of the analyzed inputText: "malicious" or "other", with a corresponding probability (0-1).</p>
<h5>Example Command</h5>
<pre>!predict-phishing inputText="Dear Info, Please confirm account password...", "Major Update: General Availability feedback..."</pre>
<h5>Example Output</h5>
<p>[{'label': [u'__label__malicious'], 'probability': '1.00'}, {'label': [u'__label__other'], 'probability': '1.00'}]</p>
<p> </p>