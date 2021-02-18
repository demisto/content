<!-- HTML_DOC -->
<p>Use the Alexa integration to get the Alexa rating for a domain. This integration was integrated and tested with Amazon Web Information Services.</p>
<h2>Use Cases</h2>
<p>The Alexa Rank Indicator enriches a given domain and provides the current Alexa Ranking of the domain. Alexa Ranking can be indicative of the trustworthiness of a domain, but should not be relied upon entirely.</p>
<h2>Configure Alexa Rank Indicator on Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Alexa Rank Indicator.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Sensitivity threshold for configuring which domains are suspicious versus trusted.</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_64423558741548570068877">Get the ranking of a domain: domain</a></li>
</ol>
<h3 id="h_64423558741548570068877">1. Get the ranking of a domain</h3>
<hr>
<p>Provides an Alexa ranking of the Domain in question.</p>
<h5>Base Command</h5>
<p><code>domain</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 287px;"><strong>Argument Name</strong></th>
<th style="width: 288px;"><strong>Description</strong></th>
<th style="width: 165px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 287px;">domain</td>
<td style="width: 288px;">Domain to get the ranking for</td>
<td style="width: 165px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 215px;"><strong>Path</strong></th>
<th style="width: 98px;"><strong>Type</strong></th>
<th style="width: 427px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 215px;">Domain.Name</td>
<td style="width: 98px;">string</td>
<td style="width: 427px;">Domain that was checked.</td>
</tr>
<tr>
<td style="width: 215px;">DBotScore.Score</td>
<td style="width: 98px;">number</td>
<td style="width: 427px;">The actual score.</td>
</tr>
<tr>
<td style="width: 215px;">DBotScore.Vendor</td>
<td style="width: 98px;">string</td>
<td style="width: 427px;">
<span class="x x-first x-last">The vendor used to calculate </span><span>the score</span><span class="x x-first x-last">.</span>
</td>
</tr>
<tr>
<td style="width: 215px;">DBotScore.Domain</td>
<td style="width: 98px;">string</td>
<td style="width: 427px;">Domain that was reported.</td>
</tr>
<tr>
<td style="width: 215px;">Alexa.Domain.Data</td>
<td style="width: 98px;">string</td>
<td style="width: 427px;">Domain that was checked.</td>
</tr>
<tr>
<td style="width: 215px;">Alexa.Domain.Rank</td>
<td style="width: 98px;">string</td>
<td style="width: 427px;">Alexa rank as determined by Amazon.</td>
</tr>
<tr>
<td style="width: 215px;"><span>DBotScore.Type</span></td>
<td style="width: 98px;">string</td>
<td style="width: 427px;"><span>The indicator type.</span></td>
</tr>
<tr>
<td style="width: 215px;"><span>DBotScore.Indicator</span></td>
<td style="width: 98px;">string</td>
<td style="width: 427px;"><span>The indicator that was tested.</span></td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!domain domain=demisto.com</code></p>
<h5>Context Example</h5>
<pre>{
    "DBotScore": {
        "Domain": "demisto.com",
        "Score": 0,
        "Vendor": "Alexa"
    },
    "Alexa": {
        "Domain": {
            "Data": "demisto.com",
            "Rank": "554606"
        }
    },
    "Domain": {
        "Name": "demisto.com"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/42912128/51466171-3b4ead80-1d72-11e9-9cff-14e997e9346a.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/42912128/51466171-3b4ead80-1d72-11e9-9cff-14e997e9346a.png" alt="screen shot 2019-01-21 at 11 46 30"></a></p>