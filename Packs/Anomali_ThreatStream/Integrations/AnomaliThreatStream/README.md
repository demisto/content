<!-- HTML_DOC -->
<h2>Overview</h2>
<p>Anomali ThreatStream (previously ThreatStream Optic) is a threat-intelligence integration that enables you to pull threat intelligence from the ThreatStream platform and use in third-party tools. The integration works with the <code>v2</code> API on product version 2.5.4, using the <code>intelligence</code> resource.</p>
<p>Commands:</p>
<ul>
<li><a href="#h_956498138931525680640820">Receive threat intelligence: threatstream-intelligence</a></li>
<li><a href="#h_5769900451251525680987811">Check IP/domain reputation: domain</a></li>
<li><a href="#h_1557915141571525681059225">Check file's checksum reputation: file</a></li>
<li><a href="#h_103925922131525681132050">Check email address reputation: threatstream-email-reputation</a></li>
<li><a href="#h_6439751152451525771642821">Check IP reputation: ip</a></li>
</ul>
<hr>
<h2>Prerequisites</h2>
<p>You need to retrieve your Anomali ThreatStream credentials, which you will enter in Cortex XSOAR.</p>
<ul>
<li><code>user ID</code></li>
<li>
<code>API key</code> </li>
</ul>
<p>If you do not have these credentials, register at <a href="http://ui.threatstream.com/" rel="nofollow">http://ui.threatstream.com</a>. </p>
<hr>
<h2>Configure Cortex XSOAR to Integrate with Anomali ThreatStream</h2>
<ol>
<li>Navigate to to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services.</strong>
</li>
<li>Search for the Anomali ThreatStream integration.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name |</strong> a meaningful name for the integration instance. (Required)</li>
<li>
<strong>Server URL |</strong> Anomali ThreatStream hostname or IP address and port. For example: <a href="https://api.threatstream.com">https://</a>api.threatstream.com. (Required)</li>
<li>
<strong>User name |</strong> Anomali ThreatStream user name. (Required)</li>
<li>
<strong>API Key |</strong> The API key you copied in the previous procedure. (Required)</li>
</ul>
</li>
<li>Click the <strong>Test</strong> button to verify the the URL and token.<br>A green light means the test was successful.</li>
</ol>
<hr>
<h2>Use Cases</h2>
<p>Use this integration to retrieve threat intelligence from the ThreatStream cloud. You can specify criteria by which the intelligence should be retrieved, as shown in the commands below. The integration supports getting reputation for IP, domain, file and email.</p>
<hr>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ul>
<li><a href="#h_956498138931525680640820">Receive threat intelligence: threatstream-intelligence</a></li>
<li><a href="#h_5769900451251525680987811">Check IP/domain reputation: domain</a></li>
<li><a href="#h_1557915141571525681059225">Check file's checksum reputation: file</a></li>
<li><a href="#h_103925922131525681132050">Check email address reputation: threatstream-email-reputation</a></li>
<li><a href="#h_6439751152451525771642821">Check IP reputation: ip</a></li>
</ul>
<h3 id="h_956498138931525680640820">Retrieve Threat Intelligence: threatstream-intelligence</h3>
<p>Use this command to retrieve threat intelligence from the ThreatStream cloud.</p>
<h4>Inputs</h4>
<table style="height: 327px; width: 688px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 374.364px;"><strong>Input Parameter</strong></td>
<td style="width: 347.636px;"><strong>Description</strong></td>
<td style="width: 423px;"><strong>Notes</strong></td>
</tr>
<tr>
<td style="width: 374.364px;">limit</td>
<td style="width: 347.636px;">Specify the amount of records in a response.</td>
<td style="width: 423px;">Integer</td>
</tr>
<tr>
<td style="width: 374.364px;">asn</td>
<td style="width: 347.636px;">Autonomous System (AS) number associated with the indicator.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">confidence</td>
<td style="width: 347.636px;">Confidence value assigned to the indicator.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">country</td>
<td style="width: 347.636px;">Country associated with the indicator.</td>
<td style="width: 423px;">Country code.</td>
</tr>
<tr>
<td style="width: 374.364px;">created_ts</td>
<td style="width: 347.636px;">Date and time when the indicator was first detected on the ThreatStream cloud platform.</td>
<td style="width: 423px;">For example, 2014-10-02T20:44:35</td>
</tr>
<tr>
<td style="width: 374.364px;">expiration_ts</td>
<td style="width: 347.636px;">Time stamp of when intelligence will expire on ThreatStream.</td>
<td style="width: 423px;">Time stamp is UTC.</td>
</tr>
<tr>
<td style="width: 374.364px;">feed_id</td>
<td style="width: 347.636px;">Numeric ID of the threat feed that generated the indicator.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">id</td>
<td style="width: 347.636px;">Unique ID for the indicator.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">import_session_id</td>
<td style="width: 347.636px;">ID of import session that the indicator was imported to.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">ip</td>
<td style="width: 347.636px;">IP address associated with the indicator, if the imported indicator is a domain or a URL.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">is_public</td>
<td style="width: 347.636px;">Classification of the indicator, either <em>public</em> or <em>private</em>.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">itype</td>
<td style="width: 347.636px;">Indicator type.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">latitude</td>
<td style="width: 347.636px;">The IP's geo-location latitude.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">longitude</td>
<td style="width: 347.636px;">The IP's geo-location longitude.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">meta.detail</td>
<td style="width: 347.636px;">A string that contains a tag associated with the indicator. </td>
<td style="width: 423px;">Use the tag to search for related incidents.</td>
</tr>
<tr>
<td style="width: 374.364px;">meta.detail2</td>
<td style="width: 347.636px;">Additional details associated with the state of the indicator. For example, why an indicator is marked <em>false-positive</em>.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">meta.maltype</td>
<td style="width: 347.636px;">Tag that specifies the malware associated with an indicator.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">meta.severity</td>
<td style="width: 347.636px;">Severity assigned to the indicator through machine-learning algorithms that ThreatStream deploys.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">modified_ts</td>
<td style="width: 347.636px;">When the indicator was last updated on the ThreatStream cloud platform.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">org</td>
<td style="width: 347.636px;">Registered owner (organization) of the IP address associated with the indicator.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">owner_ organization_id</td>
<td style="width: 347.636px;">ID of the (ThreatStream)organization that brought in the indicator through either a threat feed or the import process.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">rdns</td>
<td style="width: 347.636px;">Domain name (obtained through reverse domain name lookup) associated with the IP address that is associated with the indicator.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">source_reported_ confidence</td>
<td style="width: 347.636px;">A risk score, from 0 to 100, provided by the source of the indicator.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">status</td>
<td style="width: 347.636px;">Status assigned to the indicator.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">tags.name</td>
<td style="width: 347.636px;">Tag assigned to the indicator.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">threat_type</td>
<td style="width: 347.636px;">Summarized threat type of the indicator. For example, malware, compromised, apt, c2, and so on.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">trusted_circle_ids</td>
<td style="width: 347.636px;">IDs of the trusted circles that the indicator is shared with.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">type</td>
<td style="width: 347.636px;">Type of indicator: domain, email, ip, md5, string, url.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">update_id</td>
<td style="width: 347.636px;">An incremental numeric identifier associated with each update to intelligence on ThreatStream.</td>
<td style="width: 423px;"> </td>
</tr>
<tr>
<td style="width: 374.364px;">value</td>
<td style="width: 347.636px;">Value of the indicator.</td>
<td style="width: 423px;"> </td>
</tr>
</tbody>
</table>
<p> </p>
<h4>Context Output</h4>
<p>Path: DBotScore.Indicator<br>Description: The tested indicator<br>Path: DBotScore.Type<br>Description: The indicator type<br>Path: DBotScore.Vendor<br>Description: Vendor used to calculate the score<br>Path: DBotScore.Score<br>Description: The actual score</p>
<h4>JSON Output</h4>
<pre>{ <br> "meta":{ <br> "limit":1,<br> "next":"/api/v2/intelligence/?username=test%test.com\u0026country=IL\u0026api_key=12345678912345678
\u0026limit=1\u0026offset=1",<br> "offset":0,<br> "previous":null,<br> "took":39,<br> "total_count":49906<br> },<br> "objects":[ <br> { <br> "asn":"12849",<br> "confidence":100,<br> "country":"IL",<br> "created_ts":"2018-01-03T16:59:29.054Z",<br> "description":null,<br> "expiration_ts":"2018-04-12T13:37:28.417Z",<br> "feed_id":122,<br> "id":50460807643,<br> "import_session_id":null,<br> "ip":"5.29.211.60",<br> "is_public":false,<br> "itype":"tor_ip",<br> "latitude":"32.332900",<br> "longitude":"34.859900",<br> "meta":{ <br> "detail2":"bifocals_deactivated_on_2018-04-10_20:32:42.816201",<br> "severity":"low"<br> },<br> "modified_ts":"2018-04-11T13:37:28.423Z",<br> "org":"HOTnet",<br> "owner_organization_id":2,<br> "rdns":null,<br> "resource_uri":"/api/v2/intelligence/50460807643/",<br> "retina_confidence":-1,<br> "source":"TOR Exit Nodes",<br> "source_reported_confidence":100,<br> "status":"active",<br> "tags":null,<br> "threat_type":"tor",<br> "threatscore":25,<br> "trusted_circle_ids":[ <br> 146<br> ],<br> "type":"ip",<br> "update_id":1763222542,<br> "uuid":"56260f15-377a-48e7-ad40-121f8580a4c5",<br> "value":"5.29.211.60",<br> "workgroups":[</pre>
<h4>War Room Output</h4>
<p>Command: <code>!threatstream-intelligence limit="1" country="IL"</code></p>
<p><a href="../../doc_files/37356596-0a3037b6-26ef-11e8-8190-33c46f922e76.png" target="_blank" rel="noopener"><img src="../../doc_files/37356596-0a3037b6-26ef-11e8-8190-33c46f922e76.png" alt="image"></a></p>
<h3 id="h_5769900451251525680987811">Check IP/domain reputation: domain</h3>
<h4>Inputs</h4>
<table style="height: 75px; width: 692px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 202.557px;"><strong>Input Parameter</strong></td>
<td style="width: 460.739px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 202.557px;">domain</td>
<td style="width: 460.739px;">The domain name you want to check the reputation for.</td>
</tr>
<tr>
<td style="width: 202.557px;">threshold</td>
<td style="width: 460.739px;">The ThreatScore that determines if a domain is considered malicious.</td>
</tr>
</tbody>
</table>
<p> </p>
<h4>Context Output</h4>
<p>Path: DBotScore.Indicator<br>Description: The tested indicator<br>Path: DBotScore.Type<br>Description: The indicator type<br>Path: DBotScore.Vendor<br>Description: Vendor used to calculate the score<br>Path: DBotScore.Score<br>Description: The actual score</p>
<h4>JSON Output</h4>
<pre><span id="s-1" class="sBrace structure-1">{  </span><br>   <span id="s-2" class="sObjectK">"meta"</span><span id="s-3" class="sColon">:</span><span id="s-4" class="sBrace structure-2">{  </span><br>      <span id="s-5" class="sObjectK">"limit"</span><span id="s-6" class="sColon">:</span><span id="s-7" class="sObjectV">1000</span><span id="s-8" class="sComma">,</span><br>      <span id="s-9" class="sObjectK">"next"</span><span id="s-10" class="sColon">:</span><span id="s-11" class="sObjectV">null</span><span id="s-12" class="sComma">,</span><br>      <span id="s-13" class="sObjectK">"offset"</span><span id="s-14" class="sColon">:</span><span id="s-15" class="sObjectV">0</span><span id="s-16" class="sComma">,</span><br>      <span id="s-17" class="sObjectK">"previous"</span><span id="s-18" class="sColon">:</span><span id="s-19" class="sObjectV">null</span><span id="s-20" class="sComma">,</span><br>      <span id="s-21" class="sObjectK">"took"</span><span id="s-22" class="sColon">:</span><span id="s-23" class="sObjectV">4</span><span id="s-24" class="sComma">,</span><br>      <span id="s-25" class="sObjectK">"total_count"</span><span id="s-26" class="sColon">:</span><span id="s-27" class="sObjectV">1</span><br>   <span id="s-28" class="sBrace structure-2">}</span><span id="s-29" class="sComma">,</span><br>   <span id="s-30" class="sObjectK">"objects"</span><span id="s-31" class="sColon">:</span><span id="s-32" class="sBracket structure-2">[  </span><br>      <span id="s-33" class="sBrace structure-3">{  </span><br>         <span id="s-34" class="sObjectK">"asn"</span><span id="s-35" class="sColon">:</span><span id="s-36" class="sObjectV">""</span><span id="s-37" class="sComma">,</span><br>         <span id="s-38" class="sObjectK">"confidence"</span><span id="s-39" class="sColon">:</span><span id="s-40" class="sObjectV">17</span><span id="s-41" class="sComma">,</span><br>         <span id="s-42" class="sObjectK">"country"</span><span id="s-43" class="sColon">:</span><span id="s-44" class="sObjectV">"RO"</span><span id="s-45" class="sComma">,</span><br>         <span id="s-46" class="sObjectK">"created_ts"</span><span id="s-47" class="sColon">:</span><span id="s-48" class="sObjectV">"2017-06-02T18:09:41.986Z"</span><span id="s-49" class="sComma">,</span><br>         <span id="s-50" class="sObjectK">"description"</span><span id="s-51" class="sColon">:</span><span id="s-52" class="sObjectV">null</span><span id="s-53" class="sComma">,</span><br>         <span id="s-54" class="sObjectK">"expiration_ts"</span><span id="s-55" class="sColon">:</span><span id="s-56" class="sObjectV">"2017-08-31T11:58:38.253Z"</span><span id="s-57" class="sComma">,</span><br>         <span id="s-58" class="sObjectK">"feed_id"</span><span id="s-59" class="sColon">:</span><span id="s-60" class="sObjectV">0</span><span id="s-61" class="sComma">,</span><br>         <span id="s-62" class="sObjectK">"id"</span><span id="s-63" class="sColon">:</span><span id="s-64" class="sObjectV">859843899</span><span id="s-65" class="sComma">,</span><br>         <span id="s-66" class="sObjectK">"import_session_id"</span><span id="s-67" class="sColon">:</span><span id="s-68" class="sObjectV">213529</span><span id="s-69" class="sComma">,</span><br>         <span id="s-70" class="sObjectK">"ip"</span><span id="s-71" class="sColon">:</span><span id="s-72" class="sObjectV">"185.72.179.152"</span><span id="s-73" class="sComma">,</span><br>         <span id="s-74" class="sObjectK">"is_public"</span><span id="s-75" class="sColon">:</span><span id="s-76" class="sObjectV">true</span><span id="s-77" class="sComma">,</span><br>         <span id="s-78" class="sObjectK">"itype"</span><span id="s-79" class="sColon">:</span><span id="s-80" class="sObjectV">"adware_domain"</span><span id="s-81" class="sComma">,</span><br>         <span id="s-82" class="sObjectK">"latitude"</span><span id="s-83" class="sColon">:</span><span id="s-84" class="sObjectV">"46.000000"</span><span id="s-85" class="sComma">,</span><br>         <span id="s-86" class="sObjectK">"longitude"</span><span id="s-87" class="sColon">:</span><span id="s-88" class="sObjectV">"25.000000"</span><span id="s-89" class="sComma">,</span><br>         <span id="s-90" class="sObjectK">"meta"</span><span id="s-91" class="sColon">:</span><span id="s-92" class="sBrace structure-4">{  </span><br>            <span id="s-93" class="sObjectK">"detail"</span><span id="s-94" class="sColon">:</span><span id="s-95" class="sObjectV">""</span><span id="s-96" class="sComma">,</span><br>            <span id="s-97" class="sObjectK">"detail2"</span><span id="s-98" class="sColon">:</span><span id="s-99" class="sObjectV">"bifocals_deactivated_on_2017-08-31_12:47:29.013755"</span><span id="s-100" class="sComma">,</span><br>            <span id="s-101" class="sObjectK">"severity"</span><span id="s-102" class="sColon">:</span><span id="s-103" class="sObjectV">"low"</span><br>         <span id="s-104" class="sBrace structure-4">}</span><span id="s-105" class="sComma">,</span><br>         <span id="s-106" class="sObjectK">"modified_ts"</span><span id="s-107" class="sColon">:</span><span id="s-108" class="sObjectV">"2017-08-31T12:47:28.926Z"</span><span id="s-109" class="sComma">,</span><br>         <span id="s-110" class="sObjectK">"org"</span><span id="s-111" class="sColon">:</span><span id="s-112" class="sObjectV">"Nix Web Solutions Pvt Ltd"</span><span id="s-113" class="sComma">,</span><br>         <span id="s-114" class="sObjectK">"owner_organization_id"</span><span id="s-115" class="sColon">:</span><span id="s-116" class="sObjectV">738</span><span id="s-117" class="sComma">,</span><br>         <span id="s-118" class="sObjectK">"rdns"</span><span id="s-119" class="sColon">:</span><span id="s-120" class="sObjectV">null</span><span id="s-121" class="sComma">,</span><br>         <span id="s-122" class="sObjectK">"resource_uri"</span><span id="s-123" class="sColon">:</span><span id="s-124" class="sObjectV">"/api/v2/intelligence/859843899/"</span><span id="s-125" class="sComma">,</span><br>         <span id="s-126" class="sObjectK">"retina_confidence"</span><span id="s-127" class="sColon">:</span><span id="s-128" class="sObjectV">17</span><span id="s-129" class="sComma">,</span><br>         <span id="s-130" class="sObjectK">"source"</span><span id="s-131" class="sColon">:</span><span id="s-132" class="sObjectV">"Analyst"</span><span id="s-133" class="sComma">,</span><br>         <span id="s-134" class="sObjectK">"source_reported_confidence"</span><span id="s-135" class="sColon">:</span><span id="s-136" class="sObjectV">90</span><span id="s-137" class="sComma">,</span><br>         <span id="s-138" class="sObjectK">"status"</span><span id="s-139" class="sColon">:</span><span id="s-140" class="sObjectV">"inactive"</span><span id="s-141" class="sComma">,</span><br>         <span id="s-142" class="sObjectK">"tags"</span><span id="s-143" class="sColon">:</span><span id="s-144" class="sBracket structure-4">[  </span><br>            <span id="s-145" class="sBrace structure-5">{  </span><br>               <span id="s-146" class="sObjectK">"id"</span><span id="s-147" class="sColon">:</span><span id="s-148" class="sObjectV">"rd4"</span><span id="s-149" class="sComma">,</span><br>               <span id="s-150" class="sObjectK">"name"</span><span id="s-151" class="sColon">:</span><span id="s-152" class="sObjectV">"pony"</span><br>            <span id="s-153" class="sBrace structure-5">}</span><br>         <span id="s-154" class="sBracket structure-4">]</span><span id="s-155" class="sComma">,</span><br>         <span id="s-156" class="sObjectK">"threat_type"</span><span id="s-157" class="sColon">:</span><span id="s-158" class="sObjectV">"adware"</span><span id="s-159" class="sComma">,</span><br>         <span id="s-160" class="sObjectK">"threatscore"</span><span id="s-161" class="sColon">:</span><span id="s-162" class="sObjectV">4</span><span id="s-163" class="sComma">,</span><br>         <span id="s-164" class="sObjectK">"trusted_circle_ids"</span><span id="s-165" class="sColon">:</span><span id="s-166" class="sObjectV">null</span><span id="s-167" class="sComma">,</span><br>         <span id="s-168" class="sObjectK">"type"</span><span id="s-169" class="sColon">:</span><span id="s-170" class="sObjectV">"domain"</span><span id="s-171" class="sComma">,</span><br>         <span id="s-172" class="sObjectK">"update_id"</span><span id="s-173" class="sColon">:</span><span id="s-174" class="sObjectV">1023048164</span><span id="s-175" class="sComma">,</span><br>         <span id="s-176" class="sObjectK">"value"</span><span id="s-177" class="sColon">:</span><span id="s-178" class="sObjectV">"kpanels.in"</span><span id="s-179" class="sComma">,</span><br>         <span id="s-180" class="sObjectK">"workgroups"</span><span id="s-181" class="sColon">:</span><span id="s-182" class="sObjectV">null</span><br>      <span id="s-183" class="sBrace structure-3">}</span><br>   <span id="s-184" class="sBracket structure-2">]</span><br><span id="s-185" class="sBrace structure-1">}</span></pre>
<h4>War Room Output</h4>
<p>Command: <code>!domain domain="kpanels.in" threshold="3"</code></p>
<p><a href="../../doc_files/37357065-1d87d110-26f0-11e8-88dd-ce7fa57c2333.png" target="_blank" rel="noopener"><img src="../../doc_files/37357065-1d87d110-26f0-11e8-88dd-ce7fa57c2333.png" alt="image"></a></p>
<h3 id="h_1557915141571525681059225">Check file's checksum reputation: file</h3>
<h4>Inputs</h4>
<table style="height: 75px; width: 692px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 202.557px;"><strong>Input Parameter</strong></td>
<td style="width: 460.739px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 202.557px;">domain</td>
<td style="width: 460.739px;">The domain name you want to check the reputation for.</td>
</tr>
<tr>
<td style="width: 202.557px;">threshold</td>
<td style="width: 460.739px;">The ThreatScore that determines if a file is considered malicious.</td>
</tr>
</tbody>
</table>
<p> </p>
<h4>Context Output</h4>
<p>Path: DBotScore.Indicator<br>Description: The tested indicator<br>Path: DBotScore.Type<br>Description: The indicator type<br>Path: DBotScore.Vendor<br>Description: Vendor used to calculate the score<br>Path: DBotScore.Score<br>Description: The actual score</p>
<h4>JSON Output</h4>
<pre><span id="s-1" class="sBrace structure-1">{  </span><br>   <span id="s-2" class="sObjectK">"meta"</span><span id="s-3" class="sColon">:</span><span id="s-4" class="sBrace structure-2">{  </span><br>      <span id="s-5" class="sObjectK">"limit"</span><span id="s-6" class="sColon">:</span><span id="s-7" class="sObjectV">1000</span><span id="s-8" class="sComma">,</span><br>      <span id="s-9" class="sObjectK">"next"</span><span id="s-10" class="sColon">:</span><span id="s-11" class="sObjectV">null</span><span id="s-12" class="sComma">,</span><br>      <span id="s-13" class="sObjectK">"offset"</span><span id="s-14" class="sColon">:</span><span id="s-15" class="sObjectV">0</span><span id="s-16" class="sComma">,</span><br>      <span id="s-17" class="sObjectK">"previous"</span><span id="s-18" class="sColon">:</span><span id="s-19" class="sObjectV">null</span><span id="s-20" class="sComma">,</span><br>      <span id="s-21" class="sObjectK">"took"</span><span id="s-22" class="sColon">:</span><span id="s-23" class="sObjectV">45</span><span id="s-24" class="sComma">,</span><br>      <span id="s-25" class="sObjectK">"total_count"</span><span id="s-26" class="sColon">:</span><span id="s-27" class="sObjectV">1</span><br>   <span id="s-28" class="sBrace structure-2">}</span><span id="s-29" class="sComma">,</span><br>   <span id="s-30" class="sObjectK">"objects"</span><span id="s-31" class="sColon">:</span><span id="s-32" class="sBracket structure-2">[  </span><br>      <span id="s-33" class="sBrace structure-3">{  </span><br>         <span id="s-34" class="sObjectK">"asn"</span><span id="s-35" class="sColon">:</span><span id="s-36" class="sObjectV">""</span><span id="s-37" class="sComma">,</span><br>         <span id="s-38" class="sObjectK">"confidence"</span><span id="s-39" class="sColon">:</span><span id="s-40" class="sObjectV">92</span><span id="s-41" class="sComma">,</span><br>         <span id="s-42" class="sObjectK">"country"</span><span id="s-43" class="sColon">:</span><span id="s-44" class="sObjectV">null</span><span id="s-45" class="sComma">,</span><br>         <span id="s-46" class="sObjectK">"created_ts"</span><span id="s-47" class="sColon">:</span><span id="s-48" class="sObjectV">"2017-06-07T13:01:10.143Z"</span><span id="s-49" class="sComma">,</span><br>         <span id="s-50" class="sObjectK">"description"</span><span id="s-51" class="sColon">:</span><span id="s-52" class="sObjectV">null</span><span id="s-53" class="sComma">,</span><br>         <span id="s-54" class="sObjectK">"expiration_ts"</span><span id="s-55" class="sColon">:</span><span id="s-56" class="sObjectV">"2017-09-04T13:31:00.194Z"</span><span id="s-57" class="sComma">,</span><br>         <span id="s-58" class="sObjectK">"feed_id"</span><span id="s-59" class="sColon">:</span><span id="s-60" class="sObjectV">0</span><span id="s-61" class="sComma">,</span><br>         <span id="s-62" class="sObjectK">"id"</span><span id="s-63" class="sColon">:</span><span id="s-64" class="sObjectV">872721081</span><span id="s-65" class="sComma">,</span><br>         <span id="s-66" class="sObjectK">"import_session_id"</span><span id="s-67" class="sColon">:</span><span id="s-68" class="sObjectV">214717</span><span id="s-69" class="sComma">,</span><br>         <span id="s-70" class="sObjectK">"ip"</span><span id="s-71" class="sColon">:</span><span id="s-72" class="sObjectV">null</span><span id="s-73" class="sComma">,</span><br>         <span id="s-74" class="sObjectK">"is_public"</span><span id="s-75" class="sColon">:</span><span id="s-76" class="sObjectV">true</span><span id="s-77" class="sComma">,</span><br>         <span id="s-78" class="sObjectK">"itype"</span><span id="s-79" class="sColon">:</span><span id="s-80" class="sObjectV">"apt_md5"</span><span id="s-81" class="sComma">,</span><br>         <span id="s-82" class="sObjectK">"latitude"</span><span id="s-83" class="sColon">:</span><span id="s-84" class="sObjectV">null</span><span id="s-85" class="sComma">,</span><br>         <span id="s-86" class="sObjectK">"longitude"</span><span id="s-87" class="sColon">:</span><span id="s-88" class="sObjectV">null</span><span id="s-89" class="sComma">,</span><br>         <span id="s-90" class="sObjectK">"meta"</span><span id="s-91" class="sColon">:</span><span id="s-92" class="sBrace structure-4">{  </span><br>            <span id="s-93" class="sObjectK">"detail"</span><span id="s-94" class="sColon">:</span><span id="s-95" class="sObjectV">""</span><span id="s-96" class="sComma">,</span><br>            <span id="s-97" class="sObjectK">"detail2"</span><span id="s-98" class="sColon">:</span><span id="s-99" class="sObjectV">"imported by user 3096"</span><span id="s-100" class="sComma">,</span><br>            <span id="s-101" class="sObjectK">"severity"</span><span id="s-102" class="sColon">:</span><span id="s-103" class="sObjectV">"very-high"</span><br>         <span id="s-104" class="sBrace structure-4">}</span><span id="s-105" class="sComma">,</span><br>         <span id="s-106" class="sObjectK">"modified_ts"</span><span id="s-107" class="sColon">:</span><span id="s-108" class="sObjectV">"2017-06-07T13:03:03.200Z"</span><span id="s-109" class="sComma">,</span><br>         <span id="s-110" class="sObjectK">"org"</span><span id="s-111" class="sColon">:</span><span id="s-112" class="sObjectV">""</span><span id="s-113" class="sComma">,</span><br>         <span id="s-114" class="sObjectK">"owner_organization_id"</span><span id="s-115" class="sColon">:</span><span id="s-116" class="sObjectV">738</span><span id="s-117" class="sComma">,</span><br>         <span id="s-118" class="sObjectK">"rdns"</span><span id="s-119" class="sColon">:</span><span id="s-120" class="sObjectV">null</span><span id="s-121" class="sComma">,</span><br>         <span id="s-122" class="sObjectK">"resource_uri"</span><span id="s-123" class="sColon">:</span><span id="s-124" class="sObjectV">"/api/v2/intelligence/872721081/"</span><span id="s-125" class="sComma">,</span><br>         <span id="s-126" class="sObjectK">"retina_confidence"</span><span id="s-127" class="sColon">:</span><span id="s-128" class="sObjectV">-1</span><span id="s-129" class="sComma">,</span><br>         <span id="s-130" class="sObjectK">"source"</span><span id="s-131" class="sColon">:</span><span id="s-132" class="sObjectV">"Analyst"</span><span id="s-133" class="sComma">,</span><br>         <span id="s-134" class="sObjectK">"source_reported_confidence"</span><span id="s-135" class="sColon">:</span><span id="s-136" class="sObjectV">92</span><span id="s-137" class="sComma">,</span><br>         <span id="s-138" class="sObjectK">"status"</span><span id="s-139" class="sColon">:</span><span id="s-140" class="sObjectV">"active"</span><span id="s-141" class="sComma">,</span><br>         <span id="s-142" class="sObjectK">"tags"</span><span id="s-143" class="sColon">:</span><span id="s-144" class="sBracket structure-4">[  </span><br>            <span id="s-145" class="sBrace structure-5">{  </span><br>               <span id="s-146" class="sObjectK">"id"</span><span id="s-147" class="sColon">:</span><span id="s-148" class="sObjectV">"03e"</span><span id="s-149" class="sComma">,</span><br>               <span id="s-150" class="sObjectK">"name"</span><span id="s-151" class="sColon">:</span><span id="s-152" class="sObjectV">"trickbot"</span><br>            <span id="s-153" class="sBrace structure-5">}</span><br>         <span id="s-154" class="sBracket structure-4">]</span><span id="s-155" class="sComma">,</span><br>         <span id="s-156" class="sObjectK">"threat_type"</span><span id="s-157" class="sColon">:</span><span id="s-158" class="sObjectV">"apt"</span><span id="s-159" class="sComma">,</span><br>         <span id="s-160" class="sObjectK">"threatscore"</span><span id="s-161" class="sColon">:</span><span id="s-162" class="sObjectV">79</span><span id="s-163" class="sComma">,</span><br>         <span id="s-164" class="sObjectK">"trusted_circle_ids"</span><span id="s-165" class="sColon">:</span><span id="s-166" class="sObjectV">null</span><span id="s-167" class="sComma">,</span><br>         <span id="s-168" class="sObjectK">"type"</span><span id="s-169" class="sColon">:</span><span id="s-170" class="sObjectV">"md5"</span><span id="s-171" class="sComma">,</span><br>         <span id="s-172" class="sObjectK">"update_id"</span><span id="s-173" class="sColon">:</span><span id="s-174" class="sObjectV">854928373</span><span id="s-175" class="sComma">,</span><br>         <span id="s-176" class="sObjectK">"value"</span><span id="s-177" class="sColon">:</span><span id="s-178" class="sObjectV">"3e5d63b93a68d715f7559f42285223f4"</span><span id="s-179" class="sComma">,</span><br>         <span id="s-180" class="sObjectK">"workgroups"</span><span id="s-181" class="sColon">:</span><span id="s-182" class="sObjectV">null</span><br>      <span id="s-183" class="sBrace structure-3">}</span><br>   <span id="s-184" class="sBracket structure-2">]</span><br><span id="s-185" class="sBrace structure-1">}</span></pre>
<h4>War Room Output</h4>
<p>Command: <code>!file file="3e5d63b93a68d715f7559f42285223f4" threshold="3"</code></p>
<p><a href="../../doc_files/38622450-e197e028-3dab-11e8-8052-dcca83edaf2e.png" target="_blank" rel="noopener"><img src="../../doc_files/38622450-e197e028-3dab-11e8-8052-dcca83edaf2e.png" alt="image"></a></p>
<h3 id="h_103925922131525681132050">Check Email Address Reputation: threatstream-email-reputation</h3>
<h4>Inputs</h4>
<table style="height: 75px; width: 692px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 202.557px;"><strong>Input Parameter</strong></td>
<td style="width: 460.739px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 202.557px;">domain</td>
<td style="width: 460.739px;">The domain name you want to check the reputation for.</td>
</tr>
<tr>
<td style="width: 202.557px;">threshold</td>
<td style="width: 460.739px;">The ThreatScore that determines if an email is considered malicious.</td>
</tr>
</tbody>
</table>
<h4> </h4>
<h4>Context Output</h4>
<p>Path: DBotScore.Indicator<br>Description: The tested indicator<br>Path: DBotScore.Type<br>Description: The indicator type<br>Path: DBotScore.Vendor<br>Description: Vendor used to calculate the score<br>Path: DBotScore.Score<br>Description: The actual score</p>
<h4>JSON Output</h4>
<pre><span id="s-1" class="sBrace structure-1">{  </span><br>   <span id="s-2" class="sObjectK">"meta"</span><span id="s-3" class="sColon">:</span><span id="s-4" class="sBrace structure-2">{  </span><br>      <span id="s-5" class="sObjectK">"limit"</span><span id="s-6" class="sColon">:</span><span id="s-7" class="sObjectV">1000</span><span id="s-8" class="sComma">,</span><br>      <span id="s-9" class="sObjectK">"next"</span><span id="s-10" class="sColon">:</span><span id="s-11" class="sObjectV">null</span><span id="s-12" class="sComma">,</span><br>      <span id="s-13" class="sObjectK">"offset"</span><span id="s-14" class="sColon">:</span><span id="s-15" class="sObjectV">0</span><span id="s-16" class="sComma">,</span><br>      <span id="s-17" class="sObjectK">"previous"</span><span id="s-18" class="sColon">:</span><span id="s-19" class="sObjectV">null</span><span id="s-20" class="sComma">,</span><br>      <span id="s-21" class="sObjectK">"took"</span><span id="s-22" class="sColon">:</span><span id="s-23" class="sObjectV">4</span><span id="s-24" class="sComma">,</span><br>      <span id="s-25" class="sObjectK">"total_count"</span><span id="s-26" class="sColon">:</span><span id="s-27" class="sObjectV">1</span><br>   <span id="s-28" class="sBrace structure-2">}</span><span id="s-29" class="sComma">,</span><br>   <span id="s-30" class="sObjectK">"objects"</span><span id="s-31" class="sColon">:</span><span id="s-32" class="sBracket structure-2">[  </span><br>      <span id="s-33" class="sBrace structure-3">{  </span><br>         <span id="s-34" class="sObjectK">"asn"</span><span id="s-35" class="sColon">:</span><span id="s-36" class="sObjectV">""</span><span id="s-37" class="sComma">,</span><br>         <span id="s-38" class="sObjectK">"confidence"</span><span id="s-39" class="sColon">:</span><span id="s-40" class="sObjectV">17</span><span id="s-41" class="sComma">,</span><br>         <span id="s-42" class="sObjectK">"country"</span><span id="s-43" class="sColon">:</span><span id="s-44" class="sObjectV">"RO"</span><span id="s-45" class="sComma">,</span><br>         <span id="s-46" class="sObjectK">"created_ts"</span><span id="s-47" class="sColon">:</span><span id="s-48" class="sObjectV">"2017-06-02T18:09:41.986Z"</span><span id="s-49" class="sComma">,</span><br>         <span id="s-50" class="sObjectK">"description"</span><span id="s-51" class="sColon">:</span><span id="s-52" class="sObjectV">null</span><span id="s-53" class="sComma">,</span><br>         <span id="s-54" class="sObjectK">"expiration_ts"</span><span id="s-55" class="sColon">:</span><span id="s-56" class="sObjectV">"2017-08-31T11:58:38.253Z"</span><span id="s-57" class="sComma">,</span><br>         <span id="s-58" class="sObjectK">"feed_id"</span><span id="s-59" class="sColon">:</span><span id="s-60" class="sObjectV">0</span><span id="s-61" class="sComma">,</span><br>         <span id="s-62" class="sObjectK">"id"</span><span id="s-63" class="sColon">:</span><span id="s-64" class="sObjectV">859843899</span><span id="s-65" class="sComma">,</span><br>         <span id="s-66" class="sObjectK">"import_session_id"</span><span id="s-67" class="sColon">:</span><span id="s-68" class="sObjectV">213529</span><span id="s-69" class="sComma">,</span><br>         <span id="s-70" class="sObjectK">"ip"</span><span id="s-71" class="sColon">:</span><span id="s-72" class="sObjectV">"185.72.179.152"</span><span id="s-73" class="sComma">,</span><br>         <span id="s-74" class="sObjectK">"is_public"</span><span id="s-75" class="sColon">:</span><span id="s-76" class="sObjectV">true</span><span id="s-77" class="sComma">,</span><br>         <span id="s-78" class="sObjectK">"itype"</span><span id="s-79" class="sColon">:</span><span id="s-80" class="sObjectV">"adware_domain"</span><span id="s-81" class="sComma">,</span><br>         <span id="s-82" class="sObjectK">"latitude"</span><span id="s-83" class="sColon">:</span><span id="s-84" class="sObjectV">"46.000000"</span><span id="s-85" class="sComma">,</span><br>         <span id="s-86" class="sObjectK">"longitude"</span><span id="s-87" class="sColon">:</span><span id="s-88" class="sObjectV">"25.000000"</span><span id="s-89" class="sComma">,</span><br>         <span id="s-90" class="sObjectK">"meta"</span><span id="s-91" class="sColon">:</span><span id="s-92" class="sBrace structure-4">{  </span><br>            <span id="s-93" class="sObjectK">"detail"</span><span id="s-94" class="sColon">:</span><span id="s-95" class="sObjectV">""</span><span id="s-96" class="sComma">,</span><br>            <span id="s-97" class="sObjectK">"detail2"</span><span id="s-98" class="sColon">:</span><span id="s-99" class="sObjectV">"bifocals_deactivated_on_2017-08-31_12:47:29.013755"</span><span id="s-100" class="sComma">,</span><br>            <span id="s-101" class="sObjectK">"severity"</span><span id="s-102" class="sColon">:</span><span id="s-103" class="sObjectV">"low"</span><br>         <span id="s-104" class="sBrace structure-4">}</span><span id="s-105" class="sComma">,</span><br>         <span id="s-106" class="sObjectK">"modified_ts"</span><span id="s-107" class="sColon">:</span><span id="s-108" class="sObjectV">"2017-08-31T12:47:28.926Z"</span><span id="s-109" class="sComma">,</span><br>         <span id="s-110" class="sObjectK">"org"</span><span id="s-111" class="sColon">:</span><span id="s-112" class="sObjectV">"Nix Web Solutions Pvt Ltd"</span><span id="s-113" class="sComma">,</span><br>         <span id="s-114" class="sObjectK">"owner_organization_id"</span><span id="s-115" class="sColon">:</span><span id="s-116" class="sObjectV">738</span><span id="s-117" class="sComma">,</span><br>         <span id="s-118" class="sObjectK">"rdns"</span><span id="s-119" class="sColon">:</span><span id="s-120" class="sObjectV">null</span><span id="s-121" class="sComma">,</span><br>         <span id="s-122" class="sObjectK">"resource_uri"</span><span id="s-123" class="sColon">:</span><span id="s-124" class="sObjectV">"/api/v2/intelligence/859843899/"</span><span id="s-125" class="sComma">,</span><br>         <span id="s-126" class="sObjectK">"retina_confidence"</span><span id="s-127" class="sColon">:</span><span id="s-128" class="sObjectV">17</span><span id="s-129" class="sComma">,</span><br>         <span id="s-130" class="sObjectK">"source"</span><span id="s-131" class="sColon">:</span><span id="s-132" class="sObjectV">"Analyst"</span><span id="s-133" class="sComma">,</span><br>         <span id="s-134" class="sObjectK">"source_reported_confidence"</span><span id="s-135" class="sColon">:</span><span id="s-136" class="sObjectV">90</span><span id="s-137" class="sComma">,</span><br>         <span id="s-138" class="sObjectK">"status"</span><span id="s-139" class="sColon">:</span><span id="s-140" class="sObjectV">"inactive"</span><span id="s-141" class="sComma">,</span><br>         <span id="s-142" class="sObjectK">"tags"</span><span id="s-143" class="sColon">:</span><span id="s-144" class="sBracket structure-4">[  </span><br>            <span id="s-145" class="sBrace structure-5">{  </span><br>               <span id="s-146" class="sObjectK">"id"</span><span id="s-147" class="sColon">:</span><span id="s-148" class="sObjectV">"rd4"</span><span id="s-149" class="sComma">,</span><br>               <span id="s-150" class="sObjectK">"name"</span><span id="s-151" class="sColon">:</span><span id="s-152" class="sObjectV">"pony"</span><br>            <span id="s-153" class="sBrace structure-5">}</span><br>         <span id="s-154" class="sBracket structure-4">]</span><span id="s-155" class="sComma">,</span><br>         <span id="s-156" class="sObjectK">"threat_type"</span><span id="s-157" class="sColon">:</span><span id="s-158" class="sObjectV">"adware"</span><span id="s-159" class="sComma">,</span><br>         <span id="s-160" class="sObjectK">"threatscore"</span><span id="s-161" class="sColon">:</span><span id="s-162" class="sObjectV">4</span><span id="s-163" class="sComma">,</span><br>         <span id="s-164" class="sObjectK">"trusted_circle_ids"</span><span id="s-165" class="sColon">:</span><span id="s-166" class="sObjectV">null</span><span id="s-167" class="sComma">,</span><br>         <span id="s-168" class="sObjectK">"type"</span><span id="s-169" class="sColon">:</span><span id="s-170" class="sObjectV">"domain"</span><span id="s-171" class="sComma">,</span><br>         <span id="s-172" class="sObjectK">"update_id"</span><span id="s-173" class="sColon">:</span><span id="s-174" class="sObjectV">1023048164</span><span id="s-175" class="sComma">,</span><br>         <span id="s-176" class="sObjectK">"value"</span><span id="s-177" class="sColon">:</span><span id="s-178" class="sObjectV">"kpanels.in"</span><span id="s-179" class="sComma">,</span><br>         <span id="s-180" class="sObjectK">"workgroups"</span><span id="s-181" class="sColon">:</span><span id="s-182" class="sObjectV">null</span><br>      <span id="s-183" class="sBrace structure-3">}</span><br>   <span id="s-184" class="sBracket structure-2">]</span><br><span id="s-185" class="sBrace structure-1">}</span></pre>
<h4>War Room Output</h4>
<p>Command: <code>!threatstream-email-reputation email="mailonline_16@filposcv.com" threshold="3"</code></p>
<p><a href="../../doc_files/38622011-dee2abfc-3daa-11e8-981e-9b6df753f93c.png" target="_blank" rel="noopener"><img src="../../doc_files/38622011-dee2abfc-3daa-11e8-981e-9b6df753f93c.png" alt="image"></a></p>
<h3 id="h_6439751152451525771642821">Check IP Reputation: ip</h3>
<h4>Inputs</h4>
<table style="height: 75px; width: 692px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 202.557px;"><strong>Input Parameter</strong></td>
<td style="width: 460.739px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 202.557px;">domain</td>
<td style="width: 460.739px;">The domain name you want to check the reputation for.</td>
</tr>
<tr>
<td style="width: 202.557px;">threshold</td>
<td style="width: 460.739px;">The ThreatScore that determines if a domain is considered malicious.</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h4>Context Output</h4>
<p>Path: DBotScore.Indicator<br>Description: The tested indicator<br>Path: DBotScore.Type<br>Description: The indicator type<br>Path: DBotScore.Vendor<br>Description: Vendor used to calculate the score<br>Path: DBotScore.Score<br>Description: The actual score</p>
<h4>JSON Output</h4>
<pre>{  <br>   <span id="s-2" class="sObjectK">"meta"</span><span id="s-3" class="sColon">:</span><span id="s-4" class="sBrace structure-2">{  </span><br>      <span id="s-5" class="sObjectK">"limit"</span><span id="s-6" class="sColon">:</span><span id="s-7" class="sObjectV">1000</span><span id="s-8" class="sComma">,</span><br>      <span id="s-9" class="sObjectK">"next"</span><span id="s-10" class="sColon">:</span><span id="s-11" class="sObjectV">null</span><span id="s-12" class="sComma">,</span><br>      <span id="s-13" class="sObjectK">"offset"</span><span id="s-14" class="sColon">:</span><span id="s-15" class="sObjectV">0</span><span id="s-16" class="sComma">,</span><br>      <span id="s-17" class="sObjectK">"previous"</span><span id="s-18" class="sColon">:</span><span id="s-19" class="sObjectV">null</span><span id="s-20" class="sComma">,</span><br>      <span id="s-21" class="sObjectK">"took"</span><span id="s-22" class="sColon">:</span><span id="s-23" class="sObjectV">4</span><span id="s-24" class="sComma">,</span><br>      <span id="s-25" class="sObjectK">"total_count"</span><span id="s-26" class="sColon">:</span><span id="s-27" class="sObjectV">1</span><br>   <span id="s-28" class="sBrace structure-2">}</span><span id="s-29" class="sComma">,</span><br>   <span id="s-30" class="sObjectK">"objects"</span><span id="s-31" class="sColon">:</span><span id="s-32" class="sBracket structure-2">[  </span><br>      <span id="s-33" class="sBrace structure-3">{  </span><br>         <span id="s-34" class="sObjectK">"asn"</span><span id="s-35" class="sColon">:</span><span id="s-36" class="sObjectV">"12400"</span><span id="s-37" class="sComma">,</span><br>         <span id="s-38" class="sObjectK">"confidence"</span><span id="s-39" class="sColon">:</span><span id="s-40" class="sObjectV">69</span><span id="s-41" class="sComma">,</span><br>         <span id="s-42" class="sObjectK">"country"</span><span id="s-43" class="sColon">:</span><span id="s-44" class="sObjectV">"IL"</span><span id="s-45" class="sComma">,</span><br>         <span id="s-46" class="sObjectK">"created_ts"</span><span id="s-47" class="sColon">:</span><span id="s-48" class="sObjectV">"2018-03-13T10:45:16.182Z"</span><span id="s-49" class="sComma">,</span><br>         <span id="s-50" class="sObjectK">"description"</span><span id="s-51" class="sColon">:</span><span id="s-52" class="sObjectV">null</span><span id="s-53" class="sComma">,</span><br>         <span id="s-54" class="sObjectK">"expiration_ts"</span><span id="s-55" class="sColon">:</span><span id="s-56" class="sObjectV">"2018-03-20T10:45:16.178Z"</span><span id="s-57" class="sComma">,</span><br>         <span id="s-58" class="sObjectK">"feed_id"</span><span id="s-59" class="sColon">:</span><span id="s-60" class="sObjectV">112</span><span id="s-61" class="sComma">,</span><br>         <span id="s-62" class="sObjectK">"id"</span><span id="s-63" class="sColon">:</span><span id="s-64" class="sObjectV">50591222843</span><span id="s-65" class="sComma">,</span><br>         <span id="s-66" class="sObjectK">"import_session_id"</span><span id="s-67" class="sColon">:</span><span id="s-68" class="sObjectV">null</span><span id="s-69" class="sComma">,</span><br>         <span id="s-70" class="sObjectK">"ip"</span><span id="s-71" class="sColon">:</span><span id="s-72" class="sObjectV">"176.228.66.70"</span><span id="s-73" class="sComma">,</span><br>         <span id="s-74" class="sObjectK">"is_public"</span><span id="s-75" class="sColon">:</span><span id="s-76" class="sObjectV">false</span><span id="s-77" class="sComma">,</span><br>         <span id="s-78" class="sObjectK">"itype"</span><span id="s-79" class="sColon">:</span><span id="s-80" class="sObjectV">"scan_ip"</span><span id="s-81" class="sComma">,</span><br>         <span id="s-82" class="sObjectK">"latitude"</span><span id="s-83" class="sColon">:</span><span id="s-84" class="sObjectV">"31.964200"</span><span id="s-85" class="sComma">,</span><br>         <span id="s-86" class="sObjectK">"longitude"</span><span id="s-87" class="sColon">:</span><span id="s-88" class="sObjectV">"34.804400"</span><span id="s-89" class="sComma">,</span><br>         <span id="s-90" class="sObjectK">"meta"</span><span id="s-91" class="sColon">:</span><span id="s-92" class="sBrace structure-4">{  </span><br>            <span id="s-93" class="sObjectK">"detail2"</span><span id="s-94" class="sColon">:</span><span id="s-95" class="sObjectV">"bifocals_deactivated_on_2018-03-20_13:56:34.918843"</span><span id="s-96" class="sComma">,</span><br>            <span id="s-97" class="sObjectK">"severity"</span><span id="s-98" class="sColon">:</span><span id="s-99" class="sObjectV">"medium"</span><br>         <span id="s-100" class="sBrace structure-4">}</span><span id="s-101" class="sComma">,</span><br>         <span id="s-102" class="sObjectK">"modified_ts"</span><span id="s-103" class="sColon">:</span><span id="s-104" class="sObjectV">"2018-03-20T13:56:34.461Z"</span><span id="s-105" class="sComma">,</span><br>         <span id="s-106" class="sObjectK">"org"</span><span id="s-107" class="sColon">:</span><span id="s-108" class="sObjectV">"Orange Israel"</span><span id="s-109" class="sComma">,</span><br>         <span id="s-110" class="sObjectK">"owner_organization_id"</span><span id="s-111" class="sColon">:</span><span id="s-112" class="sObjectV">2</span><span id="s-113" class="sComma">,</span><br>         <span id="s-114" class="sObjectK">"rdns"</span><span id="s-115" class="sColon">:</span><span id="s-116" class="sObjectV">null</span><span id="s-117" class="sComma">,</span><br>         <span id="s-118" class="sObjectK">"resource_uri"</span><span id="s-119" class="sColon">:</span><span id="s-120" class="sObjectV">"/api/v2/intelligence/50591222843/"</span><span id="s-121" class="sComma">,</span><br>         <span id="s-122" class="sObjectK">"retina_confidence"</span><span id="s-123" class="sColon">:</span><span id="s-124" class="sObjectV">69</span><span id="s-125" class="sComma">,</span><br>         <span id="s-126" class="sObjectK">"source"</span><span id="s-127" class="sColon">:</span><span id="s-128" class="sObjectV">"Anomali Labs MHN"</span><span id="s-129" class="sComma">,</span><br>         <span id="s-130" class="sObjectK">"source_reported_confidence"</span><span id="s-131" class="sColon">:</span><span id="s-132" class="sObjectV">70</span><span id="s-133" class="sComma">,</span><br>         <span id="s-134" class="sObjectK">"status"</span><span id="s-135" class="sColon">:</span><span id="s-136" class="sObjectV">"inactive"</span><span id="s-137" class="sComma">,</span><br>         <span id="s-138" class="sObjectK">"tags"</span><span id="s-139" class="sColon">:</span><span id="s-140" class="sObjectV">null</span><span id="s-141" class="sComma">,</span><br>         <span id="s-142" class="sObjectK">"threat_type"</span><span id="s-143" class="sColon">:</span><span id="s-144" class="sObjectV">"scan"</span><span id="s-145" class="sComma">,</span><br>         <span id="s-146" class="sObjectK">"threatscore"</span><span id="s-147" class="sColon">:</span><span id="s-148" class="sObjectV">25</span><span id="s-149" class="sComma">,</span><br>         <span id="s-150" class="sObjectK">"trusted_circle_ids"</span><span id="s-151" class="sColon">:</span><span id="s-152" class="sBracket structure-4">[  </span><br>            <span id="s-153" class="sArrayV">145</span><br>         <span id="s-154" class="sBracket structure-4">]</span><span id="s-155" class="sComma">,</span><br>         <span id="s-156" class="sObjectK">"type"</span><span id="s-157" class="sColon">:</span><span id="s-158" class="sObjectV">"ip"</span><span id="s-159" class="sComma">,</span><br>         <span id="s-160" class="sObjectK">"update_id"</span><span id="s-161" class="sColon">:</span><span id="s-162" class="sObjectV">1695845308</span><span id="s-163" class="sComma">,</span><br>         <span id="s-164" class="sObjectK">"uuid"</span><span id="s-165" class="sColon">:</span><span id="s-166" class="sObjectV">"09688972-7581-4fb9-8e50-7c99a02cd442"</span><span id="s-167" class="sComma">,</span><br>         <span id="s-168" class="sObjectK">"value"</span><span id="s-169" class="sColon">:</span><span id="s-170" class="sObjectV">"176.228.66.70"</span><span id="s-171" class="sComma">,</span><br>         <span id="s-172" class="sObjectK">"workgroups"</span><span id="s-173" class="sColon">:</span><span id="s-174" class="sBracket structure-4">[  </span><br><br>         <span id="s-175" class="sBracket structure-4">]</span><br>      <span id="s-176" class="sBrace structure-3">}</span><br>   <span id="s-177" class="sBracket structure-2">]</span><br><span id="s-178" class="sBrace structure-1">}</span></pre>
<h4>War Room Output</h4>
<p>Command: <code>!ip ip="176.228.66.70" threshold="3"</code></p>
<p><a href="../../doc_files/38622277-7cd944ec-3dab-11e8-832b-1f8113a2d2dd.png" target="_blank" rel="noopener"><img src="../../doc_files/38622277-7cd944ec-3dab-11e8-832b-1f8113a2d2dd.png" alt="image"></a></p>
<h2>Troubleshooting</h2>
<p>The integration was tested with the <code>v2</code> API on version 2.5.4.</p>
<ul>
<li>If a command does not return a response, the server might be down, or an incorrect address was entered.</li>
<li>If you receive a <code>401 Unauthorized</code> error, the API credentials might be incorrect.</li>
</ul>
