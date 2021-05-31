<!-- HTML_DOC -->
<p>Use the Cisco Umbrella integration to manage online threats.</p>
<h2>Configure Cisco Umbrella Investigate - Python on Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Cisco Umbrella Investigate - Python.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Cisco Umbrella API token</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Base URL</strong></li>
<li><strong>DBot Score Malicious Threshold</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>How DBot Score Malicious Threshold is Calculated</h2>
<p>The DBot Score Malicious Threshold is calculated by taking the lower of two Cisco scores: <a href="https://docs.umbrella.com/investigate-api/docs/security-information-for-a-domain-1" target="_blank" rel="noopener">secure rank</a> and <a href="https://docs.umbrella.com/investigate-api/docs/domain-status-and-categorization-1" target="_blank" rel="noopener">domain status</a>.  </p>
<p>The DBot Score will be 3 (bad) in these cases:</p>
<ul>
<li>The secure rank score is lower than the threshold score</li>
<li>The domain status is -1</li>
</ul>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_95271207136361539669137295">Get a domain category: umbrella-domain-categorization/investigate-umbrella-domain-categorization</a></li>
<li><a href="#h_12059469238361539669280611">Get co-occurences for a domain: umbrella-domain-co-occurrences/investigate-umbrella-domain-co-occurrences</a></li>
<li><a href="#h_34403715040351539671521979">Get a list of domain names requested the same time as a specified domain: umbrella-domain-related/investigate-umbrella-domain-related</a></li>
<li><a href="#h_12028812242331539672611449">Get domain security data: umbrella-domain-security/investigate-umbrella-domain-security</a></li>
<li><a href="#h_68120690844301539672675764">Query the DNS database for domains: umbrella-domain-dns-history/investigate-umbrella-domain-dns-history</a></li>
<li><a href="#h_36010770446261539672842125">Query the DNS database for IPs: umbrella-ip-dns-history/investigate-umbrella-ip-dns-history</a></li>
<li><a href="#h_1511178348211539673078668">Get malicious domains associated with an IP address: umbrella-ip-malicious-domains/investigate-umbrella-ip-malicious-domains</a></li>
<li><a href="#h_89573474650151539674030486">Get a list of domains that match a regular expression (regex): umbrella-domain-search/investigate-umbrella-domain-search</a></li>
<li><a href="#h_51225163252081539674588524">Get the reputation for a domain: domain</a></li>
<li><a href="#h_94733327855831539678097346">Get a list of domain names requested the same time as a specified domain and a list of co-occurrences: umbrella-get-related-domains</a></li>
<li><a href="#h_37604647659561539678104926">List all classifiers for a domain: umbrella-get-domain-classifiers</a></li>
<li><a href="#h_10552279861461539678186711">Get the number of DNS queries for a domain: umbrella-get-domain-queryvolume</a></li>
<li><a href="#h_98718850465151539678482169">Get domain security data: umbrella-get-domain-details</a></li>
<li><a href="#h_93157940570611539678559957">Get domains associated with registrar email addresses: umbrella-get-domains-for-email-registrar</a></li>
<li><a href="#h_41869273074261539678731403">Get all domains for a nameserver: umbrella-get-domains-for-nameserver</a></li>
<li><a href="#h_17814194977891539678785713">Get WHOIS data for a domain: umbrella-get-whois-for-domain</a></li>
<li><a href="#h_3979943983261539679228550">Get malicious domains associated with an IP address: umbrella-get-malicious-domains-for-ip</a></li>
<li><a href="#h_27395371286851539680187187">Get a list of domains that match a regular expressions (regex): umbrella-get-domains-using-regex</a></li>
<li><a href="#h_67454363090421539680195481">Query when a domain was attributed to a security organization or as a threat type: umbrella-get-domain-timeline</a></li>
<li><a href="#h_84751396693971539680297675">Query when an IP address was attributed to a security organization or as a threat type: umbrella-get-ip-timeline</a></li>
<li><a href="#h_79786501397501539680422818">Query when a URL was attributed to a security organization or as a threat type: umbrella-get-url-timeline</a></li>
</ol>
<h3 id="h_95271207136361539669137295">1. Get a domain category</h3>
<hr>
<p>Returns the category of a domain, e.g., <code>domain=amazon.com</code> returns <code>Ecommerce/Shopping</code>.</p>
<h5>Base Command</h5>
<p><code>umbrella-domain-categorization</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 147px;"><strong>Argument Name</strong></th>
<th style="width: 484px;"><strong>Description</strong></th>
<th style="width: 77px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 147px;">domain</td>
<td style="width: 484px;">The domain to categorize (e.g., amazon.com)</td>
<td style="width: 77px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 209px;"><strong>Path</strong></th>
<th style="width: 439px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 209px;">Domain.Name</td>
<td style="width: 439px;">Domain name</td>
</tr>
<tr>
<td style="width: 209px;">Domain.SecurityCategories</td>
<td style="width: 439px;">The Umbrella security category, or categories, that match this domain</td>
</tr>
<tr>
<td style="width: 209px;">Domain.ContentCategories</td>
<td style="width: 439px;">The Umbrella content category or categories that match this domain</td>
</tr>
<tr>
<td style="width: 209px;">Domain.Malicious.Vendor</td>
<td style="width: 439px;">For malicious domains, the vendor that made the decision</td>
</tr>
<tr>
<td style="width: 209px;">Domain.Malicious.Description</td>
<td style="width: 439px;">For malicious domains, the reason for the vendor to make the decision</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!umbrella-domain-categorization domain=cnn.com</pre>
<h5>Context Example</h5>
<p>Domain:{} 2 items<br> ContentCategories:News/Media<br> Name:cnn.com</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46915576-2665bf80-cfb6-11e8-97df-d16a5f63022a.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46915576-2665bf80-cfb6-11e8-97df-d16a5f63022a.png" alt="1 investigate-umbrella-domain-categorization" width="752" height="261"></a></p>
<h3 id="h_12059469238361539669280611">2. Get co-occurences for a domain</h3>
<hr>
<p>Gets a list of related domains and returns a list of co-occurences for the specified domain. A co-occurrence is when two or more domains are being accessed by the same users within a short time frame. Co-occurrence are not necessarily negative. Legitimate sites co-occur with each other as a part of normal web activity. However, unusual or suspicious co-occurence can provide additional information regarding attacks.</p>
<h5>Base Command</h5>
<p><code>umbrella-domain-co-occurrences</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 193px;"><strong>Argument Name</strong></th>
<th style="width: 400px;"><strong>Description</strong></th>
<th style="width: 115px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 193px;">domain</td>
<td style="width: 400px;">Enter a domain (e.g., www.cnn.com)</td>
<td style="width: 115px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 250px;"><strong>Path</strong></th>
<th style="width: 72px;"><strong>Type</strong></th>
<th style="width: 386px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 250px;">Domain.Name</td>
<td style="width: 72px;">string</td>
<td style="width: 386px;">Domain name</td>
</tr>
<tr>
<td style="width: 250px;">Domain.CoOccurrences.Score</td>
<td style="width: 72px;">number</td>
<td style="width: 386px;">Domain score (between 0 and 1)</td>
</tr>
<tr>
<td style="width: 250px;">Domain.CoOccurrences.Name</td>
<td style="width: 72px;">string</td>
<td style="width: 386px;">Domain name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!umbrella-domain-co-occurrences domain=walla.com</pre>
<h5>Context Example</h5>
<p>Domain:{} 2 items<br> CoOccurrences:[] 1 item<br> 0:{} 2 items<br> Name:walla.co.il<br> Score:1<br> Name:walla.com</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46915591-4f865000-cfb6-11e8-8996-d7a3a69d1123.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46915591-4f865000-cfb6-11e8-8996-d7a3a69d1123.png" alt="2 investigate-umbrella-domain-co-occurrences" width="750" height="225"></a></p>
<h3 id="h_34403715040351539671521979">3. Get a list of domain names requested the same time as a specified domain</h3>
<hr>
<p>Returns a list of domain names that are frequently seen requested around the same time  as the specified domain name (up to 60 seconds before or after). The returned domain names are ones that are not frequently associated with other domain names.</p>
<h5>Base Command</h5>
<p><code>umbrella-domain-related</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 201px;"><strong>Argument Name</strong></th>
<th style="width: 391px;"><strong>Description</strong></th>
<th style="width: 116px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 201px;">domain</td>
<td style="width: 391px;">Domain name (e.g., www.cnn.com)</td>
<td style="width: 116px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 155px;"><strong>Path</strong></th>
<th style="width: 58px;"><strong>Type</strong></th>
<th style="width: 495px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 155px;">Domain.Name</td>
<td style="width: 58px;">string</td>
<td style="width: 495px;">Domain name</td>
</tr>
<tr>
<td style="width: 155px;">Domain.Related.Score</td>
<td style="width: 58px;">number</td>
<td style="width: 495px;">This is a score reflecting the number of client IPs looking up related sites within 60 seconds of the original request</td>
</tr>
<tr>
<td style="width: 155px;">Domain.Related.Name</td>
<td style="width: 58px;">string</td>
<td style="width: 495px;">Related domain name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!umbrella-domain-related domain=walla.com</pre>
<h5>Context Example</h5>
<p>Domain:{} 2 items<br> Name:walla.com<br> Related:[] 9 items<br> 0:{} 2 items<br> Name:c3s2.iphmx.com<br> Score:6<br> 1:{} 2 items<br> Name:google.co.ma<br> Score:6<br> 2:{} 2 items<br> Name:email.footsmart.com<br> Score:5<br> 3:{} 2 items<br> Name:link.expediamail.com<br> Score:4<br> 4:{} 2 items<br> Name:cdn.lemediavault.com<br> Score:4<br> 5:{} 2 items<br> Name:click.royalcaribbeanmarketing.com<br> Score:3<br> 6:{} 2 items<br> Name:e2.overtons.com<br> Score:3<br> 7:{} 2 items<br> Name:link.trustpilot.com<br> Score:3<br> 8:{} 2 items<br> Name:tr.subscribermail.com<br> Score:3</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46915640-aa1fac00-cfb6-11e8-8add-fceff77d5063.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46915640-aa1fac00-cfb6-11e8-8add-fceff77d5063.png" alt="3 investigate-umbrella-domain-related" width="751" height="419"></a></p>
<h3 id="h_12028812242331539672611449">4. Get domain security data</h3>
<hr>
<p>This contains multiple scores or security features, each of which can be used to determine relevant datapoints to build insight on the reputation or security risk posed by the site. For more security information about this specific domain, see the Cisco Umbrella documentation.</p>
<h5>Base Command</h5>
<p><code>umbrella-domain-security</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 198px;"><strong>Argument Name</strong></th>
<th style="width: 394px;"><strong>Description</strong></th>
<th style="width: 116px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 198px;">domain</td>
<td style="width: 394px;">Domain name (e.g., www.cnn.com)</td>
<td style="width: 116px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 251px;"><strong>Path</strong></th>
<th style="width: 67px;"><strong>Type</strong></th>
<th style="width: 390px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 251px;">Domain.Name</td>
<td style="width: 67px;">string</td>
<td style="width: 390px;">Domain name</td>
</tr>
<tr>
<td style="width: 251px;">Domain.Security.DGA</td>
<td style="width: 67px;">number</td>
<td style="width: 390px;">Domain Generation Algorithm. This score is generated based on the likeliness of the domain name being generated by an algorithm rather than a human</td>
</tr>
<tr>
<td style="width: 251px;">Domain.Security.Perplexity</td>
<td style="width: 67px;">number</td>
<td style="width: 390px;">A second score on the likeliness of the name to be algorithmically generated, on a scale from 0 to 1</td>
</tr>
<tr>
<td style="width: 251px;">Domain.Security.Entropy</td>
<td style="width: 67px;">number</td>
<td style="width: 390px;">The number of bits required to encode the domain name, as a score</td>
</tr>
<tr>
<td style="width: 251px;">Domain.Security.SecureRank</td>
<td style="width: 67px;">number</td>
<td style="width: 390px;">Suspicious rank for a domain that reviews based on the lookup behavior of client IP for the domain</td>
</tr>
<tr>
<td style="width: 251px;">Domain.Security.PageRank</td>
<td style="width: 67px;">number</td>
<td style="width: 390px;">Popularity according to Google's pagerank algorithm</td>
</tr>
<tr>
<td style="width: 251px;">Domain.Security.ASNScore</td>
<td style="width: 67px;">unknown</td>
<td style="width: 390px;">ASN reputation score, ranges from -100 to 0 with -100 being very suspicious</td>
</tr>
<tr>
<td style="width: 251px;">Domain.Security.PrefixScore</td>
<td style="width: 67px;">number</td>
<td style="width: 390px;">Prefix ranks domains given their IP prefixes (an IP prefix is the first three octets in an IP address) and the reputation score of these prefixes. Ranges from -100 to 0, -100 being very suspicious</td>
</tr>
<tr>
<td style="width: 251px;">Domain.Security.RipScore</td>
<td style="width: 67px;">number</td>
<td style="width: 390px;">RIP ranks domains given their IP addresses and the reputation score of these IP addresses. Ranges from -100 to 0, -100 being very suspicious</td>
</tr>
<tr>
<td style="width: 251px;">Domain.Security.Popularity</td>
<td style="width: 67px;">number</td>
<td style="width: 390px;">The number of unique client IPs visiting this site, relative to the all requests to all sites</td>
</tr>
<tr>
<td style="width: 251px;">Domain.Security.GeoScore</td>
<td style="width: 67px;">number</td>
<td style="width: 390px;">A score that represents how far the different physical locations serving this name are from each other</td>
</tr>
<tr>
<td style="width: 251px;">Domain.Security.KolmoorovSmirnov</td>
<td style="width: 67px;">number</td>
<td style="width: 390px;">olmogorov–Smirnov test on geodiversity. 0 means that the client traffic matches what is expected for this TLD</td>
</tr>
<tr>
<td style="width: 251px;">Domain.Security.AttackName</td>
<td style="width: 67px;">string</td>
<td style="width: 390px;">The name of any known attacks associated with this domain, or blank if no known threat</td>
</tr>
<tr>
<td style="width: 251px;">Domain.Security.ThreatType</td>
<td style="width: 67px;">string</td>
<td style="width: 390px;">The type of the known attack, such as botnet or APT, or blank if no known threat</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!umbrella-domain-security domain=cnn.com</pre>
<h5>Context Example</h5>
<p>Domain:{} 2 items<br> Name:cnn.com<br> Security:{} 13 items<br> PrefixScore:-0.008968782766875304<br> Geoscore:0<br> Perplexity:0.13991232622025684<br> Securerank:86.6441456065165<br> Entropy:0.9182958340544894<br> AttackName:<br> ThreatType:<br> Popularity:100<br> ASNScore:-0.009098667373339567<br> RIPScore:0<br> Pagerank:40.99643<br> KolmogorovSmirnovTest:0<br> DGA:0</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46915645-d2a7a600-cfb6-11e8-97a6-839482fe5093.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46915645-d2a7a600-cfb6-11e8-97a6-839482fe5093.png" alt="5 investigate-umbrella-domain-security" width="750" height="397"></a></p>
<h3 id="h_68120690844301539672675764">5. Query the DNS database for domains</h3>
<hr>
<p>The DNS database can be used to query the history that Umbrella has seen for a given domain. The most common use case is to obtain the RRs (Resource Record) history for a given domain, passing in the record query type as a parameter, to help build intelligence around an domain.</p>
<h5>Base Command</h5>
<p><code>umbrella-domain-dns-history</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 200px;"><strong>Argument Name</strong></th>
<th style="width: 392px;"><strong>Description</strong></th>
<th style="width: 116px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 200px;">domain</td>
<td style="width: 392px;">Domain name (e.g., www.cnn.com)</td>
<td style="width: 116px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 259px;"><strong>Path</strong></th>
<th style="width: 462px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 259px;">Domain.Address</td>
<td style="width: 462px;">IP address</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.Age</td>
<td style="width: 462px;">The day in days between now and the last request for this domain. This value is only useful if present</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.TtlsMin</td>
<td style="width: 462px;">Minimum amount of time set that DNS records should be cached</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.TtlsMax</td>
<td style="width: 462px;">Maximum amount of time set that DNS records should be cached</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.TtlsMean</td>
<td style="width: 462px;">Average amount of time set that DNS records should be cached</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.TtlsMedian</td>
<td style="width: 462px;">Median amount of time set that DNS records should be cached</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.TtlsStddev</td>
<td style="width: 462px;">Standard deviation of the amount of time set that DNS records should be cached</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.CountryCodes</td>
<td style="width: 462px;">List of country codes (ex: US, FR, TW) for the IPs the name maps to</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.CountryCount</td>
<td style="width: 462px;">Number of countries the IPs are hosted in</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.Asns</td>
<td style="width: 462px;">List of ASN numbers the IPs are in</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.AsnsCount</td>
<td style="width: 462px;">Number of ASNs the IPs map to</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.Prefixes</td>
<td style="width: 462px;">List of network prefixes the IPs map to</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.PrefixesCount</td>
<td style="width: 462px;">Number of network prefixes the IPs map to</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.Rips</td>
<td style="width: 462px;">Number of IPs seen for the domain name</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.DivRips</td>
<td style="width: 462px;">The number of prefixes over the number of IPs</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.Locations</td>
<td style="width: 462px;">List of geo coordinates (WGS84 datum, decimal format) the IPs are mapping to</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.LocationsCount</td>
<td style="width: 462px;">Number of distinct geo coordinates the IPs are mapping to</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.GeoDistanceSum</td>
<td style="width: 462px;">Minimum sum of distance between locations, in kilometers</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.GeoDistancMean</td>
<td style="width: 462px;">Mean distance between the geo median and each location, in kilometers</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.MailExchanger</td>
<td style="width: 462px;">Boolean, If an MX query for this domain name has been seen</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.NonRoutable</td>
<td style="width: 462px;">Boolean. If one of the IPs is in a reserved, non-routable IP range</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.FfCandidate</td>
<td style="width: 462px;">Boolean. If the domain name looks like a candidate for fast flux. This does not necessarily mean the domain is in fast flux, but rather that the IP address the domain resolves to changes rapidly</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.RipsStability</td>
<td style="width: 462px;">1.0 divided by the number of times the set of IP addresses changed</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.BaseDomain</td>
<td style="width: 462px;">The base domain of the requested domain</td>
</tr>
<tr>
<td style="width: 259px;">Domain.DNSHistory.IsSubdomain</td>
<td style="width: 462px;">Boolean. True if the requested domain is a subdomain of another</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!umbrella-domain-dns-history domain=cnn.com</pre>
<h5>Context Example</h5>
<p>Domain:{} 2 items<br> DNSHistory:{} 26 items<br> Prefixes:[] 1 item<br> 0:151.101.0.0<br> FfCandidate:false<br> NonRoutable:false<br> GeoDistanceSum:0<br> Ip:151.101.1.67<br> TtlsMin:60<br> DivRips:0.25<br> GeoDistanceMean:0<br> TtlsMean:60<br> Cname:false<br> PrefixesCount:1<br> RipsStability:1<br> CountryCodes:[] 1 item<br> 0:US<br> TtlsMedian:60<br> LocationsCount:1<br> BaseDomain:cnn.com<br> Asns:[] 1 item<br> 0:54113<br> AsnsCount:1<br> MailExchanger:true<br> TtlsStddev:0<br> CountryCount:1<br> IsSubdomain:false<br> Rips:4<br> TtlsMax:60<br> Locations:[] 1 item<br> 0:{} 2 items<br> lat:37.76969909667969<br> lon:-122.39329528808594<br> Age:92<br> Name:cnn.com</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46915669-2dd99880-cfb7-11e8-9a99-9a1afef99b5a.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46915669-2dd99880-cfb7-11e8-9a99-9a1afef99b5a.png" alt="6 investigate-umbrella-domain-dns-history" width="751" height="602"></a></p>
<h3 id="h_36010770446261539672842125">6. Query the DNS database for IPs</h3>
<hr>
<p>The DNS database can be used to query the history that Umbrella has seen for a given IP address. The most common use case is to obtain the DNS Resource Record (RR) history for a given IP, passing in the record query type as a parameter, to help build intelligence around an IP or a range of IPs. The information provided is from within the last 90 days.</p>
<h5>Base Command</h5>
<p><code>umbrella-ip-dns-history</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 255px;"><strong>Argument Name</strong></th>
<th style="width: 302px;"><strong>Description</strong></th>
<th style="width: 151px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 255px;">ip</td>
<td style="width: 302px;">IP address</td>
<td style="width: 151px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 241px;"><strong>Path</strong></th>
<th style="width: 480px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 241px;">IP.Address</td>
<td style="width: 480px;">IP address</td>
</tr>
<tr>
<td style="width: 241px;">IP.DNSHistory.RRS.Name</td>
<td style="width: 480px;">The looked-up IP address</td>
</tr>
<tr>
<td style="width: 241px;">IP.DNSHistory.RRS.Class</td>
<td style="width: 480px;">DNS class type</td>
</tr>
<tr>
<td style="width: 241px;">IP.DNSHistory.RRS.Type</td>
<td style="width: 480px;">Query type</td>
</tr>
<tr>
<td style="width: 241px;">IP.DNSHistory.RRS.RR</td>
<td style="width: 480px;">Resource record owner</td>
</tr>
<tr>
<td style="width: 241px;">IP.DNSHistory.RRS.TTL</td>
<td style="width: 480px;">Time to live for this record</td>
</tr>
<tr>
<td style="width: 241px;">IP.DNSHistory.Feature.RrCount</td>
<td style="width: 480px;">Number of records of that type mapping to the given IP</td>
</tr>
<tr>
<td style="width: 241px;">IP.DNSHistory.Feature.Ld2Count</td>
<td style="width: 480px;">Number of 2-level names mapping to the given IP</td>
</tr>
<tr>
<td style="width: 241px;">IP.DNSHistory.Feature.Ld3Count</td>
<td style="width: 480px;">Number of 3-level names mapping to the given IP</td>
</tr>
<tr>
<td style="width: 241px;">IP.DNSHistory.Feature.Ld21Count</td>
<td style="width: 480px;">Number of 2-level names, without the TLD, mapping to the given IP</td>
</tr>
<tr>
<td style="width: 241px;">IP.DNSHistory.Feature.Ld22Count</td>
<td style="width: 480px;">Number of 3-level names, without the TLD, mapping to the given IP</td>
</tr>
<tr>
<td style="width: 241px;">IP.DNSHistory.Feature.DivLd2</td>
<td style="width: 480px;">ld2_count divided by the number of records</td>
</tr>
<tr>
<td style="width: 241px;">IP.DNSHistory.Feature.DivLd3</td>
<td style="width: 480px;">ld3_count divided by the number of records</td>
</tr>
<tr>
<td style="width: 241px;">IP.DNSHistory.Feature.DivLd21</td>
<td style="width: 480px;">ld2_1_count divided by the number of records</td>
</tr>
<tr>
<td style="width: 241px;">IP.DNSHistory.Feature.DivLd22</td>
<td style="width: 480px;">ld2_2_count divided by the number of records</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!umbrella-ip-dns-history ip=1.2.3.99</pre>
<h5>Context Example</h5>
<p>IP:{} 2 items<br> Address:1.2.3.99<br> DNSHistory:{} 2 items<br> Features:{} 9 items<br> DivLd21:1<br> DivLd22:1<br> DivLd2:1<br> DivLd3:1<br> RrCount:2<br> Ld3Count:2<br> Ld2Count:2<br> Ld22Count:2<br> Ld21Count:2<br> RRS:[] 2 items<br> 0:{} 5 items<br> Class:IN<br> Name:1.2.3.99<br> RR:dnstest-099.brightsignnetwork.com.<br> TTL:1800<br> Type:A<br> 1:{} 5 items<br> Class:IN<br> Name:1.2.3.99<br> RR:jp.rogers.com.<br> TTL:86400<br> Type:A</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46915673-4649b300-cfb7-11e8-9ae2-0c7b8916a496.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46915673-4649b300-cfb7-11e8-9ae2-0c7b8916a496.png" alt="7 investigate-umbrella-ip-dns-history" width="751" height="421"></a></p>
<h3 id="h_1511178348211539673078668">7. Get malicious domains associated with an IP address</h3>
<hr>
<p>Determines whether the specified IP address has any known malicious domains associated with it. The domains that display when using this endpoint are those that currently exist in the Umbrella block list. This endpoint will return an array with a single domain name for each domain associated with the IP, along with an ID number, which you can ignore.</p>
<h5>Base Command</h5>
<p><code>umbrella-ip-malicious-domains</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 297px;"><strong>Argument Name</strong></th>
<th style="width: 237px;"><strong>Description</strong></th>
<th style="width: 174px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 297px;">ip</td>
<td style="width: 237px;">IP address</td>
<td style="width: 174px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 211px;"><strong>Path</strong></th>
<th style="width: 510px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 211px;">Domain.Name</td>
<td style="width: 510px;">Domain name</td>
</tr>
<tr>
<td style="width: 211px;">Domain.Malicious.Vendor</td>
<td style="width: 510px;">For malicious domains, the vendor that made the decision</td>
</tr>
<tr>
<td style="width: 211px;">Domain.Malicious.Description</td>
<td style="width: 510px;">For malicious domains, the reason for the vendor to make the decision</td>
</tr>
<tr>
<td style="width: 211px;">DBotScore.Indicator</td>
<td style="width: 510px;">The Indicator</td>
</tr>
<tr>
<td style="width: 211px;">DBotScore.Vendor</td>
<td style="width: 510px;">The DBot score vendor</td>
</tr>
<tr>
<td style="width: 211px;">DBotScore.Type</td>
<td style="width: 510px;">The Indicator type</td>
</tr>
<tr>
<td style="width: 211px;">DBotScore.Score</td>
<td style="width: 510px;">The DBot score</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!umbrella-ip-malicious-domains ip=1.2.3.4</pre>
<h5>Context Example</h5>
<p>Domain:{} 2 items<br> Malicious:{} 2 items<br> Description:For IP 1.2.3.4<br> Vendor:Cisco Umbrella<br> Name:summaryorder-qpc.serveftp.com</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46915683-709b7080-cfb7-11e8-99c2-7824a6a4dde1.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46915683-709b7080-cfb7-11e8-99c2-7824a6a4dde1.png" alt="8 investigate-umbrella-ip-malicious-domains" width="747" height="137"></a></p>
<h3 id="h_89573474650151539674030486">8. Get a list of domains that match a regular expression (regex)</h3>
<hr>
<p>Returns a list of domains that match a a regular expression. You can use this for domain squatting. The pattern search functionality in Investigate uses regular expressions (regex) to search against the Investigate database. For more information on regex, see online tools, such as <a href="http://regexr.com/" rel="nofollow">http://regexr.com</a>.</p>
<h5>Base Command</h5>
<p><code>umbrella-domain-search</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 135px;"><strong>Argument Name</strong></th>
<th style="width: 502px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 135px;">regex</td>
<td style="width: 502px;">Enter a domain regular expression (e.g. "cn.*\\.com"). Note to use double backslash ("\\")</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 135px;">start</td>
<td style="width: 502px;">Example: -2weeks, -1 day, -1000minutes, EPOCH unix time, MAX: -31days</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 299px;"><strong>Path</strong></th>
<th style="width: 422px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 299px;">Domain.Name</td>
<td style="width: 422px;">Domain name</td>
</tr>
<tr>
<td style="width: 299px;">Domain.FirstSeen</td>
<td style="width: 422px;">First seen time in Epoch format</td>
</tr>
<tr>
<td style="width: 299px;">Domain.FirstSeenISO</td>
<td style="width: 422px;">First seen time in ISO format</td>
</tr>
<tr>
<td style="width: 299px;">Domain. SecurityCategories</td>
<td style="width: 422px;">Matching Umbrella Security Categories</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!umbrella-domain-search regex=googlem.*.com start=-1days</pre>
<h5>Context Example</h5>
<p>Domain:{} 4 items<br> FirstSeen:1535363700000<br> FirstSeenISO:2018-08-27T09:55:00.000Z<br> Name:googlemail.top-office.com<br> SecurityCategories:null</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46915760-b1e05000-cfb8-11e8-918b-eac0ed61af53.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46915760-b1e05000-cfb8-11e8-918b-eac0ed61af53.png" alt="9 investigate-umbrella-domain-search" width="752" height="313"></a></p>
<h3 id="h_51225163252081539674588524">9. Get the reputation for a domain</h3>
<hr>
<p>Get Domain Reputation info using Cisco Umbrella Investigate.</p>
<h5>Base Command</h5>
<p><code>domain</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 137px;"><strong>Argument Name</strong></th>
<th style="width: 500px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 137px;">domain</td>
<td style="width: 500px;">The domain name to categorize, supports comma-separated lists (e.g., www.amazon.com,www.facebook.com,www.yahoo.com)</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 256px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 393px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 256px;">Domain.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 393px;">Domain name</td>
</tr>
<tr>
<td style="width: 256px;">Domain.Umbrella.RiskScore</td>
<td style="width: 59px;">number</td>
<td style="width: 393px;">The status will be "-1" if the domain is believed to be malicious, "1" if the domain is believed to be benign, "0" if it hasn't been classified yet.</td>
</tr>
<tr>
<td style="width: 256px;">Domain.Umbrella.SecureRank </td>
<td style="width: 59px;">number</td>
<td style="width: 393px;">Suspicious rank for a domain that reviews based on the lookup behavior of client IP for the domain. Securerank is designed to identify hostnames requested by known infected clients but never requested by clean clients, assuming these domains are more likely to be bad. Scores returned range from -100 (suspicious) to 100 (benign).</td>
</tr>
<tr>
<td style="width: 256px;">Domain.Umbrella.FirstQueriedTime</td>
<td style="width: 59px;">number</td>
<td style="width: 393px;">The time when the attribution for this Domain was made.</td>
</tr>
<tr>
<td style="width: 256px;">DBotScore.Indicator</td>
<td style="width: 59px;">string</td>
<td style="width: 393px;">The Indicator</td>
</tr>
<tr>
<td style="width: 256px;">DBotScore.Score</td>
<td style="width: 59px;">number</td>
<td style="width: 393px;">The DBot score</td>
</tr>
<tr>
<td style="width: 256px;">DBotScore.Type</td>
<td style="width: 59px;">string</td>
<td style="width: 393px;">The Indicator type</td>
</tr>
<tr>
<td style="width: 256px;">DBotScore.Vendor</td>
<td style="width: 59px;">string</td>
<td style="width: 393px;">The DBot score vendor</td>
</tr>
<tr>
<td style="width: 256px;">Domain.Umbrella.ContentCategories</td>
<td style="width: 59px;">string</td>
<td style="width: 393px;">The Umbrella content category or categories that match this domain. If none of them match, the return will be blank.</td>
</tr>
<tr>
<td style="width: 256px;">Domain.Umbrella.MalwareCategories</td>
<td style="width: 59px;">string</td>
<td style="width: 393px;">The Umbrella security category, or categories, that match this domain or that this domain is associated with. If none match, the return will be blank.</td>
</tr>
<tr>
<td style="width: 256px;">Domain.Malicious.Vendor</td>
<td style="width: 59px;">string</td>
<td style="width: 393px;">For malicious domains, the vendor that made the decision</td>
</tr>
<tr>
<td style="width: 256px;">Domain.Malicious.Description</td>
<td style="width: 59px;">string</td>
<td style="width: 393px;">For malicious domains, the reason for the vendor to make the decision</td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.Admin.Country</span></td>
<td style="width: 59px;">string</td>
<td style="width: 393px;">The country of the domain administrator.</td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.Admin.Email</span></td>
<td style="width: 59px;">string</td>
<td style="width: 393px;">The email address of the domain administrator.</td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.Admin.Name</span></td>
<td style="width: 59px;">string</td>
<td style="width: 393px;">The name of the domain administrator.</td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.Admin.Phone</span></td>
<td style="width: 59px;">string</td>
<td style="width: 393px;">The phone number of the domain administrator.</td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.Registrant.Country</span></td>
<td style="width: 59px;">string</td>
<td style="width: 393px;"><span>The country of the registrant.</span></td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.Registrant.Email</span></td>
<td style="width: 59px;">string</td>
<td style="width: 393px;"><span>The email address of the registrant.</span></td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.Registrant.Name</span></td>
<td style="width: 59px;">string</td>
<td style="width: 393px;"><span>The name of the registrant.</span></td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.Registrant.Phone</span></td>
<td style="width: 59px;">string</td>
<td style="width: 393px;"><span>The phone number of the registrant.</span></td>
</tr>
<tr>
<td style="width: 256px;"> <span>Domain.CreationDate</span>
</td>
<td style="width: 59px;">date</td>
<td style="width: 393px;"><span>The date on which the domain was created.</span></td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.DomainStatus</span></td>
<td style="width: 59px;">string</td>
<td style="width: 393px;"><span>The status of the domain.</span></td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.UpdatedDate</span></td>
<td style="width: 59px;">date</td>
<td style="width: 393px;"><span>The date on which the domain was last updated.</span></td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.ExpirationDate</span></td>
<td style="width: 59px;">date</td>
<td style="width: 393px;"><span>The expiration date of the domain.</span></td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.Registrar.Name</span></td>
<td style="width: 59px;">string</td>
<td style="width: 393px;"><span>The name of the registrar, such as "GoDaddy".</span></td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!domain domain=cnn.com using-brand="Cisco Umbrella Investigate - Python"</pre>
<h5>Context Example</h5>
<p>DBotScore:{} 4 items<br> Indicator:cnn.com<br> Score:1<br> Type:Domain<br> Vendor:Cisco Umbrella<br> Domain:{} 2 items<br> Name:cnn.com<br> Umbrella:{} 5 items<br> ContentCategories:[] 1 item<br> 0:News/Media<br> FirstQueriedTime:1993-09-22<br> MalwareCategories:[] 0 items<br> RiskScore:1<br> SecureRank:86.5019890432578</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46915875-e05f2a80-cfba-11e8-949a-4b76b7528cab.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46915875-e05f2a80-cfba-11e8-949a-4b76b7528cab.png" alt="image" width="750" height="332"></a><br> <a href="https://user-images.githubusercontent.com/12241410/46915878-e9e89280-cfba-11e8-8eaf-24e1569f8d0d.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46915878-e9e89280-cfba-11e8-8eaf-24e1569f8d0d.png" alt="image" width="751" height="203"></a></p>
<h3 id="h_94733327855831539678097346">10. Get a list of domain names requested the same time as a specified domain and a list of co-occurences</h3>
<hr>
<p>Returns a list of domain names that are frequently seen requested around the same time  as the specified domain name (up to 60 seconds before or after), and a list of co-occurences.</p>
<h5>Base Command</h5>
<p><code>umbrella-get-related-domains</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 135px;"><strong>Argument Name</strong></th>
<th style="width: 502px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 135px;">domain</td>
<td style="width: 502px;">The domain name to see related domains for (e.g., www.cnn.com)</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 135px;">coOccurences</td>
<td style="width: 502px;">Set to true to get a list of co-occurences. (A co-occurrence is when two or more domains are being accessed by the same users within a small window of time) By default, this value will be false.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 263px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 386px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 263px;">Umbrella.RelatedDomains.Domain</td>
<td style="width: 59px;">string</td>
<td style="width: 386px;">Domain name</td>
</tr>
<tr>
<td style="width: 263px;">Umbrella.RelatedDomains.Data.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 386px;">Domain names that have been frequently seen requested around the same time (up to 60 seconds before or after) as the given domain name.</td>
</tr>
<tr>
<td style="width: 263px;">Umbrella.CoOccurences.Data.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 386px;">All co-occurences of requests from client IPs are returned for the previous seven days whether the co-occurence is suspicious or not.</td>
</tr>
<tr>
<td style="width: 263px;">Umbrella.CoOccurences.Data.Score</td>
<td style="width: 59px;">number</td>
<td style="width: 386px;">The values range between 0 and 1 and should not exceed 1.</td>
</tr>
<tr>
<td style="width: 263px;">Umbrella.RelatedDomains.Data.Score</td>
<td style="width: 59px;">number</td>
<td style="width: 386px;">The score here is the number of client IP requests to the site around the same time as the site being looked up. This is a score reflecting the number of client IPs looking up related sites within 60 seconds of the original request</td>
</tr>
<tr>
<td style="width: 263px;">Umbrella.CoOccurences.Domain</td>
<td style="width: 59px;">string</td>
<td style="width: 386px;">The domain's name.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!umbrella-get-related-domains domain=walla.com coOccurences=true</pre>
<h5>Context Example</h5>
<p>Umbrella:{} 2 items<br> CoOccurences:{} 2 items<br> Data:[] 3 items<br> 0:{} 2 items<br> Name:rgmkt.net<br> Score:0.9783944034610161<br> 1:{} 2 items<br> Name:ns43.domaincontrol.com<br> Score:0.013178370929884454<br> 2:{} 2 items<br> Name:ns44.domaincontrol.com<br> Score:0.008427225609099349<br> Domain:walla.com<br> RelatedDomains:{} 2 items<br> Data:[] 2 items<br> 0:{} 2 items<br> Name:c3s2.iphmx.com<br> Score:4<br> 1:{} 2 items<br> Name:rgmkt.net<br> Score:3<br> Domain:walla.com</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46915887-17354080-cfbb-11e8-9b5e-7a019339293b.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46915887-17354080-cfbb-11e8-9b5e-7a019339293b.png" alt="image" width="750" height="504"></a></p>
<h3 id="h_37604647659561539678104926">11. List all classifiers for a domain</h3>
<hr>
<p>List all the classifiers used for a particular domain to assign a particular security categorization or threat type (indicators of compromise).</p>
<h5>Base Command</h5>
<p><code>umbrella-get-domain-classifiers</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 141px;"><strong>Argument Name</strong></th>
<th style="width: 496px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 141px;">domain</td>
<td style="width: 496px;">The domain name to see classifiers for (e.g., www.cnn.com)</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 369px;"><strong>Path</strong></th>
<th style="width: 42px;"><strong>Type</strong></th>
<th style="width: 297px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 369px;">Umbrella.DomainClassifiers.Domain</td>
<td style="width: 42px;">string</td>
<td style="width: 297px;">Domain name</td>
</tr>
<tr>
<td style="width: 369px;">Umbrella.DomainClassifiers.Data.MalwareCategories</td>
<td style="width: 42px;">string</td>
<td style="width: 297px;">Which Umbrella security category, if any, matched the input</td>
</tr>
<tr>
<td style="width: 369px;">Umbrella.DomainClassifiers.Data.AttackNames</td>
<td style="width: 42px;">string</td>
<td style="width: 297px;">Which named attacks, if any, matched the input</td>
</tr>
<tr>
<td style="width: 369px;">Umbrella.DomainClassifiers.Data.ThreatTypes</td>
<td style="width: 42px;">string</td>
<td style="width: 297px;">Which threat type, if any, matched in the input.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!umbrella-get-domain-classifiers domain=cosmos.furnipict.com</pre>
<h5>Context Example</h5>
<p>Umbrella:{} 1 item<br> DomainClassifiers:{} 2 items<br> Data:{} 3 items<br> Attacks:[] 1 item<br> 0:Neutrino<br> SecurityCategories:[] 1 item<br> 0:Malware<br> ThreatTypes:[] 1 item<br> 0:Exploit Kit<br> Domain:cosmos.furnipict.com</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46915906-506db080-cfbb-11e8-9be4-8cae18d2de6a.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46915906-506db080-cfbb-11e8-9be4-8cae18d2de6a.png" alt="image" width="750" height="260"></a></p>
<h3 id="h_10552279861461539678186711">12. Get the number of DNS queries for a domain</h3>
<hr>
<p>Returns the number of DNS queries made per hour to the specified domain by users of Umbrella's recursive DNS servers.</p>
<h5>Base Command</h5>
<p><code>umbrella-get-domain-queryvolume</code></p>
<h5>Input</h5>
<table style="width: 742px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 141px;"><strong>Argument Name</strong></th>
<th style="width: 496px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 141px;">domain</td>
<td style="width: 496px;">The domain name to see the volume for (e.g., www.cnn.com)</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 141px;">start</td>
<td style="width: 496px;">Point in time in the past, expressed as a timestamp in the following format or relative time. Valid formats: start=-2days start=-2hours start=1997-07-16T19:20:30+01:00 i.e YYYY-MM-DDThh:mm:ssTZD Note the negative sign. The max is 30 days.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 141px;">stop</td>
<td style="width: 496px;">Point in time in the past expressed as a timestamp in milliseconds or relative time. Also valid is 'now'. Valid formats: stop=-1days stop=now start=1997-07-16T19:20:30+01:00 i.e YYYY-MM-DDThh:mm:ssTZD Note the negative sign. The max is 30 days.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 141px;">match</td>
<td style="width: 496px;">Valid options are: exact, component, or all (default).     1.Using "cisco.com" as an example, "exact" only gives results for cisco.com.    2. Component gives results for every component of cisco.com, but not cisco.com. Examples are <a href="http://www.cisco.com/" rel="nofollow">www.cisco.com</a>, mail.cisco.com, wwwin.cisco.com, something.else.cisco.com. 3.All returns the sum of component and exact, this is the default.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 366px;"><strong>Path</strong></th>
<th style="width: 45px;"><strong>Type</strong></th>
<th style="width: 297px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 366px;">Umbrella.QueryVolume.Domain</td>
<td style="width: 45px;">string</td>
<td style="width: 297px;">Domain name</td>
</tr>
<tr>
<td style="width: 366px;">Umbrella.QueryVolume.Data.StartDate</td>
<td style="width: 45px;">string</td>
<td style="width: 297px;">Start date for which the volume data is returned.</td>
</tr>
<tr>
<td style="width: 366px;">Umbrella.QueryVolume.Data.StopDate</td>
<td style="width: 45px;">string</td>
<td style="width: 297px;">Stop date for which the volume data is returned.</td>
</tr>
<tr>
<td style="width: 366px;">Umbrella.QueryVolume.Data.QueriesInfo.QueryHour</td>
<td style="width: 45px;">string</td>
<td style="width: 297px;">Query hour for which the queries data is returned.</td>
</tr>
<tr>
<td style="width: 366px;">Umbrella.QueryVolume.Data.QueriesInfo.Queries</td>
<td style="width: 45px;">string</td>
<td style="width: 297px;">Number of DNS queries per hour, in ascending order, to the specified domain.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!umbrella-get-domain-queryvolume domain=walla.com match=all start=-6hours</pre>
<h5>Context Example</h5>
<p>Umbrella:{} 1 item<br> QueryVolume:{} 2 items<br> Data:{} 3 items<br> QueriesInfo:[] 7 items<br> 0:{} 2 items<br> Queries:3021<br> QueryHour:2018-10-14T06:00:00<br> 1:{} 2 items<br> Queries:2924<br> QueryHour:2018-10-14T07:00:00<br> 2:{} 2 items<br> Queries:3086<br> QueryHour:2018-10-14T08:00:00<br> 3:{} 2 items<br> Queries:3189<br> QueryHour:2018-10-14T09:00:00<br> 4:{} 2 items<br> Queries:3068<br> QueryHour:2018-10-14T10:00:00<br> 5:{} 2 items<br> Queries:0<br> QueryHour:2018-10-14T11:00:00<br> 6:{} 2 items<br> Queries:0<br> QueryHour:2018-10-14T12:00:00<br> StartDate:2018-10-14T06:00:00<br> StopDate:2018-10-14T12:00:00<br> Domain:walla.com</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46916493-28367f80-cfc4-11e8-83fb-e40dff0b3f07.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46916493-28367f80-cfc4-11e8-83fb-e40dff0b3f07.png" alt="image" width="750" height="520"></a></p>
<h3 id="h_98718850465151539678482169">13. Get domain security data</h3>
<hr>
<p>The security information API method contains multiple scores or security features, which can act as relevant datapoints to build insight on the reputation.</p>
<h5>Base Command</h5>
<p><code>umbrella-get-domain-details</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 144px;"><strong>Argument Name</strong></th>
<th style="width: 493px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 144px;">domain</td>
<td style="width: 493px;">The domain name to see security information for (e.g., www.cnn.com)</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 379px;"><strong>Path</strong></th>
<th style="width: 60px;"><strong>Type</strong></th>
<th style="width: 269px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 379px;">Umbrella.DomainDetails.Domain</td>
<td style="width: 60px;">string</td>
<td style="width: 269px;">Domain name</td>
</tr>
<tr>
<td style="width: 379px;">Umbrella.DomainDetails.Data.DGA</td>
<td style="width: 60px;">string</td>
<td style="width: 269px;">Domain Generation Algorithm. This score is generated based on the likeliness of the domain name being generated by an algorithm rather than a human. This score ranges from -100 (suspicious) to 0 (benign).</td>
</tr>
<tr>
<td style="width: 379px;">Umbrella.DomainDetails.Data.Entropy</td>
<td style="width: 60px;">number</td>
<td style="width: 269px;">The number of bits required to encode the domain name, as a score. This score is to be used in conjunction with DGA and Perplexity.</td>
</tr>
<tr>
<td style="width: 379px;">Umbrella.DomainDetails.Data.SecureRank </td>
<td style="width: 60px;">number</td>
<td style="width: 269px;">Suspicious rank for a domain that reviews based on the lookup behavior of client IP for the domain. Securerank is designed to identify hostnames requested by known infected clients but never requested by clean clients, assuming these domains are more likely to be bad. Scores returned range from -100 (suspicious) to 100 (benign).</td>
</tr>
<tr>
<td style="width: 379px;">Umbrella.DomainDetails.Data.PrefixScore</td>
<td style="width: 60px;">number</td>
<td style="width: 269px;">Prefix ranks domains given their IP prefixes (an IP prefix is the first three octets in an IP address) and the reputation score of these prefixes. Ranges from -100 to 0, -100 being very suspicious.</td>
</tr>
<tr>
<td style="width: 379px;">Umbrella.DomainDetails.Data.RipScore</td>
<td style="width: 60px;">number</td>
<td style="width: 269px;">RIP ranks domains given their IP addresses and the reputation score of these IP addresses. Ranges from -100 to 0, -100 being very suspicious.</td>
</tr>
<tr>
<td style="width: 379px;">Umbrella.DomainDetails.Data.Popularity</td>
<td style="width: 60px;">number</td>
<td style="width: 269px;">The number of unique client IPs visiting this site, relative to the all requests to all sites. A score of how many different client/unique IPs go to this domain compared to others.</td>
</tr>
<tr>
<td style="width: 379px;">Umbrella.DomainDetails.Data.Geodiversity</td>
<td style="width: 60px;">number</td>
<td style="width: 269px;">A score representing the number of queries from clients visiting the domain, broken down by country. Score is a non-normalized ratio between 0 and 1.</td>
</tr>
<tr>
<td style="width: 379px;">Umbrella.DomainDetails.Data.TldGeodiversity</td>
<td style="width: 60px;">number</td>
<td style="width: 269px;">A score that represents the TLD country code geodiversity as a percentage of clients visiting the domain. Occurs most often with domains that have a ccTLD. Score is normalized ratio between 0 and 1.</td>
</tr>
<tr>
<td style="width: 379px;">Umbrella.DomainDetails.Data.KolmogorovSmirnovTest</td>
<td style="width: 60px;">number</td>
<td style="width: 269px;">Kolmogorov–Smirnov test on geodiversity. 0 means that the client traffic matches what is expected for this TLD.</td>
</tr>
<tr>
<td style="width: 379px;">DBotScore.Indicator</td>
<td style="width: 60px;">string</td>
<td style="width: 269px;">The Indicator</td>
</tr>
<tr>
<td style="width: 379px;">DBotScore.Score</td>
<td style="width: 60px;">number</td>
<td style="width: 269px;">The DBot score</td>
</tr>
<tr>
<td style="width: 379px;">DBotScore.Type</td>
<td style="width: 60px;">string</td>
<td style="width: 269px;">The Indicator type</td>
</tr>
<tr>
<td style="width: 379px;">DBotScore.Vendor</td>
<td style="width: 60px;">string</td>
<td style="width: 269px;">The DBot score vendor</td>
</tr>
<tr>
<td style="width: 379px;">Domain.Malicious.Vendor</td>
<td style="width: 60px;">string</td>
<td style="width: 269px;">For malicious domains, the vendor that made the decision</td>
</tr>
<tr>
<td style="width: 379px;">Domain.Malicious.Description</td>
<td style="width: 60px;">string</td>
<td style="width: 269px;">For malicious domains, the reason for the vendor to make the decision</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!umbrella-get-domain-details domain=cnn.com</pre>
<h5>Context Example</h5>
<p>DBotScore:{} 4 items<br> Indicator:cnn.com<br> Score:1<br> Type:Domain<br> Vendor:Cisco Umbrella<br> Umbrella:{} 1 item<br> DomainDetails:{} 2 items<br> Data:{} 13 items<br> PrefixScore:-0.01103978469603726<br> Geoscore:0<br> Perplexity:0.13991232622025684<br> Securerank:86.5019890432578<br> Entropy:0.9182958340544894<br> AttackName:<br> ThreatType:<br> Popularity:100<br> ASNScore:-0.033617132988484844<br> RIPScore:0<br> Pagerank:39.26072<br> KolmogorovSmirnovTest:0<br> DGA:0<br> Domain:cnn.com</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46916516-7b103700-cfc4-11e8-9a66-9582910c62a4.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46916516-7b103700-cfc4-11e8-9a66-9582910c62a4.png" alt="image" width="751" height="293"></a></p>
<h3 id="h_93157940570611539678559957">14. Get domains associated with registrar email addresses</h3>
<hr>
<p>Returns the domains associated with the email addresses of the registrar that are looked up.</p>
<h5>Base Command</h5>
<p><code>umbrella-get-domains-for-email-registrar</code></p>
<h5>Input</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 137px;"><strong>Argument Name</strong></th>
<th style="width: 500px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 137px;">emails</td>
<td style="width: 500px;">Email address following rfc5322 conventions. (e.g. : <a href="mailto:admin@google.com">admin@google.com</a>) Comma separated list allowed. (e.g. : <a href="mailto:admin@google.com">admin@google.com</a>, <a href="mailto:dns-admin@google.com">dns-admin@google.com</a>, <a href="mailto:hostmaster@charter.com">hostmaster@charter.com</a>)</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 137px;">offset</td>
<td style="width: 500px;">For paging with offset for domains with more than 500 results, set the url-param limit. Default value is 10.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">sort</td>
<td style="width: 500px;">To sort the list of domains based on timestamp. By default, domains are simply sorted by name in alphabetical order. Possible values are: ""created"", ""updated"", and ""expired"", each of which sorts from the most recent date for the value of the WHOIS entry.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">limit</td>
<td style="width: 500px;">To limit the total number of results (domains).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 487px;"><strong>Path</strong></th>
<th style="width: 62px;"><strong>Type</strong></th>
<th style="width: 159px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 487px;">Umbrella.AssociatedDomains.Email</td>
<td style="width: 62px;">string</td>
<td style="width: 159px;">Email address</td>
</tr>
<tr>
<td style="width: 487px;">Umbrella.AssociatedDomains.Data.TotalResults</td>
<td style="width: 62px;">number</td>
<td style="width: 159px;">Total number of results for this email.</td>
</tr>
<tr>
<td style="width: 487px;">Umbrella.AssociatedDomains.Data.MoreDataAvailable</td>
<td style="width: 62px;">boolean</td>
<td style="width: 159px;">Whether or not there are more than 500 results for this email, either yes or no.</td>
</tr>
<tr>
<td style="width: 487px;">Umbrella.AssociatedDomains.Data.ResultLimit</td>
<td style="width: 62px;">number</td>
<td style="width: 159px;">Total number of results for this page of results, default 500.</td>
</tr>
<tr>
<td style="width: 487px;">Umbrella.AssociatedDomains.Data.Domains.Name</td>
<td style="width: 62px;">string</td>
<td style="width: 159px;">Domains registered by this email</td>
</tr>
<tr>
<td style="width: 487px;">Umbrella.AssociatedDomains.Data.Domains.Name.SecurityCategories</td>
<td style="width: 62px;">string</td>
<td style="width: 159px;">Security Categories associated with the domain.</td>
</tr>
<tr>
<td style="width: 487px;">Umbrella.AssociatedDomains.Data.Domains.Name.ContentCategories</td>
<td style="width: 62px;">string</td>
<td style="width: 159px;">Content Categories associated with the domain.</td>
</tr>
<tr>
<td style="width: 487px;">Umbrella.AssociatedDomains.Data.Domains.LastObserved</td>
<td style="width: 62px;">string</td>
<td style="width: 159px;">Whether the domain is current, meaning currently registered by this email address. Values : Past or Current</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!umbrella-get-domains-for-email-registrar emails=<a href="mailto:dns@google.com">dns@google.com</a></pre>
<h5>Context Example</h5>
<p>Umbrella:{} 1 item<br> AssociatedDomains:{} 2 items<br> Data:[] 1 item<br> 0:{} 4 items<br> Domains:[] 2 items<br> 0:{} 4 items<br> Content Categories:[] 0 items<br> Is Current:true<br> Name:careersgoogle.com<br> Security Categories:[] 0 items<br> 1:{} 4 items<br> Content Categories:[] 0 items<br> Is Current:true<br> Name:chronweb.com<br> Security Categories:[] 0 items<br> MoreDataAvailable:false<br> ResultLimit:500<br> TotalResults:2<br> Email:<a href="mailto:dns@google.com">dns@google.com</a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46916546-be6aa580-cfc4-11e8-972e-6f65297b4dda.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46916546-be6aa580-cfc4-11e8-972e-6f65297b4dda.png" alt="image" width="753" height="267"></a></p>
<h3 id="h_41869273074261539678731403">15. Get all domains for a nameserver</h3>
<hr>
<p>Get all domains registered by a specified nameserver. In a query, you can search against a single nameserver or multiple nameservers.</p>
<h5>Base Command</h5>
<p><code>umbrella-get-domains-for-nameserver</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 131px;"><strong>Argument Name</strong></th>
<th style="width: 506px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 131px;">nameservers</td>
<td style="width: 506px;">Domain name of the Nameserver (e.g., ns2.google.com) Comma separated list allowed. (e.g. : ns2.google.com, ns1.google.com)</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 131px;">offset</td>
<td style="width: 506px;">For paging with offset for domains with more than 500 results, set the url-param limit. Default value is 10.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">sort</td>
<td style="width: 506px;">"To sort the list of domains based on timestamp. By default, domains are simply sorted by name in alphabetical order. Possible values are: ""created"", ""updated"", and ""expired"", each of which sorts from the most recent date for the value of the WHOIS entry."</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">limit</td>
<td style="width: 506px;">To limit the total number of results (domains).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 488px;"><strong>Path</strong></th>
<th style="width: 61px;"><strong>Type</strong></th>
<th style="width: 159px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 488px;">Umbrella.AssociatedDomains.Nameserver</td>
<td style="width: 61px;">string</td>
<td style="width: 159px;">Nameserver's domain name.</td>
</tr>
<tr>
<td style="width: 488px;">Umbrella.AssociatedDomains.Data.TotalResults</td>
<td style="width: 61px;">string</td>
<td style="width: 159px;">Total number of results for this nameserver domain name.</td>
</tr>
<tr>
<td style="width: 488px;">Umbrella.AssociatedDomains.Data.MoreDataAvailable</td>
<td style="width: 61px;">boolean</td>
<td style="width: 159px;">Whether or not there are more than 500 results for this email, either yes or no.</td>
</tr>
<tr>
<td style="width: 488px;">Umbrella.AssociatedDomains.Data.ResultLimit</td>
<td style="width: 61px;">number</td>
<td style="width: 159px;">Total number of results for this page of results, default 500.</td>
</tr>
<tr>
<td style="width: 488px;">Umbrella.AssociatedDomains.Data.Domains.Name</td>
<td style="width: 61px;">string</td>
<td style="width: 159px;">Domains registered by this nameserver.</td>
</tr>
<tr>
<td style="width: 488px;">Umbrella.AssociatedDomains.Data.Domains.Name.SecurityCategories</td>
<td style="width: 61px;">string</td>
<td style="width: 159px;">Security Categories associated with the domain.</td>
</tr>
<tr>
<td style="width: 488px;">Umbrella.AssociatedDomains.Data.Domains.Name.ContentCategories</td>
<td style="width: 61px;">string</td>
<td style="width: 159px;">Content Categories associated with the domain.</td>
</tr>
<tr>
<td style="width: 488px;">Umbrella.AssociatedDomains.Data.Domains.LastObserved</td>
<td style="width: 61px;">string</td>
<td style="width: 159px;">Whether the domain is current, meaning currently registered by this email address. Values : Past or Current</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!umbrella-get-domains-for-nameserver nameservers=ns1.google.com limit=2</pre>
<h5>Context Example</h5>
<p>Umbrella:{} 1 item<br> AssociatedDomains:{} 2 items<br> Data:[] 1 item<br> 0:{} 4 items<br> Domains:[] 2 items<br> 0:{} 4 items<br> Content Categories:[] 0 items<br> Is Current:false<br> Name:googlerightsflow.net<br> Security Categories:[] 0 items<br> 1:{} 4 items<br> Content Categories:[] 0 items<br> Is Current:true<br> Name:mycloudaudit.net<br> Security Categories:[] 0 items<br> MoreDataAvailable:true<br> ResultLimit:2<br> TotalResults:2<br> Nameserver:ns1.google.com</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46916586-5cf70680-cfc5-11e8-967f-5f62ad9f084f.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46916586-5cf70680-cfc5-11e8-967f-5f62ad9f084f.png" alt="image" width="750" height="271"></a></p>
<h3 id="h_17814194977891539678785713">16. Get WHOIS data for a domain</h3>
<hr>
<p>Return a standard WHOIS response record for a single domain with all available WHOIS data returned. </p>
<h5>Base Command</h5>
<p><code>umbrella-get-whois-for-domain</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 164px;"><strong>Argument Name</strong></th>
<th style="width: 473px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 164px;">domain</td>
<td style="width: 473px;">Domain name, including TLD, and excluding wildcards (e.g., www.cnn.com)</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 392px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 253px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 392px;">Umbrella.WHOIS.Domain</td>
<td style="width: 63px;">string</td>
<td style="width: 253px;">Domain name</td>
</tr>
<tr>
<td style="width: 392px;">Umbrella.WHOIS.Data.RegistrarName</td>
<td style="width: 63px;">string</td>
<td style="width: 253px;">Domain registrar name</td>
</tr>
<tr>
<td style="width: 392px;">Umbrella.WHOIS.Data.LastRetrieved</td>
<td style="width: 63px;">string</td>
<td style="width: 253px;">Domain last retrieved date</td>
</tr>
<tr>
<td style="width: 392px;">Umbrella.WHOIS.Data.Created</td>
<td style="width: 63px;">string</td>
<td style="width: 253px;">Domain created date</td>
</tr>
<tr>
<td style="width: 392px;">Umbrella.WHOIS.Data.Updated</td>
<td style="width: 63px;">string</td>
<td style="width: 253px;">Domain updated date</td>
</tr>
<tr>
<td style="width: 392px;">Umbrella.WHOIS.Data.Expires</td>
<td style="width: 63px;">string</td>
<td style="width: 253px;">Domain expiry date</td>
</tr>
<tr>
<td style="width: 392px;">Umbrella.WHOIS.Data.IANAID</td>
<td style="width: 63px;">string</td>
<td style="width: 253px;">IANA ID</td>
</tr>
<tr>
<td style="width: 392px;">Umbrella.WHOIS.Data.LastObserved</td>
<td style="width: 63px;">string</td>
<td style="width: 253px;">Domain last observed</td>
</tr>
<tr>
<td style="width: 392px;">Umbrella.WHOIS.Data.Nameservers.Name</td>
<td style="width: 63px;">string</td>
<td style="width: 253px;">Domain's name servers</td>
</tr>
<tr>
<td style="width: 392px;">Umbrella.WHOIS.Data.Emails.Name</td>
<td style="width: 63px;">string</td>
<td style="width: 253px;">Domain's email</td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.Admin.Country</span></td>
<td style="width: 59px;">string</td>
<td style="width: 393px;">The country of the domain administrator.</td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.Admin.Email</span></td>
<td style="width: 59px;">string</td>
<td style="width: 393px;">The email address of the domain administrator.</td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.Admin.Name</span></td>
<td style="width: 59px;">string</td>
<td style="width: 393px;">The name of the domain administrator.</td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.Admin.Phone</span></td>
<td style="width: 59px;">string</td>
<td style="width: 393px;">The phone number of the domain administrator.</td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.Registrant.Country</span></td>
<td style="width: 59px;">string</td>
<td style="width: 393px;"><span>The country of the registrant.</span></td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.Registrant.Email</span></td>
<td style="width: 59px;">string</td>
<td style="width: 393px;"><span>The email address of the registrant.</span></td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.Registrant.Name</span></td>
<td style="width: 59px;">string</td>
<td style="width: 393px;"><span>The name of the registrant.</span></td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.Registrant.Phone</span></td>
<td style="width: 59px;">string</td>
<td style="width: 393px;"><span>The phone number of the registrant.</span></td>
</tr>
<tr>
<td style="width: 256px;"> <span>Domain.CreationDate</span>
</td>
<td style="width: 59px;">date</td>
<td style="width: 393px;"><span>The date on which the domain was created.</span></td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.DomainStatus</span></td>
<td style="width: 59px;">string</td>
<td style="width: 393px;"><span>The status of the domain.</span></td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.UpdatedDate</span></td>
<td style="width: 59px;">date</td>
<td style="width: 393px;"><span>The date on which the domain was last updated.</span></td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.ExpirationDate</span></td>
<td style="width: 59px;">date</td>
<td style="width: 393px;"><span>The expiration date of the domain.</span></td>
</tr>
<tr>
<td style="width: 256px;"><span>Domain.Registrar.Name</span></td>
<td style="width: 59px;">string</td>
<td style="width: 393px;"><span>The name of the registrar, such as "GoDaddy".</span></td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!umbrella-get-whois-for-domain domain=cnn.com</pre>
<h5>Context Example</h5>
<p>Umbrella:{} 1 item<br> WHOIS:{} 2 items<br> Data:{} 10 items<br> Nameservers:[] 4 items<br> 0:ns-1086.awsdns-07.org<br> 1:ns-1630.awsdns-11.co.uk<br> 2:ns-47.awsdns-05.com<br> 3:ns-576.awsdns-08.net<br> IANAID:299<br> Created:1993-09-22<br> Name:cnn.com<br> LastRetrieved:1537481654499<br> Expires:2026-09-21<br> Emails:[] 2 items<br> 0:<a href="mailto:example.gmail.com">example.gmail.com</a><br> 1:<a href="mailto:example.gmail.com">example.gmail.com</a><br> RegistrarName:CSC CORPORATE DOMAINS, INC.<br> Updated:2018-04-10<br> LastObserved:2018-09-20 16:53:49.000 UTC<br> Domain:cnn.com</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46916628-d131aa00-cfc5-11e8-8661-33f6a8e3105a.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46916628-d131aa00-cfc5-11e8-8661-33f6a8e3105a.png" alt="image" width="751" height="506"></a></p>
<h3 id="h_3979943983261539679228550">17. Get malicious domains associated with an IP address</h3>
<hr>
<p>Returns a list of malicious domains associated with the specified IP address.</p>
<h5>Base Command</h5>
<p><code>umbrella-get-malicious-domains-for-ip</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 177px;"><strong>Argument Name</strong></th>
<th style="width: 428px;"><strong>Description</strong></th>
<th style="width: 103px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 177px;">ip</td>
<td style="width: 428px;">IP address to check for malicious domains</td>
<td style="width: 103px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 364px;"><strong>Path</strong></th>
<th style="width: 47px;"><strong>Type</strong></th>
<th style="width: 297px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 364px;">Umbrella.MaliciousDomains.IP</td>
<td style="width: 47px;">string</td>
<td style="width: 297px;">IP address</td>
</tr>
<tr>
<td style="width: 364px;">Umbrella.MaliciousDomains.Data.Name</td>
<td style="width: 47px;">string</td>
<td style="width: 297px;">The block list domain associated with the IP</td>
</tr>
<tr>
<td style="width: 364px;">Umbrella.MaliciousDomains.Data.LastObserved</td>
<td style="width: 47px;">string</td>
<td style="width: 297px;">Whether the domain is current, meaning currently registered by this email address (Values: <em><strong>Past</strong></em> or <em><strong>Current</strong></em>)</td>
</tr>
<tr>
<td style="width: 364px;">Umbrella.MaliciousDomains.Data.MalwareCategories</td>
<td style="width: 47px;">string</td>
<td style="width: 297px;">Security categories associated with the domain.</td>
</tr>
<tr>
<td style="width: 364px;">Umbrella.MaliciousDomains.Data.ContentCategories</td>
<td style="width: 47px;">string</td>
<td style="width: 297px;">Content categories associated with the domain</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!umbrella-get-malicious-domains-for-ip ip=8.8.8.8</pre>
<h5>Context Example</h5>
<p>DBotScore:[] 52 items<br> 0:{} 4 items<br> Indicator:bo1aa21.com<br> Score:3<br> Type:Domain<br> Vendor:Cisco Umbrella<br> 1:{} 4 items<br> Indicator:z015.mypsx.net<br> Score:3<br> Type:Domain<br> Vendor:Cisco Umbrella<br> Domain:[] 52 items<br> 0:{} 2 items<br> Malicious:{} 2 items<br> Description:For IP 8.8.8.8<br> Vendor:Cisco Umbrella<br> Name:bo1aa21.com<br> 1:{} 2 items<br> Malicious:{} 2 items<br> Description:For IP 8.8.8.8<br> Vendor:Cisco Umbrella<br> Name:z015.mypsx.net<br> Umbrella:{} 1 item<br> MaliciousDomains:{} 2 items<br> Data:[] 52 items<br> 0:{} 3 items<br> ContentCategories:[] 0 items<br> MalwareCategories:[] 1 item<br> 0:Command and Control<br> Name:bo1aa21.com<br> 1:{} 3 items<br> ContentCategories:[] 1 item<br> 0:Infrastructure<br> MalwareCategories:[] 1 item<br> 0:Malware<br> Name:z015.mypsx.net</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46916774-c0823380-cfc7-11e8-9c81-8668e9470600.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46916774-c0823380-cfc7-11e8-9c81-8668e9470600.png" alt="image" width="750" height="507"></a></p>
<h3 id="h_27395371286851539680187187">18. Get a list of domains that match a regular expression (regex)</h3>
<hr>
<p>Get a list of domains that match a regular expression (regex).</p>
<h5>Base Command</h5>
<p><code>umbrella-get-domains-using-regex</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 143px;"><strong>Argument Name</strong></th>
<th style="width: 494px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 143px;">expression</td>
<td style="width: 494px;">A standard RegEx search pattern, must be encoded in a double quoted bracket.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 143px;">start</td>
<td style="width: 494px;">Can either be specified in relative or absolute time. Point in time in the past, expressed as a timestamp in the following format or relative time. Valid formats: start=-2days start=-2hours start=-1000minutes start=-3weeks start=1997-07-16T19:20:30+01:00 i.e YYYY-MM-DDThh:mm:ssTZD Note the negative sign for relative time. Max is -30days.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 143px;">includeCategory</td>
<td style="width: 494px;">Default is false, if set to true this will include security categories in the results and may slow the return times.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">stop</td>
<td style="width: 494px;">The exclusive end time in milliseconds absolute or relative time (eg: 'now', '-2days','1997-07-16T19:20:30+01:00') for a query.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">limit</td>
<td style="width: 494px;">The maximum number of items to return - combine with offset for result pagination</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">type</td>
<td style="width: 494px;">Search database node type (URL, IP, HOST).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 276px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 373px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 276px;">Umbrella.DomainSearch.TotalResults</td>
<td style="width: 59px;">number</td>
<td style="width: 373px;">Total results from this search string. The default number of results is 100 and can be expanded using the limit parameter. </td>
</tr>
<tr>
<td style="width: 276px;">Umbrella.DomainSearch.Data.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 373px;">Name of the domain found</td>
</tr>
<tr>
<td style="width: 276px;">Umbrella.DomainSearch.Data.FirstSeen</td>
<td style="width: 59px;">string</td>
<td style="width: 373px;">Date the first time the domain was first seen</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!umbrella-get-domains-using-regex expression=googleapis.*.com limit=2</pre>
<h5>Context Example</h5>
<p>Umbrella:{} 1 item<br> DomainSearch:{} 3 items<br> Data:[] 2 items<br> 0:{} 2 items<br> FirstSeen:1539042240000<br> Name:googleapis.com.nauticaintegral.com<br> 1:{} 2 items<br> FirstSeen:1539244920000<br> Name:googleapis.com.sanpada.com<br> Expression:googleapis.*.com<br> TotalResults:2</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46917196-b6166880-cfcc-11e8-8e3d-ccc9dd2583d1.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46917196-b6166880-cfcc-11e8-8e3d-ccc9dd2583d1.png" alt="image" width="750" height="471"></a></p>
<h3 id="h_67454363090421539680195481">19. Query when a domain was attributed to a security category or as a threat type</h3>
<hr>
<p>Shows when a domain was attributed to a particular security categorization or threat type (indicators of compromise).</p>
<h5>Base Command</h5>
<p><code>umbrella-get-domain-timeline</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 149px;"><strong>Argument Name</strong></th>
<th style="width: 488px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 149px;">domain</td>
<td style="width: 488px;">The domain name to see the timeline for (e.g., www.cnn.com)</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 296px;"><strong>Path</strong></th>
<th style="width: 49px;"><strong>Type</strong></th>
<th style="width: 363px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 296px;">Umbrella.Timeline.Domain</td>
<td style="width: 49px;">string</td>
<td style="width: 363px;">Domain name</td>
</tr>
<tr>
<td style="width: 296px;">Umbrella.Timeline.Data.MalwareCategories</td>
<td style="width: 49px;">string</td>
<td style="width: 363px;">Which Umbrella security category, if any, matched the input</td>
</tr>
<tr>
<td style="width: 296px;">Umbrella.Timeline.Data.Attacks</td>
<td style="width: 49px;">string</td>
<td style="width: 363px;">Which named attacks, if any, matched the input</td>
</tr>
<tr>
<td style="width: 296px;">Umbrella.Timeline.Data.ThreatTypes</td>
<td style="width: 49px;">string</td>
<td style="width: 363px;">Which threat type, if any, matched in the input.</td>
</tr>
<tr>
<td style="width: 296px;">Umbrella.Timeline.Data.Timestamp</td>
<td style="width: 49px;">string</td>
<td style="width: 363px;">The time when the attribution for this Domain changed. </td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!umbrella-get-domain-timeline domain=cosmos.furnipict.com</pre>
<h5>Context Example</h5>
<p>Umbrella:{} 1 item<br> Timeline:{} 2 items<br> Data:[] 4 items<br> 0:{} 4 items<br> Attacks:[] 1 item<br> 0:Neutrino<br> MalwareCategories:[] 1 item<br> 0:Malware<br> ThreatTypes:[] 1 item<br> 0:Exploit Kit<br> Timestamp:2017-10-21T19:30:33<br> 1:{} 4 items<br> Attacks:[] 1 item<br> 0:Neutrino<br> MalwareCategories:[] 2 items<br> 0:Dynamic DNS<br> 1:Malware<br> ThreatTypes:[] 1 item<br> 0:Exploit Kit<br> Timestamp:2016-10-21T17:22:03<br> 2:{} 4 items<br> Attacks:[] 1 item<br> 0:Neutrino<br> MalwareCategories:[] 1 item<br> 0:Malware<br> ThreatTypes:[] 1 item<br> 0:Exploit Kit<br> Timestamp:2016-07-11T18:12:06<br> 3:{} 4 items<br> Attacks:[] 0 items<br> MalwareCategories:[] 0 items<br> ThreatTypes:[] 0 items<br> Timestamp:2016-07-09T03:49:08<br> Domain:cosmos.furnipict.com</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46917220-0f7e9780-cfcd-11e8-8b5e-4252c6a93a7e.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46917220-0f7e9780-cfcd-11e8-8b5e-4252c6a93a7e.png" alt="image" width="750" height="357"></a></p>
<h3 id="h_84751396693971539680297675">20. Query when an IP address was attributed to a security organization or as a threat type</h3>
<hr>
<p>Shows when an IP was attributed to a particular security categorization or threat type (indicators of compromise).</p>
<h5>Base Command</h5>
<p><code>umbrella-get-ip-timeline</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 168px;"><strong>Argument Name</strong></th>
<th style="width: 451px;"><strong>Description</strong></th>
<th style="width: 89px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 168px;">ip</td>
<td style="width: 451px;">The IP to see the timeline for (e.g., 8.8.8.8)</td>
<td style="width: 89px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 298px;"><strong>Path</strong></th>
<th style="width: 47px;"><strong>Type</strong></th>
<th style="width: 363px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 298px;">Umbrella.Timeline.IP</td>
<td style="width: 47px;">string</td>
<td style="width: 363px;">IP address</td>
</tr>
<tr>
<td style="width: 298px;">Umbrella.Timeline.Data.MalwareCategories</td>
<td style="width: 47px;">string</td>
<td style="width: 363px;">Which Umbrella security category, if any, matched the input</td>
</tr>
<tr>
<td style="width: 298px;">Umbrella.Timeline.Data.Attacks</td>
<td style="width: 47px;">string</td>
<td style="width: 363px;">Which named attacks, if any, matched the inputWhich threat type, if any, matched in the input.</td>
</tr>
<tr>
<td style="width: 298px;">Umbrella.Timeline.Data.ThreatTypes</td>
<td style="width: 47px;">string</td>
<td style="width: 363px;">Which threat type, if any, matched in the input.</td>
</tr>
<tr>
<td style="width: 298px;">Umbrella.Timeline.Data.Timestamp</td>
<td style="width: 47px;">string</td>
<td style="width: 363px;">The time when the attribution for this IP changed. </td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!umbrella-get-ip-timeline ip=1.2.3.4</pre>
<h5>Context Example</h5>
<p>Umbrella:{} 1 item<br> Timeline:{} 2 items<br> Data:[] 1 item<br> 0:{} 4 items<br> Attacks:[] 0 items<br> MalwareCategories:[] 0 items<br> ThreatTypes:[] 0 items<br> Timestamp:2018-05-31T20:48:59<br> IP:1.2.3.4</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46917241-58cee700-cfcd-11e8-8d4b-91e9d49005f8.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46917241-58cee700-cfcd-11e8-8d4b-91e9d49005f8.png" alt="image" width="749" height="251"></a></p>
<h3 id="h_79786501397501539680422818">21. Query when a URL was attributed to a security organization or as a threat type</h3>
<hr>
<p>Shows when a URL was attributed to a particular security categorization or threat type (indicators of compromise).</p>
<h5>Base Command</h5>
<p><code>umbrella-get-url-timeline</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 132px;"><strong>Argument Name</strong></th>
<th style="width: 504px;"><strong>Description</strong></th>
<th style="width: 72px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 132px;">url</td>
<td style="width: 504px;">The URL to see the timeline for (e.g., www.aws.amazon.com)</td>
<td style="width: 72px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 299px;"><strong>Path</strong></th>
<th style="width: 46px;"><strong>Type</strong></th>
<th style="width: 363px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 299px;">Umbrella.Timeline.URL</td>
<td style="width: 46px;">string</td>
<td style="width: 363px;">URL value</td>
</tr>
<tr>
<td style="width: 299px;">Umbrella.Timeline.Data.MalwareCategories</td>
<td style="width: 46px;">string</td>
<td style="width: 363px;">Umbrella security category that matches the the URL</td>
</tr>
<tr>
<td style="width: 299px;">Umbrella.Timeline.Data.Attacks</td>
<td style="width: 46px;">string</td>
<td style="width: 363px;">Which named attacks, if any, matched the input</td>
</tr>
<tr>
<td style="width: 299px;">Umbrella.Timeline.Data.ThreatTypes</td>
<td style="width: 46px;">string</td>
<td style="width: 363px;">Which threat type, if any, matched in the input.</td>
</tr>
<tr>
<td style="width: 299px;">Umbrella.Timeline.Data.Timestamp</td>
<td style="width: 46px;">date</td>
<td style="width: 363px;">The time when the attribution for this URL changed. </td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!umbrella-get-url-timeline url=httpx://gauttam.com/wp-includes/</pre>
<h5>Context Example</h5>
<p>Umbrella:{} 1 item<br> Timeline:{} 2 items<br> Data:[] 1 item<br> 0:{} 4 items<br> Attacks:[] 0 items<br> MalwareCategories:[] 1 item<br> 0:Malware<br> ThreatTypes:[] 0 items<br> Timestamp:2018-08-21T13:21:55<br> URL:httpx://gauttam.com/wp-includes/</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/12241410/46917266-a64b5400-cfcd-11e8-9aaf-277c50fd8f02.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/12241410/46917266-a64b5400-cfcd-11e8-9aaf-277c50fd8f02.png" alt="image" width="750" height="288"></a></p>
