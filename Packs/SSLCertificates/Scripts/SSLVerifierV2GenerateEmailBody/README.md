This automation utilizes the outputs of the !SSLVerifierV2 and !SSLVerifierV2_ParseOutput automation scripts and produces a nicely formatted block of HTML that can be used for sending status report emails.

This script requires previous use of the !SSLVerifierV2 and !SSLVerifierV2_ParseOutput automations. See the "Order of operations" section of the content pack readme. 

**Automation Input:**

**NONE**

**Automation Output:**

Context Key: SSLReport.HTML - The raw HTML code for the status report. 

**Sample Output:** 

    <html>
	<head>
		<style>
			p {
				text-align: center;
			}
			h1 {
				text-align: center;
				color: #ff0000;
			}
			h2 {
				text-align: center;
				color: #ff0000;
			}
			h3 {
				text-align: center;
				color: #000000;
				font-weight: bold;
				font-size: 1.5em;
				text-decoration: underline;
			}</style></head>
	<body>
		<h3>
			SSL Certificate Report for 2023/02/17
		</h3>
		<p>
			<span>
				<h1>EXPIRED CERTIFICATES</h1>
			</span>
		</p>
		<table style="border-collapse: collapse; width: 100%;" border="1">
			<tbody>
				<tr><td style="width: 33.3333%; text-align: center;"><strong>Site/Domain/IP</strong></td><td style="width: 33.3333%; text-align: center;"><strong>Expiration Date</strong></td><td style="width: 33.3333%; text-align: center;"><strong>Days Expired</strong></td></tr>
				<tr>
					<td style="text-align: center;">expired.badssl.com</td>
					<td style="text-align: center;">2015/04/12 - 23:59:59</td>
					<td style="text-align: center;">-2868 days</td>
				</tr>
				<tr>
					<td style="text-align: center;">expired-rsa-dv.ssl.com</td>
					<td style="text-align: center;">2016/08/02 - 20:48:30</td>
					<td style="text-align: center;">-2390 days</td>
				</tr>
			</tbody>
		</table>
		<p>
			<span>
				<h2>Certificates expiring in 90 days or less</h2>
			</span>
		</p>
		<table style="border-collapse: collapse; width: 100%;" border="1">
			<tbody>
				<tr><td style="width: 33.3333%; text-align: center;"><strong>Site/Domain/IP</strong></td><td style="width: 33.3333%; text-align: center;"><strong>Expiration Date</strong></td><td style="width: 33.3333%; text-align: center;"><strong>Days to Expiration</strong></td></tr>
				<tr>
					<td style="text-align: center;">www.google.com</td>
					<td style="text-align: center;">2023/04/26 - 19:43:58</td>
					<td style="text-align: center;">68 days</td>
				</tr>
				<tr>
					<td style="text-align: center;">www.norton.com</td>
					<td style="text-align: center;">2023/03/10 - 23:59:59</td>
					<td style="text-align: center;">21 days</td>
				</tr>
			</tbody>
		</table>
		<p>
			<span style="color: #ff9900;">
				<strong>Certificates expiring between 91 and 180 days from today</strong>
			</span>
		</p>
		<table style="border-collapse: collapse; width: 100%;" border="1">
			<tbody>
				<tr><td style="width: 33.3333%; text-align: center;"><strong>Site/Domain/IP</strong></td><td style="width: 33.3333%; text-align: center;"><strong>Expiration Date</strong></td><td style="width: 33.3333%; text-align: center;"><strong>Days to Expiration</strong></td></tr>
				<tr>
					<td style="text-align: center;">www.sans.org</td>
					<td style="text-align: center;">2023/06/13 - 18:47:34</td>
					<td style="text-align: center;">116 days</td>
				</tr>
				<tr>
					<td style="text-align: center;">www.paloaltonetworks.com</td>
					<td style="text-align: center;">2023/07/26 - 23:59:59</td>
					<td style="text-align: center;">159 days</td>
				</tr>
			</tbody>
		</table>
		<p>
			<span style="color: #339966;">
				<strong>Certificates expiring more than 180 days from today</strong>
			</span>
		</p>
		<table style="border-collapse: collapse; width: 100%;" border="1">
			<tbody>
				<tr><td style="width: 33.3333%; text-align: center;"><strong>Site/Domain/IP</strong></td><td style="width: 33.3333%; text-align: center;"><strong>Expiration Date</strong></td><td style="width: 33.3333%; text-align: center;"><strong>Days to Expiration</strong></td></tr>
				<tr>
					<td style="text-align: center;">www.microsoft.com</td>
					<td style="text-align: center;">2023/09/29 - 23:23:11</td>
					<td style="text-align: center;">224 days</td>
				</tr>
				<tr>
					<td style="text-align: center;">www.chase.com</td>
					<td style="text-align: center;">2024/01/19 - 04:02:21</td>
					<td style="text-align: center;">335 days</td>
				</tr>
			</tbody>
		</table>
	</body>
	</html>


