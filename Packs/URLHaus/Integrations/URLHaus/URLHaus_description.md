## How DBot Score is Calculated

### URL
Determined by the status of the URL.
  <table>
    <tr>
    <th>Status</th>
    <th>DBotScore</th>
  </tr>
    <tr>
    <th>online</th>
    <th>Malicious</th>
  </tr>
    <tr>
    <th>offline</th>
    <th>Suspicious</th>
  </tr>
    <tr>
    <th>unknown</th>
    <th>Unknown</th>
  </tr>
    </table>

### Domain
Determined by the blacklist spamhaus_dbl/surbl of the Domain.
  <table>
    <tr>
    <th>Status</th>
    <th>DBotScore</th>
  </tr>
    <tr>
    <th>spammer_domain/ phishing_domain/ 
        botnet_cc_domain/ listed</th>
    <th>Malicious</th>
  </tr>
    <tr>
    <th>not listed</th>
    <th>Unknown</th>
  </tr>
    <tr>
    <th>-</th>
    <th>Benign</th>
  </tr>
    </table>

### File
Score is Malicious.
  <table>
    <tr>
    <th>Status</th>
    <th>DBotScore</th>
  </tr>
    <tr>
    <th>-</th>
    <th>Malicious</th>
  </tr>
    </table>