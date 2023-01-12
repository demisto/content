<p>
Use the S/MIME (Secure Multipurpose Internet Mail Extensions) integration to send and receive secure MIME data.

</p>
<h2>Use Cases</h2>
<ul>
<li>Send an S/MIME-signed message.</li>
<li>Send an S/MIME-encrypted message.</li>
<li>Send an S/MIME-signed and encrypted message.</li>
<li>Decrypt an S/MIME message</li>
</ul>

<h2>Usage</h2>
<p>
In order to send signed/encrypted messages using the S/MIME Messaging and Mail Sender (New) perform the following steps.
  
1. Run the required command in the S/MIME Messaging integration (e.g., `smime-sign-and-encrypt`).
2. Enter the output of the command executed from step 1 as the input for the `raw_message` argument of the `send-mail` command in the Mail Sender (New) integration (e.g. the value stored in the Context Data under `SMIME.SignedAndEncrypted.Message`).
3. Run the `send-mail` command with the `raw_message` argument (as described in step 2), with any of the optional arguments `to`, `cc` and `bcc` (e.g., `!send-mail to=user@email.com raw_message=${SMIME.SignedAndEncrypted.Message}`).
</p>

<h2>Configure SMIME Messaging on Cortex XSOAR</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for SMIME Messaging.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>Public Key</strong></li>
   <li><strong>Private Key</strong></li>
    </ul>
  </li>
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>
<h2>Commands</h2>
<p>
  You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li>smime-sign-email: smime-sign-email</li>
  <li>smime-encrypt-email-body: smime-encrypt-email-body</li>
  <li>smime-verify-sign: smime-verify-sign</li>
  <li>smime-decrypt-email-body: smime-decrypt-email-body</li>
  <li>smime-sign-and-encrypt: smime-sign-and-encrypt</li>
</ol>
<h3>1. smime-sign-email</h3>
<hr>
<p>Retrieves items from the service.</p>
<h5>Base Command</h5>
<p>
  <code>smime-sign-email</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>
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
      <td>message_body</td>
      <td>The message body to send.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>use_transport_encoding</td>
      <td>Set 'true' to use content transfer encoding.</td>
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
      <td>SMIME.Signed.Message</td>
      <td>String</td>
      <td>The signed message body.</td>
    </tr>
    <tr>
      <td>SMIME.Signed.Headers</td>
      <td>String</td>
      <td>The S/MIME signing headers.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!smime-sign-email message_body="Hello World"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "SMIME.Signed": {
        "Headers": "MIME-Version=1.0,Content-Type=multipart/signed; protocol=\"application/x-pkcs7-signature\"; micalg=\"sha1\"; boundary=\"----5DAD2A4AC7C108E6B3D263AADB9D2BDB\"",
        "Message": "MIME-Version: 1.0\nContent-Type: multipart/signed; protocol=\"application/x-pkcs7-signature\"; micalg=\"sha1\"; boundary=\"----5DAD2A4AC7C108E6B3D263AADB9D2BDB\"\n\nThis is an S/MIME signed message\n\n------5DAD2A4AC7C108E6B3D263AADB9D2BDB\nContent-Type: text/plain\r\n\r\nHello World\n------5DAD2A4AC7C108E6B3D263AADB9D2BDB\nContent-Type: application/x-pkcs7-signature; name=\"smime.p7s\"\nContent-Transfer-Encoding: base64\nContent-Disposition: attachment; filename=\"smime.p7s\"\n\nMIIGEQYJKoZIhvcNAQcCoIIGAjCCBf4CAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3\nDQEHAaCCA1wwggNYMIICQAIJAO117pJfuoxMMA0GCSqGSIb3DQEBCwUAMG4xCzAJ\nBgNVBAYTAklMMQ8wDQYDVQQIDAZJc3JhZWwxGzAZBgNVBAoMElBhbG8gYWx0byBu\nZXR3b3JrczExMC8GCSqGSIb3DQEJARYiYXZpc2hhaUBkZW1pc3RvZGV2Lm9ubWlj\ncm9zb2Z0LmNvbTAeFw0xOTEwMTcxOTMxMThaFw0yMDEwMTYxOTMxMThaMG4xCzAJ\nBgNVBAYTAklMMQ8wDQYDVQQIDAZJc3JhZWwxGzAZBgNVBAoMElBhbG8gYWx0byBu\nZXR3b3JrczExMC8GCSqGSIb3DQEJARYiYXZpc2hhaUBkZW1pc3RvZGV2Lm9ubWlj\ncm9zb2Z0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKOg9k/f\noKdoYZpVwxy6vdFEy7Bo7DLBHUf5WSmyO88kjtv2HGTZKPwCDbuZfi4643nkEtFp\nbPWFwIBbfICsOxdL6P4Oj1IOcVnIN0ohT7DEsgb69R5cD/p9n98P6R7DSws8fX1G\naXMExRazoVYFYmvLGrZT8bCXoqPsyuRSPiluxaQ15UILA9R0/ss5/P2tNZRZdsAT\naetY4hlktw1QR3Hv2LlbC0Sibni+6ZaaB5LR8gWF2J71Vb1YznV988FZwUZBTx2u\n0+Y1loKtEVQ1pf6T7wtLlJjoka97LP/53/UcLs7bihrKCVMpcr2noS4/HRM1aDf8\nyCpxEiZFXU2L6DMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAoUN9fLxDgwfHl+NF\nRsYuRU+vOT9zi6s82onsWbbyCzCpx0VH2casluOf/6591xVZjhhqOM/+/qYThp41\n79mq98Mu4jVuU/xumaP82KnBrORu8jTa3ZncUAQMiMeIY5lDcnpoF9QW4Lp55D3X\ncS8y+vlw9NB/4NG6C8+VOgvEaWzMlsRbrVQ5bb4/oz5TK2isLDQSK6p0bw54Lxwh\noZcUnORDd0c7kSlkzB3/E/u3h59WQ4nuPC0weOIQFdqRoqgqKLmwa4Ucw4FjU8eR\nMVhPj6DZc6qnPath2ynCJBwJlOXYh2Sy89eGGiKbFCveWYqV2f2XxXiCpvJOwQt8\nkgaddTGCAn0wggJ5AgEBMHswbjELMAkGA1UEBhMCSUwxDzANBgNVBAgMBklzcmFl\nbDEbMBkGA1UECgwSUGFsbyBhbHRvIG5ldHdvcmtzMTEwLwYJKoZIhvcNAQkBFiJh\ndmlzaGFpQGRlbWlzdG9kZXYub25taWNyb3NvZnQuY29tAgkA7XXukl+6jEwwCQYF\nKw4DAhoFAKCB2DAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ\nBTEPFw0xOTEwMjkwOTA0NTRaMCMGCSqGSIb3DQEJBDEWBBRTe/xmyOR/ymt0oatw\npHauxOm1STB5BgkqhkiG9w0BCQ8xbDBqMAsGCWCGSAFlAwQBKjALBglghkgBZQME\nARYwCwYJYIZIAWUDBAECMAoGCCqGSIb3DQMHMA4GCCqGSIb3DQMCAgIAgDANBggq\nhkiG9w0DAgIBQDAHBgUrDgMCBzANBggqhkiG9w0DAgIBKDANBgkqhkiG9w0BAQEF\nAASCAQCSXAiT+9rmR964OgTOWgebTU2KooxChBAoKUOWXJDi1/25uTjs8OJcrfDy\nN4OAGaP/mjfDEYbkEXMYC6lDcSErYdGGegACNURJlh+fIh3ZBrbdWnh8B672g9Zx\nFIDM7MxtDEdt9ScNAaqKiZCKsZlk4bcXGLK6oI8PUUsLupgUhdTiKHplKbrsUBC8\nJckJ+xSbRHP2dQTAYr0LW87lvVQgi05hmKecICuTDU3/qSqTZbh/ajQk7HHB9XtI\nPmizUK2s+F3OazeJx0IFpeEeK4YIVxV+tbYQkNrZTxwe7sKFkcyfiJ2QGcw8hzly\nfRciC1z2msLtmgPUH81DqLx+B+pY\n\n------5DAD2A4AC7C108E6B3D263AADB9D2BDB--\n\n"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
MIME-Version: 1.0
Content-Type: multipart/signed; protocol="application/x-pkcs7-signature"; micalg="sha1"; boundary="----5DAD2A4AC7C108E6B3D263AADB9D2BDB"

This is an S/MIME signed message

------5DAD2A4AC7C108E6B3D263AADB9D2BDB
Content-Type: text/plain

Hello World
------5DAD2A4AC7C108E6B3D263AADB9D2BDB
Content-Type: application/x-pkcs7-signature; name="smime.p7s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="smime.p7s"

MIIGEQYJKoZIhvcNAQcCoIIGAjCCBf4CAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3
DQEHAaCCA1wwggNYMIICQAIJAO117pJfuoxMMA0GCSqGSIb3DQEBCwUAMG4xCzAJ
BgNVBAYTAklMMQ8wDQYDVQQIDAZJc3JhZWwxGzAZBgNVBAoMElBhbG8gYWx0byBu
ZXR3b3JrczExMC8GCSqGSIb3DQEJARYiYXZpc2hhaUBkZW1pc3RvZGV2Lm9ubWlj
cm9zb2Z0LmNvbTAeFw0xOTEwMTcxOTMxMThaFw0yMDEwMTYxOTMxMThaMG4xCzAJ
BgNVBAYTAklMMQ8wDQYDVQQIDAZJc3JhZWwxGzAZBgNVBAoMElBhbG8gYWx0byBu
ZXR3b3JrczExMC8GCSqGSIb3DQEJARYiYXZpc2hhaUBkZW1pc3RvZGV2Lm9ubWlj
cm9zb2Z0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKOg9k/f
oKdoYZpVwxy6vdFEy7Bo7DLBHUf5WSmyO88kjtv2HGTZKPwCDbuZfi4643nkEtFp
bPWFwIBbfICsOxdL6P4Oj1IOcVnIN0ohT7DEsgb69R5cD/p9n98P6R7DSws8fX1G
aXMExRazoVYFYmvLGrZT8bCXoqPsyuRSPiluxaQ15UILA9R0/ss5/P2tNZRZdsAT
aetY4hlktw1QR3Hv2LlbC0Sibni+6ZaaB5LR8gWF2J71Vb1YznV988FZwUZBTx2u
0+Y1loKtEVQ1pf6T7wtLlJjoka97LP/53/UcLs7bihrKCVMpcr2noS4/HRM1aDf8
yCpxEiZFXU2L6DMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAoUN9fLxDgwfHl+NF
RsYuRU+vOT9zi6s82onsWbbyCzCpx0VH2casluOf/6591xVZjhhqOM/+/qYThp41
79mq98Mu4jVuU/xumaP82KnBrORu8jTa3ZncUAQMiMeIY5lDcnpoF9QW4Lp55D3X
cS8y+vlw9NB/4NG6C8+VOgvEaWzMlsRbrVQ5bb4/oz5TK2isLDQSK6p0bw54Lxwh
oZcUnORDd0c7kSlkzB3/E/u3h59WQ4nuPC0weOIQFdqRoqgqKLmwa4Ucw4FjU8eR
MVhPj6DZc6qnPath2ynCJBwJlOXYh2Sy89eGGiKbFCveWYqV2f2XxXiCpvJOwQt8
kgaddTGCAn0wggJ5AgEBMHswbjELMAkGA1UEBhMCSUwxDzANBgNVBAgMBklzcmFl
bDEbMBkGA1UECgwSUGFsbyBhbHRvIG5ldHdvcmtzMTEwLwYJKoZIhvcNAQkBFiJh
dmlzaGFpQGRlbWlzdG9kZXYub25taWNyb3NvZnQuY29tAgkA7XXukl+6jEwwCQYF
Kw4DAhoFAKCB2DAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
BTEPFw0xOTEwMjkwOTA0NTRaMCMGCSqGSIb3DQEJBDEWBBRTe/xmyOR/ymt0oatw
pHauxOm1STB5BgkqhkiG9w0BCQ8xbDBqMAsGCWCGSAFlAwQBKjALBglghkgBZQME
ARYwCwYJYIZIAWUDBAECMAoGCCqGSIb3DQMHMA4GCCqGSIb3DQMCAgIAgDANBggq
hkiG9w0DAgIBQDAHBgUrDgMCBzANBggqhkiG9w0DAgIBKDANBgkqhkiG9w0BAQEF
AASCAQCSXAiT+9rmR964OgTOWgebTU2KooxChBAoKUOWXJDi1/25uTjs8OJcrfDy
N4OAGaP/mjfDEYbkEXMYC6lDcSErYdGGegACNURJlh+fIh3ZBrbdWnh8B672g9Zx
FIDM7MxtDEdt9ScNAaqKiZCKsZlk4bcXGLK6oI8PUUsLupgUhdTiKHplKbrsUBC8
JckJ+xSbRHP2dQTAYr0LW87lvVQgi05hmKecICuTDU3/qSqTZbh/ajQk7HHB9XtI
PmizUK2s+F3OazeJx0IFpeEeK4YIVxV+tbYQkNrZTxwe7sKFkcyfiJ2QGcw8hzly
fRciC1z2msLtmgPUH81DqLx+B+pY

------5DAD2A4AC7C108E6B3D263AADB9D2BDB--
</p>
</p>

<h3>2. smime-encrypt-email-body</h3>
<hr>
<p>Encrypts an email message with S/MIME protocol by using a public RSA certificate.</p>
<h5>Base Command</h5>
<p>
  <code>smime-encrypt-email-body</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>
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
      <td>message</td>
      <td>The message body to encrypt.</td>
      <td>Required</td>
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
      <td>SMIME.Encrypted.Message</td>
      <td>String</td>
      <td>The encrypted message.</td>
    </tr>
    <tr>
      <td>SMIME.Encrypted.Headers</td>
      <td>String</td>
      <td>The encryption headers.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!smime-encrypt-email-body message="Hello World"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "SMIME.Encrypted": {
        "Headers": "MIME-Version=1.0,Content-Disposition=attachment; filename=\"smime.p7m\",Content-Type=application/x-pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\",Content-Transfer-Encoding=base64",
        "Message": "MIME-Version: 1.0\nContent-Disposition: attachment; filename=\"smime.p7m\"\nContent-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\nContent-Transfer-Encoding: base64\n\nMIIB5gYJKoZIhvcNAQcDoIIB1zCCAdMCAQAxggGXMIIBkwIBADB7MG4xCzAJBgNV\nBAYTAklMMQ8wDQYDVQQIDAZJc3JhZWwxGzAZBgNVBAoMElBhbG8gYWx0byBuZXR3\nb3JrczExMC8GCSqGSIb3DQEJARYiYXZpc2hhaUBkZW1pc3RvZGV2Lm9ubWljcm9z\nb2Z0LmNvbQIJAO117pJfuoxMMA0GCSqGSIb3DQEBAQUABIIBAHIauLY6zZviXMfo\ngiAH00ugmMrOf8kWXyXzTtY8ujb0q3FWCLjm3SQvozuiyH+hfpFAaCqq2WLviHx7\ne1f+NtdDuaJuoANHl0WfYUNW2UUhzQkRFUVJZRnsr9W8uhhRNYPv5SD/g7G/xWMs\n+cfrJOAd2q3AwRHvcEVFW+xNNHoQDCk2KcjLiE5Vr2q5Fly2Gyxhs1iZ5Yq1bq2O\nczqUdgV8Uh6pxJ8t+n31GvrBSLA3xo1MwV6Nvj1AGYTQx53jDp9H0NSjqw8/LURP\n6jeH8uuF7/0flJmPfJigx/fYXfg2tCRdI75UMIm+0zywG0NDCk4l3PLM3iqi+sej\nNG8dZ3YwMwYJKoZIhvcNAQcBMBQGCCqGSIb3DQMHBAhJHDbFpz5R94AQ6QST/8pU\nijTpyt7V40F8Pg==\n\n"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
MIME-Version: 1.0
Content-Disposition: attachment; filename="smime.p7m"
Content-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"
Content-Transfer-Encoding: base64

MIIB5gYJKoZIhvcNAQcDoIIB1zCCAdMCAQAxggGXMIIBkwIBADB7MG4xCzAJBgNV
BAYTAklMMQ8wDQYDVQQIDAZJc3JhZWwxGzAZBgNVBAoMElBhbG8gYWx0byBuZXR3
b3JrczExMC8GCSqGSIb3DQEJARYiYXZpc2hhaUBkZW1pc3RvZGV2Lm9ubWljcm9z
b2Z0LmNvbQIJAO117pJfuoxMMA0GCSqGSIb3DQEBAQUABIIBAHIauLY6zZviXMfo
giAH00ugmMrOf8kWXyXzTtY8ujb0q3FWCLjm3SQvozuiyH+hfpFAaCqq2WLviHx7
e1f+NtdDuaJuoANHl0WfYUNW2UUhzQkRFUVJZRnsr9W8uhhRNYPv5SD/g7G/xWMs
+cfrJOAd2q3AwRHvcEVFW+xNNHoQDCk2KcjLiE5Vr2q5Fly2Gyxhs1iZ5Yq1bq2O
czqUdgV8Uh6pxJ8t+n31GvrBSLA3xo1MwV6Nvj1AGYTQx53jDp9H0NSjqw8/LURP
6jeH8uuF7/0flJmPfJigx/fYXfg2tCRdI75UMIm+0zywG0NDCk4l3PLM3iqi+sej
NG8dZ3YwMwYJKoZIhvcNAQcBMBQGCCqGSIb3DQMHBAhJHDbFpz5R94AQ6QST/8pU
ijTpyt7V40F8Pg==
</p>
</p>

<h3>3. smime-verify-sign</h3>
<hr>
<p>Verifies the signature.</p>
<h5>Base Command</h5>
<p>
  <code>smime-verify-sign</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>
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
      <td>signed_message</td>
      <td>The signed email with .p7 extension.</td>
      <td>Required</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!smime-verify-sign signed_message=3828@09847cac-04e1-459f-8b56-9385b4fcb06e</code>
</p>
<h5>Context Example</h5>
<pre>
{}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
The signature verified
b'a sign of our times'
</p>
</p>

<h3>4. smime-decrypt-email-body</h3>
<hr>
<p>Decrypts the message body. Please note we are using chardet module to find the correct encoding for the given text. Detected types are shown <a href="https://pypi.org/project/chardet/">here</a>.
    If you need to use different encoding to decode the message body, you can use the <code>encoding</code> argument when executing command. 
</p>
<h5>Base Command</h5>
<p>
  <code>smime-decrypt-email-body</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>
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
      <td>encrypt_message</td>
      <td>The encrypted message with .p7 extension.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>encoding</td>
      <td>The encoding code to use when decode the message body, e.g 'ISO-8859-2'. You can find description of the different encoding types <a href="https://docs.python.org/3/library/codecs.html#standard-encodings">here</a>.</td>
      <td> </td>
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
      <td>SMIME.Decrypted.Message</td>
      <td>String</td>
      <td>The decrypted message.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!smime-decrypt-email-body encrypt_message=3833@09847cac-04e1-459f-8b56-9385b4fcb06e</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "SMIME.Decrypted": {
        "Message": "Hello World"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
The decrypted message is: 
Hello World
</p>
</p>

<h3>5. smime-sign-and-encrypt</h3>
<hr>
<p>Encrypts and signs an email message with S/MIME protocol by using a public RSA certificate.</p>
<h5>Base Command</h5>
<p>
  <code>smime-sign-and-encrypt</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>permission 1</li>
    <li>permission 2</li>
</ul>
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
      <td>message</td>
      <td>The message body to encrypt and sign.</td>
      <td>Required</td>
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
      <td>SMIME.SignedAndEncrypted.Message</td>
      <td>String</td>
      <td>The raw message to send.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!smime-sign-and-encrypt message="Hello"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "SMIME.SignedAndEncrypted": {
        "Message": "MIME-Version: 1.0\nContent-Disposition: attachment; filename=\"smime.p7m\"\nContent-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\nContent-Transfer-Encoding: base64\n\n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\n\n"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
MIME-Version: 1.0
Content-Disposition: attachment; filename="smime.p7m"
Content-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"
Content-Transfer-Encoding: base64

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
</p>

</p>
<h2>Additional Information</h2>
<p>For the S/MIME Messaging integration, you will need an RSA key pair
(this consists of a public key and a private key) and an X.509 certificate of said public key.</p>
<p>The public key parameter will start and end as the following:

-----BEGIN CERTIFICATE-----

key

-----END CERTIFICATE-----</p>

The private key parameter will start and end as the following:

-----BEGIN RSA PRIVATE KEY-----

key

-----END RSA PRIVATE KEY-----
</p>
