The GenerateCSR automation script produces a certificate signing request (CSR) file with optional war room/playground output. 

This automation utilizes the python cryptography/x509 module and supports all standard CSR fields. 

**Parameters for the automation:**

**cn (Mandatory)**: The certificate common name
**email**: The certificate email address
**org**: The certificate organization
**orgUnit**: The certificate organizational unit
**country**: The country for the certificate
**state**: The state for the certificate
**locality**: The locality/city for the certificate
**OutputToWarRoom**: Whether or not to print the raw CSR text to the war room (True/False)

**Automation Output:**

Context Key: File - The CSR file is placed under the "File" context key, which can then be accessed using the automatically generated download link. Additionally, the raw text can be accessed by passing the File "**EntryID**" to the !ReadFile automation. 

**Sample Command Input**

***Generate a CSR for server hosted at IP address 192.168.100.99 with custom parameters for each of the CSR fields, outputting the result to the war room***
!GenerateCSR cn=192.168.100.99 country=US email="admin@domain.tld" locality="SomeCity" org="Super 1337 Tech Company" orgUnit="Sales" state="CA" OutputToWarRoom=True

**Sample Context Output**

**Context data:**

    {
    "File": [
        {
            "EntryID": "274@d232bd06-332f-4dbb-80b7-d4487199ca1f",
            "Extension": "csr",
            "Info": "csr",
            "MD5": "cb07904e2619ee57540ab443a4e625e9",
            "Name": "request.csr",
            "SHA1": "2c418fcc766dccdab4ec549c9a7cd27bc231d3f8",
            "SHA256": "a19fe01d202eb7f55ad09a8b8108dd7219ba844382d41d4101f410008ff91894",
            "SHA512": "de7cec4ca1dd128d71d57ce8466a439d866454e8c1a3ae7049ed5e45df230a6c2bab5424a8246193471a86849976d0cfaa3ec24ebe14610835b615f0ccd07bc6",
            "SSDeep": "24:LrxXnh/WyTeHWG+AQOJuYKWVSWz33/J8wDiA3BuvAgz/C7LZ4oaeiikGQ7+:LrJnYyqHWGPt5XHuw+2uI8/C3ZFTDkGX",
            "Size": 1110,
            "Type": "PEM certificate request"
        }
    ]
}

**CSR Text Output**

> -----BEGIN CERTIFICATE REQUEST----- MIIC+zCCAeMCAQAwgZkxFzAVBgNVBAMMDjE5Mi4xNjguMTAwLjk5MR8wHQYJKoZI
> hvcNAQkBFhBhZG1pbkBkb21haW4udGxkMSAwHgYDVQQKDBdTdXBlciAxMzM3IFRl
> Y2ggQ29tcGFueTEOMAwGA1UECwwFU2FsZXMxCzAJBgNVBAYTAlVTMQswCQYDVQQI
> DAJDQTERMA8GA1UEBwwIU29tZUNpdHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
> ggEKAoIBAQDXbVKOxAdwjVIg4Jy0JOs6YBtQHVaF+Jf1Sv+BHoXlH4+xvExAhDb0
> EKpniYusr4H+XXqcLZuNjm+DoQhgEBhTqU/x+GjkWOabpCjwLmvdaLY1cJAHq6qy
> wC+/8EyXDoKtrRoL9ExgdL8+S4CgDJIdhsMzHIP8nzPy/aJyvCSpuyRgORuDwDcg
> /BykmnI6q0JqsbyKMdb0zoVs4EWOSYZOOgItE8GuMCvY2IgO+MkHoi94C8iI1Vtc
> v1UIBafLxldO8M+KKazEgxGmn36GkdHPEeOuMqLTlY5qnRheM9Mw8cBT8R/shZ6R
> jRz9cVgwjQAMXcR+uKHcL0Zxh+fHzEYtAgMBAAGgHDAaBgkqhkiG9w0BCQ4xDTAL
> MAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggEBAHKDustn+JuOBiMoOgakAOLw
> 7PxK4rnWw+IZJFvInhO+y3wnsV5IxKaAe2tyFxTT6cfo7wTN9sv1pCeH9yJmvcPJ
> 7HuvU6fMua9eK43+9VTUYqnaqtxQFqkWP+74YBbloBv2QMBtg3+/J8/9OuQJbxGQ
> nYx6IpQNAVm+3cV79eKZLn//r5v03tKTW7luAhcXQzWQmZL7BY0sRwiQ85+Ax9k/
> vgfx524df+g6agjhyi9Du9sLLezkehWWYq7gLrTQ9YOJm/bVpsjHt+d7RZ4lancF
> cPMAiHBtABJwxVJzIb7lacw/nvHikGjn3GD8h6RWSGqVzP8E9cTbDzA4xwHQf+w=
> -----END CERTIFICATE REQUEST

Example of reading the above context file data and outputting it to the war room/playground, assuming that OutputToWarRoom was set to False:

!ReadFile entryID="274@d232bd06-332f-4dbb-80b7-d4487199ca1f"
!Print value=${FileData} raw-response=true

***Please note*** that **raw-response=true** is required when printing data from the !ReadFile command to prevent XSOAR from formatting the text as markdown. When downloading the file via the automatically generated link, this issue is not present. This issue only applies to printing outputs associated with the !ReadFile and !Print commands.
