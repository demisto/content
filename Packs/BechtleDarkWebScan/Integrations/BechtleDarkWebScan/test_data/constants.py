MOCK_BASE_URL = "https://darkwebscanfake"

MOCK_PARAMS = {
    'insecure': True,
    'server_name': MOCK_BASE_URL,
    'proxy': False
}

MOCK_GET_COMPANIES_RESPONSE = [
  {
    "company_id": 212,
    "printableName": "Test Company"
  },
  {
    "company_id": 232,
    "printableName": "Example Org"
  }
]

MOCK_GET_ARGS = {
    'company_id': 212
}

MOCK_GET_LEAKS_RESPONSE = {
  "domain": "example.org",
  "numberOfResults": 5,
  "searchResults": [
    {
      "links": "vpn.example.org",
      "country": "Germany, Baden-Wurttemberg\nISP: Vodafone",
      "username": "john.doe@example.org",
      "date": "2025-12-30",
      "price": "$ 10.00",
      "size": "5.42Mb",
      "stealer": "redline",
      "vendor": "VendorName"
    },
    {
      "links": "webmail.example.org",
      "country": "Germany, Baden-Wurttemberg\nISP: Vodafone",
      "username": "jane.doe@example.org",
      "date": "2025-12-22",
      "price": "$ 5.00",
      "size": "0.71Mb",
      "stealer": "lumma",
      "vendor": "AnotherOne"
    }
  ]
}

MOCK_RESETCONTEXT_RESPONSE = "Integration context cleared."

MOCK_GET_EMAILSECURITY_RESPONSE = {
  "spf": {
    "domain": "test.com",
    "spfRecord": "v=spf1 ip4:1.2.3.4 include:spf.protection.outlook.com -all",
    "created": "2026-06-25 10:48:16",
    "warningColor": "green",
    "warning": "Your SPF record uses the hard fail qualifier (-all). This is good news. However, you should be aware that cybercriminals can still gather information about your network and/or used software through the SPF record as depicted below.",
    "summary": "Using hard fail qualifier (-all). This is good news.",
    "parts": [
      {
        "spfPart": "ip4:1.2.3.4",
        "spfPartDescription": "IPv4 address"
      }
    ]
  },
  "dmarc": {
    "domain": "test.com",
    "dmarcRecord": "v=DMARC1; p=quarantine;pct=50; rua=mailto:dmarc-reports-rua@test.com; ruf=mailto:dmarc-reports-ruf@test.com;aspf=r;adkim=r; ri=604800; fo=0",
    "created": "2026-06-25 10:45:46",
    "warningColor": "red",
    "warning": "Your DMARC record uses the \"quarantine\" policy. This is okay for testing purposes, but you should consider switchting to the \"reject\" policy soon. ",
    "summary": "DMARC using quarantine policy. This is okay but switching to reject is better.",
    "parts": [
      {
        "dmarcPart": "v=DMARC1",
        "dmarcPartDescription": "Version"
      }
    ]
  },
  "dane": {
    "warningColor": "red",
    "warning": "None or not all of your MX records have DANE configured. Without DANE, an attacker could potentially intercept or downgrade the email connection to an insecure one, even if the mail server supports encryption. Without this verification, an attacker could impersonate your email server or decrypt email traffic in transit.",
    "summary": "DANE not configured",
    "emailHosts": [
      {
        "domain": "test.com",
        "mxRecord": "mail.example.org",
        "tlsaResponse": "DANE not configured",
        "created": "2026-06-25 10:48:16"
      }
    ]
  }
}

MOCK_GET_OSINT_RESPONSE = {
  "subdomains": [
    {
      "subdomain": "rbrk01.example.org",
      "dnsARecord": None,
      "asName4": None,
      "dnsAAAARecord": None,
      "asName6": None,
      "dnsCNAMERecord": None,
      "asNameCNAME": None,
      "created": "2026-03-30 16:00:57",
      "description": "Undisclosed software"
    }
  ],
  "emailAddresses": [
    {
      "email": "john.doe@example.org"
    },
    {
      "email": "jane.doe@example.org"
    }
  ]
}

MOCK_GET_WAF_RESPONSE = {
  "product": "BIG-IP AppSec Manager (F5 Networks)",
  "warningColor": "green",
  "warning": "You are using a Web Application Firewall (WAF). This is good.",
  "summary": "A Web Application Firewall (WAF) is in use (BIG-IP AppSec Manager (F5 Networks))"
}
