IP_RESPONSE = [
    {
        'address': '100 CenturyLink Drive',
        'as_name': 'AS15169 Google Inc',
        'asn_cidr': '8.8.8.0/24',
        'asn_country_code': 'US',
        'asn_date': '1992-12-01 00:00:00',
        'asn_registry': 'arin',
        'blacklist': [
            {'count': 1,
             'description': 'Malware site',
             'first_seen': '2018-07-21 15:45:10',
             'last_seen': '2018-07-21 15:45:10',
             'source': 'Hybrid-Analysis'
             },
            {'count': 1,
             'description': 'HTTP Spammer',
             'first_seen': '2018-09-14 07:13:13',
             'last_seen': '2018-11-12 07:15:06',
             'source': 'Cleantalk.org'
             },
        ],
        'cidr': ['8.0.0.0/9'],
        'city': 'Monroe',
        'classification': 'whitelist',
        'country_code': 'US',
        'creation_time': '2018-07-21 15:45:10',
        'email': ['ipaddressing@level3.com'],
        'ip_addr': '1.2.3.4',
        'last_updated': '2018-04-23 00:00:00',
        'location': {'lat': 37.751, 'lon': -97.822},
        'modification_time': '2020-03-25 07:52:07',
        'postal_code': '71203',
        'registrant_name': 'Level 3 Parent, LLC',
        'state': 'LA',
        'tag': ['phishing', 'abuse', 'bot'],
        'type': 'ip'
    }
]

URL_RESPONSE = [
    {
        'blacklist': [
            {'count': 1,
             'description': 'Phishing Aetna Health Plans &amp; Dental Coverage',
             'first_seen': '2020-03-29 02:54:46',
             'last_seen': '2020-03-29 02:54:46',
             'source': 'Phishtank'
             }
        ],
        'classification': 'malicious',
        'creation_time': '2020-03-29 02:54:46',
        'domain': 'dv-expert.org',
        'hostname': 'dv-expert.org',
        'modification_time': '2020-03-29 02:54:46',
        'tag': ['phishing'],
        'tld': 'org',
        'type': 'url',
        'url': 'https://dv-expert.org',
        'urlchecksum': 'a70c027c6d76fb703f0d2e5a14526f219bf3b771557e4a36685365b960b98233'
    }
]

DOMAIN_RESPONSE = [
    {
        'as_name': 'AS15169 Google Inc.',
        'blacklist': [
            {'description': 'Malicious URL',
             'first_seen': '2019-03-17 12:57:27',
             'last_seen': '2019-03-17 12:57:28',
             'source': 'Maltiverse'
             },
            {'description': 'apple phishing',
             'first_seen': '2019-06-11 08:10:59',
             'last_seen': '2019-06-11 08:10:59',
             'ref': [279],
             'source': 'Antiphishing.com.ar'
             }
        ],
        'classification': 'suspicious',
        'creation_time': '2019-03-17 12:57:27',
        'domain': 'google.com',
        'domain_consonants': 5,
        'domain_lenght': 10,
        'entropy': 2.6464393446710157,
        'hostname': 'google.com',
        'modification_time': '2019-06-11 08:10:59',
        'resolved_ip': [
            {'ip_addr': '172.217.7.174',
             'timestamp': '2019-03-17 12:57:27'
             }
        ],
        'tag': ['phishing'],
        'tld': 'com',
        'type': 'hostname',
        'visits': 0
    }
]

FILE_RESPONSE = [
    {
        'antivirus': [
            {'description': 'Trojan.InstallCore.3953',
             'name': 'DrWeb'},
            {'description': 'Artemis!AA212C59CD30',
             'name': 'McAfee'},
            {'description': 'PUA.Win32.FusionCore.UKJAL',
             'name': 'TrendMicro'},
        ],
        'classification': 'malicious',
        'contacted_host': ['136.243.154.86', '52.84.125.27'],
        'creation_time': '2020-03-11 15:00:52',
        'dns_request': ['cloud.nitehe-nutete.com', 'isrg.trustid.ocsp.identrust.com', 'offers.filezilla-project.org'],
        'filename': ['FileZilla_3.47.2.1_win64_sponsored-setup.exe'],
        'filetype': 'PE32 executable (GUI) Intel 80386, for MS Windows, ...',
        'md5': 'f13b929e6bf9c07a90d7da493b2825e3',
        'modification_time': '2020-03-11 15:00:52',
        'process_list': [
            {'name': 'FileZilla_3.47.2.1_win64_sponsored-setup.exe',
             'normalizedpath': 'C:\\FileZilla_3.47.2.1_win64_sponsored-setup.exe',
             'sha256': 'edb2f88c29844117cd74acf8bb357edf92487a1b142fe6f60b6ac5e15d2d718f',
             'uid': '00016638-00002652'}
        ],
        'score': 10.0,
        'sha1': 'a17ddc7c691cc66f0e76233172051ab4cd69dd45',
        'sha256': 'edb2f88c29844117cd74acf8bb357edf92487a1b142fe6f60b6ac5e15d2d718f',
        'size': 10032728,
        'type': 'sample',
        'visits': 3
    }
]
