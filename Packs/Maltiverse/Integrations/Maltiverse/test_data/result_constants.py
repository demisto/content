EXPECTED_IP_RESULT = {
    'IP(val.Address && val.Address == obj.Address)': [
        {
            'Address': '1.2.3.4',
            'Geo.Country': 'US',
            'PositiveDetections': 2,
            'Malicious.Description': ['Malware site', 'HTTP Spammer']
        }
    ],
    'Maltiverse.IP(val.Address && val.Address == obj.Address)': [
        {
            'Blacklist': {
                'Description': ['Malware site', 'HTTP Spammer'],
                'FirstSeen': ['2018-07-21 15:45:10', '2018-09-14 07:13:13'],
                'LastSeen': ['2018-07-21 15:45:10', '2018-11-12 07:15:06'],
                'Source': ['Hybrid-Analysis', 'Cleantalk.org']
            },
            'Classification': 'whitelist',
            'Tag': ['phishing', 'abuse', 'bot'],
            'Address': '1.2.3.4'
        }
    ],
    'DBotScore(val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)': [
        {
            'Indicator': '1.2.3.4',
            'Type': 'ip',
            'Vendor': 'Maltiverse',
            'Score': 1
        }
    ]
}

EXPECTED_URL_RESULT = {
    'URL(val.Data && val.Data == obj.Data)': [
        {
            'Data': 'https://dv-expert.org',
            'PositiveDetections': 1,
            'Malicious': {
                'Description': ['Phishing Aetna Health Plans &amp; Dental Coverage'],
                'Vendor': 'Maltiverse'
            }
        }
    ],
    'Maltiverse.URL(val.Data && val.Data == obj.Data)': [
        {
            'Blacklist': {
                'Description': ['Phishing Aetna Health Plans &amp; Dental Coverage'],
                'FirstSeen': ['2020-03-29 02:54:46'],
                'LastSeen': ['2020-03-29 02:54:46'],
                'Source': ['Phishtank']
            },
            'Classification': 'malicious',
            'Tag': ['phishing'],
            'ModificationTime': '2020-03-29 02:54:46',
            'CreationTime': '2020-03-29 02:54:46',
            'Hostname': 'dv-expert.org',
            'Domain': 'dv-expert.org',
            'Tld': 'org',
            'Address': 'https://dv-expert.org',
        }
    ],
    'DBotScore(val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)': [
        {
            'Indicator': 'dv-expert.org',
            'Type': 'url',
            'Vendor': 'Maltiverse',
            'Score': 3
        }
    ]
}

EXPECTED_DOMAIN_RESULT = {
    'Domain(val.Name && val.Name == obj.Name)': [
        {'CreationTime': '2019-03-17 12:57:27',
         'ModificationTime': '2019-06-11 08:10:59',
         'Tld': 'com',
         'Name': 'google.com',
         'ASName': 'AS15169 Google Inc.'
         }
    ],
    'DBotScore(val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)': [
        {'Indicator': 'google.com',
         'Type': 'Domain',
         'Vendor': 'Maltiverse',
         'Score': 2
         }
    ],
    'Maltiverse.Domain(val.Name && val.Name == obj.Name)': [
        {'CreationTime': '2019-03-17 12:57:27',
         'ModificationTime': '2019-06-11 08:10:59',
         'Tld': 'com',
         'Classification': 'suspicious',
         'Tag': ['phishing'],
         'Address': 'google.com',
         'Blacklist': {
             'Description': ['Malicious URL', 'apple phishing'],
             'FirstSeen': ['2019-03-17 12:57:27', '2019-06-11 08:10:59'],
             'LastSeen': ['2019-03-17 12:57:28', '2019-06-11 08:10:59'],
             'Source': ['Maltiverse', 'Antiphishing.com.ar']
         },
         'ResolvedIP': {
             'IP': ['172.217.7.174'],
             'Timestamp': ['2019-03-17 12:57:27']
         }
         }
    ]
}

EXPECTED_FILE_RESULT = {
    'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 '
    '|| val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == '
    'obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)': [
        {
            'Md5': 'f13b929e6bf9c07a90d7da493b2825e3',
            'Sha1': 'a17ddc7c691cc66f0e76233172051ab4cd69dd45',
            'Sha256': 'edb2f88c29844117cd74acf8bb357edf92487a1b142fe6f60b6ac5e15d2d718f',
            'Size': 10032728,
            'Type': 'sample',
            'Name': 'FileZilla_3.47.2.1_win64_sponsored-setup.exe',
            'Extension': 'exe',
            'Path': 'C:\\FileZilla_3.47.2.1_win64_sponsored-setup.exe'
        }
    ],
    'DBotScore(val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)': [
        {
            'Indicator': 'FileZilla_3.47.2.1_win64_sponsored-setup.exe',
            'Type': 'File',
            'Vendor': 'Maltiverse',
            'Score': 3
        }
    ],
    'Maltiverse.File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == '
    'obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && '
    'val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)':
        [
            {
                'Score': 10.0,
                'Classification': 'malicious',
                'ModificationTime': '2020-03-11 15:00:52',
                'CreationTime': '2020-03-11 15:00:52',
                'Size': 10032728,
                'ContactedHost': ['136.243.154.86', '52.84.125.27'],
                'DnsRequest': ['cloud.nitehe-nutete.com', 'isrg.trustid.ocsp.identrust.com',
                               'offers.filezilla-project.org'],
                'PositiveDetections': 1,
                'Name': 'FileZilla_3.47.2.1_win64_sponsored-setup.exe',
                'Tag': '',
                'ProcessList':
                    {
                        'Name': 'FileZilla_3.47.2.1_win64_sponsored-setup.exe',
                        'Normalizedpath': 'C:\\FileZilla_3.47.2.1_win64_sponsored-setup.exe',
                        'Sha256': 'edb2f88c29844117cd74acf8bb357edf92487a1b142fe6f60b6ac5e15d2d718f',
                        'Uid': '00016638-00002652'
                    },
                'Blacklist': {
                    'Description': ['PUA.FusionCore'],
                    'FirstSeen': ['2020-03-11 15:00:52'],
                    'LastSeen': ['2020-03-11 15:00:52'],
                    'Source': ['Hybrid-Analysis']
                },
                'Malicious': {
                    'Vendor': 'Maltiverse',
                    'Description': ['PUA.FusionCore']
                }
            }
        ]
}
