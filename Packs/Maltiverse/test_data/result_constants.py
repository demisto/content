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