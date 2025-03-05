EXPECTED_IP_RESULT = {
    "IP(val.Address && val.Address == obj.Address)": [
        {
            "Address": "1.1.1.0",
            "Geo": {"Country": "AU"},
            "PositiveDetections": 1,
            "Malicious": {"Description": ["Anonymizer"]},
            "Tags": ["anonymizer"],
            "ThreatTypes": {"threatcategory": ["Anonymizer"]},
        }
    ],
    "Maltiverse.IP(val.Address && val.Address == obj.Address)": [
        {
            "Blacklist": [
                {
                    "Description": "Anonymizer",
                    "FirstSeen": "2018-08-02 07:59:16",
                    "LastSeen": "2018-08-02 07:59:16",
                    "Source": "Maltiverse",
                }
            ],
            "Tags": ["anonymizer"],
            "Classification": "malicious",
            "Address": "1.1.1.0",
        }
    ],
    "DBotScore(val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)": [
        {"Indicator": "1.1.1.0", "Type": "ip", "Vendor": "Maltiverse", "Score": 3, "Reliability": "C - Fairly reliable"}
    ],
}

EXPECTED_URL_RESULT = {
    "URL(val.Data && val.Data == obj.Data)": [
        {
            "Data": "https://dv-expert.org",
            "PositiveDetections": 1,
            "Tags": ["phishing"],
            "ThreatTypes": {"threatcategory": ["Phishing Aetna Health Plans &amp; Dental Coverage"]},
            "Malicious": {"Description": ["Phishing Aetna Health Plans &amp; Dental Coverage"], "Vendor": "Maltiverse"},
        }
    ],
    "DBotScore(val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)": [
        {
            "Indicator": "https://dv-expert.org",
            "Type": "Url",
            "Vendor": "Maltiverse",
            "Score": 3,
            "Reliability": "C - Fairly reliable",
        }
    ],
    "Maltiverse.URL(val.Data && val.Data == obj.Data)": [
        {
            "Classification": "malicious",
            "ModificationTime": "2020-03-29 02:54:46",
            "CreationTime": "2020-03-29 02:54:46",
            "Hostname": "dv-expert.org",
            "Domain": "dv-expert.org",
            "Tld": "org",
            "Address": "https://dv-expert.org",
            "Tags": ["phishing"],
            "Blacklist": [
                {
                    "Count": 1,
                    "Description": "Phishing Aetna Health Plans &amp; Dental Coverage",
                    "FirstSeen": "2020-03-29 02:54:46",
                    "LastSeen": "2020-03-29 02:54:46",
                    "Source": "Phishtank",
                }
            ],
        }
    ],
}

EXPECTED_DOMAIN_RESULT = {
    "Domain(val.Name && val.Name == obj.Name)": [
        {
            "CreationTime": "2019-03-17 12:57:27",
            "ModificationTime": "2020-04-03 10:41:04",
            "TLD": "com",
            "Tags": ["phishing"],
            "Name": "google.com",
            "ASName": "AS15169 Google Inc.",
            "ThreatTypes": {"threatcategory": ["Malicious URL", "apple phishing", "Malicious URL"]},
        }
    ],
    "DBotScore(val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)": [
        {"Indicator": "google.com", "Type": "Domain", "Vendor": "Maltiverse", "Score": 2, "Reliability": "C - Fairly reliable"}
    ],
    "Maltiverse.Domain(val.Name && val.Name == obj.Name)": [
        {
            "CreationTime": "2019-03-17 12:57:27",
            "ModificationTime": "2020-04-03 10:41:04",
            "TLD": "com",
            "Classification": "suspicious",
            "Tags": ["phishing"],
            "Address": "google.com",
            "Blacklist": [
                {
                    "Count": 1,
                    "Description": "Malicious URL",
                    "FirstSeen": "2019-03-17 12:57:27",
                    "LastSeen": "2019-03-17 12:57:28",
                    "Source": "Maltiverse",
                },
                {
                    "Count": 1,
                    "Description": "apple phishing",
                    "FirstSeen": "2019-06-11 08:10:59",
                    "LastSeen": "2019-06-11 08:10:59",
                    "Ref": [279],
                    "Source": "Antiphishing.com.ar",
                },
                {
                    "Count": 1,
                    "Description": "Malicious URL",
                    "FirstSeen": "2020-04-03 10:41:04",
                    "LastSeen": "2020-04-03 10:41:04",
                    "Ref": [2],
                    "Source": "Maltiverse Research Team",
                },
            ],
        }
    ],
}

EXPECTED_FILE_RESULT = {
    "File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 "
    "|| val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == "
    "obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)": [
        {
            "Name": "FileZilla_3.47.2.1_win64_sponsored-setup.exe",
            "MD5": "f13b929e6bf9c07a90d7da493b2825e3",
            "SHA1": "a17ddc7c691cc66f0e76233172051ab4cd69dd45",
            "SHA256": "edb2f88c29844117cd74acf8bb357edf92487a1b142fe6f60b6ac5e15d2d718f",
            "Size": 10032728,
            "Type": "sample",
            "Extension": "exe",
            "Path": "C:\\FileZilla_3.47.2.1_win64_sponsored-setup.exe",
            "Tags": [],
            "ThreatTypes": {"threatcategory": ["PUA.FusionCore"]},
        }
    ],
    "DBotScore(val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)": [
        {
            "Indicator": "edb2f88c29844117cd74acf8bb357edf92487a1b142fe6f60b6ac5e15d2d718f",
            "Type": "File",
            "Vendor": "Maltiverse",
            "Score": 3,
            "Reliability": "C - Fairly reliable",
        }
    ],
    "Maltiverse.File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == "
    "obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && "
    "val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)": [
        {
            "Score": 10.0,
            "Classification": "malicious",
            "ModificationTime": "2020-03-11 15:00:52",
            "CreationTime": "2020-03-11 15:00:52",
            "Size": 10032728,
            "ContactedHost": ["136.243.154.86", "52.84.125.27"],
            "DnsRequest": ["cloud.nitehe-nutete.com", "isrg.trustid.ocsp.identrust.com", "offers.filezilla-project.org"],
            "PositiveDetections": 1,
            "Name": "FileZilla_3.47.2.1_win64_sponsored-setup.exe",
            "Tags": [],
            "ProcessList": {
                "Name": "FileZilla_3.47.2.1_win64_sponsored-setup.exe",
                "Normalizedpath": "C:\\FileZilla_3.47.2.1_win64_sponsored-setup.exe",
                "Sha256": "edb2f88c29844117cd74acf8bb357edf92487a1b142fe6f60b6ac5e15d2d718f",
                "Uid": "00016638-00002652",
            },
            "Blacklist": [
                {
                    "Description": "PUA.FusionCore",
                    "FirstSeen": "2020-03-11 15:00:52",
                    "LastSeen": "2020-03-11 15:00:52",
                    "Source": "Hybrid-Analysis",
                }
            ],
            "Malicious": {"Vendor": "Maltiverse", "Description": ["PUA.FusionCore"]},
        }
    ],
}

EXPECTED_FILE_RESULT_NO_PROCESS_LIST = {
    "File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 &&"
    " val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32"
    " || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)": [
        {
            "Name": "FileZilla_3.47.2.1_win64_sponsored-setup.exe",
            "MD5": "f13b929e6bf9c07a90d7da493b2825e3",
            "SHA1": "a17ddc7c691cc66f0e76233172051ab4cd69dd45",
            "SHA256": "edb2f88c29844117cd74acf8bb357edf92487a1b142fe6f60b6ac5e15d2d718f",
            "Size": 10032728,
            "Type": "sample",
            "Extension": "exe",
            "Path": None,
            "Tags": [],
            "ThreatTypes": {"threatcategory": ["PUA.FusionCore"]},
        }
    ],
    "DBotScore(val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)": [
        {
            "Indicator": "edb2f88c29844117cd74acf8bb357edf92487a1b142fe6f60b6ac5e15d2d718f",
            "Type": "File",
            "Vendor": "Maltiverse",
            "Score": 3,
            "Reliability": "C - Fairly reliable",
        }
    ],
    "Maltiverse.File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || "
    "val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && "
    "val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)": [
        {
            "Score": 10.0,
            "Classification": "malicious",
            "ModificationTime": "2020-03-11 15:00:52",
            "CreationTime": "2020-03-11 15:00:52",
            "Size": 10032728,
            "ContactedHost": ["136.243.154.86", "52.84.125.27"],
            "DnsRequest": ["cloud.nitehe-nutete.com", "isrg.trustid.ocsp.identrust.com", "offers.filezilla-project.org"],
            "PositiveDetections": 1,
            "Name": "FileZilla_3.47.2.1_win64_sponsored-setup.exe",
            "Tags": [],
            "ProcessList": {"Name": None, "Normalizedpath": None, "Sha256": None, "Uid": None},
            "Blacklist": [
                {
                    "Description": "PUA.FusionCore",
                    "FirstSeen": "2020-03-11 15:00:52",
                    "LastSeen": "2020-03-11 15:00:52",
                    "Source": "Hybrid-Analysis",
                }
            ],
            "Malicious": {"Vendor": "Maltiverse", "Description": ["PUA.FusionCore"]},
        }
    ],
}
