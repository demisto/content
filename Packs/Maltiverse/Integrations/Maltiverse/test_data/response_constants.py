IP_RESPONSE = {
    "address": "PO Box 3646\nSouth Brisbane, QLD 4101\nAustralia",
    "asn_cidr": "1.1.1.0/24",
    "asn_country_code": "AU",
    "asn_date": "2011-08-11 00:00:00",
    "asn_registry": "apnic",
    "blacklist": [
        {
            "description": "Anonymizer",
            "first_seen": "2018-08-02 07:59:16",
            "last_seen": "2018-08-02 07:59:16",
            "source": "Maltiverse",
        }
    ],
    "cidr": ["1.1.1.0/24"],
    "classification": "malicious",
    "country_code": "AU",
    "creation_time": "2018-08-02 07:59:16",
    "email": ["resolver-abuse@cloudflare.com", "abuse@apnic.net", "helpdesk@apnic.net", "research@apnic.net"],
    "ip_addr": "1.1.1.0",
    "location": {"lat": -37.7, "lon": 145.1833},
    "modification_time": "2018-08-02 07:59:16",
    "registrant_name": "APNIC and Cloudflare DNS Resolver project\nRouted globally by AS13335/Cloudflare\nResearch "
    "prefix for APNIC Labs",
    "tag": ["anonymizer"],
    "type": "ip",
}

URL_RESPONSE = {
    "blacklist": [
        {
            "count": 1,
            "description": "Phishing Aetna Health Plans &amp; Dental Coverage",
            "first_seen": "2020-03-29 02:54:46",
            "last_seen": "2020-03-29 02:54:46",
            "source": "Phishtank",
        }
    ],
    "classification": "malicious",
    "creation_time": "2020-03-29 02:54:46",
    "domain": "dv-expert.org",
    "hostname": "dv-expert.org",
    "modification_time": "2020-03-29 02:54:46",
    "tag": ["phishing"],
    "tld": "org",
    "type": "url",
    "url": "https://dv-expert.org",
    "urlchecksum": "a70c027c6d76fb703f0d2e5a14526f219bf3b771557e4a36685365b960b98233",
}

DOMAIN_RESPONSE = {
    "as_name": "AS15169 Google Inc.",
    "blacklist": [
        {
            "count": 1,
            "description": "Malicious URL",
            "first_seen": "2019-03-17 12:57:27",
            "last_seen": "2019-03-17 12:57:28",
            "source": "Maltiverse",
        },
        {
            "count": 1,
            "description": "apple phishing",
            "first_seen": "2019-06-11 08:10:59",
            "last_seen": "2019-06-11 08:10:59",
            "ref": [279],
            "source": "Antiphishing.com.ar",
        },
        {
            "count": 1,
            "description": "Malicious URL",
            "first_seen": "2020-04-03 10:41:04",
            "last_seen": "2020-04-03 10:41:04",
            "ref": [2],
            "source": "Maltiverse Research Team",
        },
    ],
    "classification": "suspicious",
    "creation_time": "2019-03-17 12:57:27",
    "domain": "google.com",
    "domain_consonants": 5,
    "domain_lenght": 10,
    "entropy": 2.6464393446710157,
    "hostname": "google.com",
    "modification_time": "2020-04-03 10:41:04",
    "tag": ["phishing"],
    "tld": "com",
    "type": "hostname",
}

FILE_RESPONSE = {
    "antivirus": [
        {"description": "Trojan.InstallCore.3953", "name": "DrWeb"},
        {"description": "Artemis!AA212C59CD30", "name": "McAfee"},
        {"description": "PUA.Win32.FusionCore.UKJAL", "name": "TrendMicro"},
        {"description": "a variant of Win32/FusionCore.AY.gen potentially unwanted", "name": "ESET-NOD32"},
        {"description": "PUA.FusionCore!8.124 (CLOUD)", "name": "Rising"},
        {"description": "FusionCore", "name": "McAfee-GW-Edition"},
        {"description": "W32/FusionCore.D.gen!Eldorado", "name": "Cyren"},
        {"description": "PUA/Fusion.cij", "name": "Avira"},
        {"description": "PUA:Win32/FusionCore", "name": "Microsoft"},
        {"description": "TScope.Trojan.Delf", "name": "VBA32"},
        {"description": "PUA.Win32.FusionCore.UKJAL", "name": "TrendMicro-HouseCall"},
    ],
    "av_ratio": 15,
    "blacklist": [
        {
            "description": "PUA.FusionCore",
            "first_seen": "2020-03-11 15:00:52",
            "last_seen": "2020-03-11 15:00:52",
            "source": "Hybrid-Analysis",
        }
    ],
    "classification": "malicious",
    "contacted_host": ["136.243.154.86", "52.84.125.27"],
    "creation_time": "2020-03-11 15:00:52",
    "dns_request": ["cloud.nitehe-nutete.com", "isrg.trustid.ocsp.identrust.com", "offers.filezilla-project.org"],
    "filename": ["FileZilla_3.47.2.1_win64_sponsored-setup.exe"],
    "filetype": "PE32 executable (GUI) Intel 80386, for MS Windows, ...",
    "md5": "f13b929e6bf9c07a90d7da493b2825e3",
    "modification_time": "2020-03-11 15:00:52",
    "process_list": [
        {
            "name": "FileZilla_3.47.2.1_win64_sponsored-setup.exe",
            "normalizedpath": "C:\\FileZilla_3.47.2.1_win64_sponsored-setup.exe",
            "sha256": "edb2f88c29844117cd74acf8bb357edf92487a1b142fe6f60b6ac5e15d2d718f",
            "uid": "00016638-00002652",
        }
    ],
    "score": 10.0,
    "sha1": "a17ddc7c691cc66f0e76233172051ab4cd69dd45",
    "sha256": "edb2f88c29844117cd74acf8bb357edf92487a1b142fe6f60b6ac5e15d2d718f",
    "size": 10032728,
    "type": "sample",
    "visits": 3,
}

FILE_RESPONSE_NO_PROCCESS_LIST = {
    "antivirus": [
        {"description": "Trojan.InstallCore.3953", "name": "DrWeb"},
        {"description": "PUA.Win32.FusionCore.UKJAL", "name": "TrendMicro-HouseCall"},
    ],
    "av_ratio": 15,
    "blacklist": [
        {
            "description": "PUA.FusionCore",
            "first_seen": "2020-03-11 15:00:52",
            "last_seen": "2020-03-11 15:00:52",
            "source": "Hybrid-Analysis",
        }
    ],
    "classification": "malicious",
    "contacted_host": ["136.243.154.86", "52.84.125.27"],
    "creation_time": "2020-03-11 15:00:52",
    "dns_request": ["cloud.nitehe-nutete.com", "isrg.trustid.ocsp.identrust.com", "offers.filezilla-project.org"],
    "filename": ["FileZilla_3.47.2.1_win64_sponsored-setup.exe"],
    "filetype": "PE32 executable (GUI) Intel 80386, for MS Windows, ...",
    "md5": "f13b929e6bf9c07a90d7da493b2825e3",
    "modification_time": "2020-03-11 15:00:52",
    "score": 10.0,
    "sha1": "a17ddc7c691cc66f0e76233172051ab4cd69dd45",
    "sha256": "edb2f88c29844117cd74acf8bb357edf92487a1b142fe6f60b6ac5e15d2d718f",
    "size": 10032728,
    "type": "sample",
    "visits": 3,
}
