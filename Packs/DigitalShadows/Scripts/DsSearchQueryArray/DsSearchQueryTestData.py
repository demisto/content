TEST_DATA_URL = {
    "field": "URL.Data",
    "value": {
        "URL": [
            {
                "Data": "https://http://GermDetectives.com/learn/risk-profiles/IMPERSONATING_DOMAIN"
            },
            {"Data": "http://microsoft365cpmsetup.com"},
            {"Data": "http://portal-digitalshadows.com.still.valid/learn/risk-profiles/MARKED_DOCUMENT"},
            {"Data": "https://http://microsoft365cpmsetup.com/triage/alerts/BGWZC"},
            {
                "Data": "https://http://microsoft365cpmsetup.com/api/external/resources/2de38dac-bba5-46c9-9ceb"
                        + "-e0fd72944a11"
            },
            {
                "Data": "https://http://microsoft365cpmsetup.com/api/external/resources/2de38dac-bba5-46c9-9ceb"
                        + "-e0fd72944a11"
            },
            {
                "Data": "https://portal-digitalshadows.com/learn/risk-profiles/MARKED_DOCUMENT"
            },
        ]
    },
}
TEST_DATA_URL_EXPECTED = [
    "http://microsoft365cpmsetup.com OR https://http://microsoft365cpmsetup.com/triage/alerts/BGWZC OR "
    + "https://http://GermDetectives.com/learn/risk-profiles/IMPERSONATING_DOMAIN OR "
    + "http://portal-digitalshadows.com.still.valid/learn/risk-profiles/MARKED_DOCUMENT",
    "https://http://microsoft365cpmsetup.com/api/external/resources/2de38dac-bba5-46c9-9ceb-e0fd72944a11 OR "
    + "https://http://microsoft365cpmsetup.com/api/external/resources/2de38dac-bba5-46c9-9ceb-e0fd72944a11",
]

TEST_DATA_URL_SINGLE = {
    "field": "URL.Data",
    "value": {
        "URL": {
            "Data": "https://http://GermDetectives.com/learn/risk-profiles/IMPERSONATING_DOMAIN"
        }
    },
}
TEST_DATA_URL_SINGLE_EXPECTED = (
    "https://http://GermDetectives.com/learn/risk-profiles/IMPERSONATING_DOMAIN"
)
TEST_DATA_URL_SINGLE_FILTER = {
    "field": "URL.Data",
    "value": {
        "URL": {
            "Data": "https://portal-digitalshadows.com/learn/risk-profiles/MARKED_DOCUMENT"
        }
    },
}

TEST_DATA_IP = {
    "field": "IP.Address",
    "value": {
        "IP": [
            {"Address": "192.168.0.1"},
            {"Address": "0.0.0.0"},
            {"Address": "1.1.1.1"},
            {"Address": "123.456.2.124"},
        ]
    },
}
TEST_DATA_IP_EXPECTED = ["192.168.0.1 OR 1.1.1.1 OR 123.456.2.124"]
TEST_DATA_IP_SINGLE = {
    "field": "IP.Address",
    "value": {"IP": {"Address": "192.168.0.1"}},
}
TEST_DATA_IP_SINGLE_EXPECTED = "192.168.0.1"
TEST_DATA_IP_SINGLE_FILTER = {
    "field": "IP.Address",
    "value": {"IP": {"Address": "0.0.0.0"}},
}

TEST_DATA_DOMAIN = {
    "field": "Domain.Name",
    "value": {
        "Domain": [
            {"Name": "GermDetectives.com"},
            {"Name": "TutorialFriend.com"},
            {"Name": "LessIsFull.com"},
            {"Name": "SaveJam.com"},
            {"Name": "SaveItDay.com"},
            {"Name": "portal-digitalshadows.com.still.valid"},
            {"Name": "portal-digitalshadows.com"},
        ]
    },
}
TEST_DATA_DOMAIN_EXPECTED = [
    "GermDetectives.com OR TutorialFriend.com OR LessIsFull.com OR SaveJam.com OR SaveItDay.com OR "
    + "portal-digitalshadows.com.still.valid"
]
TEST_DATA_DOMAIN_SINGLE = {
    "field": "Domain.Name",
    "value": {"Domain": {"Name": "GermDetectives.com"}},
}
TEST_DATA_DOMAIN_SINGLE_EXPECTED = "GermDetectives.com"
TEST_DATA_DOMAIN_FILTER = {
    "field": "Domain.Name",
    "value": {"Domain": {"Name": "portal-digitalshadows.com"}},
}

TEST_DATA_FILE_SHA1 = {
    "field": "File.SHA1",
    "value": {
        "File": [
            {"SHA1": "fd340743293eae593da4796e868ce57dfabf4147"},
            {"SHA1": "fd340743293eae593da4796e868ce57dfabf4147"},
            {"SHA1": "4eeff478822995573f4a5c45e746f01f93e23f28"},
        ]
    },
}
TEST_DATA_FILE_SHA1_EXPECTED = [
    "fd340743293eae593da4796e868ce57dfabf4147 OR fd340743293eae593da4796e868ce57dfabf4147 OR "
    + "4eeff478822995573f4a5c45e746f01f93e23f28"
]
TEST_DATA_FILE_SHA1_SINGLE = {
    "field": "File.SHA1",
    "value": {"File": {"SHA1": "fd340743293eae593da4796e868ce57dfabf4147"}},
}
TEST_DATA_FILE_SHA1_SINGLE_EXPECTED = "fd340743293eae593da4796e868ce57dfabf4147"

TEST_DATA_FILE_SHA256 = {
    "field": "File.SHA256",
    "value": {
        "File": [
            {
                "MD5": "57b0ed216fac388b6d99774d256fa5542d32cfdfe72a45b32fd7932ec154731d"
            },
            {
                "SHA256": "57b0ed216fac388b6d99774d256fa5542d32cfdfe72a45b32fd7932ec154731d"
            },
            {
                "SHA256": "8dca20e35098837cc003b54f17688386aabd9a5640884f5e4397e755ca8bc606"
            },
        ]
    },
}
TEST_DATA_FILE_SHA256_EXPECTED = [
    "57b0ed216fac388b6d99774d256fa5542d32cfdfe72a45b32fd7932ec154731d OR "
    + "8dca20e35098837cc003b54f17688386aabd9a5640884f5e4397e755ca8bc606"
]
TEST_DATA_FILE_SHA256_SINGLE = {
    "field": "File.SHA256",
    "value": {
        "File": {
            "SHA256": "57b0ed216fac388b6d99774d256fa5542d32cfdfe72a45b32fd7932ec154731d"
        }
    },
}
TEST_DATA_FILE_SHA256_SINGLE_EXPECTED = (
    "57b0ed216fac388b6d99774d256fa5542d32cfdfe72a45b32fd7932ec154731d"
)

TEST_DATA_FILE_MD5 = {
    "field": "File.MD5",
    "value": {
        "File": [
            {"SHA": "fd8df0f90ab838325b4e442322b7343e"},
            {"MD5": "fd8df0f90ab838325b4e442322b7343e"},
            {"MD5": "5f09950f7c75828ed0ea296853b518c1"},
        ]
    },
}
TEST_DATA_FILE_MD5_EXPECTED = [
    "fd8df0f90ab838325b4e442322b7343e OR 5f09950f7c75828ed0ea296853b518c1"
]
TEST_DATA_FILE_MD5_SINGLE = {
    "field": "File.MD5",
    "value": {"File": {"MD5": "fd8df0f90ab838325b4e442322b7343e"}},
}
TEST_DATA_FILE_MD5_SINGLE_EXPECTED = "fd8df0f90ab838325b4e442322b7343e"

TEST_DATA_CVE = {
    "field": "CVE.ID",
    "value": {
        "CVE": [
            {"ID": "CVE-2012-2311"},
            {"ID": "CVE-2012-1823"},
            {"ID": "CVE-2022-34491"},
        ]
    },
}
TEST_DATA_CVE_EXPECTED = ["CVE-2012-2311 OR CVE-2012-1823 OR CVE-2022-34491"]
TEST_DATA_CVE_SINGLE = {"field": "CVE.ID", "value": {"CVE": {"ID": "CVE-2012-2311"}}}
TEST_DATA_CVE_SINGLE_EXPECTED = "CVE-2012-2311"
