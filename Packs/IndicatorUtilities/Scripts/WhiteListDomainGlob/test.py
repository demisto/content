from WhiteListDomainGlob import glob_match

TEST_GLOB = [
    {
        "value": "*.office365.com"
    },
    {
        "value": "*-files.sharepoint.com"
    },
    {
        "value": "*.office.com"
    }
]

TEST_ALT_GLOB = [
    {
        "value": "*.symcb.com"
    }
]

GOOD_ALT_MATCHES = [
    "test.symcb.com",
    "badgood.symcb.com",
]

GOOD_MATCHES = [
    "office365.com",
    "www.office365.com",
    "http://www.office365.com/spaghetti",
    "https://www.office365.com/spaghett",
    "spaghett-files.sharepoint.com"
    "http://spaghett-files.sharepoint.com/"
]

BAD_MATCHES = [
    "www.office365.com.au",
    "cloud365office.com",
    "spaghettioffice365.com"
    "http://www.office365.com.au/spaghetti",
    "https://www.office365.com.au/spaghetti",
    "https://badwesbite.com/spaghetti?blah=www.office365.com",
    "https://badwesbite.com/spaghetti?blah=spaghett-files.sharepoint.com",
]


def test_glob_match():
    for match in GOOD_MATCHES:
        # Test the good matches return true
        r = glob_match(match, TEST_GLOB)
        assert r

    for match in BAD_MATCHES:
        # Test the bad matches return false
        r = glob_match(match, TEST_GLOB)

        assert not r


def test_alt_glob_match():
    for match in GOOD_ALT_MATCHES:
        # Test the good matches return true
        r = glob_match(match, TEST_ALT_GLOB)
        assert r

    for match in BAD_MATCHES:
        # Test the bad matches return false
        r = glob_match(match, TEST_GLOB)

        assert not r
