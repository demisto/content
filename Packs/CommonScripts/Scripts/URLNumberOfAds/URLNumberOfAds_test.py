import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from URLNumberOfAds import ads

HTML_TEXT = """<!doctype html>
<html lang="en">
<head>
<script src="https://ad_url" async></script>
</html>"""


def test_ads():
    term_list = '  \n||ad_url\n##another_url\n'
    res = ads(HTML_TEXT, term_list)
    assert res == {'ad_ur': 1}
