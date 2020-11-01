from PenteraDynamicTable import pentera_dynamic_table

PENTERA_INCIDENT = {
    "details": "Pentera Insight details: BlueKeep (CVE-2019-0708) Vulnerability Discovery",
    "name": "Pentera Insight: BlueKeep (CVE-2019-0708) Vulnerability Discovery",
    "penteraoperationdetails": [
        {
            "host": None,
            "ipv4": "1.1.1.1"
        },
        {
            "host": "1.1.1.1",
            "ipv4": None
        },
        {
            "host": None,
            "ipv4": "1.1.1.2"
        },
        {
            "host": "1.1.1.2",
            "ipv4": None
        },
        {
            "host": None,
            "ipv4": "1.1.1.3"
        },
        {
            "host": "1.1.1.3",
            "ipv4": None
        }
    ],
    "penteraoperationdetails_cf": "{\"penteraoperationdetails\": [{\"ipv4\": \"1.1.1.1\", \"host\": null}, "
                                  "{\"host\": \"1.1.1.1\", \"ipv4\": null}, {\"ipv4\": \"1.1.1.2\", \"host\": null}, "
                                  "{\"host\": \"1.1.1.2\", \"ipv4\": null}, {\"ipv4\": \"1.1.1.3\", \"host\": null}, "
                                  "{\"host\": \"1.1.1.3\", \"ipv4\": null}]}",
    "penteraoperationtype": "BlueKeep (CVE-2019-0708) Vulnerability Discovery"
}


def test_pentera_dynamic_table():
    incident = {'CustomFields': PENTERA_INCIDENT}
    details_table = pentera_dynamic_table(incident)
    assert isinstance(details_table, str)
    assert '### BlueKeep (CVE-2019-0708) Vulnerability Discovery' in details_table
    assert '|host|ipv4|' in details_table
    assert '|  | 1.1.1.1 |' in details_table
    assert '| 1.1.1.2 |  |' in details_table
    assert '|  | 1.1.1.3 |' in details_table
