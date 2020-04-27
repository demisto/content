from PenteraDynamicTable import pentera_dynamic_table
import demistomock as demisto

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


def test_pentera_dynamic_table(mocker):
    mocker.patch.object(demisto, 'incidents', return_value=[{'CustomFields': PENTERA_INCIDENT}])
    incident = demisto.incidents()[0]
    details_table = pentera_dynamic_table(incident)

    assert isinstance(details_table, str)
    assert details_table
