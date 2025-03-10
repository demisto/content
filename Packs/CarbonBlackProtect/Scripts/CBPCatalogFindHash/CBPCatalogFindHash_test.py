import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def test_cbp_catalog_find_hash(mocker):
    from CBPCatalogFindHash import cbp_catalog_find_hash

    args = {"md5": ["md5_hash"]}
    catalog = [{"Type": 3, "Contents": {"getTicketResponse": {"some_info": {"info": "test"}}}}]
    mocker.patch.object(demisto, "executeCommand", return_value=catalog)
    mocker.patch.object(demisto, "results")
    cbp_catalog_find_hash(args)
    res = demisto.results
    content = res.call_args[0][0]
    assert [{"Type": 1, "ContentsFormat": "table", "Contents": ["getTicketResponse"]}] == content
