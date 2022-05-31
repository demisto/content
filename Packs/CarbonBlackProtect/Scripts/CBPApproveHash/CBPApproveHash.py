import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

CBP_HASH_APPROVED = '2'
demisto.results(demisto.executeCommand("cbp-fileRule-createOrUpdate",
                {"fileState": CBP_HASH_APPROVED, "hash": demisto.args()["hash"]}))
