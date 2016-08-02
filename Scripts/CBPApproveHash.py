CBP_HASH_APPROVED = '2'
demisto.results(demisto.executeCommand("cbp-fileRule-update", {"fileState": CBP_HASH_APPROVED,"hash": demisto.args()["hash"]}))
