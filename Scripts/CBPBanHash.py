CBP_HASH_BANNED = '3'
demisto.results(demisto.executeCommand("cbp-fileRule-update", {"fileState": CBP_HASH_BANNED, "hash": demisto.args()["hash"]}))
