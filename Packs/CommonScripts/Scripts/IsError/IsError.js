entryIds = (Array.isArray(args.entryId)) ? args.entryId : [args.entryId];
for(var entryIdx=0; entryIdx < entryIds.length; ++entryIdx) {
    res = executeCommand("getEntry", {"id":entryIds[entryIdx]});
    for (var resIdx=0; resIdx < res.length; ++resIdx) {
        if (isError(res[resIdx])) {
            return 'yes';
        }
    }
}
return 'no';
