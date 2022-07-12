var e = executeCommand( 'getEntry', { 'id' : args.entryid } );
if ( e.length === 0 )
    return "Entry " + args.entryid + " not found.";
if ( e.length>1 )
    return "More than one entry with that ID found. Assertion error.";
e = e[0];
if ( e.File ) {
    var fileName = fileNameFromEntry( args.entryid );
    var rep = executeCommand( 'D2Drop', { destpath : args.destpath , files : fileName, using : args.system, force: args.force } );
    return rep;
} else
    return "Entry " + args.entryid + " does not include a file.";
