var tempDir = '';
if( env.TEMP ) {
    tempDir = env.TEMP;
} else if ( env.TMPDIR ) {
    tempDir = env.TMPDIR;
} else if ( env.TMP) {
    tempDir = env.TMP;
} else {
    tempDir = '/tmp';
}

var filesRes = files( tempDir, true, false, args.files );
if ( filesRes && filesRes.length > 0 ) {
    if ( 1 != copy( filesRes[0].Path, args.destpath, args.force === 'true') )
        throw "Error copying file " + filesRes[0].Path + " to " + filesRes[0].destpath + ".";
    else
        pack("File copied successfully.");
} else {
    pack("Failed to find temp file.");
}
