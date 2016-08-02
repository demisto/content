var files = files( '/tmp', true, false, args.files );
if ( files && files.length > 0 ) {
    if ( 1 != copy( files[0].Path, args.destpath ) )
        throw "Error copying file " + files[0].Path + " to " + files[0].destpath + ".";
    else
        pack("File copied successfully.");
}

