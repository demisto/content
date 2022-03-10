var files = files('/tmp', true, false, args.file);
if (files && files.length > 0) {
    packOutput('pedump ' + files[0].Path);
}
