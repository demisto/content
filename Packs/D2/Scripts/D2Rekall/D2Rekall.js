if (args.format)
    fmt = args.format;
else
    fmt= "text";
var out = execute('rekal --format ' + fmt + ' -f ' + args.file + ' ' + args.cmd, 60*60); // 1 hour timeout
pack(out.Stdout);
if( ! out.Success) {
    pack('Exception thrown: ' + out.Error + "\nStderr: " + out.Stderr);
}
