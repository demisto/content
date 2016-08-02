var cmdline = 'vol.py -f ' + args.memdump + ' ' + 'malfind';
if (args.pid) {
   cmdline = cmdline + ' -p ' + args.pid;
}
var dumpdir = args.dumpdir;

cmdline = cmdline + ' -D ' + dumpdir;
var timeout = 600 ;
if (args.timeout) {
   timeout = args.timeout ;
}

mkdir(dumpdir);
var output = execute(cmdline,timeout);
if (output.Success) {
   // we need to take all the files and move them over.
   pack(output);
   var results = files(dumpdir);
   for (var i = 0; i < results.length; i++) {
     if (results[i].Type !== "Folder") {
       var fileName = results[i].Path;
       pack_file(fileName);
       del(fileName);
     }
   }
}
rmdir(dumpdir);