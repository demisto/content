var imginfo = executeCommand('Vol', {file:args.memdump, system: args.system, cmd:'imageinfo'});
if (imginfo) {
   imginfo[0].Contents = '================ Image Info for ' + args.memdump + '==============\n' + imginfo[0].Contents;
}
var pstree = executeCommand('Vol', {file:args.memdump, system: args.system, cmd:'pstree'});
if (pstree) {
   pstree[0].Contents = '================ Process Tree for ' + args.memdump + '==============\n' + pstree[0].Contents;
}
var connscan = executeCommand('Vol', {file:args.memdump, system: args.system, cmd:'connscan'});
if (connscan) {
   connscan[0].Contents = '================ Past Network Connections for ' + args.memdump + '==============\n' + connscan[0].Contents;
}
var res = [];
res.push(imginfo);
res.push(pstree);
res.push(connscan);
return res;
