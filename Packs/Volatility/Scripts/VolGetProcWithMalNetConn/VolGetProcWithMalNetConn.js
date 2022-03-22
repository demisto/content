// get all the network connections
// use the ip address in the connections
var reputationthreshold = 4;
if (args.repthreshold) {
    reputationthreshold = args.repthreshold;
}
var cmds = [];
switch (args.profile) {
    case 'VistaSP0x64' :
    case 'VistaSP0x86' :
    case 'VistaSP1x64' :
    case 'VistaSP1x86' :
    case 'VistaSP2x64' :
    case 'VistaSP2x86' :
    case 'Win2008R2SP0x64' :
    case 'Win2008R2SP1x64' :
    case 'Win2008SP1x64' :
    case 'Win2008SP1x86' :
    case 'Win2008SP2x64' :
    case 'Win2008SP2x86' :
    case 'Win7SP0x64' :
    case 'Win7SP0x86' :
    case 'Win7SP1x64' :
    case 'Win7SP1x86' :
    case 'Win81U1x64' :
    case 'Win81U1x86' :
    case 'Win8SP0x64' :
    case 'Win8SP0x86' :
    case 'Win8SP1x64' :
    case 'Win8SP1x86' :
    case 'Win10x64' :
    case 'Win10x86' :
    case 'Win2012R2x64' :
    case 'Win2012x64' :
        cmds.push('netscan');
        break;
    case 'Win2003SP0x86' :
    case 'Win2003SP1x64' :
    case 'Win2003SP1x86' :
    case 'Win2003SP2x64' :
    case 'Win2003SP2x86' :
    case 'WinXPSP1x64' :
    case 'WinXPSP2x64' :
    case 'WinXPSP2x86' :
    case 'WinXPSP3x86' :
        cmds.push('connections');
        cmds.push('connscan');
        break;
    default:
        break;
}
var resultarr = [];
var ipaddrarr = [];
for (var i = 0; i < cmds.length; i++) {
    var cmdline = cmds[i];
    if (args.profile) {
        cmdline = cmdline + ' --profile=' + args.profile;
    }
    var out = executeCommand('VolJson', {file:args.memdump, system: args.system, cmd:cmdline});
    if (out) {
      for (var r = 0; r < out.length; r++) {
          if (out[r].Type !== entryTypes.error) {
            var jsonout = JSON.parse(out[r].Contents);
            result = {};
            var ipindex = jsonout.columns.indexOf('RemoteAddress');
            var pidindex = jsonout.columns.indexOf('PID');
            if ((ipindex > -1) && (pidindex > -1)) {
              for (var j = 0; j < jsonout.rows.length; j++) {
                var obj = {'ip':jsonout.rows[j][ipindex].split(':')[0], 'port':jsonout.rows[j][ipindex].split(':')[1], 'pid':jsonout.rows[j][pidindex]}
                ipaddrarr.push(obj);
              }
            }
          }
      }
    }
}
for (var i = 0; i < ipaddrarr.length; i++) {
  var repscript = 'DataIPReputation';
  if (args.repscript){
      repscript = args.repscript;
  }
  var iprep = executeCommand(repscript, {input: ipaddrarr[i].ip});
  if (iprep[0].Type !== entryTypes.error) {
    if (iprep[0].Contents <= reputationthreshold) {
        var result = {};
        result['PID'] = ipaddrarr[i].pid;
        result['IP'] = ipaddrarr[i].ip;
        result['PORT'] = ipaddrarr[i].port;
        result['REPUTATION'] = iprep[0].Contents;
        resultarr.push(result);
    }
  }
}
var result = {};
result.Contents = resultarr;
result.ContentsFormat = formats.table;
result.Type = entryTypes.note;
return result;
