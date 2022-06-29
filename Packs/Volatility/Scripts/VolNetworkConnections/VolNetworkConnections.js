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
        cmds.push('sockets');
        cmds.push('sockscan');
        break;
    default:
        break;
}
var resultarr = [];
for (var i = 0; i < cmds.length; i++) {
    var cmdline = cmds[i];
    if (args.profile) {
        cmdline = cmdline + ' --profile=' + args.profile;
    }
    var out = executeCommand('VolJson', {file:args.memdump, system: args.system, cmd:cmdline});
    if (out) {
        var mapper = function(columns) {
            return function(val) {
                return val.reduce(function(prev, curr, i) {
                    prev[columns[i]] = '' + curr;
                    return prev;
                }, {});
            };
        };
        for (var r = 0; r < out.length; r++) {
            if (out[r].Type !== entryTypes.error) {
                var jsonout = JSON.parse(out[r].Contents);
                result = {};
                result.Contents = jsonout.rows.map(mapper(jsonout.columns));
                result.ContentsFormat = formats.table;
                result.Type = entryTypes.note;
                resultarr.push(result);
            }
            else
            {
                result = {};
                var errstring = out[r].Contents;
                result.Contents = errstring.split('Stderr:')[1];
                result.ContentsFormat = formats.text;
                result.Type = entryTypes.error;
                resultarr.push(result);
            }
        }
    }
}
return resultarr;
