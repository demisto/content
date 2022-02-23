var cmds = args.cmds.split(',');
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
