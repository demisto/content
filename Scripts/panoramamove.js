var req = {
        type: 'config',
        action: 'move',
        key: 'keyvalue',
        xpath: args.xpath || '/config/devices/entry/vsys/entry/rulebase/security/rules/entry[@name=\'' + args.src +'\']',
        where: args.where,
    };
if (args.dst) {
    req.dst = args.dst
}
var raw = executeCommand('panorama', req);
return raw[0].Contents.response['-status'];