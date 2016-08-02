function AddArgumentOpen(arg, fieldName, member) {
    if (arg) {
        if (member) {
            return '<'+fieldName+'><member>' + arg+ '</member></'+fieldName+'>';
        } else {
            return '<'+fieldName+'>' + arg + '</'+fieldName+'>';
        }
    }
    return '';
}

function AddArgumentYesNo(arg, fieldName) {
    if (arg  !== undefined) {
            return '<'+fieldName+'>' + (arg ? 'yes' : 'no') + '</'+fieldName+'>';
        }
    return '';
}
var req = {
        type: 'config',
        action: 'set',
        key: 'keyvalue',
        xpath: args.xpath || '/config/devices/entry/vsys/entry/rulebase/security/rules/entry[@name=\'' + args.ruleName +'\']',
        element: AddArgumentOpen(args.action, 'action') +
        AddArgumentOpen(args.description, 'description') +
            AddArgumentOpen(args.srcIP, 'source', true) +
            AddArgumentOpen(args.dstIP, 'destination', true) +
            AddArgumentOpen(args.application, 'application', true) +
            AddArgumentOpen(args.srcUser, 'source-user', true) +
            AddArgumentOpen(args.from, 'from', true) +
            AddArgumentOpen(args.to, 'to', true) +
            AddArgumentOpen(args.service, 'service', true) +
            AddArgumentYesNo(args.negateSrc, 'negate-source') +
            AddArgumentYesNo(args.negateDst, 'negate-destination') +
            AddArgumentYesNo(args.disable, 'disabled') +
            AddArgumentYesNo(args.disableServerResponseInspection, 'disable-server-response-inspection')
    };
var raw = executeCommand('panorama', req);
return raw[0].Contents.response['-status'];