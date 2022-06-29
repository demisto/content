var lh = args.lh;
var rh = args.rh;
var action = args.action;
var lhRegex = args.lhRegex;
var rhRegex = args.rhRegex;
var lRadix = args.lhRadix ? args.lRadix : 10;
var rRadix = args.rhRadix ? args.rRadix : 10;
var supportedActions = {
    '+': function() { return lh + rh; },
    '-': function() { return lh - rh; },
    '>': function() { return lh > rh; },
    '<': function() { return lh < rh; },
    '*': function() { return lh * rh; },
    '/': function() { return lh / rh; },
    '%': function() { return lh % rh; },
    '==': function() { return lh == rh; }
}

actionKeys = Object.keys(supportedActions);

//verfiy action is supported
if (!action || actionKeys.indexOf(action) < 0 ) {
  return {ContentsFormat: formats.markdown, Type: entryTypes.error, Contents: '**[' + action + ']** is not a supported action, only ' + actionKeys.join() + ' are supported'};
}


//parse lh according to regex
if (lhRegex) {
    var lr = new RegExp(lhRegex, 'i');
    lh = lh.match(lr);
    if (!lh) {
        return {ContentsFormat: formats.markdown, Type: entryTypes.error, Contents: 'lh - parsed to be an empty value from regex **[' + lhRegex + ']**, on value **[' + args.lh + ']**'};
    }
}

//parse rh according to regex
if (rhRegex) {
    var rr = new RegExp(rhRegex, 'i');
    rh = rh.match(rr);
    if (!rh) {
        return {ContentsFormat: formats.markdown, Type: entryTypes.error, Contents: 'rh - parsed to be an empty value from regex **[' + rhRegex + ']**, on value **[' + args.rh + ']**'};
    }
}

if (isNaN(lh)) {
    return {ContentsFormat: formats.markdown, Type: entryTypes.error, Contents: '**[' + lh + ']** is not a number'};
}

if (isNaN(rh)) {
    return {ContentsFormat: formats.markdown, Type: entryTypes.error, Contents: '**[' + rh + ']** is not a number'};
}

lh = parseInt(lh, lRadix)
rh = parseInt(rh, rRadix)

//do action on params
var res = supportedActions[action]();

// We need to override the context value so we use setContext
if (args.contextKey) {
    setContext(args.contextKey, res);
} else {
    setContext('MathResult', res);
}

return {ContentsFormat: formats.markdown, Type: entryTypes.note, Contents: lh + ' ' + action + ' ' + rh + ' = ' + res};
