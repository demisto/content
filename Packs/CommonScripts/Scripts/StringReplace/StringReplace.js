if ((typeof args.data) !== 'string') {
    return {
        Type: entryTypes.error,
        ContentsFormat: formats.text,
        Contents: 'Invalid input - please make sure \'data\' is of type string'
    }
}

var arr = [];
if (args.replaceAll === 'true') {
    arr.push('g');
}
if (args.caseInsensitive === 'true') {
    arr.push('i');
}
if (args.multiLine === 'true') {
    arr.push('m');
}

var newValue = args.newValue === "''" ? "" : args.newValue;
var r = new RegExp(args.regex, arr.join(''));
var val = args.data.replace(r, newValue);

//if no match found - return the original string
setContext('StringReplace.Result', val);
return {
    Type: entryTypes.note,
    Contents: val,
    ContentsFormat: formats.text
};
