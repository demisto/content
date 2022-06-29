if (!args.data) {
    return {ContentsFormat: formats.text, Type: entryTypes.error, Contents: 'Data is empty, filter not applied'};
}

if (['upper', 'lower', 'split', 'substr', 'trim', 'regex', 'replace'].indexOf(args.filterType) >= 0 && typeof args.data !== 'string') {
    return {ContentsFormat: formats.text, Type: entryTypes.error, Contents: 'Data is not a string, cannot convert'};
}

if (['join', 'index'].indexOf(args.filterType) >= 0 && !Array.isArray(args.data)) {
    return {ContentsFormat: formats.text, Type: entryTypes.error, Contents: 'Data is not a array, cannot convert'};
}
var ec = {};
var md = '';
// Supported types are upper, lower, join, split, index, substr, trim, regex, replace, jq
switch (args.filterType) {
    case 'upper':
        ec[args.out] = args.data.toUpperCase();
        md = 'Converted data to upper case and stored in ' + args.out;
        break
    case 'lower':
        ec[args.out] = args.data.toLowerCase();
        md = 'Converted data to lower case and stored in ' + args.out;
        break
    case 'join':
        var join = (args.filter) ? args.filter : ',';
        ec[args.out] = args.data.join(join);
        md = 'Joined data to ' + args.out;
        break
    case 'split':
        var split = (args.filter) ? args.filter : ',';
        ec[args.out] = args.data.split(split);
        md = 'Split data to ' + args.out;
        break
    case 'index':
        var index = (args.filter) ? args.filter : '0';
        var i = parseInt(index);
        if (isNaN(i)) {
            return {ContentsFormat: formats.text, Type: entryTypes.error, Contents: 'filter is not a number'};
        }
        if (i < 0) {
            i = args.data.length + (i % args.data.length);
        }
        ec[args.out] = args.data[i];
        md = 'Returned element ' + index + ' from data to ' + args.out;
        break
    case 'substr':
        var sub = (args.filter) ? args.filter : '0';
        var from = parseInt(sub);
        if (isNaN(from)) {
            return {ContentsFormat: formats.text, Type: entryTypes.error, Contents: 'filter from is not a number'};
        }
        var len = args.data.length - from;
        if (args.additional) {
            len = parseInt(args.additional);
            if (isNaN(len)) {
                return {ContentsFormat: formats.text, Type: entryTypes.error, Contents: 'filter length is not a number'};
            }
        }
        ec[args.out] = args.data.substr(from, len);
        md = 'Returned substr from data to ' + args.out;
        break
    case 'trim':
        ec[args.out] = args.data.substr(from, len);
        md = 'Trimmed data to ' + args.out;
        break
    case 'regex':
        if (!args.filter) {
            return {ContentsFormat: formats.text, Type: entryTypes.error, Contents: 'Regex not provided to filter'};
        }
        var flags = (args.additional) ? args.additional : 'i'; // Default is to ignore case
        var r = new RegExp(args.filter, flags);
        var res = r.exec(args.data);
        if (!res) {
            ec[args.out] = '';
            md = 'Regex was not found. Placed empty string in ' + args.out;
        } else {
            ec[args.out] = res[0];
            md = 'Returned regex match from data to ' + args.out;
        }
        break
    case 'replace':
        if (!args.filter) {
            return {ContentsFormat: formats.text, Type: entryTypes.error, Contents: 'Regex not provided to filter'};
        }
        var replace = (args.additional) ? args.additional : ''; // Default is to just remove the match
        var r = new RegExp(args.filter, 'i');
        ec[args.out] = args.data.replace(r, replace);
        md = 'Replaced match from data to ' + args.out;
        break
}
if (md !== '') {
    return {Type: entryTypes.note, Contents: ec, ContentsFormat: formats.json, HumanReadable: md, EntryContext: ec};
}
return {ContentsFormat: formats.text, Type: entryTypes.error, Contents: 'Unknown filter type - ' + args.filterType};
