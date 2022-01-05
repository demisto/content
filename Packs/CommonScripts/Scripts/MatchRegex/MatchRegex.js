var data = (typeof args.data) === 'string' ? args.data : JSON.stringify(args.data);
var flags = args.flags ? args.flags : 'gim';
var r = new RegExp(args.regex, flags);
var m;
var vals = [];
while ((m = r.exec(data)) !== null) {
    if (m && m.length > 0) {
        var val = m[0];
        var group = parseInt(args.group);
        if (args.group && m.length > group) {
            val = m[group];
        }
        var ec = {};
        if (args.contextKey) {
            ec[args.contextKey] = val;
        }
        vals.push(val);

        if (flags.indexOf('g') === -1) {
          break;
        }
    }
}
if (vals.length == 1) {
  setContext('MatchRegex.results', vals[0])
  return {Type: entryTypes.note, Contents: vals[0], ContentsFormat: formats.text, EntryContext: ec};
} else if (vals.length) {
  setContext('MatchRegex.results', vals)
  return {Type: entryTypes.note, Contents: vals, ContentsFormat: formats.text, EntryContext: ec};
} else {
  setContext('MatchRegex.results', vals)
  return {Type: entryTypes.note, Contents: 'Regex does not match', ContentsFormat: formats.text};
}
