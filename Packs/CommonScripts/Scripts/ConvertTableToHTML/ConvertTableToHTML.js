headers = args.headers ? args.headers.split(",") : [];
if (args.table) {
    ec = {};
    ec[args.context_key || 'HTMLTable'] = tableToHTML(args.title, args.table, headers);
    return {
        Type: entryTypes.note, Contents: '', ContentsFormat: formats.text,
        HumanReadable: tableToMarkdown(args.title, args.table, headers),
        EntryContext: ec
    };
}
return 'Data does not exist';
