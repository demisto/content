if (args.headers) {
    headers = args.headers.split(",");
} else {
    headers = []
}
if (args.table) {
    return {Type: entryTypes.note, Contents: '', ContentsFormat: formats.text,
        HumanReadable: tableToMarkdown(args.title, args.table, headers),
        EntryContext: {HTMLTable: tableToHTML(args.title, args.table, headers)}};
}
return 'Data does not exist';
