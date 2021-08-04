if (args.table) {
    return {Type: entryTypes.note, Contents: '', ContentsFormat: formats.text,
        HumanReadable: tableToMarkdown(args.title, args.table),
        EntryContext: {HTMLTable: tableToHTML(args.title, args.table)}};
}
return 'Data does not exist';
