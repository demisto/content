var result = Base64.encode(args.input);
return {Type: entryTypes.note,
    Contents: result,
    ContentsFormat: formats.note,
    HumanReadable: result,
    EntryContext: {"Base64.encoded": result}
};
