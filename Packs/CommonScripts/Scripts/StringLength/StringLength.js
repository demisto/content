setContext('StringLength.Result', args.str.length);
return {
    Type: entryTypes.note,
    Contents: args.str.length,
    ContentsFormat: formats.txt

};
