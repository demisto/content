var res = executeCommand("getEntry", {"id":args.responseEntryId});

if (res[0].Type==entryTypes.note || res[0].Type==entryTypes.file) {
    text = res[0].Contents;
    text = text.replace(/<br\/?>/gi,'\n')
                .replace(/\r/g,'')
                .replace(/\n/g,'__NL__')
                .replace(/<script .+?<\/script>/g,'')
                .replace(/<style .+?<\/style>/g,'')
                .replace(/__NL____NL__/g,'')
                .replace(/__NL__/g,'\n');
    response = text.replace(/<(?:.|\n)*?>/gm, '').trim("\n").split("\n")[0].trim();
    setContext('EmailAskUserResponse', response);
    return response;
} else {
    return res;
}
