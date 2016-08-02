function AddArgument(arg, argName,req) {
    if (arg) {
        req[argName] = arg;
    }
    return req;
}

var reqArgs = {
        type: 'export',
        category: args.pcapType,
    };
if (args.password) {
    reqArgs['dlp-password'] = args.password;
} else if (args.pcapType === 'dlp-pcap') {
    return 'can not provide dlp-pcap without password';
}

AddArgument(args.from, 'from', reqArgs);
AddArgument(args.to, 'to', reqArgs);
AddArgument(args.serialNo, 'serialno', reqArgs);
AddArgument(args.searchTime, 'search-time', reqArgs);
AddArgument(args.pcapID, 'pcap-id', reqArgs);

raw = executeCommand('panorama', reqArgs);
if (raw[0].ContentsFormat === 'json') {
    var content = raw[0].Contents.response;
    if (content['-status'] === 'success') {
        return content.result;
    } else {
        return content['-status'];
    }
} else {
    return raw;
}