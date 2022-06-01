if (typeof args.value === 'string' || args.value instanceof String) {
    if (args.value === 'true' || args.value === 'True') {
        return 'yes';
    }
    return 'no';
}
var val = Boolean(args.value);
if (val) {
    return 'yes';
}
return 'no';
