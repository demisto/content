if (args.value) {
    if (Array.isArray(args.value)) {
        return args.value.length > 0 ? 'yes' : 'no';
    }
    return 'yes';
}
return 'no';
