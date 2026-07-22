first = parseFloat(args.first);
if (isNaN(first)) {
    throw 'first is not valid: '+args.first;
}
second = parseFloat(args.second);
if (isNaN(second)) {
    throw 'second is not valid: '+args.second;
}
if (first > second) {
    return 'yes';
} else {
    return 'no';
}
