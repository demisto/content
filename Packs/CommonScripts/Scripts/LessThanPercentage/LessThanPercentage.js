first = parseFloat(args.firstPercentage);
if (!first) {
    throw 'firstPercentage is not valid: '+args.firstPercentage;
}
second = parseFloat(args.secondPercentage);
if (!second) {
    throw 'firstPercentage is not valid: '+args.secondPercentage;
}
if (first < second) {
    return 'less';
} else {
    return 'more';
}
