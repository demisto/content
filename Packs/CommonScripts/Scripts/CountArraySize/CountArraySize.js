var arr = args.array;
if (Array.isArray(arr)) {
    var key = 'ArraySize';
    if ((args.contextKey) && (args.contextKey.length > 0 )) {
        key = args.contextKey;
    }
    setContext(key,arr.length);
    return arr.length;
}
return 'Given input is not an array';
