var str = args.left;
var substring = args.right;

if(!str || !substring){
    return false;
}

if (Array.isArray(substring)) {
    var arr = substring;
    for (var i = 0; i < arr.length; ++i) {
        if (arr[i] && str.indexOf(arr[i]) > -1) {
                return true;
        }
    }
} else {
    if (str.indexOf(substring) > -1) {
        return true;
    }
}

return false;
