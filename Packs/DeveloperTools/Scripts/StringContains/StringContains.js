var str = args.string;
var substring = args.substring;
var substringSeperator = args.substringSeperator;

if (Array.isArray(substring) || substringSeperator) {
    var arr = Array.isArray(substring) ? substring : substring.split(substringSeperator);
    for (var i = 0; i < arr.length; ++i) {
        if (arr[i] && str.indexOf(arr[i]) > -1) {
                return 'yes';
        }
    }
} else {
    if (str.indexOf(substring) > -1) {
        return 'yes';
    }
}
return 'no';
