var left = args.left;
var right = args.right;

if (right === undefined ||
    right === null ||
    (typeof(right) == 'string' && !right) ||
    (Array.isArray(right) && right.length === 0) ||
    (right instanceof Object && !(right instanceof Array) && Object.keys(right).length === 0)) {
    return true;
}
if (Array.isArray(left)) {
    for (var elem of left) {
        if (elem == right) {
            return true;
        }
    }
    return false;
} else {
    return left == right;
}
