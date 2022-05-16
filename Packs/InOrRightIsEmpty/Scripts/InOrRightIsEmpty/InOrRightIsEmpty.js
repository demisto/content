var left = args.left;
var right = args.right;

if (right === undefined || right === null || (typeof(right) == 'string' && !right)) {
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
