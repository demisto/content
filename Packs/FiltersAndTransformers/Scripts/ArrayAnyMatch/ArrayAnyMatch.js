function main() {
    var leftArg = args.left;
    var rightArg = args.right;
    var leftList = leftArg ? argToList(leftArg) : [];
    var rightList = argToList(rightArg);
    var foundCommon = false;
    
    for (var i = 0; i < rightList.length; i++) {
        var rightVal = rightList[i];
        if (leftList.indexOf(rightVal) > -1) {
            foundCommon = true;
            break;
        }
    }

    return foundCommon;
}

try {
    return main();
} catch (err) {
    return 'Error: ' + err.message;
}