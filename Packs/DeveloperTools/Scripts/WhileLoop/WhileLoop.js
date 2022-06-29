var val = invContext.keyToWatch;
var expectedValue = args.value;
var argumentsVal = args.cmdArguments;
var argsArr = argumentsVal.split(",");
var maxIterations = 100;
var lastEntry = {};

if ((args.maxIterations) && (args.maxIterations.length > 0)) {
    maxIterations = parseInt(args.maxIterations);
}
sleepTime = 10;
if ((args.sleepTime) && (args.sleepTime.length > 0)) {
    sleepTime = parseInt(args.sleepTime);
}

var argsToCmd = {};
for (i = 0; i < argsArr.length ; i++) {
    var keyval = argsArr[i].split("=");
    if (keyval.length == 2) {
        argsToCmd[keyval[0]] = keyval[1];
    }
}
for (i = 0; i < maxIterations && (val != expectedValue); i++) {
    lastEntry = executeCommand(args.cmdToRun, argsToCmd );
    val = lastEntry[0].EntryContext[args.keyToWatch];
    var expectedValueArrived = false;
    if (Array.isArray(val)){ // handle case where there is an array of results in val, will check each one
        for (i = 0; i < val.length ; i++) {
            if (val[i]===expectedValue){
                expectedValueArrived = true;
            }
        }
    }
    if (expectedValueArrived) {
        break;
    }
    wait(sleepTime);
}
return lastEntry;
