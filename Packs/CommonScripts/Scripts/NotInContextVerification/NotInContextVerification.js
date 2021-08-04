var val = invContext.keyToWatch;
var argumentsVal = args.cmdArguments;
var argsArr = argumentsVal.split(",");

var argsToCmd = {};
for (i = 0; i < argsArr.length ; i++) {
    var keyval = argsArr[i].split("=");
    if (keyval.length == 2) {
        argsToCmd[keyval[0].trim()] = keyval[1];
    }
}

var entry = executeCommand(args.cmdToRun, argsToCmd);
if(!entry[0].EntryContext[args.keyToWatch]){
    return entry;
}
else{
    throw args.keyToWatch + ' in context is not empty';
}


