//Show a list of carbon black sessions.
//Argument: Verbose = true, to show all properties.
var output = [];
var entries = executeCommand("cb-list-sessions", {});
var array = entries[0].Contents;
var outTable = [];
for (var index in array) {
    var item = array[index];
    var outItem = {};
    if (args.verbose === "true") {
        for (var name in item) {
            var value = item[name];
            if (typeof (value) !== "object") {
                outItem[name] = value;
            }
        }
    } else {
        outItem["status"] = item["status"];
        outItem["id"] = item["id"];
        outItem["sensor"]=item["sensor_id"];
    }
    outTable.push(outItem);
}
output.push({ContentsFormat: formats.table, Type: entryTypes.note, Contents: outTable});
return output;
