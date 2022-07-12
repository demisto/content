//Show a list of carbon black sensors.
var sensors = executeCommand("cb-list-sensors",{})
var output = sensors[0];
output.ContentsFormat = formats.table;
return output;
