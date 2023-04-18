//Show a list of carbon black sensors.
var sensors = executeCommand("cb-edr-sensors-list",{})
var output = sensors[0];
output.ContentsFormat = formats.table;
return output;
