//+ o365/office365searchdelete.ps1
//Params: Username, Password and Query in exchange syntax
if ((env.ARCH !== "amd64") && (env.OS !== "windows")) {
    throw("Script can run only in 64bit Windows Agents");
}
var command = [];
command.push("powershell.exe");
command.push("-NonInteractive");
command.push("-NoLogo");
command.push("'" + which("office365searchdelete.ps1")+ "'");
if (typeof (args.password) !== "undefined") {
    command.push("-password");
    command.push("'" + args.password + "'");
}
if (typeof (args.username) !== "undefined") {
    command.push("-username");
    command.push(args.username);
}
if (typeof (args.query) !== "undefined") {
    command.push("-query");
    command.push(args.query);
}
//pack(command.join(" "));
timeout = 60 * 5;
if (typeof (args.timeout) !== "undefined") {
    //pack('timeout: ' + timeout + '\n');
    timeout = args.timeout;
}
var results = execute(command.join(" "), timeout);//, 'table');
if(results.Error !== "exit status 0" || results.Stderr.length > 0) {
    throw "script failed with an error. \n" + results.Error +
    "\nstderr: " + results.Stderr + "\nstdout: " +results.Stdout;
}
pack(results.Stdout);
