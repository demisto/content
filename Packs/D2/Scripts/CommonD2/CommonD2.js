// Common functions script
// =======================
// This script will be appended to each d2 agent script before being executed.
// Place here all common functions you'd like to share between d2 agent scripts.
/**
 * Checks if the given string represents a valid IPv4 address
 * @param {String} ip - the string to check
 * @returns {Boolean} true if valid IPv4 address
 */
function isIp(ip) {
  var d = ip.split('.'), i = d.length;
  if (i !== 4) {
    return false;
  }
  var ok = true;
  while (i-- && ok) {
    ok = d[i].length !== 0 && !isNaN(parseInt(d[i])) && d[i] > -1 && d[i] < 256;
  }
  return ok;
}
/**
 * Execute a command and pack the standard output or throw the error
 * @param {String} command - the command to execute on the OS
 * @returns {Void}
 */
function packOutput(command){
  var output = execute(command);
  if (output.Success) {
    pack(output.Stdout);
  } else {
    throw 'Errcode:' + output.Error + '\nStderr:' + output.Stderr + '\nStdout: ' + output.Stdout;
  }
}
