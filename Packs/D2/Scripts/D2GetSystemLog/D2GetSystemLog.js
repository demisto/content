function copyLogUnix() {
  pack_file('/var/log/' + args.logName, args.logName);
}
function copyLogWindows() {
  var fileName = 'c:\\' + args.logName + '.log';
  var output = execute('wevtutil epl ' + args.logName + ' ' + fileName);
  if (!output.Success) {
    pack(output);
    throw output.Error + ': ';
  }
  pack_file(fileName, args.logName);
  del(fileName);
}
try {
  if (env.OS === 'windows') {
    copyLogWindows();
  } else  {
    copyLogUnix();
  }
} catch (ex) {
  pack('Error: ' + ex);
}
