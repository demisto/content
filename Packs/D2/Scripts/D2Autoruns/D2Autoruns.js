//+Autoruns/autorunsc64.exe
//+Autoruns/autorunsc.exe
try {
  if (env.OS !== 'windows') {
    throw ('script can only run on Windows');
  }

  var arch = wmi_query('select OSArchitecture from win32_operatingsystem')[0].OSArchitecture;

  var binary = 'autorunsc.exe';
  if (arch === '64-bit') {
    binary = 'autorunsc64.exe';
  }

  var output = execute(binary + ' -ct -h -s -t -accepteula');

  if (output.Success) {
    pack(output.Stdout);
  } else {
    throw output.Stdout + '\n' + output.Error;
  }
} catch (ex) {
  pack('Execution failed: ' + ex);
}
