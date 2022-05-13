//+winpmem/winpmem_2.0.1.exe
try {
  if (env.OS !== 'windows') {
    throw ('script can only run on Windows');
  }
  var arch = wmi_query('select OSArchitecture from win32_operatingsystem')[0].OSArchitecture;
  var exename = 'winpmem_2.0.1.exe';
  var dumpFile = env.TEMP + '\\mem.dump';
  var output = execute(exename + ' -v -o ' + dumpFile, 600); // 10 minutes timeout
  pack(output.Stdout);
  if (output.Success) {
    pack_file(dumpFile);
    del(dumpFile);
  } else {
    throw output.Error;
  }
} catch (ex) {
  pack('Winpmem failed: ' + ex);
}
