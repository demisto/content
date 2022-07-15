//+Scanner/Scanner.exe


if (env.OS !== 'windows') {
  throw ('script can only run on Windows');
}

var exename = 'Scanner.exe';
var output = execute(exename + ' -k ' + args['api_key'] + ' -i ' + args['endpoint_analysis_id'], 900); // 15 minutes timeout
if (output.Success) {
  pack('Scan finished');
} else if (output.Error.indexOf('1') != -1){
        throw 'Scan failed due to qouta limit reached or server error';
} else{
    throw 'Error executing scanner';
}
