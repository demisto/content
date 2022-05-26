var res = http('https://raw.githubusercontent.com/Yelp/osxcollector/master/osxcollector/osxcollector.py', {SaveToFile: true});
execute('chmod +x '+res.Path);
var cmd = res.Path ;
if (args.section) {
    cmd = cmd + " -s " + args.section ;
}
var timeout = 600 ;
if (args.timeout) {
    timeout = args.timeout ;
}
pack(cmd);
var output = execute(cmd,timeout);
pack(output);
var result = output.Stderr;
var fileNameStartIndex = result.lastIndexOf("osxcollect");
var fileName = result.substring(fileNameStartIndex, result.length-1);
pack_file(String(fileName));
fileNameWithoutExtension = fileName.substring(0, fileName.length-7);
execute('tar -zxvf '+fileName+' ./'+fileNameWithoutExtension+'/'+fileNameWithoutExtension+'.json');
var jsonResultStr = read_file(fileNameWithoutExtension+'/'+fileNameWithoutExtension+'.json');
var arr = jsonResultStr.split('\n');
str = arr.join(',');
var result = '{"osxcollector_result":['+str.substring(0, str.length-1)+']}';
pack(JSON.parse(result));
