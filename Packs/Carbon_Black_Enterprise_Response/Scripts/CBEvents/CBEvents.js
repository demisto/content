//Searches for all processes with a given query - and lists events associated with processes.
//Args - process search query
var output = [];
function formatEvents(header, pname, pid, segid, arr) {
    var entry = [];
    if (typeof (arr) !== 'undefined') {
        for (var i = 0; i < arr.length; i++) {
            var items = arr[i].split("|");
            var row = {};
            row["name"]=pname;
            row["pid"]=pid;
            row["segid"]=segid;
            for (var k = 0; k < items.length; k++){
                row[header[k]]=items[k];
            }
            entry.push(row);
        }
        output.push({ContentsFormat: formats.table, Type: entryTypes.note, Contents: entry});
    }
}
var res = executeCommand("cb-process", {session: args.sessionid, query: args.query});
if (res.length > 0) {
    var list = res[0].Contents.results;
    if (typeof (list) !== 'undefined') {
        if (list.length === 0) {
            output.push({ContentsFormat: formats.text, Type: entryTypes.note, Contents: "No results"});
        }
        for (var i = 0; i < list.length; i++) {
            var process = list[i];
            var res1 = executeCommand("process-events", {pid: process.id.toString(), segid: process.segment_id.toString()});
            var pevent = res1[0].Contents;
            formatEvents(["time","md5","path"],pevent.process.process_name,process.id, process.segment_id, pevent.process.modload_complete);
            formatEvents(["type","time","reg path"],pevent.process.process_name,process.id, process.segment_id, pevent.process.regmod_complete);
            formatEvents(["type","time","file path","last md5","file type","tamper"],pevent.process.process_name,process.id, process.segment_id, pevent.process.filemod_complete);
            formatEvents(["time","remote ip","remote port","proto","dns name","outbound"],pevent.process.process_name,process.id, process.segment_id, pevent.process.netconn_complete);
            formatEvents(["time","uid","md5","path","pid","started","tamper"],pevent.process.process_name,process.id, process.segment_id, pevent.process.childproc_complete);
            formatEvents(["type","time","uid","md5","path","sub-type","access","tamper"],pevent.process.process_name,process.id, process.segment_id, pevent.process.crossproc_complete);
        }
    } else {
        output.push(res);
    }
}
return output;
