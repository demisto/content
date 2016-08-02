// Demisto script for LimaCharlie
var r = executeCommand('objectloc', {obj_name: args.domain, obj_type: 'DOMAIN_NAME'});

if (r && Array.isArray(r) && r.length === 1 && r[0].ContentsFormat === formats.json && r[0].Contents && r[0].Contents && Array.isArray(r[0].Contents)) {
    var res = {Contents: [], ContentsFormat: formats.table, Type: entryTypes.note};
    for (var i=0; i<r[0].Contents.length; i++) {
        res.Contents.push({
            Sensor: r[0].Contents[i][1],
            Timestamp: r[0].Contents[i][2] ? (new Date(r[0].Contents[i][2] * 1000)).toString() : ''
        });
    }
    if (res.Contents.length > 0) {
        return res;
    }
}
return r;
