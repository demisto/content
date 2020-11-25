var blockPanorama = !!executeCommand('IsIntegrationAvailable',{'brandname': 'panorama'})[0].Contents;
var blockCP = !!executeCommand('IsIntegrationAvailable',{'brandname': 'check point'})[0].Contents;

if (args['using-brand']) {
    switch (args['using-brand'].toLowerCase()) {
        case 'panorama':
            blockCP = false;
            break;
        case 'check point':
            blockPanorama = false;
            break;
    }
}

if (!args.rulename) {
    args.rulename = 'ip' + args.ip + ' blocked in direction ' + args.direction;
}

var entries = [];
if (blockPanorama) {
    entries.push(executeCommand('PanoramaBlockIP', args));
}

if (blockCP) {
    if (!args.ipname) {
        args.ipname = + args.ip + ' . ' + args.direction;
    }
    entries.push(executeCommand('CPBlockIP', args));
}

return entries;
