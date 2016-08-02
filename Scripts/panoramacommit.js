var reqArgs = {
        type: 'commit',
        cmd: '<commit></commit>'
    };
return executeCommand('panorama', reqArgs)[0].Contents.response['-status'];