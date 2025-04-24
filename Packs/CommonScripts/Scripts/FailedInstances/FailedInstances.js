var INTERNAL_MODULES_BRANDS = ['Scripts', 'Builtin', 'testmodule'];

var failedInstances = [];
var all = getModules();
var countFailed = 0;
var countSuccess = 0;
var instances = [];

const brandConfig = {
    "ServiceNow v2": {
        command: "servicenow-oauth-test",
        message: "Test button cannot be used"
    },
    "ServiceNow CMDB": {
        command: "servicenow-cmdb-oauth-test",
        message: "Test button cannot be used"
    },
    "Microsoft Graph Mail Single User": {
        command: "msgraph-mail-test",
        message: "Please use !msgraph-mail-test instead"
    },
    "Microsoft Graph API": {
        command: "msgraph-api-test",
        message: "Use the !msgraph-api-test command instead"
    },
    "Microsoft Graph User": {
        command: "msgraph-user-test",
        message: "run the !msgraph-user-test command"
    },
    "Gmail Single User": {
        command: "gmail-auth-test",
        message: "Test is not supported."
    },
    "Microsoft 365 Defender": {
        command: "microsoft-365-defender-auth-test",
        message: "run the !microsoft-365-defender-auth-test"
    }
};

Object.keys(all).forEach(function(m) {
    var isShouldBeTesting = all[m].defaultIgnored !== 'true' && INTERNAL_MODULES_BRANDS.indexOf(all[m].brand) === -1;
    if (all[m].state === 'active' && isShouldBeTesting) {
        var cmd = m.replace(/\s/g,'_') + '-test-module';
        var firstRest = executeCommand("addEntries", {"entries": JSON.stringify([{
            Type: entryTypes.note,
            Contents: 'testing **' + m + '**',
            HumanReadable: 'testing **' + m + '**',
            ContentsFormat: formats.markdown
        }])});

        var res =  executeCommand(cmd, {});
        var content = res[0].Contents
        var brand = all[m].brand;
        var config = brandConfig[brand];

        if (
            config &&
            content.includes(config.message)
        ) {
            logDebug("Enhanced test logic triggered for brand: \"{0}\", instance: \"{1}\".".format(brand, m));
            logDebug("Detected message: \"{0}\". Running command: \"{1}\".".format(config.message, config.command));
            cmd = config.command;
            res = executeCommand(cmd, { using: m });
            logDebug("Command \"{0}\" executed for instance: \"{1}\". Result: {2}".format(cmd, m, res[0].Contents));
        }
        executeCommand("addEntries", {"entries": JSON.stringify([{
            Type: entryTypes.note,
            Contents: 'done testing **' + m + '**:\n' + res[0].Contents,
            HumanReadable: 'done testing **' + m + '**:\n' + res[0].Contents,
            ContentsFormat: formats.markdown
        }])});
        if (res[0].Type === entryTypes.error) {
            countFailed++;
        }
        else {
            countSuccess++;
        }

        if (res[0].Type === entryTypes.error) {
            failedInstances.push({instance: m, brand: all[m].brand, category: all[m].category, information: res[0].Contents, status: 'failure' });
        }
        else {
            instances.push({instance: m, brand: all[m].brand, category: all[m].category, information: 'succeed', status: 'success' });
        }

    } else if (all[m].state === 'error' && isShouldBeTesting) {
            var errorMessage = 'The instance is in an error state, potentially due to an issue with the engine.';
            executeCommand("addEntries", {"entries": JSON.stringify([{
                Type: entryTypes.note,
                Contents: 'done testing **' + m + '**:\n' + errorMessage,
                HumanReadable: 'done testing **' + m + '**:\n' + errorMessage,
                ContentsFormat: formats.markdown
            }])});
            countFailed++;
            failedInstances.push({instance: m, brand: all[m].brand, category: all[m].category, information: errorMessage, status: 'failure' });
    }
});

var hr;
var success = countSuccess.toString();
var failed = countFailed.toString();
var total = (countSuccess + countFailed).toString();
// When no failed instances were found, the script returns a list with an empty dict because several scripts
// expect the output to be [{}].
if (countFailed === 0) {
    failedInstances.push({})
    hr = '### All active instances are available! ✅';
} else {
    hr = 'Total instances: ' + total +'\n';
    hr += 'Successed Instances: ' + success +'\n';
    hr += 'Failed Instances: ' + failed +'\n';
    hr += tableToMarkdown('Failed Instances:', failedInstances, ['instance', 'brand', 'category', 'information']);
}

return {
    Type: entryTypes.note,
    Contents: failedInstances,
    ContentsFormat: formats.markdown,
    HumanReadable: hr,
    EntryContext: {
        'FailedInstances': failedInstances,
        'SuccessInstances': instances,
        'InstancesCount':{
            'FailedCount': failed,
            'SuccessCount': success,
            'TotalCount': total
        }
    }
};
