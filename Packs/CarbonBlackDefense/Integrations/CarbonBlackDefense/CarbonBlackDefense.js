var CBDefence = function() {
    var client = (function() {
        var urlTemplae = '%url%/integrationServices/%version%/';
        var authTemplate = '%key%/%connectorId%';
        var authSiemTemplate = '%siemKey%/%siemConnector%';
        var urlFull = replaceInTemplates(urlTemplae, params);
        var AuthToken = replaceInTemplates(authTemplate, params);
        var SiemToken = replaceInTemplates(authSiemTemplate, params);
        function addAuthToHeaders(headerObj, token) {
             if (headerObj === 'undefined') {
                return { 'X-Auth-Token': [token] };
            }
            headerObj['X-Auth-Token'] = [token];
            return headerObj;
        }
        var addClientAuthToHeaders = function(headerObj) {
            return addAuthToHeaders(headerObj, AuthToken);
        };
        var addSiemKeyToHeaders = function(headerObj) {
            return addAuthToHeaders(headerObj, SiemToken);
        };
        return {
            url: urlFull,
            addClientAuthToHeaders: addClientAuthToHeaders,
            addSiemKeyToHeaders: addSiemKeyToHeaders
        };
    })();
    var policyData = [
        {to: 'Id', from: 'id'},
        {to: 'PriorityLevel', from: 'priorityLevel'},
        {to: 'SystemPolicy',from: 'systemPolicy'},
        {to: 'LatestRevision',from: 'latestRevision'},
        {to: 'Policy',from: 'policy'}
    ];
    var commands = {
        'cbd-get-devices-status': {
            path: 'device',
            method: 'GET',
            queryParams: {
                start: true,
                rows: true,
                hostName: true,
                hostNameExact: true,
                ownerName: true,
                ownerNameExact: true,
                ipAddress: true
            },
            extended: true,
            translator:[
                {
                    contextPath: 'CarbonBlackDefense.GetDevicesStatus.Results(val.DeviceId==obj.DeviceId)',
                    title: 'Carbon Black Defense Get Devices Status',
                    innerPath: 'results',
                    data: [
                        { to: 'Name', from: 'name'},
                        { to: 'LastReportedTime', from: 'lastReportedTime'},
                        { to: 'PolicyId', from: 'policyId'},
                        { to: 'LastShutdownTime', from: 'lastShutdownTime'},
                        { to: 'LastContact', from: 'lastContact'},
                        { to: 'LastExternalIpAddress', from: 'lastExternalIpAddress'},
                        { to: 'AvStatus', from: 'avStatus'},
                        { to: 'RegisteredTime', from: 'registeredTime'},
                        { to: 'TargetPriorityType', from: 'targetPriorityType'},
                        { to: 'OrganizationId', from: 'organizationId'},
                        { to: 'DeviceOwnerId', from: 'deviceOwnerId'},
                        { to: 'Email', from: 'email'},
                        { to: 'ActivationCodeExpiryTime', from: 'activationCodeExpiryTime'},
                        { to: 'SensorVersion', from: 'sensorVersion'},
                        { to: 'Status', from: 'status'},
                        { to: 'TestId', from: 'testId'},
                        { to: 'DeviceId', from: 'deviceId'},
                        { to: 'SensorStates', from: 'sensorStates'},
                        { to: 'PolicyName', from: 'policyName'},
                        { to: 'SensorOutOfDate', from: 'sensorOutOfDate'},
                        { to: 'LastLocation', from: 'lastLocation'},
                        { to: 'DeviceType', from: 'deviceType'},
                        { to: 'OsVersion', from: 'osVersion'},
                        { to: 'LastInternalIpAddress', from: 'lastInternalIpAddress'},
                        { to: 'OrganizationName', from: 'organizationName'}
                    ]
                }
            ]
        },
        'cbd-get-device-status': {
            path: 'device/%deviceId%',
            method: 'GET',
            extended: true,
            translator:[
                {
                    contextPath: 'CarbonBlackDefense.GetDeviceStatus.DeviceInfo(val.DeviceId==obj.DeviceId)',
                    title: 'Carbon Black Defense Get Device Status',
                    innerPath: 'deviceInfo',
                    data: [
                        { to: 'Name', from: 'name'},
                        { to: 'LastReportedTime', from: 'lastReportedTime'},
                        { to: 'PolicyId', from: 'policyId'},
                        { to: 'LastShutdownTime', from: 'lastShutdownTime'},
                        { to: 'LastContact', from: 'lastContact'},
                        { to: 'LastExternalIpAddress', from: 'lastExternalIpAddress'},
                        { to: 'AvStatus', from: 'avStatus'},
                        { to: 'RegisteredTime', from: 'registeredTime'},
                        { to: 'TargetPriorityType', from: 'targetPriorityType'},
                        { to: 'OrganizationId', from: 'organizationId'},
                        { to: 'DeviceOwnerId', from: 'deviceOwnerId'},
                        { to: 'Email', from: 'email'},
                        { to: 'ActivationCodeExpiryTime', from: 'activationCodeExpiryTime'},
                        { to: 'SensorVersion', from: 'sensorVersion'},
                        { to: 'Status', from: 'status'},
                        { to: 'TestId', from: 'testId'},
                        { to: 'DeviceId', from: 'deviceId'},
                        { to: 'SensorStates', from: 'sensorStates'},
                        { to: 'PolicyName', from: 'policyName'},
                        { to: 'SensorOutOfDate', from: 'sensorOutOfDate'},
                        { to: 'LastLocation', from: 'lastLocation'},
                        { to: 'DeviceType', from: 'deviceType'},
                        { to: 'OsVersion', from: 'osVersion'},
                        { to: 'LastInternalIpAddress', from: 'lastInternalIpAddress'},
                        { to: 'OrganizationName', from: 'organizationName'}
                    ]
                }
            ]
        },
        'cbd-change-device-status': {
            path: 'device/%deviceId%',
            method: 'PATCH',
            content: {'policyName' : null},
            extended: true,
            translator:[
                {
                    contextPath: 'CarbonBlackDefense.ChangeDeviceStatus.DeviceInfo(val.DeviceId==obj.DeviceId)',
                    title: 'Carbon Black Defense Change Device Status',
                    innerPath: 'deviceInfo',
                    data: [
                        { to: 'Name', from: 'name'},
                        { to: 'LastReportedTime', from: 'lastReportedTime'},
                        { to: 'PolicyId', from: 'policyId'},
                        { to: 'LastShutdownTime', from: 'lastShutdownTime'},
                        { to: 'LastContact', from: 'lastContact'},
                        { to: 'LastExternalIpAddress', from: 'lastExternalIpAddress'},
                        { to: 'AvStatus', from: 'avStatus'},
                        { to: 'RegisteredTime', from: 'registeredTime'},
                        { to: 'TargetPriorityType', from: 'targetPriorityType'},
                        { to: 'OrganizationId', from: 'organizationId'},
                        { to: 'DeviceOwnerId', from: 'deviceOwnerId'},
                        { to: 'Email', from: 'email'},
                        { to: 'SensorVersion', from: 'sensorVersion'},
                        { to: 'Status', from: 'status'},
                        { to: 'TestId', from: 'testId'},
                        { to: 'DeviceId', from: 'deviceId'},
                        { to: 'SensorStates', from: 'sensorStates'},
                        { to: 'PolicyName', from: 'policyName'},
                        { to: 'SensorOutOfDate', from: 'sensorOutOfDate'},
                        { to: 'LastLocation', from: 'lastLocation'},
                        { to: 'DeviceType', from: 'deviceType'},
                        { to: 'OsVersion', from: 'osVersion'},
                        { to: 'LastInternalIpAddress', from: 'lastInternalIpAddress'},
                        { to: 'OrganizationName', from: 'organizationName'}
                    ]
                }
                ]
        },
        'cbd-find-events': {
            path: 'event',
            method: 'GET',
            queryParams: {
                start: true,
                rows: true,
                hostName: true,
                hostNameExact: true,
                ownerName: true,
                ownerNameExact: true,
                ipAddress: true,
                sha256Hash: true,
                applicationName: true,
                eventType: true,
                searchWindow: true
            },
            extended: true,
            translator: [
                {
                    contextPath: 'CarbonBlackDefense.FindEvents.Results(val.EventId==obj.EventId)',
                    innerPath: 'results',
                    title: 'Carbon Black Defense Find Events',
                    data: [
                        { to: 'EventTime', from: 'eventTime'},
                        { to: 'LongDescription', from: 'longDescription'},
                        { to: 'EventId', from: 'eventId'},
                        { to: 'EventType', from: 'eventType'},
                        { to: 'SelectedApp.EffectiveReputationSource', from: 'selectedApp.effectiveReputationSource'},
                        { to: 'SelectedApp.ReputationProperty', from: 'selectedApp.reputationProperty'},
                        { to: 'SelectedApp.Sha256Hash', from: 'selectedApp.sha256Hash'},
                        { to: 'SelectedApp.ApplicationName', from: 'selectedApp.applicationName'},
                        { to: 'SelectedApp.ApplicationPath', from: 'selectedApp.applicationPath'},
                        { to: 'SelectedApp.EffectiveReputation', from: 'selectedApp.effectiveReputation'},
                        { to: 'SelectedApp.Md5Hash', from: 'selectedApp.md5Hash'},
                        { to: 'ProcessDetails.UserName', from: 'processDetails.userName'},
                        { to: 'ProcessDetails.MilisSinceProcessStart', from: 'processDetails.milisSinceProcessStart'},
                        { to: 'ProcessDetails.Name', from: 'processDetails.name'},
                        { to: 'ProcessDetails.TargetCommandLine', from: 'processDetails.targetCommandLine'},
                        { to: 'ProcessDetails.TargetName', from: 'processDetails.targetName'},
                        { to: 'ProcessDetails.TargetPid', from: 'processDetails.targetPid'},
                        { to: 'ProcessDetails.FullUserName', from: 'processDetails.fullUserName'},
                        { to: 'ProcessDetails.TargetPrivatePid', from: 'processDetails.targetPrivatePid'},
                        { to: 'ProcessDetails.CommandLine', from: 'processDetails.commandLine'},
                        { to: 'ProcessDetails.PrivatePid', from: 'processDetails.privatePid'},
                        { to: 'ProcessDetails.ProcessId', from: 'processDetails.processId'},
                        { to: 'CreateTime', from: 'createTime'},
                        { to: 'DeviceDetails.Email', from: 'deviceDetails.email'},
                        { to: 'DeviceDetails.DeviceLocation.Region', from: 'deviceDetails.deviceLocation.region'},
                        { to: 'DeviceDetails.DeviceLocation.City', from: 'deviceDetails.deviceLocation.city'},
                        { to: 'DeviceDetails.DeviceLocation.Latitude', from: 'deviceDetails.deviceLocation.latitude'},
                        { to: 'DeviceDetails.DeviceLocation.CountryCode', from: 'deviceDetails.deviceLocation.countryCode'},
                        { to: 'DeviceDetails.DeviceLocation.CountryName', from: 'deviceDetails.deviceLocation.countryName'},
                        { to: 'DeviceDetails.DeviceLocation.Longitude', from: 'deviceDetails.deviceLocation.longitude'},
                        { to: 'DeviceDetails.DeviceType', from: 'deviceDetails.deviceType'},
                        { to: 'DeviceDetails.TargetPriorityType', from: 'deviceDetails.targetPriorityType'},
                        { to: 'DeviceDetails.PolicyName', from: 'deviceDetails.policyName'},
                        { to: 'DeviceDetails.DeviceId', from: 'deviceDetails.deviceId'},
                        { to: 'DeviceDetails.DeviceIpAddress', from: 'deviceDetails.deviceIpAddress'},
                        { to: 'DeviceDetails.DeviceIpV4Address', from: 'deviceDetails.deviceIpV4Address'},
                        { to: 'DeviceDetails.DeviceVersion', from: 'deviceDetails.deviceVersion'},
                        { to: 'DeviceDetails.AgentLocation', from: 'deviceDetails.agentLocation'},
                        { to: 'DeviceDetails.DeviceName', from: 'deviceDetails.deviceName'},
                        { to: 'DeviceDetails.TargetPriorityCode', from: 'deviceDetails.targetPriorityCode'},
                        { to: 'ShortDescription', from: 'shortDescription'},
                        { to: 'TargetApp.EffectiveReputation', from: 'targetApp.effectiveReputation'},
                        { to: 'TargetApp.ReputationProperty', from: 'targetApp.reputationProperty'},
                        { to: 'TargetApp.Sha256Hash', from: 'targetApp.sha256Hash'},
                        { to: 'TargetApp.ApplicationName', from: 'targetApp.applicationName'},
                        { to: 'TargetApp.EffectiveReputationSource', from: 'targetApp.effectiveReputationSource'}
                    ],
                    contextTranslator : [
                        {
                            contextPath: 'Endpoint(val.Hostname==obj.Hostname)',
                            innerPath: 'results',
                            data: [
                                {to: 'Hostname', from: 'deviceDetails.deviceName'},
                                {to: 'Domain', from: 'deviceDetails.deviceHostName'},
                                {to: 'OS', from: 'deviceDetails.deviceType'},
                                {to: 'IPAddress', from: 'deviceDetails.deviceIpV4Address'},
                            ]
                        },
                        {
                            contextPath: 'Process(val.PID==obj.PID)',
                            innerPath: 'results',
                            data: [
                                {to: 'PID', from: 'processDetails.processId'},
                                {to: 'Name', from: 'processDetails.name'},
                                {to: 'Endpoint', from: 'processDetails.deviceName'},
                                {to: 'CommandLine', from: 'processDetails.commandLine'},
                                {to: 'MD5', from: 'processDetails.md5Hash'},
                                {to: 'SHA1', from: 'processDetails.sha256Hash'},
                                {to: 'Path', from: 'processDetails.applicationPath'},
                                {to: 'ParentName', from: 'processDetails.parentName'},
                                {to: 'ParentID', from: 'processDetails.parentPid'}
                            ]
                        }
                    ]
                },
                {
                    contextPath: 'CarbonBlackDefense.FindEvents.TotalResults(val.TotalResults==obj.TotalResults)',
                    title: 'Carbon Black Defense Find Events - Total Results',
                    data: [{to:'TotalResults', from: 'totalResults'}]
                }
            ]
        },
        'cbd-find-event': {
            path: 'event/%eventId%',
            method: 'GET',
            extended: true,
            translator: [
                {
                    contextPath: 'CarbonBlackDefense.FindEvent.EventInfo(val.EventId==obj.EventId)',
                    innerPath: 'eventInfo',
                    title: 'Carbon Black Defense Find Events',
                    data: [
                      { to: 'ShortDescription', from: 'shortDescription'},
                      { to: 'TargetHash.ApplicationName', from: 'targetHash.applicationName'},
                      { to: 'TargetHash.ReputationProperty', from: 'targetHash.reputationProperty'},
                      { to: 'TargetHash.Sha256Hash', from: 'targetHash.sha256Hash'},
                      { to: 'EventType', from: 'eventType'},
                      { to: 'ProcessHash.Md5Hash', from: 'processHash.md5Hash'},
                      { to: 'ProcessHash.Sha256Hash', from: 'processHash.sha256Hash'},
                      { to: 'ProcessHash.ApplicationPath', from: 'processHash.applicationPath'},
                      { to: 'ProcessHash.ReputationProperty', from: 'processHash.reputationProperty'},
                      { to: 'ProcessHash.ApplicationName', from: 'processHash.applicationName'},
                      { to: 'OrgDetails.OrganizationId', from: 'orgDetails.organizationId'},
                      { to: 'OrgDetails.OrganizationName', from: 'orgDetails.organizationName'},
                      { to: 'OrgDetails.OrganizationType', from: 'orgDetails.organizationType'},
                      { to: 'ParentHash.ApplicationName', from: 'parentHash.applicationName'},
                      { to: 'ParentHash.Sha256Hash', from: 'parentHash.sha256Hash'},
                      { to: 'ThreatIndicators', from: 'threatIndicators'},
                      { to: 'EventId', from: 'eventId'},
                      { to: 'LongDescription', from: 'longDescription'},
                      { to: 'DeviceDetails.DeviceIpV4Address', from: 'deviceDetails.deviceIpV4Address'},
                      { to: 'DeviceDetails.DeviceType', from: 'deviceDetails.deviceType'},
                      { to: 'DeviceDetails.Email', from: 'deviceDetails.email'},
                      { to: 'DeviceDetails.TargetPriorityCode', from: 'deviceDetails.targetPriorityCode'},
                      { to: 'DeviceDetails.AgentLocation', from: 'deviceDetails.agentLocation'},
                      { to: 'DeviceDetails.DeviceHostName', from: 'deviceDetails.deviceHostName'},
                      { to: 'DeviceDetails.DeviceId', from: 'deviceDetails.deviceId'},
                      { to: 'DeviceDetails.GroupName', from: 'deviceDetails.groupName'},
                      { to: 'DeviceDetails.DeviceVersion', from: 'deviceDetails.deviceVersion'},
                      { to: 'DeviceDetails.TargetPriorityType', from: 'deviceDetails.targetPriorityType'},
                      { to: 'DeviceDetails.DeviceIpAddress', from: 'deviceDetails.deviceIpAddress'},
                      { to: 'DeviceDetails.DeviceLocation.Latitude', from: 'deviceDetails.deviceLocation.latitude'},
                      { to: 'DeviceDetails.DeviceLocation.City', from: 'deviceDetails.deviceLocation.city'},
                      { to: 'DeviceDetails.DeviceLocation.CountryCode', from: 'deviceDetails.deviceLocation.countryCode'},
                      { to: 'DeviceDetails.DeviceLocation.DmaCode', from: 'deviceDetails.deviceLocation.dmaCode'},
                      { to: 'DeviceDetails.DeviceLocation.Longitude', from: 'deviceDetails.deviceLocation.longitude'},
                      { to: 'DeviceDetails.DeviceLocation.MetroCode', from: 'deviceDetails.deviceLocation.metroCode'},
                      { to: 'DeviceDetails.DeviceLocation.PostalCode', from: 'deviceDetails.deviceLocation.postalCode'},
                      { to: 'DeviceDetails.DeviceLocation.Region', from: 'deviceDetails.deviceLocation.region'},
                      { to: 'DeviceDetails.DeviceLocation.AreaCode', from: 'deviceDetails.deviceLocation.areaCode'},
                      { to: 'DeviceDetails.DeviceLocation.CountryName', from: 'deviceDetails.deviceLocation.countryName'},
                      { to: 'DeviceDetails.DeviceName', from: 'deviceDetails.deviceName'},
                      { to: 'CreateTime', from: 'createTime'},
                      { to: 'EventTime', from: 'eventTime'},
                      { to: 'ProcessDetails.FullUserName', from: 'processDetails.fullUserName'},
                      { to: 'ProcessDetails.Name', from: 'processDetails.name'},
                      { to: 'ProcessDetails.ParentCommandLine', from: 'processDetails.parentCommandLine'},
                      { to: 'ProcessDetails.ParentName', from: 'processDetails.parentName'},
                      { to: 'ProcessDetails.ParentPid', from: 'processDetails.parentPid'},
                      { to: 'ProcessDetails.ProcessId', from: 'processDetails.processId'},
                      { to: 'ProcessDetails.CommandLine', from: 'processDetails.commandLine'},
                      { to: 'ProcessDetails.MilisSinceProcessStart', from: 'processDetails.milisSinceProcessStart'},
                      { to: 'ProcessDetails.TargetCommandLine', from: 'processDetails.targetCommandLine'},
                      { to: 'ProcessDetails.TargetPid', from: 'processDetails.targetPid'},
                      { to: 'ProcessDetails.UserName', from: 'processDetails.userName'},
                      { to: 'ProcessDetails.ParentPrivatePid', from: 'processDetails.parentPrivatePid'},
                      { to: 'ProcessDetails.PrivatePid', from: 'processDetails.privatePid'},
                      { to: 'ProcessDetails.TargetName', from: 'processDetails.targetName'},
                      { to: 'ProcessDetails.TargetPrivatePid', from: 'processDetails.targetPrivatePid'}
                    ],
                    contextTranslator: [
                        {
                            contextPath: 'Endpoint',
                            innerPath: 'deviceDetails',
                            data: [
                                {to: 'Hostname', from: 'deviceName'},
                                {to: 'Domain', from: 'deviceHostName'},
                                {to: 'OS', from: 'deviceType'},
                                {to: 'IPAddress', from: 'deviceIpV4Address'},
                            ]
                        },
                        {
                            contextPath: 'Process',
                            innerPath: 'processDetails',
                            data: [
                                {to: 'PID', from: 'processId'},
                                {to: 'Name', from: 'name'},
                                {to: 'Endpoint', from: 'deviceName'},
                                {to: 'CommandLine', from: 'commandLine'},
                                {to: 'MD5', from: 'md5Hash'},
                                {to: 'SHA1', from: 'sha256Hash'},
                                {to: 'Path', from: 'applicationPath'},
                                {to: 'ParentName', from: 'parentName'},
                                {to: 'ParentID', from: 'parentPid'}
                            ]
                        }
                    ]
                }
            ]
        },
        'cbd-find-processes': {
            path: 'process',
            method: 'GET',
            queryParams: {
                start: true,
                rows: true,
                hostNameExact: true,
                ownerName: true,
                ownerNameExact: true,
                ipAddress: true,
                searchWindow: true
            },
            extended: true,
            translator: [
                {
                    title: 'Carbon Black Defense Get Processes.Results',
                    contextPath:'CarbonBlackDefense.GetProcesses(val.ProcessId==obj.ProcessId)',
                    innerPath: 'results',
                    data: [
                        {to: 'ApplicationName',from: 'applicationName'},
                        {to: 'ProcessId', from: 'processId'},
                        {to: 'NumEvents', from: 'numEvents'},
                        {to: 'ApplicationPath', from: 'applicationPath'},
                        {to: 'PrivatePid', from:  'privatePid'},
                        {to: 'Sha256Hash', from: 'sha256Hash'}
                    ]
                },
                {
                    title: 'Carbon Black Defense Get Processes - Total Results',
                    contextPath:'CarbonBlackDefense.GetProcesses',
                    data: [{to: 'TotalResults',from: 'totalResults'}],
                }
            ]
        },
        'cbd-get-alert-details': {
            path: 'alert/%alertId%',
            method: 'GET',
            extended: true,
            translator : [
                {
                    contextPath: 'CarbonBlackDefense.GetAlertDetails.DeviceInfo(val.DeviceId==obj.DeviceId)',
                    title: 'Carbon Black Defense Get Alert Details',
                    data: [
                        { to: 'DeviceInfo.DeviceType', from: 'deviceInfo.deviceType'},
                        { to: 'DeviceInfo.Group', from: 'deviceInfo.adGroupName'},
                        { to: 'DeviceInfo.GroupId', from: 'deviceInfo.adGroupId'},
                        { to: 'DeviceInfo.RegisteredTime', from: 'deviceInfo.registeredTime'},
                        { to: 'DeviceInfo.DeviceId', from: 'deviceInfo.deviceId'},
                        { to: 'DeviceInfo.DeviceName', from: 'deviceInfo.deviceName'},
                        { to: 'DeviceInfo.Status', from: 'deviceInfo.status'},
                        { to: 'DeviceInfo.OsVersion', from: 'deviceInfo.osVersion'},
                        { to: 'DeviceInfo.SensorVersion', from: 'deviceInfo.sensorVersion'},
                        { to: 'DeviceInfo.UserName', from: 'deviceInfo.userName'},
                        { to: 'DeviceInfo.Importance', from: 'deviceInfo.importance'},
                        { to: 'DeviceInfo.Message', from: 'deviceInfo.message'},
                        { to: 'DeviceInfo.Success', from: 'deviceInfo.success'},
                        { to: 'Events.ParentHash', from: 'events.parentHash'},
                        { to: 'Events.PolicyState', from: 'events.policyState'},
                        { to: 'Events.LongDescription', from: 'events.longDescription'},
                        { to: 'Events.CommandLine', from: 'events.commandLine'},
                        { to: 'Events.ParentPid', from: 'events.parentPid'},
                        { to: 'Events.ProcessId', from: 'events.processId'},
                        { to: 'Events.ThreatIndicators', from: 'events.threatIndicators'},
                        { to: 'Events.ApplicationPath', from: 'events.applicationPath'},
                        { to: 'Events.ProcessHash', from: 'events.processHash'},
                        { to: 'Events.ProcessMd5Hash', from: 'events.processMd5Hash'},
                        { to: 'Events.EventId', from: 'events.eventId'},
                        { to: 'Events.EventTime', from: 'events.eventTime'},
                        { to: 'Events.EventType', from: 'events.eventType'},
                        { to: 'Events.KillChainStatus', from: 'events.killChainStatus'},
                        { to: 'Events.ParentName', from: 'events.parentName'},
                        { to: 'Events.ParentPPid', from: 'events.parentPPid'},
                        { to: 'Events.ProcessPPid', from: 'events.processPPid'},
                        { to: 'OrgId', from: 'orgId'},
                        { to: 'ThreatInfo.IncidentId', from: 'threatInfo.incidentId'},
                        { to: 'ThreatInfo.Indicators.ApplicationName', from: 'threatInfo.indicators.applicationName'},
                        { to: 'ThreatInfo.Indicators.IndicatorName', from: 'threatInfo.indicators.indicatorName'},
                        { to: 'ThreatInfo.Indicators.Sha256Hash', from: 'threatInfo.indicators.sha256Hash'},
                        { to: 'ThreatInfo.Summary', from: 'threatInfo.summary'},
                        { to: 'ThreatInfo.ThreatId', from: 'threatInfo.threatId'},
                        { to: 'ThreatInfo.ThreatScore', from: 'threatInfo.threatScore'},
                        { to: 'ThreatInfo.Time', from: 'threatInfo.time'}
                    ],
                    contextTranslator: [
                        {
                            contextPath: 'Endpoint(val.deviceName==obj.deviceName)',
                            innerPath: 'deviceInfo',
                            data: [
                                {to: 'Hostname', from: 'deviceName'},
                                {to: 'OS', from: 'deviceType'}
                            ]
                        },
                        {
                            contextPath: 'Process(val.processId==obj.processId)',
                            innerPath: 'events',
                            data: [
                                {to: 'PID', from: 'processId'},
                                {to: 'CommandLine', from: 'commandLine'},
                                {to: 'MD5', from: 'processMd5Hash'},
                                {to: 'Path', from: 'applicationPath'},
                                {to: 'ParentName', from: 'parentName'},
                                {to: 'ParentID', from: 'parentPid'}
                            ]
                        },
                        {
                            contextPath: 'Process(val.deviceName==obj.deviceName)',
                            innerPath: 'deviceInfo',
                            data: [{to: 'Endpoint', from: 'deviceName'}]
                        },
                        {
                            contextPath: 'Account(val.Email==obj.Email)',
                            innerPath: 'deviceInfo',
                            data: [
                                {to: 'Email', from: 'userName'},
                                {to: 'Groups', from: 'group'}
                            ]
                        }
                    ]
                }
            ]
        },
        "cbd-get-notifications": {
            path: 'notification',
            method: 'GET',
            siemKey: true
        },
        'cbd-get-policies': {
            path: 'policy',
            method: 'GET',
            queryParams: {
                start: true,
                rows: true
            },
            extended: true,
            translator : [
                {
                    title: 'Carbon Black Defense Get Policies',
                    contextPath: 'CarbonBlackDefense.GetPolicies(val.Id==obj.Id)',
                    innerPath: 'results',
                    data: policyData
                }
            ]
        },
        'cbd-get-policy': {
            path: 'policy/%policyId%',
            method: 'GET',
            extended: true,
            translator: [
                {
                    title: 'Carbon Black Defense Get Policy',
                    contextPath: 'CarbonBlackDefense.GetPolicy(val.Id==obj.Id)',
                    innerPath: 'policyInfo',
                    data: policyData
                }
            ]
        },
        'cbd-create-policy': {
            path: 'policy',
            method: 'POST',
            content: {
                'policyInfo' : {
                    'description': null,
                    'name': null,
                    'version': 2,
                    'priorityLevel': null,
                    'policy': null
                }
            },
            extended: true,
            translator: [
                {
                    title: 'Carbon Black Defense Create New Policy',
                    contextPath:'CarbonBlackDefense.CreatePolicy(val.PolicyId==obj.PolicyId)',
                    data:[{to: 'PolicyId', from: 'policyId'}]
                }
            ]
        },
        'cbd-update-policy': {
            path: 'policy/%id%',
            method: 'PUT',
            content: {
                'policyInfo' : {
                    'description': null,
                    'name': null,
                    'version': 2,
                    'priorityLevel': null,
                    'policy': null,
                    'id': null
                }
            }
        },
        'cbd-delete-policy': {
            path: 'policy/%policyId%',
            method: 'DELETE'
        },
        'cbd-add-rule-to-policy': {
            path: 'policy/%policyId%/rule',
            method: 'POST',
            content: {
                'ruleInfo': {
                    'action': null,
                    'application': {
                        'type': null,
                        'value': null
                    },
                    'operation': null,
                    'required': null,
                    'id': null
                }
            }
        },
        'cbd-delete-rule-from-policy': {
            path: 'policy/%policyId%/rule/%ruleId%',
            method: 'DELETE'
        },
        'cbd-update-rule-in-policy': {
            path: 'policy/%policyId%/rule/%id%',
            method: 'PUT',
            content: {
                'ruleInfo': {
                    'action': null,
                    'application': {
                        'type': null,
                        'value': null
                    },
                    'operation': null,
                    'required': null,
                    'id': null
                    }
                }
            }
    };
    //Taken from common server- with modifications
    var createEntry = function(result, translator, headerTransform) {
        /* filters out all fields where humanReadable is false */
        var filter = function(obj) {
          if(obj.humanReadable !== false) {
              return true;
          }
          return false;
        };
        var entry = {
          Type: entryTypes.note,
          Contents: result,
          ContentsType: formats.json,
          ReadableContentsFormat: formats.markdown,
          EntryContext: {}
        };
        var content = translator.innerPath ? dq(result, translator.innerPath) : result;
        var translatedContext = mapObjFunction(translator.data) (content);
        var translatedMD = mapObjFunction(translator.data, filter) (content);
        var context = createContext(translatedContext);
        entry.EntryContext[translator.contextPath] = context;
        entry.HumanReadable = tableToMarkdown(translator.title, translatedMD, undefined, undefined, headerTransform || dotToSpace);
        if (translator.contextTranslator) {
            var conTranslator = translator.contextTranslator;
            for (var i = 0; i < conTranslator.length; i++ ) {
                addContextToEntry(result, entry, conTranslator[i]);
            }
        }
        return entry;
    };
    function addContextToEntry(result, entry, translator) {
        var content = translator.innerPath ? dq(result, translator.innerPath) : result;
        var translatedContext = mapObjFunction(translator.data) (content);
        var context = createContext(translatedContext);
        entry.EntryContext[translator.contextPath] = context;
    }
    var generateQuery = function(cmd) {
        var seperateQueryParams = (function() {
            var seperated = {};
            if (cmd.queryParams) {
                for (var arg in args) {
                    if (cmd.queryParams[arg]) {
                       seperated[arg] = args[arg];
                    }
                }
            }
            return seperated;
        })();
        var queryString = (function() {
            return encodeToURLQuery(seperateQueryParams);
        })();
        return {
            str: queryString,
            parameters: seperateQueryParams
        };
    };
    function sendRequest(fullurl, method, headers, body) {
        var req = {
                Method: method,
                Headers: headers
            };
        if (body !== 'undifiend') {
            req.Body = body;
        }
        var res = http(fullurl, req, params.insecure, params.proxy);
        return res;
    }
    function pathify(cmd) {
        return replaceInTemplates(cmd.path,args);
    }
    function buildBody(cmd) {
        content = cmd.content;
        assignContentFromArgs(content);
        return JSON.stringify(content);
    }
    function assignContentFromArgs(obj) {
        for (var key in obj) {
            if (obj[key] === null) {
                if (args[key]) {
                    if (args[key] === 'true' || args[key] === 'false') {
                        obj[key] = (args[key] === 'true');
                    } else if (!isNaN(args[key])) {
                        obj[key] = parseInt(args[key]);
                    }
                    else {
                        obj[key] = args[key];
                    }
                }
            } else if(typeof obj[key] === 'object' ) {
                assignContentFromArgs(obj[key]);
            }
        }
    }
    var setPolicy = function() {
        var setter;
        var policy = args.policy;
        try {
            setter = JSON.parse(args.keyValue);
        } catch(err) {
            throw err;
        }
        for (var path in setter) {
            var val = setter[path];
            var keysArr = path.split('.');
            var obj = policy;
            var i = 0;
            while (obj && i < keysArr.length - 1) {
                obj = obj[keysArr[i]];
                i++;
            }
            if (!(obj && obj[keysArr[i]])) {
                throw 'field path ' + path + ' is not defined in the policy object';
            }
            obj[keysArr[i]] = val;
        }
        return {
            Type: entryTypes.note,
            Contents: policy,
            ContentsFormat: formats.json,
            EntryContext : {'CarbonBlackDefense.SetPolicy.Policy': policy }
        };
    };
    function executeCommand(cmd) {
        var query = generateQuery(cmd);
        var uniquePath = pathify(cmd);
        var url = client.url + uniquePath + query.str;
        var headers = {};
        var body;
        if (cmd.content) {
            body = buildBody(cmd);
        }
        headers = {
            'Content-Type': ['application/json'],
            'Accept': ['application/json']
        };
        if (cmd.siemKey) {
            client.addSiemKeyToHeaders(headers);
        } else {
            client.addClientAuthToHeaders(headers);
        }
        var res = sendRequest(url, cmd.method, headers, body);
        return res;
    }
    var executeAndShowResult = function (cmdName) {
        var cmd = commands[cmdName];
        var res = executeCommand(cmd);
        var body = parseBody(res);
        if (!cmd.extended) {
            return {
                Type: entryTypes.note,
                ContentsFormat: formats.text,
                Contents: 'Request Success'
            };
        }
        var entries = [];
        for (var i = 0; i < cmd.translator.length; i++) {
            entries.push(createEntry(body, cmd.translator[i]));
        }
        return entries;
    };
    function parseBody(httpResponse) {
        var body = JSON.parse(httpResponse.Body);
        if (httpResponse.StatusCode !== 200) {
            throw 'Request failed: ' + httpResponse.Status + ".\n" + body.message
        }
        return body;
    }
    var runTest = function() {
        args = { rows: '0' };
        var res = executeCommand(commands['cbd-get-devices-status']);
        if (res.StatusCode === 200) {
            return 'ok';
        }
        if (res.StatusCode === 401) {
            throw 'Test failed. Make sure that the Connector ID and API key are valid.';
        }
        throw 'Test failed for unknown reason';
    };
    function createIncidentsFromNotification(notification) {
        return {
            'name': 'event ' + notification.eventId + ', ' + notification.eventDescription,
            'rawJson': JSON.stringify(notification)
        };
    }
    var getNotifications = function() {
        if (!params.siemKey || !params.siemConnector) {
            throw 'SIEM key and SIEM connector are mandatory parameters to fetch incidents.';
        }
        var res = executeCommand(commands['cbd-get-notifications']);
        if (res.StatusCode !== 200 ) {
            throw 'Request failed with status code: ' + res.StatusCode;
        }
        var body = JSON.parse(res.Body);
        if (!body.notifications) {
            return;
        }
        var notifications = body.notifications;
        var incidents = [];
        for (var i = 0; i < notifications.length; i++) {
            var incident = createIncidentsFromNotification(notifications[i]);
            incidents.push(incident);
        }
        return JSON.stringify(incidents);
    };
    return {
        execute: executeAndShowResult,
        runTest: runTest,
        getNotifications: getNotifications,
        setPolicy: setPolicy
    };
};
var cbd = CBDefence();
switch (command) {
    case 'test-module':
        return cbd.runTest();
    case 'fetch-incidents':
        return cbd.getNotifications();
    case 'cbd-set-policy':
        return cbd.setPolicy();
    default:
        if (args.policy && typeof args.policy === 'string') {
            try {
                var p = JSON.parse(args.policy);
                args.policy = p;
            } catch (err) {
                return "Failed to parse policy into a JSON object.\n" + err;
            }
        }
        return cbd.execute(command);
}
