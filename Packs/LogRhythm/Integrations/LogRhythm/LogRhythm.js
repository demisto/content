// SOAP templates
var tmplAddAlarmComment = '<?xml version="1.0" encoding="UTF-8"?>' +
'<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:tns="http://www.logrhythm.com/webservices" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ins0="http://schemas.microsoft.com/2003/10/Serialization/Arrays">' +
'  <env:Header>' +
'    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
'      <wsse:UsernameToken xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="UsernameToken-1">' +
'        <wsse:Username>{{.Username}}</wsse:Username>' +
'        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">{{.Password}}</wsse:Password>' +
'      </wsse:UsernameToken>' +
'    </wsse:Security>' +
'  </env:Header>' +
'  <env:Body>' +
'    <tns:AddAlarmComments>' +
'        <tns:alarmID>{{.AlarmID}}</tns:alarmID>' +
'        <tns:comments>{{.Comments}}</tns:comments>' +
'    </tns:AddAlarmComments>' +
'  </env:Body>' +
'</env:Envelope>';

var tmplGetAlarmByID =
'<?xml version="1.0" encoding="UTF-8"?>' +
'<SOAP-ENV:Envelope xmlns:ns0="http://www.logrhythm.com/webservices" xmlns:ns1="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">' +
' <SOAP-ENV:Header>' +
'  <wsse:Security mustUnderstand="true">' +
'   <wsse:UsernameToken>' +
'    <wsse:Username>{{.Username}}</wsse:Username>' +
'    <wsse:Password>{{.Password}}</wsse:Password>' +
'   </wsse:UsernameToken>' +
'  </wsse:Security>' +
' </SOAP-ENV:Header>' +
' <ns1:Body>' +
"  <ns0:GetAlarmByID xmlns:ns1='http://www.logrhythm.com/webservices'>" +
'    <ns1:alarmID>{{.AlarmID}}</ns1:alarmID>' +
'  </ns0:GetAlarmByID>' +
' </ns1:Body>' +
'</SOAP-ENV:Envelope>';

var tmplGetAlarmEventsByID = '<?xml version="1.0" encoding="UTF-8"?>' +
'<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:tns="http://www.logrhythm.com/webservices" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ins0="http://schemas.microsoft.com/2003/10/Serialization/Arrays">' +
'  <env:Header>' +
'    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
'      <wsse:UsernameToken xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="UsernameToken-1">' +
'       <wsse:Username>{{.Username}}</wsse:Username>' +
'        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">{{.Password}}</wsse:Password>' +
'      </wsse:UsernameToken>' +
'    </wsse:Security>' +
'  </env:Header>' +
'  <env:Body>' +
'    <tns:GetAlarmEventsByID>' +
'        <tns:alarmID>{{.AlarmID}}</tns:alarmID>' +
'        <tns:includeRawLog>{{.IncludeRawLog}}</tns:includeRawLog>' +
'    </tns:GetAlarmEventsByID>' +
'  </env:Body>' +
'</env:Envelope>';

var tmplGetAlarmHistoryByID = '<?xml version="1.0" encoding="UTF-8"?>' +
'<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:tns="http://www.logrhythm.com/webservices" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ins0="http://schemas.microsoft.com/2003/10/Serialization/Arrays">' +
'  <env:Header>' +
'    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
'      <wsse:UsernameToken xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="UsernameToken-1">' +
'        <wsse:Username>{{.Username}}</wsse:Username>' +
'        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">{{.Password}}</wsse:Password>' +
'      </wsse:UsernameToken>' +
'    </wsse:Security>' +
'  </env:Header>' +
'  <env:Body>' +
'    <tns:GetAlarmHistoryByID>' +
'        <tns:alarmID>{{.AlarmID}}</tns:alarmID>' +
'        <tns:includeNotifications>{{.IncludeNotifications}}</tns:includeNotifications>' +
'        <tns:includeComments>{{.IncludeComments}}</tns:includeComments>' +
'    </tns:GetAlarmHistoryByID>' +
'  </env:Body>' +
'</env:Envelope>';

var tmplUpdateAlarmStatus = '<?xml version="1.0" encoding="UTF-8"?>' +
'<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:tns="http://www.logrhythm.com/webservices" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ins0="http://schemas.microsoft.com/2003/10/Serialization/Arrays">' +
'  <env:Header>' +
'    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
'      <wsse:UsernameToken xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="UsernameToken-1">' +
'        <wsse:Username>{{.Username}}</wsse:Username>' +
'        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">{{.Password}}</wsse:Password>' +
'      </wsse:UsernameToken>' +
'    </wsse:Security>' +
'  </env:Header>' +
'  <env:Body>' +
'    <tns:UpdateAlarmStatus>' +
'        <tns:alarmID>{{.AlarmID}}</tns:alarmID>' +
'        <tns:status>{{.Status}}</tns:status>' +
'        {{.Comments}}' +
'    </tns:UpdateAlarmStatus>' +
'  </env:Body>' +
'</env:Envelope>';

var tmplGetFirstPageAlarmsByAlarmStatus =
'<?xml version="1.0" encoding="UTF-8"?>' +
'<SOAP-ENV:Envelope xmlns:ns0="http://www.logrhythm.com/webservices" xmlns:ns1="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">' +
' <SOAP-ENV:Header>' +
'  <wsse:Security mustUnderstand="true">' +
'   <wsse:UsernameToken>' +
'    <wsse:Username>{{.Username}}</wsse:Username>' +
'    <wsse:Password>{{.Password}}</wsse:Password>' +
'   </wsse:UsernameToken>' +
'  </wsse:Security>' +
' </SOAP-ENV:Header>' +
' <ns1:Body>' +
"    <ns1:GetFirstPageAlarmsByAlarmStatus xmlns:ns1='http://www.logrhythm.com/webservices'>" +
'      <ns1:startDate>{{.StartDate}}</ns1:startDate>' +
'      <ns1:endDate>{{.EndDate}}</ns1:endDate>' +
'      <ns1:status>{{.Status}}</ns1:status>' +
'      <ns1:allUsers>{{.AllUsers}}</ns1:allUsers>' +
'      <ns1:maximumResultsPerPage>{{.MaxResultsPerPage}}</ns1:maximumResultsPerPage>' +
'    </ns1:GetFirstPageAlarmsByAlarmStatus>' +
' </ns1:Body>' +
'</SOAP-ENV:Envelope>'

var tmplGetNextPageAlarms = '<?xml version="1.0" encoding="UTF-8"?>' +
'<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:tns="http://www.logrhythm.com/webservices" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ins0="http://schemas.microsoft.com/2003/10/Serialization/Arrays">' +
'  <env:Header>' +
'    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
'      <wsse:UsernameToken xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="UsernameToken-1">' +
'        <wsse:Username>{{.Username}}</wsse:Username>' +
'        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">{{.Password}}</wsse:Password>' +
'      </wsse:UsernameToken>' +
'    </wsse:Security>' +
'  </env:Header>' +
'  <env:Body>' +
'    <tns:GetNextPageAlarms>' +
'      <tns:nextPageID>{{.NextPageID}}</tns:nextPageID>' +
'    </tns:GetNextPageAlarms>' +
'  </env:Body>' +
'</env:Envelope>';

var tmplGetHostByEntity = '<?xml version="1.0" encoding="UTF-8"?>' +
'  <SOAP-ENV:Envelope xmlns:ns0="http://www.logrhythm.com/webservices" xmlns:ns1="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">' +
'  <SOAP-ENV:Header>' +
'    <wsse:Security mustUnderstand="true">' +
'      <wsse:UsernameToken>' +
'        <wsse:Username>{{.Username}}</wsse:Username>' +
'        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">{{.Password}}</wsse:Password>' +
'      </wsse:UsernameToken>' +
'    </wsse:Security>' +
'  </SOAP-ENV:Header>' +
'  <ns1:Body>' +
'    <ns0:GetHostsByEntity xmlns:ns1="http://www.logrhythm.com/webservices">' +
'      <ns1:entityID>{{.EntityId}}</ns1:entityID>' +
'    </ns0:GetHostsByEntity>' +
'  </ns1:Body>' +
'</SOAP-ENV:Envelope>';

var tmplAddHost1 = '<?xml version="1.0" encoding="UTF-8"?>' +
'<SOAP-ENV:Envelope xmlns:ns0="http://www.logrhythm.com/webservices" xmlns:ns1="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">' +
' <SOAP-ENV:Header>' +
'  <wsse:Security mustUnderstand="true">' +
'   <wsse:UsernameToken>' +
'    <wsse:Username>{{.Username}}</wsse:Username>' +
'    <wsse:Password>{{.Password}}</wsse:Password>' +
'   </wsse:UsernameToken>' +
'  </wsse:Security>' +
' </SOAP-ENV:Header>' +
' <ns1:Body>' +
'  <ns0:AddHost xmlns:ns1="http://www.logrhythm.com/webservices">' +
'    <ns0:hostToAdd>' +
'        <ns0:EntityID>{{.EntityId}}</ns0:EntityID>' +
'        <ns0:HostName>{{.Hostname}}</ns0:HostName>' +
'        <ns0:Identifiers>';


var tmplAddHostIdentifier = '           <ns0:HostIdentifierDataModel>' +
'               <ns0:IdentifierType>{{.Type}}</ns0:IdentifierType>' +
'               <ns0:IdentifierValue>{{.Value}}</ns0:IdentifierValue>' +
'               <ns0:Add>true</ns0:Add>' +
'           </ns0:HostIdentifierDataModel>'


var tmplAddHost2 = '        </ns0:Identifiers>' +
'        <ns0:ShortDescription>{{.ShortDesc}}</ns0:ShortDescription>' +
'        <ns0:LongDescription>{{.LongDesc}}</ns0:LongDescription>' +
'        <ns0:DateUpdated>{{.DateUpdated}}</ns0:DateUpdated>' +
'        <ns0:RiskThreshold>{{.RiskThreshold}}</ns0:RiskThreshold>' +
'        <ns0:OSType>{{.OsType}}</ns0:OSType>' +
'        <ns0:OSVersion>{{.OsVersion}}</ns0:OSVersion>' +
'        <ns0:ThreatThreshold>{{.ThreatThreshold}}</ns0:ThreatThreshold>' +
'    </ns0:hostToAdd>' +
'  </ns0:AddHost>' +
' </ns1:Body>' +
'</SOAP-ENV:Envelope>'

var tmpExecuteQuery = ' <SOAP-ENV:Envelope xmlns:ns0="http://www.logrhythm.com/webservices" xmlns:ns1="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"    >' +
' <SOAP-ENV:Header>' +
'        <wsse:Security mustUnderstand="true">' +
'            <wsse:UsernameToken>' +
'                <wsse:Username>{{.Username}}</wsse:Username>' +
'                <wsse:Password>{{.Password}}</wsse:Password>' +
'            </wsse:UsernameToken>' +
'        </wsse:Security>' +
'    </SOAP-ENV:Header>' +
' <ns1:Body>' +
'   <ExecuteQuery xmlns="http://www.logrhythm.com/webservices">' +
'     <Query xmlns:i="http://www.w3.org/2001/XMLSchema-instance">' +
'       <includeRawLogs>false</includeRawLogs>' +
'       <logSourceIDs xmlns:d5p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays" i:nil="true" />' +
'       <logSourceListIDs xmlns:d5p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays" i:nil="true" />' +
'       <MaxItems>100</MaxItems>' +
'       <PrimaryFilter>' +
'         <LogQueryFilterDataModel>' +
'           <FilterType>NormalMsgDateRange</FilterType>' +
'           <FilterMode>FilterIn</FilterMode>' +
'           <FilterOperator>And</FilterOperator>' +
'           <FilterValues i:type="LogQueryFilterValueDateRangeDataModel">' +
'             <ValueType>DateRange</ValueType>' +
'             <Value>' +
'               <LogQueryDateRangeValue>' +
'                 <StartRangeValue>{{.StartDate}}</StartRangeValue>' +
'                 <EndRangeValue>{{.EndDate}}</EndRangeValue>' +
'               </LogQueryDateRangeValue>' +
'             </Value>' +
'           </FilterValues>' +
'           <IncludeNullValues>false</IncludeNullValues>' +
'         </LogQueryFilterDataModel>' +
'         <LogQueryFilterDataModel>' +
'           <FilterType>Message</FilterType>' +
'           <FilterMode>FilterIn</FilterMode>' +
'           <FilterOperator>And</FilterOperator>' +
'           <FilterValues i:type="LogQueryFilterValueStringDataModel">' +
'             <ValueType>String</ValueType>' +
'             <Value xmlns:d8p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays">' +
'               <d8p1:string>{{.Keyword}}</d8p1:string>' +
'             </Value>' +
'           </FilterValues>' +
'           <IncludeNullValues>false</IncludeNullValues>' +
'         </LogQueryFilterDataModel>' +
'       </PrimaryFilter>' +
'       <QueryEventManager>true</QueryEventManager>' +
'       <QueryLogManagers>false</QueryLogManagers>' +
'       <CacheID i:nil="true" />' +
'       <PageNumber>0</PageNumber>' +
'       <TotalPages>0</TotalPages>' +
'       <PageSize>100</PageSize>' +
'       <LogManagers xmlns:d5p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays">' +
'         <d5p1:int>1</d5p1:int>' +
'       </LogManagers>' +
'       <GetPagingStructure>false</GetPagingStructure>' +
'     </Query>' +
'   </ExecuteQuery>' +
' </ns1:Body>' +
'</SOAP-ENV:Envelope>'

// global variables and helper functions

var soapActionURIGetNextPageAlarms               = 'http://www.logrhythm.com/webservices/AlarmService/GetNextPageAlarms';
var soapActionURIGetFirstPageAlarmsByAlarmStatus = 'http://www.logrhythm.com/webservices/AlarmService/GetFirstPageAlarmsByAlarmStatus';
var logRhythmAlarmAPI = params.use_ntlm ? 'AlarmServiceWindowsAuth.svc' : 'AlarmServiceBasicAuth.svc';
var logRhythmHostAPI = params.use_ntlm ? 'HostServiceWindowsAuth.svc' : 'HostServiceBasicAuth.svc';
var logRhythmQueryAPI = params.use_ntlm ? 'LogQueryServiceWindowsAuth.svc' : 'LogQueryServiceBasicAuth.svc';
var defaultAlarmsPageSize = 2000;
var defaultCount = 1000;
var alarmsFieldsToRemove = ["EntityID","LastUpdatedID","LastUpdatedName","DateInserted","DateUpdated","EventDateFirst","EventDateLast","EventCount","RuleID"];
var hostsFieldsToRemove = ["Key","Identifiers"];

var myTimezone = new Date().getTimezoneOffset();
var tz = params.timeZone ? parseInt(params.timeZone) : myTimezone;

var fixUrl = function(base) {
    res = base;
    if (base && base[base.length - 1] != '/') {
        res = res + '/';
    }
    return res + 'LogRhythm.API/Services/';
};

var getRequestUrl = function(api) {
    var url;
    // includes server URL that starts with http or https
    if (params.Host.startsWith('http')) {
        url = fixUrl(params.Host) + api;
    }
    else {
        url = 'https://' + fixUrl(params.Host) + api;
    }
    return url;
};


var getRaw = function(url) {
    username = params.Credentials.identifier.split('\\')[1]
    password = params.Credentials.password
    domain = params.domain
    if (params.use_ntlm) {
        res = http(
            url,
            {
                AuthProtocol:['NTLM'],
                Username: username,
                Password: password,
                Domain: domain,
                Method: 'GET'
            },
            params.Insecure,
            params.useproxy
        );
    } else {
        res = http(
            url,
            {
                Method: 'GET',
            },
            params.Insecure,
            params.useproxy
        );
    }
    return res;
};

var fixTemplate = function(template, data) {
    var keys = Object.keys(data);
    for (var i = 0 ; i < keys.length; i++) {
        var key = keys[i];
        template = template.replace('{{.'+key+'}}',data[key]);
    }
    return template;
};

var sendRequest = function(envelope, soapAction, apiUrl) {
    username = params.Credentials.identifier.split('\\')[1]
    password = params.Credentials.password
    domain = params.domain
    url = getRequestUrl(apiUrl)
    if (params.use_ntlm) {
        res = http(
            url,
            {
                Method: 'POST',
                AuthProtocol:['NTLM'],
                Username: username,
                Password: password,
                Domain: domain,
                Body: envelope,
                Headers: {
                    'Content-Type': ['text/xml'],
                    Soapaction: [soapAction]
                }
            },
            params.Insecure,
            params.useproxy
        );
    } else {
        res = http(
            url,
            {
                Method: 'POST',
                Body: envelope,
                Headers: {
                    'Content-Type': ['text/xml; charset=utf-8'],
                    Soapaction: [soapAction]
                }
            },
            params.Insecure,
            params.useproxy
        );
    }

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request to LogRhythm ' + url + ' failed, request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
    }
    return res.Body;
};

var parseResponse = function(body) {
    return JSON.parse(x2j(body));
};

var doBatch = function(envelope, action, count, pageSize) {
    var alarmPath = 'Envelope.Body.GetFirstPageAlarmsByAlarmStatusResponse.GetFirstPageAlarmsByAlarmStatusResult.Alarms.AlarmSummaryDataModel';
    var hasMorePath = 'Envelope.Body.GetFirstPageAlarmsByAlarmStatusResponse.GetFirstPageAlarmsByAlarmStatusResult.HasMoreResults';
    var nextPagePath = 'Envelope.Body.GetFirstPageAlarmsByAlarmStatusResponse.GetFirstPageAlarmsByAlarmStatusResult.NextPageID';
    var alarms = [];
    var res = parseResponse(sendRequest(envelope, action, logRhythmAlarmAPI));
    while (true) {
        var alarmObj = dq(res,alarmPath);
        if (!alarmObj) {
            break;
        }
        if (alarmObj.length) {
            alarms = alarms.concat(alarmObj);
        } else {
            alarms.push(alarmObj);
        }
        var hasMore = dq(res,hasMorePath);
        var nextPage  = dq(res,nextPagePath);
        if (!hasMore || count <= pageSize || count <= alarms.length || !nextPage) {
            break;
        }

        var obj = {
            Username: params.Credentials.identifier,
            Password: params.Credentials.password,
            NextPageID: nextPage
        };
        var nextEnvelope = fixTemplate(tmplGetNextPageAlarms, obj);
        res = parseResponse(sendRequest(nextEnvelope, soapActionURIGetNextPageAlarms, logRhythmAlarmAPI));
        alarmPath = 'Envelope.Body.GetNextPageAlarmsResponse.GetNextPageAlarmsResult.Alarms.AlarmSummaryDataModel';
        hasMorePath = 'Envelope.Body.GetNextPageAlarmsResponse.GetNextPageAlarmsResult.HasMoreResults';
        nextPagePath = 'Envelope.Body.GetNextPageAlarmsResponse.GetNextPageAlarmsResult.NextPageID';
    }

    alarms.forEach(function(element) {
        alarmsFieldsToRemove.forEach(function(field){
            delete element[field];
        });
    });

    return alarms.length > count ? alarms.slice(0,count) : alarms;
};

function fixDictionaryKeys(dict){
    //remove the word 'Alarm' from dictionary keys (e.g AlarmID to ID)
    Object.keys(dict).forEach(function(key) {
        if(key.indexOf("Alarm") !== -1){
            var newkey = key.replace('Alarm', '');
            dict[newkey] = dict[key];
            delete dict[key];
        }
    });
}

function getAlarmsData(allUsers, count, pageSize, startDate, endDate, status, dataObj) {
    dataObj.StartDate = startDate;
    dataObj.EndDate = endDate;
    dataObj.Status = status;
    dataObj.AllUsers = allUsers;
    dataObj.MaxResultsPerPage = pageSize;
    var envelope = fixTemplate(tmplGetFirstPageAlarmsByAlarmStatus, dataObj);
    return doBatch(envelope, soapActionURIGetFirstPageAlarmsByAlarmStatus, count, pageSize);
}

var prepareDetailsString = function(al) {
    return JSON.stringify(
        {
            AlarmRuleID: al.AlarmRuleID,
            AlarmStatus: al.AlarmStatus,
            EntityID: al.EntityID,
            LastUpdatedID: al.LastUpdatedID,
            EventCount: al.EventCount,
            EventDateFirst: al.EventDateFirst,
            EventDateLast: al.EventDateLast,
            RBPAvg: al.RBPAvg,
            RBPMax: al.RBPMax,
            DateInserted: al.DateInserted,
            DateUpdated: al.DateUpdated,
            AlarmRuleName: al.AlarmRuleName,
            EntityName: al.EntityName,
            LastUpdatedName: al.LastUpdatedName
        }
    );
};

var getOccurredTime = function(al) {
    var occurred = new Date();
    if (al.AlarmDate) {
        var hour = tz / 60;
        var minute = tz % 60;
        var tzPrefix = tz < 0 ? '-' : '+';
        var hourstr = hour +'';
        if (hourstr.length < 2) {
            hourstr = '0' + hourstr;
        }
        var minutestr = minute +'';
        if (minutestr.length < 2) {
            minutestr = '0' + minutestr;
        }
        occurred = new Date(Date.parse(al.AlarmDate + tzPrefix + hourstr + minutestr));
    }
    return occurred;
};

var alarmsToIncident = function(alarmList, lastRun) {
    var incs = [];
    var orgLastId = lastRun.lastId;
    for (var i = 0; i < alarmList.length; i++) {
        logDebug("Got alarm from LR",JSON.stringify(alarmList[i]));
        inc = {
            name: 'LogRhythm alarm ' + alarmList[i].AlarmID,
            occurred: getOccurredTime(alarmList[i]),
            created: new Date(),
            details: prepareDetailsString(alarmList[i]),
            rawJSON: JSON.stringify(alarmList[i])
        };
        // Check that it is in the time range and in the id range
        var alarmIdInt = parseInt(alarmList[i].AlarmID);
        if (alarmIdInt && alarmIdInt <= orgLastId) {
            continue;
        }
        if (alarmIdInt > lastRun.lastId) {
            lastRun.lastId = alarmIdInt;
        }
        if (inc.occurred.getTime() > lastRun.lastTime) {
            lastRun.lastTime = inc.occurred.getTime();
        }
        incs.push(inc);
    }
    setLastRun(lastRun);
    logDebug("LogRythm: lastRun is",JSON.stringify(lastRun));
    logDebug("LogRythm: returning incs",JSON.stringify(incs));
    return JSON.stringify(incs);
};

function getTimeFrame(timeFrame, startArg, endArg){
    var start = new Date();
    var end = new Date();

    switch(timeFrame){
    case 'Today':
        start = new Date(end.getFullYear(), end.getMonth(), end.getDate(), 0, 0, 0, 0);
        break;
    case 'LastHour':
        start.setHours(new Date().getHours() - 1);
        break;
    case 'Last2Days':
        start.setDate(start.getDate()-2);
        break;
    case 'LastWeek':
        start.setDate(start.getDate()-7);
        break;
    case 'LastMonth':
        start.setDate(start.getDate()-30);
        break;
    case 'Custom':
        if(!startArg){
            throw 'start-date argument is missing';
        }

        if(!endArg){
            throw 'end-date argument is missing';
        }

        start = new Date(startArg);
        end = new Date(endArg);
    }


    return {
        start: start.toISOString(),
        end: end.toISOString()
    };
}

var getDateAsString = function(d) {
    return d.toISOString();
}

function processAlarmEventsMd(mdRaw){
    // flattening the AlarmEvents structure
    var processedMd = {};
    mdRaw = mdRaw['LogDataModel'];
    Object.keys(mdRaw).forEach(function(key) {
        if (mdRaw[key] === undefined || mdRaw[key] === "" || mdRaw[key] === "NaN") {
            return;
        }
        else if (typeof (mdRaw[key]) === 'object'){
            var inputString = "";
            Object.keys(mdRaw[key]).forEach(function(innerKey) {
                inputString += innerKey + ":" + mdRaw[key][innerKey] + "\n";
            });
            processedMd[key] = inputString;
        } else {
            processedMd[key] = mdRaw[key];
        }
    });
    return processedMd;
}

// commands functions

function addAlarmComments(args){
    // corresponds to lr-add-alarm-comments command. Adds a comment to an alarm

    var dataObj = {
        Username: params.Credentials.identifier,
        Password: params.Credentials.password,
        AlarmID: args['alarm-id'],
        Comments: args['comments']
    };


    var soapActionURIAddAlarmComments = 'http://www.logrhythm.com/webservices/AlarmService/AddAlarmComments';
    var envelope = fixTemplate(tmplAddAlarmComment, dataObj);
    var jsResponse = parseResponse(sendRequest(envelope, soapActionURIAddAlarmComments, logRhythmAlarmAPI));
    var mdRaw = dq(jsResponse, 'Envelope.Body.AddAlarmCommentsResponse.AddAlarmCommentsResult');

    fixDictionaryKeys(mdRaw);


    var md = 'LogRhythm added alarm comment ' + args['comments'] + ' for ID: ' + args['alarm-id'];


    var ec= {};
    ec["LogRhythm.Alarm(val.ID && val.ID == " + args['alarm-id'] + ")"] = {'ID' : args['alarm-id']};
    ec["LogRhythm.Alarm(val.ID && val.ID == " + args['alarm-id'] + ").Comment"] = [args['comments']];

    return {
        Type: entryTypes.note,
        Contents: jsResponse,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
}

function getAlarmById(args){
    // corresponds to lr-get-alarm-by-id command. Get the data by a specific alarm id

    var dataObj = {
        Username: params.Credentials.identifier,
        Password: params.Credentials.password,
        AlarmID: args['alarm-id']
    };

    var soapActionURIGetAlarmByID = 'http://www.logrhythm.com/webservices/AlarmService/GetAlarmByID';
    var envelope = fixTemplate(tmplGetAlarmByID, dataObj);
    var jsResponse =  parseResponse(sendRequest(envelope, soapActionURIGetAlarmByID, logRhythmAlarmAPI));
    var mdRaw = dq(jsResponse, 'Envelope.Body.GetAlarmByIDResponse.GetAlarmByIDResult');
    if (mdRaw['-i']) {
        delete mdRaw['-i'];
    }

    fixDictionaryKeys(mdRaw);

    alarmsFieldsToRemove.forEach(function(field){
        delete mdRaw[field];
    });

    var md = tableToMarkdown('LogRhythm alarm for ID: ' + args['alarm-id'],  mdRaw);

    var ec = {};
    ec["LogRhythm.Alarm(val.ID && val.ID == " + mdRaw['ID'] + ")"] = mdRaw;


    return {
        Type: entryTypes.note,
        Contents: jsResponse,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
}

function getAlarmEventsById(args){
    // corresponds to lr-get-alarm-events-by-id command. Get the alarm's events by a specific alarm id


    var fieldsToRemove = ["Bytes","ClassificationID","ClassificationTypeName","CommonEventID","DirectionName","EntityID","ImpactedZone",
    "ImpactedEntityID","ImpactedHostID","ImpactedLocation","ImpactedLocationID","ImpactedNATPort","ImpactedNetwork","ImpactedNetworkID",
    "ImpactedPort","LogDate","LogSourceHost","LogSourceHostID","LogSourceID","LogSourceType","LogSourceTypeName","Login","MPERuleID",
    "MPERuleName","MessageID","NormalDateMax","OriginEntityID","OriginHostID","OriginLocation","OriginLocationID","LogSourceHostName",
    "OriginNATPort","OriginName","OriginNetwork","OriginNetworkID","OriginPort","Priority","ProcessID","ProtocolID","Direction",
    "SequenceNumber","ServiceID","ServiceName","Count","DateInserted","OriginZone","MessageType","EntityName","ImpactedHostID"];

    var dataObj = {
        Username: params.Credentials.identifier,
        Password: params.Credentials.password,
        AlarmID: args['alarm-id'],
        IncludeRawLog: args['include-raw-log'] === 'true'
    };

    var soapActionURIGetAlarmsEventsByID = 'http://www.logrhythm.com/webservices/AlarmService/GetAlarmEventsByID';
    var envelope = fixTemplate(tmplGetAlarmEventsByID, dataObj);
    var jsResponse = parseResponse(sendRequest(envelope, soapActionURIGetAlarmsEventsByID, logRhythmAlarmAPI));
    var mdRaw = dq(jsResponse, 'Envelope.Body.GetAlarmEventsByIDResponse.GetAlarmEventsByIDResult.Events')
    if (mdRaw['-i']) {
        delete mdRaw['-i'];
    }

    if(!mdRaw['LogDataModel']){
        return {
            Type: entryTypes.note,
            Contents: "No events found for this alarm",
            ContentsFormat: formats.text
        };
    }

    var processedMd = processAlarmEventsMd(mdRaw);


    fieldsToRemove.forEach(function(field){
        delete processedMd[field];
    });


    var md = tableToMarkdown('LogRhythm alarm events for ID: ' + args['alarm-id'],  processedMd);


    var historyRow = {};
    historyRow['ID'] = args['alarm-id'];
    historyRow['Event'] = processedMd;

    var ec = {};
    ec['LogRhythm.Alarm(val.ID && val.ID == ' + args['alarm-id'] + ')'] = historyRow;


    return {
        Type: entryTypes.note,
        Contents: jsResponse,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
}

function getAlarmHistoryById(args){
    // corresponds to lr-get-alarm-history-by-id command. Get the alarm's history by a specific alarm id

    var dataObj = {
        Username: params.Credentials.identifier,
        Password: params.Credentials.password,
        AlarmID: args['alarm-id'],
        IncludeComments: args['include-comments'] === 'true',
        IncludeNotifications: args['include-notifications'] === 'true'
    };

    //Verify that at least one of the 2 are marked as true, else throw an error
    if (!dataObj.IncludeNotifications && !dataObj.IncludeComments) {
        throw 'At least one of "include-comments", "include-notifications" should be true';
    }

    var soapActionURIGetAlarmsHistoryByID = 'http://www.logrhythm.com/webservices/AlarmService/GetAlarmHistoryByID';
    var envelope = fixTemplate(tmplGetAlarmHistoryByID, dataObj);
    var jsResponse =  parseResponse(sendRequest(envelope, soapActionURIGetAlarmsHistoryByID, logRhythmAlarmAPI));
    var md = "", mdRaw;
    if (dataObj.IncludeNotifications) {
        mdRaw = dq(jsResponse, 'Envelope.Body.GetAlarmHistoryByIDResponse.GetAlarmHistoryByIDResult.Notifications.AlarmNotificationDataModel')
        md = tableToMarkdown('LogRhythm alarm notifications history for ID: ' + args['alarm-id'],  mdRaw);
    }
    if (dataObj.IncludeComments) {
        if (md.length > 0) {
            md += '\n\n';
        }
        mdRaw = dq(jsResponse, 'Envelope.Body.GetAlarmHistoryByIDResponse.GetAlarmHistoryByIDResult.Comments.AlarmCommentDataModel')
        md += tableToMarkdown('LogRhythm alarm comments history for ID: ' + args['alarm-id'],  mdRaw);
    }

    var historyRow = {};
    historyRow['ID'] = args['alarm-id'];
    historyRow['History'] = mdRaw;

    var ec = {};
    ec['LogRhythm.Alarm(val.ID && val.ID == ' + args['alarm-id'] + ')'] = historyRow;

    return {
        Type: entryTypes.note,
        Contents: jsResponse,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
}

function updateAlarmStatus(args){
    // corresponds to lr-update-alarm-status command. Updates an alarm's current status

    var dataObj = {
        Username: params.Credentials.identifier,
        Password: params.Credentials.password,
        AlarmID: args['alarm-id'],
        Status: args['status'],
        Comments: (args.comments ? ('<tns:comments>' + args.comments + '</tns:comments>') : '')
    };

    var soapActionURIUpdateAlarmStatus = 'http://www.logrhythm.com/webservices/AlarmService/UpdateAlarmStatus';
    var envelope = fixTemplate(tmplUpdateAlarmStatus, dataObj);
    var jsResponse = parseResponse(sendRequest(envelope, soapActionURIUpdateAlarmStatus, logRhythmAlarmAPI));
    var mdRaw = dq(jsResponse, 'Envelope.Body.UpdateAlarmStatusResponse.UpdateAlarmStatusResult')

    fixDictionaryKeys(mdRaw);

    var md = 'LogRhythm alarm status updated for alarm: *' + args['alarm-id']+'* status: *' + args.status +'*';

    var status = {
        'Status' : args['status'],
        'ID' : args['alarm-id']
    };

    var ec= {};
    ec["LogRhythm.Alarm(val.ID && val.ID == " + args['alarm-id'] + ")"] = status;

    return {
        Type: entryTypes.note,
        Contents: jsResponse,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext : ec
    };
}

function getAlarms(dataArgs){
    /* corresponds to lr-get-alarms command. Retrieves data about alarms in a particular time range.
       time format follows iso 8601, for example: startDate="2017-03-27" */

    var dataObj = {
        Username: params.Credentials.identifier,
        Password: params.Credentials.password,
    };

    var allUsers = dataArgs['all-users'] === 'true';
    var count = dataArgs.count ? parseInt(dataArgs.count) : defaultCount;
    count = count || defaultCount;

    var pageSize = params.pageSize ? parseInt(params.pageSize) : defaultAlarmsPageSize;
    pageSize = pageSize || defaultAlarmsPageSize;
    if (count < pageSize) {
        pageSize = count;
    }

    var timeFrame = getTimeFrame(dataArgs['time_frame'], dataArgs['start-date'], dataArgs['end-date']);
    var alarms = getAlarmsData(allUsers, count, pageSize, timeFrame.start, timeFrame.end, dataArgs.status, dataObj);

    var ec = {};

    alarms.forEach(function(alarm) {
        fixDictionaryKeys(alarm);
        ec['LogRhythm.Alarm(val.ID && val.ID == ' + alarm['ID'] + ')'] = alarm;
    });

    if (alarms.length) {
        var md = tableToMarkdown('',  alarms);
        return {
            Type: entryTypes.note,
            Contents: alarms,
            ContentsFormat: formats.json,
            HumanReadable: md,
            EntryContext: ec
        };
    } else {
        return {
            Type: entryTypes.note,
            Contents: "No results",
            ContentsFormat: formats.text
        };
    }
}

function getHostsByEntityId(dataArgs){
    var dataObj = {
        Username: params.Credentials.identifier,
        Password: params.Credentials.password,
        EntityId: dataArgs['entity-id']
    };

    var soapActionURIUgethostbyentity = 'http://www.logrhythm.com/webservices/HostService/GetHostsByEntity';
    var envelope = fixTemplate(tmplGetHostByEntity, dataObj);
    var jsResponse = parseResponse(sendRequest(envelope, soapActionURIUgethostbyentity, logRhythmHostAPI));

    var mdRaw = dq(jsResponse, 'Envelope.Body.GetHostsByEntityResponse.GetHostsByEntityResult.HostDataModel')

    if (mdRaw['-i']) {
        delete mdRaw['-i'];
    }

    fixDictionaryKeys(mdRaw);

    mdRaw.forEach(function(row){
        hostsFieldsToRemove.forEach(function(field){
            delete row[field];
        });
    });

    var md = tableToMarkdown('LogRhythm hosts for entity ID: ' + args['entity-id'],  mdRaw);

    var ec = {};
    ec["LogRhythm.Host(val.ID && val.ID == " + mdRaw['ID'] + ")"] = mdRaw;

    return {
        Type: entryTypes.note,
        Contents: jsResponse,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };

}

function addHost(dataArgs){
    var dataObj = {
        Username: params.Credentials.identifier,
        Password: params.Credentials.password,
        Hostname: dataArgs['host-name'],
        EntityId: dataArgs['entity-id'],
        ShortDesc: dataArgs['short-description'],
        LongDesc: dataArgs['long-description'],
        DateUpdated: new Date().toISOString(),
        RiskThreshold: dataArgs['risk-threshold'],
        OsType: dataArgs['os-type'],
        OsVersion: dataArgs['os-version'],
        ThreatThreshold: dataArgs['threat-threshold']
    };

    var soapActionURIUaddHost = 'http://www.logrhythm.com/webservices/HostService/AddHost';

    var envelope = fixTemplate(tmplAddHost1, dataObj);

    if(dataArgs['ip-address']){
        envelope += fixTemplate(tmplAddHostIdentifier, {Type: 'IPAddress', Value: dataArgs['ip-address']});
    }
    if(dataArgs['dns-name']){
        envelope += fixTemplate(tmplAddHostIdentifier, {Type: 'DNSName', Value: dataArgs['dns-name']});
    }
    if(dataArgs['windows-name']){
        envelope += fixTemplate(tmplAddHostIdentifier, {Type: 'WindowsName', Value: dataArgs['windows-name']});
    }

    envelope += fixTemplate(tmplAddHost2, dataObj);

    var jsResponse = parseResponse(sendRequest(envelope, soapActionURIUaddHost, logRhythmHostAPI));

    var mdRaw = dq(jsResponse, 'Envelope.Body.AddHostResponse.AddHostResult')

    if (mdRaw['Succeeded'] == 'true'){
        var host = {};
        host["ShortDescription"] = dataObj['ShortDesc'];
        host["LongDescription"] = dataObj['LongDesc'];
        host["HostID"] = mdRaw['DataID'];
        host["RecordStatus"] = 'NewRecord';
        host["DateUpdated"] = dataObj['DateUpdated'];
        host["ThreatThreshold"] = dataObj['ThreatThreshold'];
        host["HostName"] = dataObj['Hostname'];
        host["OSVersion"] = dataObj['OsVersion'];
        host["RiskThreshold"] = dataObj['RiskThreshold'];
        host["EntityID"] = dataObj['EntityId'];
        host["OSType"] = dataObj['OsType'];

        var ec = {};
        ec["LogRhythm.Host"] = host;

        return {
            Type: entryTypes.note,
            Contents: jsResponse,
            ContentsFormat: formats.json,
            HumanReadable: 'Host ' + dataArgs['host-name'] + ' added succesfuly',
            EntryContext: ec
        };

    }
    else{
        throw mdRaw['Errors']['ErrorInfo']['ErrorMessage'];
    }
}

function executeQuery(dataArgs){

    var queryFieldsToRemove = ["Amount","Bytes","BytesIn","BytesOut","ClassificationID","ClassificationTypeName","CommonEventID","DirectionName","Domain","Duration","EntityID",
   "ImpactedEntityName","ImpactedHostID","ImpactedIP","ImpactedInterface","ImpactedLocation","ImpactedLocationID","ImpactedMAC","ImpactedNATIP","ImpactedNATPort","ImpactedEntityID",
   "ImpactedNetwork","ImpactedNetworkID","ImpactedPort","ImpactedZoneName","ItemsPacketsIn","ItemsPacketsOut","LogSourceHostID","LogSourceID","LogSourceType","MPERuleID",
   "MessageID","OriginEntityID","OriginHostID","OriginIP","OriginInterface","OriginLocation","OriginLocationID","OriginLogin","OriginMAC","OriginNATIP","OriginNATPort",
   "OriginNetwork","OriginNetworkID","OriginPort","OriginZoneName","Process","ProcessID","ProtocolID","ProtocolName","Quantity","Rate","Recipient","Sender","SequenceNumber",
   "ServiceID","ServiceName","Size","URL","Version","Account","Command","Group","DateInserted","Login","NormalDate","NormalDateMax","Object","OriginName","Subject"];

    var timeFrame = getTimeFrame(dataArgs['time_frame'], dataArgs['start-date'], dataArgs['end-date']);
    var dataObj = {
        Username: params.Credentials.identifier,
        Password: params.Credentials.password,
        Keyword: dataArgs['keyword'],
        StartDate: timeFrame.start,
        EndDate: timeFrame.end
    };

    var soapActionURIUexecuteQuery = 'http://www.logrhythm.com/webservices/LogQueryService/ExecuteQuery';
    var envelope = fixTemplate(tmpExecuteQuery, dataObj);

    var jsResponse = parseResponse(sendRequest(envelope, soapActionURIUexecuteQuery, logRhythmQueryAPI));
    var mdRaw = dq(jsResponse, 'Envelope.Body.ExecuteQueryResponse.ExecuteQueryResult.LogDataModel');

    if(mdRaw === undefined || mdRaw === null){
         return {
                Type: entryTypes.note,
                Contents: "No results",
                ContentsFormat: formats.text
            };
    }

    if(Array.isArray(mdRaw)){
        mdRaw.forEach(function(row){
            queryFieldsToRemove.forEach(function(field){
                delete row[field];
            });
        });
    }
    else{
        queryFieldsToRemove.forEach(function(field){
                delete mdRaw[field];
            });
    }

    var md = tableToMarkdown('LogRhythm query results:',  mdRaw);

    var ec = {};
    ec["LogRhythm.Log"] = mdRaw;

    return {
        Type: entryTypes.note,
        Contents: jsResponse,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
}

function fetchIncidents(){

    var dataObj = {
        Username: params.Credentials.identifier,
        Password: params.Credentials.password
    };

    var lastRun = getLastRun();
    if (!lastRun || !lastRun.lastTime) {
        lastRun = {
            lastId: 0,
            lastTime: new Date().getTime() - (10 * 60 * 1000)
        }
    }
    var pageSize = params.pageSize ? parseInt(params.pageSize) : defaultAlarmsPageSize;
    pageSize = pageSize || defaultAlarmsPageSize;
    var alarms = getAlarmsData(true, pageSize, pageSize, getDateAsString(new Date(lastRun.lastTime)), getDateAsString(new Date()), 'New',dataObj);
    if (alarms.length) {
        return alarmsToIncident(alarms, lastRun);
    }
    return '[]';
}
// The command input arg holds the command sent from the user.
switch (command) {
    // This is the call made when pressing the integration test button.
    case 'test-module':
        var url = params.use_ntlm ? getRequestUrl('AlarmServiceWindowsAuth.svc?singleWsdl') : getRequestUrl('AlarmServiceBasicAuth.svc?singleWsdl')
        var resp = getRaw(url);
        var alarmsArgs = {};
        alarmsArgs['all-users'] = "true";
        alarmsArgs['start-date'] = "2018-03-01";
        alarmsArgs['end-date'] = "2018-03-30";
        alarmsArgs['status'] = "New";
        var alarmsResponse = getAlarms(alarmsArgs);
        // if we get alarmsResponse.Type it means that no error was raised in getAlarms
        if (resp.StatusCode === 200 && alarmsResponse.Type) {
            return 'ok';
        } else if (resp.Status) {
            return resp.Status;
        } else {
            return resp;
        }
        break;
    case 'lr-add-alarm-comments':
        return addAlarmComments(args);

    case 'lr-get-alarm-by-id':
        return getAlarmById(args);

    case 'lr-get-alarm-events-by-id':
        return getAlarmEventsById(args);

    case 'lr-get-alarm-history-by-id':
        return getAlarmHistoryById(args);

    case 'lr-update-alarm-status':
        return updateAlarmStatus(args);

    case 'lr-get-alarms':
        return getAlarms(args);

    case 'lr-get-hosts-by-entity-id':
        return getHostsByEntityId(args);

    case 'lr-add-host':
        return addHost(args);

    case 'lr-execute-query':
        return executeQuery(args);

    case 'fetch-incidents':
        return fetchIncidents();
}
