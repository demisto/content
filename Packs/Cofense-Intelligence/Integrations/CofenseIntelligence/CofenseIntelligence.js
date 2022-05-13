 var reliability = params.integrationReliability;

 if(!reliability){
     reliability = 'B - Usually reliable';
 }
 var isValidReliability = function(reliability) {
     var reliability_options = ['A+ - 3rd party enrichment', 'A - Completely reliable', 'B - Usually reliable', 'C - Fairly reliable', 'D - Not usually reliable', 'E - Unreliable', 'F - Reliability cannot be judged'];
     return reliability_options.indexOf(reliability) >= 0;}
 if(!isValidReliability(reliability)) {
     return 'Error, Source Reliability value is invalid. Please choose from available reliability options.';}

  var auth = 'Basic ' + Base64.encode(params.credentials.identifier + ':' + params.credentials.password);
     var sendRequest = function(method,api,urlargs) {
         var url = params.url;
         if (url[url.length - 1] === '/') {
             url = url.substring(0, url.length - 1);
         }
         var requestUrl = url + '/' + api + encodeToURLQuery(urlargs);
         var res = http(
             requestUrl,
             {
                 Method: method,
                 Headers: {
                     'Authorization': [auth]
                 }
             },
             params.insecure,
             params.proxy
         );
         if ((res.StatusCode < 200 || res.StatusCode >= 300) && res.success === false) {
             throw 'Cofense Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
         }
         try{
             return JSON.parse(res.Body);
         }
         catch(exc){
             throw "Cofense Error: JSON parse error\n" + res;
         }
     };
     var addMD = function(threat) {
         var md = "";
         md += '### Threat ID: ' + threat.id + '\n';
         if (threat.label !== undefined) {
             md += "Name of the campaign: **" + threat.label + "**\n";
         }
         if (threat.blockSet[0].ipDetail !== undefined) {
             md += "ASN: **" + threat.blockSet[0].ipDetail.asn + " " + threat.blockSet[0].ipDetail.asnOrganization+"**\n";
         }
         if (threat.blockSet[0].ipDetail !== undefined) {
             md += "Country: **" + threat.blockSet[0].ipDetail.countryName + "**\n";
         }
         if (threat.executiveSummary !== undefined) {
             md += "#### Executive Summary: \n";
         }
         if (threat.executiveSummary !== undefined) {
             md += threat.executiveSummary + "\n";
         }
         md += "#### Threat Types:\n";
         for (var j = 0; j < threat.malwareFamilySet.length; j++){
             md += "* " + threat.malwareFamilySet[j].description + "\n";
         }
         md += '##### Last published: ' + new Date(threat.lastPublished) +'\n';
         return md;
     };
     // Returns {severityScore: 'The severity score found', md: 'The markdown for the threat', indicatorFound: 'set to true if indicator was found in threat'}
     var checkThreat = function(threat, threshold, indicator) {
         var severityLevel = 0;
         var md = '';
         var threshold_score = calcScore(threshold);
         if (threshold_score === -1) {
             throw "Cofense error: Invalid threshold value: " + threshold + ". Valid values are: None, Minor, Moderate or Major.";
         }
         res = {}
         for (var i = 0; i < threat.blockSet.length; i++){
             if (threat.blockSet[i]['impact']) {
                 var threat_score = calcScore(threat.blockSet[i]['impact']);
                 var adjusted_score = threshold_score <= threat_score ? 3 : threat_score;
                 // if the queried indicator has a severity level, we'll take it
                 if (threat.blockSet[i]['data'] === indicator) {
                     severityLevel = adjusted_score;
                     res.indicatorFound = true;
                     break;
                 }
                 severityLevel = Math.max(severityLevel, adjusted_score);
             }
         }
         var threatLevel = calcVerdict(severityLevel);
         md += 'Verdict: ' + threatLevel +'\n';
         md += addMD(threat);
         res.severityScore = severityLevel;
         res.md = md;
         return res;
     }
     var searchUrl = function(url) {
         var tmpargs = {};
         tmpargs.urlSearch = url;
         var res = sendRequest("POST","threat/search",tmpargs);
         var threats = res.data.threats;
         var ec = {};
         var md = "## Cofense URL Reputation for: "+url+"\n";
         var dbotScore = 0;
         var threatArray = [];
         var threshold = params.urlThreshold;
         var indicatorFnd = false;
         if (threats.length && threats.length !== 0) {
             ec[outputPaths.url] = {
                 Data: url
             };
             for (var k = 0; k < threats.length; k++) {
                 threatAnalysis = checkThreat(threats[k], threshold, url);
                 threatArray[k] = threats[k].id;
                 md += threatAnalysis['md'];
                 if (threatAnalysis.indicatorFound) {
                     indicatorFnd = true;
                     dbotScore = threatAnalysis['severityScore'];
                 } else if (!indicatorFnd) {
                     dbotScore = Math.max(dbotScore, threatAnalysis['severityScore']);
                 }
             }
             ec[outputPaths.url]['Cofense'] = {};
             ec[outputPaths.url].Cofense['ThreatIDs'] = threatArray;
             ec["Cofense." + outputPaths.url] = {
                 Data: url,
                 ThreatIDs: threatArray
             };
             if (dbotScore === 3) {
                 ec[outputPaths.url].Malicious = {
                     Vendor: 'Cofense',
                     Description: 'Match found in Cofense database'
                 };
                 ec["Cofense." + outputPaths.url].Malicious = ec[outputPaths.url].Malicious;
             }
         } else {
             md += "No information found for this url";
         }
         ec.DBotScore = {Indicator: url, Type: 'url', Vendor: 'Cofense', Score: dbotScore, Reliability: reliability};
         return ( {'ContentsFormat': formats.json, 'Type': entryTypes.note, 'Contents': res, "HumanReadable": md, "EntryContext": ec} );
     };
     var extractedString = function(str,limit) {
         var tmpargs = {};
         tmpargs.extractedString = str;
         var res = sendRequest("POST","threat/search",tmpargs);
         var threats = res.data.threats;
         var countThreats = 0;
         var md = "## Cofense Search Reputation for: "+str+"\n";
         var mdBody = "";
         var ec = {};
         if (threats.length !== 0) {
             if(limit === undefined){
                 limit = 10;
             }
             for(var i = 0; i < threats.length && (countThreats<limit); i++){
                 if (threats[i].hasReport === true){
                     countThreats += 1;
                     mdBody += addMD(threats[i]);
                 }
             }
             md += "There are " + countThreats + " threats regarding your string search.\n";
             md += "### Details from the last campaign\n";
             md += mdBody;
             ec = {"Cofense" : {}};
             ec.Cofense = {"String": str, "NumOfThreats": countThreats};
         } else {
             md += "There are no results for this search\n";
             ec = {"Cofense" : {}};
             ec.Cofense = {"String": str, "NumOfThreats": 0};
         }
         return ( {'ContentsFormat': formats.json, 'Type': entryTypes.note, 'Contents': res, "HumanReadable": md, "EntryContext": ec} );
     };
     var checkEmail = function(sender_name) {
         var tmpargs = {};
         tmpargs.watchListEmail = sender_name;
         var res = sendRequest("POST","threat/search",tmpargs);
         var threats = res.data.threats;
         var ec = {};
         var md = "## Cofense email Reputation for: " + sender_name + "\n";
         var dbotScore = 0;
         var threatArray = [];
         var threshold = params.emailThreshold;
         var indicatorFnd = false;
         var contextEmailKey = 'Email(val.Data && val.Data === obj.Data)';
         if (threats.length && threats.length !== 0) {
             ec[contextEmailKey] = {
                 'Data': sender_name
             };
             ec[outputPaths.email] = {
                 'Address': sender_name
             };
             for (var k = 0; k < threats.length; k++) {
                 threatAnalysis = checkThreat(threats[k], threshold, sender_name);
                 threatArray[k] = threats[k].id;
                 md += threatAnalysis['md'];
                 if (threatAnalysis.indicatorFound) {
                     indicatorFnd = true;
                     dbotScore = threatAnalysis['severityScore'];
                 } else if (!indicatorFnd) {
                     dbotScore = Math.max(dbotScore, threatAnalysis['severityScore']);
                 }
             }
             ec[contextEmailKey]['Cofense'] = {};
             ec[contextEmailKey].Cofense['ThreatIDs'] = threatArray;
             ec['Cofense.' + contextEmailKey] = {
                 Data: sender_name,
                 ThreatIDs: threatArray
             };
             if (dbotScore === 3) {
                 ec[outputPaths.email].Malicious = {
                     Vendor: 'Cofense',
                     Description: 'Match found in Cofense database'
                 };
                 ec["Cofense." + contextEmailKey].Malicious = ec[outputPaths.email].Malicious;
             }
         } else {
             md += "No infomation found for this email";
         }
         ec.DBotScore = {Indicator: sender_name, Type: 'email', Vendor: 'Cofense', Score: dbotScore, Reliability: reliability};
         return ( {'ContentsFormat': formats.json, 'Type': entryTypes.note, 'Contents': res, "HumanReadable": md, "EntryContext": ec} );
     };
     var checkMD5 = function(str) {
         var tmpargs = {};
         tmpargs.allMD5 = str;
         var res = sendRequest("POST","threat/search",tmpargs);
         var threats = res.data.threats;
         var ec = {};
         var md = "## Cofense Hash Reputation for: "+str+"\n";
         var dbotScore = 0;
         var threatArray = [];
         var threshold = params.fileThreshold;
         var indicatorFnd = false;
         var threshold_score = calcScore(threshold);
         if (threshold_score === -1) {
             throw "Cofense error: Invalid threshold value: " + threshold + ". Valid values are: None, Minor, Moderate or Major.";
         }
         if (threats.length !== 0) {
             ec[outputPaths.file] = {
                 MD5: str
             };
             for (var k = 0; k < threats.length; k++) {
                 var severityLevel = 0;
                 for (var i = 0; i < threats[k].blockSet.length; i++){
                     if (threats[k].blockSet[i]['impact']) {
                         var threat_score = calcScore(threats[k].blockSet[i]['impact']);
                         var adjusted_score = threshold_score <= threat_score ? 3 : threat_score;
                         // if the queried indicator has a severity level, we'll take it
                         if (threats[k].executableSet[i] && threats[k].executableSet[i]['md5Hex'] === str) {
                             severityLevel = adjusted_score;
                             dbotScore = severityLevel;
                             indicatorFnd = true;
                             break;
                         }
                         severityLevel = Math.max(severityLevel, adjusted_score);
                     }
                 }
                 var threatLevel = calcVerdict(severityLevel);
                 md += 'Verdict: ' + threatLevel +'\n';
                 md += addMD(threats[k]);
                 threatArray[k] = threats[k].id;
                 if (!indicatorFnd) {
                     dbotScore = Math.max(dbotScore, severityLevel);
                 }
             }
             ec[outputPaths.file]['Cofense'] = {};
             ec[outputPaths.file]['ThreatIDs'] = threatArray;
             ec['Cofense.' + outputPaths.file] = {
                     MD5: str,
                     ThreatIDs: threatArray
             };
             if (dbotScore === 3) {
                 ec[outputPaths.file].Malicious = {
                     Vendor: 'Cofense',
                     Description: 'Match found in Cofense database'
                 };
                 ec["Cofense." + outputPaths.file].Malicious = ec[outputPaths.file].Malicious;
             }
         } else {
             md += "No information found for this hash";
         }
         ec.DBotScore = {Indicator: str, Type: 'file', Vendor: 'Cofense', Score: dbotScore, Reliability: reliability};
         return ( {'ContentsFormat': formats.json, 'Type': entryTypes.note, 'Contents': res, "HumanReadable": md, "EntryContext": ec} );
     }
     var checkIP = function(ip) {
         var tmpargs = {};
         tmpargs.ip = ip;
         var res = sendRequest("POST","threat/search",tmpargs);
         var threats = res.data.threats;
         var ec = {};
         var md = "## Cofense IP Reputation for: "+ip+"\n";
         var dbotScore = 0;
         var threatArray = [];
         var threshold = params.ipThreshold;
         var indicatorFnd = false;
         var threshold_score = calcScore(threshold);
         if (threshold_score === -1) {
             throw "Cofense error: Invalid threshold value: " + threshold + ". Valid values are: None, Minor, Moderate or Major.";
         }
         if (threats.length && threats.length !== 0) {
             ec[outputPaths.ip] = {
                 Data: ip,
                 'Address': ip
             };
             for (var k = 0; k < threats.length; k++) {
                 var severityLevel = 0;
                 for (var i = 0; i < threats[k].blockSet.length; i++){
                     if (threats[k].blockSet[i].data === ip && threats[k].blockSet[i].ipDetail) {
                         ec[outputPaths.ip].ASN = threats[k].blockSet[i].ipDetail.asn;
                         ec[outputPaths.ip].GEO = {
                             "Location": (threats[k].blockSet[i].ipDetail.latitude + ', ' + threats[k].blockSet[i].ipDetail.longitude),
                             "Country": threats[k].blockSet[i].ipDetail.countryIsoCode
                         };
                     }
                     if (threats[k].blockSet[i]['impact']) {
                         var threat_score = calcScore(threats[k].blockSet[i]['impact']);
                         var adjusted_score = threshold_score <= threat_score ? 3 : threat_score;
                         // if the queried indicator has a severity level, we'll take it
                         if (threats[k].blockSet[i]['ipDetail'] && threats[k].blockSet[i]['ipDetail']['ip']===ip) {
                             severityLevel = adjusted_score;
                             dbotScore = severityLevel;
                             indicatorFnd = true;
                             break;
                         }
                         severityLevel = Math.max(severityLevel, adjusted_score);
                     }
                 }
                 var threatLevel = calcVerdict(severityLevel);
                 md += 'Verdict: ' + threatLevel +'\n';
                 md += addMD(threats[k]);
                 threatArray[k] = threats[k].id;
                 if (!indicatorFnd) {
                     dbotScore = Math.max(dbotScore, severityLevel);
                 }
             }
             ec[outputPaths.ip]['Cofense'] = {};
             ec[outputPaths.ip].Cofense['ThreatIDs'] = threatArray;
             ec["Cofense." + outputPaths.ip] = {
                 Data: ip,
                 ThreatIDs: threatArray
             };
             if (dbotScore === 3) {
                 ec[outputPaths.ip].Malicious = {
                     Vendor: 'Cofense',
                     Description: 'Match found in Cofense database'
                 };
                 ec["Cofense." + outputPaths.ip].Malicious = ec[outputPaths.ip].Malicious;
             }
         } else {
             md += "No information found for this ip";
         }
         ec.DBotScore = {Indicator: ip, Type: 'ip', Vendor: 'Cofense', Score: dbotScore, Reliability: reliability};
         return ( {'ContentsFormat': formats.json, 'Type': entryTypes.note, 'Contents': res, "HumanReadable": md, "EntryContext": ec} );
     }
     var calcVerdict = function (dbotScore) {
         switch (dbotScore){
             case 0:
                 return 'Unknown';
             case 2:
                 return 'Suspicious';
             case 3:
                 return 'Bad';
         }
     }
     var calcScore = function (severityLevel) {
         switch (severityLevel){
             case 'None':
                 return 0;
             case 'Minor':
                 return 2;
             case 'Moderate':
                 return 2;
             case 'Major':
                 return 3;
             default:
                 return -1;
         }
     }
     function addDays(theDate, days) {
         return theDate.getTime() - days*24*60*60*1000;
     }
     var updates = function(){
         var newDate = addDays(new Date(), 50);
         var tmpargs = {};
         tmpargs.timestamp = newDate;
         var res = sendRequest("POST","threat/updates", tmpargs);
         var ec = {};
         var md = "";
         return res;
     }
     switch (command) {
         // This is the call made when pressing the integration test button.
         case 'test-module':
             res = updates();
             if (res.success === true){
                 return 'ok';
             }else {
                 return JSON.stringify(res);
             }
         case "url":
             return searchUrl(args.url);
         case "cofense-search":
             return extractedString(args.str, args.limit);
         case "email":
             return checkEmail(args.email)
         case "file":
             return checkMD5(args.file);
         case "ip":
             return checkIP(args.ip);
         default:
    }
