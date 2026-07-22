var apiid = params.creds ? params.creds.identifier : params.apiid;
var apikey = params.creds ? params.creds.password : params.apikey;
var base = 'https://my.incapsula.com';
var proxy = params.proxy;

var sendRequest = function(url, body, queryName) {
    urlWithParams = (url).toString()+"?"+(body).toString()
    var res = http(
            urlWithParams,
            {
                Method: 'POST',
                Headers: {'content-type': ['application/json'], 'x-API-Id': [apiid], 'x-API-Key': [apikey]},
            },
            true,
            proxy
        );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to ' + queryName + ', request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
    }
    var response = JSON.parse(res.Body);

    if (parseInt(response.res)) {
        throw 'Got error response from incapsula for ' + queryName + '\nerror code: ' + response.res +'\nmessage: ' + response['res_message'] + '\ndebug info: ' + JSON.stringify(response['debug_info']);
    }
    return response;
}

var urlDict = {
    /*
        Account Management
     */
    'incap-add-managed-account': '/api/prov/v1/accounts/add',
    'incap-list-managed-accounts': '/api/prov/v1/accounts/list',
    'incap-add-subaccount': '/api/prov/v1/subaccounts/add',
    'incap-list-subaccounts': '/api/prov/v1/accounts/listSubAccounts',
    'incap-get-account-status': '/api/prov/v1/account',
    'incap-modify-account-configuration': '/api/prov/v1/accounts/configure',
    'incap-set-account-log-level': '/api/prov/v1/accounts/setlog',
    'incap-test-account-s3-connection': '/api/prov/v1/accounts/testS3Connection',
    'incap-test-account-sftp-connection': '/api/prov/v1/accounts/testSftpConnection',
    'incap-set-account-s3-log-storage': '/api/prov/v1/accounts/setAmazonSiemStorage',
    'incap-set-account-sftp-log-storage': '/api/prov/v1/accounts/setSftpSiemStorage',
    'incap-set-account-default-log-storage': '/api/prov/v1/accounts/setDefaultSiemStorage',
    'incap-get-account-login-token': '/api/prov/v1/accounts/gettoken',
    'incap-delete-managed-account': '/api/prov/v1/accounts/delete',
    'incap-delete-subaccount': '/api/prov/v1/subaccounts/delete',
    'incap-get-account-audit-events': '/api/prov/v1/accounts/audit',
    'incap-set-account-default-data-storage-region': '/api/prov/v1/accounts/data-privacy/set-region-default',
    'incap-get-account-default-data-storage-region': '/api/prov/v1/accounts/data-privacy/show',
    /*
        Site Management - Site Configuration
     */
    'incap-add-site':'/api/prov/v1/sites/add',
    'incap-get-site-status': '/api/prov/v1/sites/status',
    'incap-get-domain-approver-email':'/api/prov/v1/domain/emails',
    'incap-modify-site-configuration':'/api/prov/v1/sites/configure',
    'incap-modify-site-log-level':'/api/prov/v1/sites/setlog',
    'incap-modify-site-tls-support': '/api/prov/v1/sites/tls',
    'incap-modify-site-scurity-config':'/api/prov/v1/sites/configure/security',
    'incap-modify-site-acl-config':'/api/prov/v1/sites/configure/acl',
    'incap-modify-site-wl-config':'/api/prov/v1/sites/configure/whitelists',
    'incap-delete-site':'/api/prov/v1/sites/delete',
    'incap-list-sites':'/api/prov/v1/sites/list',
    'incap-get-site-report':'/api/prov/v1/sites/report',
    'incap-get-site-html-injection-rules': '/api/prov/v1/sites/htmlinjections',
    'incap-add-site-html-injection-rule': '/api/prov/v1/sites/configure/htmlInjections',
    'incap-delete-site-html-injection-rule': '/api/prov/v1/sites/configure/htmlInjections',
    'incap-create-new-csr': '/api/prov/v1/sites/customCertificate/csr',
    'incap-upload-certificate':'/api/prov/v1/sites/customCertificate/upload',
    'incap-remove-custom-integration':'/api/prov/v1/sites/customCertificate/remove',
    'incap-move-site': '/api/prov/v1/sites/moveSite',
    'incap-check-compliance': '/api/prov/v1/caa/check-compliance',
    'incap-set-site-data-storage-region': '/api/prov/v1/sites/data-privacy/region-change',
    'incap-get-site-data-storage-region': '/api/prov/v1/sites/data-privacy/show',
    'incap-set-site-data-storage-region-geo-override': '/api/prov/v1/sites/data-privacy/override-by-geo',
    'incap-get-site-data-storage-region-geo-override': '/api/prov/v1/sites/data-privacy/show-override-by-geo',
    /*
        Site Management - Caching
    */
    'incap-purge-site-cache':'/api/prov/v1/sites/cache/purge',
    'incap-modify-cache-mode':'/api/prov/v1/sites/performance/cache-mode',
    'incap-purge-resources':'/api/prov/v1/sites/performance/purge',
    'incap-modify-caching-rules':'/api/prov/v1/sites/performance/caching-rules',
    'incap-set-advanced-caching-settings':'/api/prov/v1/sites/performance/advanced',
    'incap-purge-hostname-from-cache':'/api/prov/v1/sites/hostname/purge',
    'incap-site-get-xray-link': '/api/prov/v1/sites/xray/get-link',
    /*
        Site Management - Rules
     */
    'incap-list-site-rule-revisions': '/api/prov/v1/sites/incapRules/revisions',
    'incap-add-site-rule': '/api/prov/v1/sites/incapRules/add',
    'incap-edit-site-rule': '/api/prov/v1/sites/incapRules/edit',
    'incap-enable-site-rule': '/api/prov/v1/sites/incapRules/enableDisable',
    'incap-delete-site-rule': '/api/prov/v1/sites/incapRules/delete',
    'incap-list-site-rules': '/api/prov/v1/sites/incapRules/list',
    'incap-revert-site-rule': '/api/prov/v1/sites/incapRules/revert',
    'incap-set-site-rule-priority': '/api/prov/v1/sites/incapRules/priority/set',
    /*
        Site Management - Data Centers
     */
    'incap-add-site-datacenter':'/api/prov/v1/sites/dataCenters/add',
    'incap-edit-site-datacenter':'/api/prov/v1/sites/dataCenters/edit',
    'incap-delete-site-datacenter':'/api/prov/v1/sites/dataCenters/delete',
    'incap-list-site-datacenters':'/api/prov/v1/sites/dataCenters/list',
    'incap-add-site-datacenter-server':'/api/prov/v1/sites/dataCenters/servers/add',
    'incap-edit-site-datacenter-server':'/api/prov/v1/sites/dataCenters/servers/edit',
    'incap-delete-site-datacenter-server':'/api/prov/v1/sites/dataCenters/servers/delete',
    /*
        Traffic Statistics and Details
     */
    'incap-get-statistics':'/api/stats/v1',
    'incap-get-visits':'/api/visits/v1',
    'incap-upload-public-key': '/api/logscollector/upload/publickey',
    'incap-change-logs-collector-configuration':'/api/logscollector/change/status',
    'incap-get-infra-protection-statistics': '/api/v1/infra/stats',
    'incap-get-infra-protection-events': '/api/v1/infra/events',
    'incap-get-infra-protection-top-items-table': '/api/v1/infra/top-table',
    /*
        Login Protect
     */
    'incap-add-login-protect':'/api/prov/v1/sites/lp/add-user',
    'incap-edit-login-protect':'/api/prov/v1/sites/lp/edit-user',
    'incap-get-login-protect':'/api/prov/v1/sites/lp/users',
    'incap-remove-login-protect':'/api/prov/v1/sites/lp/remove',
    'incap-send-sms-to-user':'/api/prov/v1/sites/lp/send-sms',
    'incap-modify-login-protect':'/api/prov/v1/sites/lp/configure',
    'incap-configure-app':'/api/prov/v1/sites/lp/configure-app',
    /*
        Integration
     */
    'incap-get-ip-ranges': '/api/integration/v1/ips',
    'incap-get-texts':'/api/integration/v1/texts',
    'incap-get-geo-info':'/api/integration/v1/geo',
    'incap-get-app-info':'/api/integration/v1/clapps',
    /*
        Infrastructure Protection Test Alerts
     */
    'incap-test-alert-ddos-start': '/api/v1/infra-protect/test-alerts/ddos/start',
    'incap-test-alert-ddos-stop': '/api/v1/infra-protect/test-alerts/ddos/stop',
    'incap-test-alert-connection-up': '/api/v1/infra-protect/test-alerts/connection/up',
    'incap-test-alert-connection-down': '/api/v1/infra-protect/test-alerts/connection/down',
    'incap-test-alert-ip-protection-status-up': '/api/v1/infra-protect/test-alerts/ip-protection-status/up',
    'incap-test-alert-ip-protection-status-down': '/api/v1/infra-protect/test-alerts/ip-protection-status/down',
    'incap-test-alert-netflow-monitoring-start': '/api/v1/infra-protect/test-alerts/monitoring/start',
    'incap-test-alert-netflow-monitoring-stop': '/api/v1/infra-protect/test-alerts/monitoring/stop',
    'incap-test-alert-bad-data-monitoring': '/api/v1/infra-protect/test-alerts/monitoring/bad-data',
    'incap-test-alert-attack-monitoring-start': '/api/v1/infra-protect/test-alerts/monitoring/attack-start'
}


switch (command) {
    case 'test-module':
        var res = sendRequest(base + urlDict['incap-get-texts'], encodeToURLQuery(args).substr(1), 'test');
        if (res) {
            return 'ok';
        }
        return 'not cool';
    default:
        return sendRequest(base + urlDict[command], encodeToURLQuery(args).substr(1), urlDict[command]);
}
