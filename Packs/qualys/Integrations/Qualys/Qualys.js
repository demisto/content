var baseUrl = params.server;

var commandToMethod = {
        'qualys-report-list': 'reportList',
        'qualys-report-cancel': 'reportCancel',
        'qualys-report-delete': 'reportDelete',
        'qualys-scorecard-launch': 'scorecardLaunch',
        'qualys-report-fetch': 'reportFetch',
        'qualys-vm-scan-list': 'vmScanList',
        'qualys-vm-scan-launch': 'vmScanLaunch',
        'qualys-vm-scan-action': 'vmScanAction',
        'qualys-vm-scan-fetch': 'vmScanFetch',
        'qualys-scap-scan-list': 'scapScanList',
        'qualys-pc-scan-list': 'pcScanList',
        'qualys-pc-scan-launch': 'pcScanLaunch',
        'qualys-pc-scan-manage': 'pcScanManage',
        'qualys-pc-scan-fetch': 'pcScanFetch',
        'qualys-schedule-scan-list': 'scheduleScanList',
        'qualys-ip-restricted-list': 'ipRestrictedList',
        'qualys-ip-list': 'ipList',
        'qualys-ip-add': 'ipAdd',
        'qualys-ip-update': 'ipUpdate',
        'qualys-host-list': 'hostList',
        'qualys-virtual-host-list': 'virtualHostList',
        'qualys-virtual-host-manage': 'virtualHostManage',
        'qualys-host-excluded-list': 'hostExcludedList',
        'qualys-host-excluded-manage': 'hostExcludedManage',
        'qualys-scheduled-report-list': 'scheduledReportList',
        'qualys-scheduled-report-launch': 'scheduledReportLaunch',
        'qualys-report-template-list': 'reportTemplateList',
        'qualys-report-launch-map': 'reportLaunchMap',
        'qualys-report-launch-scan-based-findings': 'reportLaunchScanBasedFindings',
        'qualys-report-launch-host-based-findings': 'reportLaunchHostBasedFindings',
        'qualys-report-launch-patch': 'reportLaunchPatch',
        'qualys-report-launch-remediation': 'reportLaunchRemediation',
        'qualys-report-launch-compliance': 'reportLaunchCompliance',
        'qualys-report-launch-compliance-policy': 'reportLaunchCompliancePolicy',
        'qualys-vulnerability-list': 'vulnerabilityList',
        'qualys-group-list': 'groupList'
    };

var methodFixedParams = {
    'reportList': [['action','list']],
   'reportCancel': [['action', 'cancel']],
   'reportDelete': [['action', 'delete']],
   'scorecardLaunch': [['action', 'launch']],
   'pcScanList': [['action','list']],
   'pcScanLaunch': [['action', 'launch']],
   'pcScanFetch': [['action','fetch']],
   'reportFetch': [['action', 'fetch']],
   'vmScanList': [['action', 'list']],
   'vmScanLaunch': [['action', 'launch']],
   'vmScanFetch': [['action', 'fetch'], ['output_format','json']],
   'scapScanList': [['action', 'list']],
   'scheduleScanList': [['action', 'list']],
   'ipRestrictedList': [['action', 'list']],
   'ipList': [['action', 'list']],
   'ipAdd': [['action', 'add']],
   'ipUpdate': [['action', 'update']],
   'hostList': [['action', 'list']],
   'virtualHostList': [['action', 'list']],
   'hostExcludedList': [['action', 'list']],
   'scheduledReportList': [['action', 'list']],
   'scheduledReportLaunch': [['action', 'launch_now']],
   'reportLaunchMap': [['action','launch'], ['report_type', 'Map']],
   'reportLaunchScanBasedFindings': [['action','launch'], ['report_type', 'Scan']],
   'reportLaunchHostBasedFindings':[['action','launch'], ['report_type', 'Scan']],
    'reportLaunchPatch':[['action','launch'], ['report_type', 'Patch']],
    'reportLaunchRemediation': [['action','launch'], ['report_type', 'Remediation']],
    'reportLaunchCompliance': [['action','launch'], ['report_type', 'Compliance']],
    'reportLaunchCompliancePolicy': [['action','launch'], ['report_type', 'Policy']],
   'vulnerabilityList': [['action', 'list']],
   'groupList': [['action', 'list']]
};



var methodPath = {
    'reportList': '/api/2.0/fo/report/',
    'reportCancel': '/api/2.0/fo/report/',
    'reportDelete': '/api/2.0/fo/report/',
    'scorecardLaunch':'/api/2.0/fo/report/scorecard/',
    'pcScanList': '/api/2.0/fo/scan/compliance/',
    'reportFetch': '/api/2.0/fo/report/',
    'vmScanList': '/api/2.0/fo/scan/',
    'vmScanLaunch': '/api/2.0/fo/scan/',
    'vmScanAction': '/api/2.0/fo/scan/',
    'vmScanFetch': '/api/2.0/fo/scan/',
    'scapScanList': '/api/2.0/fo/scan/scap/',
    'pcScanManage': '/api/2.0/fo/scan/compliance/',
    'pcScanLaunch': '/api/2.0/fo/scan/compliance/',
    'pcScanFetch': '/api/2.0/fo/scan/compliance/',
    'scheduleScanList': '/api/2.0/fo/schedule/scan/',
    'ipRestrictedList': '/api/2.0/fo/setup/restricted_ips/',
    'ipList': '/api/2.0/fo/asset/ip/',
    'ipAdd': '/api/2.0/fo/asset/ip/',
    'ipUpdate': '/api/2.0/fo/asset/ip/',
    'hostList': '/api/2.0/fo/asset/host/',
    'virtualHostList': '/api/2.0/fo/asset/vhost/',
    'virtualHostManage': '/api/2.0/fo/asset/vhost/',
    'hostExcludedList': '/api/2.0/fo/asset/excluded_ip/',
    'hostExcludedManage': '/api/2.0/fo/asset/excluded_ip/',
    'scheduledReportList': '/api/2.0/fo/schedule/report/',
    'scheduledReportLaunch': '/api/2.0/fo/schedule/report/',
    'reportLaunchMap': '/api/2.0/fo/report/',
    'reportLaunchScanBasedFindings': '/api/2.0/fo/report/',
    'reportLaunchHostBasedFindings':'/api/2.0/fo/report/',
    'reportLaunchPatch':'/api/2.0/fo/report/',
    'reportLaunchRemediation':'/api/2.0/fo/report/',
    'reportLaunchCompliance':'/api/2.0/fo/report/',
    'reportLaunchCompliancePolicy':'/api/2.0/fo/report/',
    'vulnerabilityList': '/api/2.0/fo/knowledge_base/vuln/',
    'groupList': '/api/2.0/fo/asset/group/',
    'reportTemplateList': '/msp/report_template_list.php'
};

var methodArgs = {
    'reportList': ['id','state','user_login','expires_before_datetime'],
    'reportCancel': ['id'],
    'reportDelete': ['id'],
    'scorecardLaunch': ['name','report_title','output_format','hide_header','pdf_password',
                        'recipient_group','recipient_group_id','source','asset_groups',
                        'all_asset_groups','business_unit','division','function','location',
                        'patch_qids','missing_qids'],
    'pcScanList':['scan_id','scan_ref','state','processed','type','target','user_login',
                    'launched_after_datetime','launched_before_datetime',
                        'show_ags','show_op','show_status','show_last'],
    'pcScanLaunch': ['scan_title','option_id','option_title','ip','asset_group_ids','asset_groups','runtime_http_header',
                    'exclude_ip_per_scan','default_scanner','scanners_in_ag','target_from','tag_include_selector',
                    'tag_exclude_selector','tag_set_by','tag_set_include','tag_set_exclude','use_ip_nt_range_tags','ip_network_id',
'iscanner_name'],
    'reportFetch': ['id'],
    'vmScanList': ['scan_ref', 'state', 'processed', 'type',
                    'target', 'user_login', 'launched_after_datetime',
                    'launched_before_datetime', 'show_ags', 'show_op',
                    'show_status', 'show_last'],
    'vmScanLaunch': ['scan_title','option_id','option_title','ip','asset_group_ids','asset_groups','runtime_http_header',
                    'exclude_ip_per_scan','default_scanner','scanners_in_ag','target_from','tag_include_selector',
                    'tag_exclude_selector','tag_set_by','tag_set_include','tag_set_exclude','use_ip_nt_range_tags','ip_network_id',
'iscanner_name'],
    'vmScanAction': ['action','scan_ref'],
    'vmScanFetch': ['scan_ref','ips','mode'],
    'scapScanList': ['scan_ref', 'state', 'processed', 'type',
                    'target', 'user_login', 'launched_after_datetime',
                    'launched_before_datetime', 'show_ags', 'show_op',
                    'show_status', 'show_last'],
    'pcScanManage': ['action','scan_ref'],
    'pcScanFetch': ['scan_ref'],
    'scheduleScanList': ['id','active'],
    'ipRestrictedList': [],
    'ipList': ['ips','network_id','tracking_method','compliance_enabled'],
    'ipAdd': ['ips','tracking_method','enable_vm','enable_pc',
                    'owner','ud1','ud2','ud3','comment','ag_title'],
    'ipUpdate': ['ips','tracking_method','host_dns','host_netbios',
                    'owner','ud1','ud2','ud3','comment'],
    'hostList':['truncation_limit','details','ips','ids','ag_ids','ag_titles','id_min',
                'id_max','network_ids','no_vm_scan_since','no_compliance_scan_since','vm_scan_since',
                'compliance_scan_since','compliance_enabled','os_pattern'],
    'virtualHostList': ['port','ip'],
    'virtualHostManage': ['action','ip','port','fqdn'],
    'hostExcludedList': ['ips','network_id'],
    'hostExcludedManage': ['action','ips','comment','network_id'],
    'scheduledReportList': ['id','is_active'],
    'scheduledReportLaunch': ['id'],
    'reportLaunchMap':['template_id','report_title','output_format','hide_header',
                        'recipient_group_id','pdf_password','recipient_group','hide_header',
                        'domain','ip_restriction','report_refs',
                        'use_tags','tag_include_selector','tag_exclude_selector','tag_set_by','tag_set_include','tag_set_exclude'],
    'reportLaunchScanBasedFindings': ['template_id','report_title','output_format','hide_header',
                        'recipient_group_id','pdf_password','recipient_group',
                        'domain','ip_restriction','report_refs',
                        'use_tags','tag_include_selector','tag_exclude_selector','tag_set_by','tag_set_include','tag_set_exclude'],

    'reportLaunchHostBasedFindings': ['template_id','report_title','output_format','hide_header',
                                        'recipient_group_id','pdf_password','recipient_group',
                                        'ips','asset_group_ids','ips_network_id','ips_network_id',
                                        'use_tags','tag_include_selector','tag_exclude_selector','tag_set_by','tag_set_include','tag_set_exclude'],

    'reportLaunchPatch':['template_id','report_title','output_format','hide_header',
                        'ips','asset_group_ids','recipient_group_id','pdf_password','recipient_group',
                        'use_tags','tag_include_selector','tag_exclude_selector','tag_set_by','tag_set_include','tag_set_exclude'],

    'reportLaunchRemediation':['template_id','report_title','output_format','hide_header',
                                'ips','asset_group_ids','assignee_type','recipient_group_id','pdf_password','recipient_group',
                                'use_tags','tag_include_selector','tag_exclude_selector','tag_set_by','tag_set_include','tag_set_exclude'],

    'reportLaunchCompliance':['template_id','report_title','output_format','hide_header',
                                'ips','asset_group_ids','report_refs','recipient_group_id','pdf_password','recipient_group',
                                'use_tags','tag_include_selector','tag_exclude_selector','tag_set_by','tag_set_include','tag_set_exclude'],

    'reportLaunchCompliancePolicy': ['template_id','report_title','output_format','hide_header',
                                    'recipient_group_id','pdf_password','recipient_group',
'policy_id',
                                     'report_refs','asset_group_ids','ips','host_id','instance_string',
                                     'use_tags','tag_include_selector','tag_exclude_selector','tag_set_by','tag_set_include','tag_set_exclude'],

    'vulnerabilityList': ['details','ids','id_min','id_max','is_patchable','last_modified_after','last_modified_before',
                            'last_modified_by_user_after','last_modified_by_user_before',
                            'last_modified_by_service_after','last_modified_by_service_before','published_after',
                            'published_before','discovery_method','discovery_auth_types','show_pci_reasons'],
   'groupList': ['ids','id_min','id_max','truncation_limit','network_i1ds',
                'unit_id','user_id','title','show_attributes'],
    'reportTemplateList': []

};



var methodHttpMethod = {
    'reportList': 'GET',
    'reportCancel': 'POST',
    'reportDelete': 'POST',
    'scorecardLaunch': 'POST',
    'pcScanLaunch': 'POST',
    'pcScanList': 'POST',
    'reportFetch': 'POST',
    'vmScanList': 'GET',
    'vmScanAction': 'POST',
    'vmScanLaunch': 'POST',
    'vmScanFetch': 'GET',
    'scapScanList': 'GET',
    'pcScanManage': 'POST',
    'pcScanFetch': 'GET',
    'scheduleScanList': 'GET',
    'ipRestrictedList': 'GET',
    'ipList': 'GET',
    'ipAdd': 'POST',
    'ipUpdate': 'POST',
    'hostList': 'POST',
    'virtualHostList': 'GET',
    'virtualHostManage': 'POST',
    'hostExcludedList': 'GET',
    'hostExcludedManage': 'POST',
    'scheduledReportList': 'GET',
    'scheduledReportLaunch': 'POST',
    'reportLaunchMap': 'POST',
    'reportLaunchScanBasedFindings': 'POST',
    'reportLaunchHostBasedFindings': 'POST',
    'reportLaunchPatch': 'POST',
    'reportLaunchRemediation': 'POST',
    'reportLaunchCompliance': 'POST',
    'reportLaunchCompliancePolicy': 'POST',
    'vulnerabilityList': 'POST',
    'groupList': 'GET',
    'reportTemplateList': 'GET'
};



var titleDict = {
    'reportList': 'Qualys Report List',
    'reportCancel': 'Qualys Report Cancel',
    'reportDelete': 'Qualys Report Delete',
    'scorecardLaunch':'',
    'pcScanList': '',
    'reportFetch': '',
    'vmScanList': 'Qualys VM Scan List',
    'vmScanLaunch': '',
    'vmScanAction': '',
    'vmScanFetch': 'Qualys VM Scan',
    'scapScanList': 'Qualys SCAP Scan List',
    'pcScanManage': '',
    'pcScanLaunch': '',
    'pcScanFetch': '',
    'scheduleScanList': '',
    'ipRestrictedList': '',
    'ipList': 'Qualys IP List',
    'ipAdd': 'Qualys IP Add',
    'ipUpdate': '',
    'hostList': '',
    'virtualHostList': '',
    'virtualHostManage': '',
    'hostExcludedList': 'Qualys Excluded Hosts List',
    'hostExcludedManage': '',
    'scheduledReportList': '',
    'scheduledReportLaunch': '',
    'reportLaunchMap': '',
    'reportLaunchScanBasedFindings': '',
    'reportLaunchHostBasedFindings':'',
    'reportLaunchPatch':'',
    'reportLaunchRemediation':'',
    'reportLaunchCompliance':'',
    'reportLaunchCompliancePolicy':'',
    'vulnerabilityList': '',
    'hostAssetList': '',
    'groupList': 'Qualys Asset Groups List',
    'reportTemplateList': 'Qualys Report Template List'
};


var entityDict = {
    'report': [
                {to: 'ID', from: 'ID'},
                {to: 'Title', from: 'TITLE'},
                {to: 'Type', from: 'TYPE'},
                {to: 'LaunchDatetime', from: 'LAUNCH_DATETIME'},
                {to: 'OutputFormat', from: 'OUTPUT_FORMAT'},
                {to: 'Size', from: 'SIZE'},
                {to: 'Status.State', from: 'STATUS.STATE'},
                {to: 'Status.Message', from: 'STATUS.MESSAGE'},
                {to: 'Status.Precent', from: 'STATUS.PERCENT'},
                {to: 'ExpirationDatetime', from: 'EXPIRATION_DATETIME'},
                {to: 'Schedule', from: 'SCHEDULE'}
            ],
    'launchedReport': [
                {to: 'ID', from: 'VALUE'}
                ],
    'reportTemplate': [
                {to: 'ID', from: 'ID'},
                {to: 'Title', from: 'TITLE'},
                {to: 'Type', from: 'TYPE'},
                {to: 'TemplateType', from: 'TEMPLATE_TYPE'},
                {to: 'User.Login', from: 'USER.LOGIN'},
                {to: 'User.FirstName', from: 'USER.FIRSTNAME'},
                {to: 'User.LastName', from: 'USER.LASTNAME'},
                {to: 'LastUpdate', from: 'LAST_UPDATE'},
                {to: 'Global', from: 'GLOBAL'},
                {to: 'Default', from: 'DEFAULT'}
            ],
        'scan': [
                {to: 'ID', from: 'ID'},
                {to: 'Reference', from: 'REFERENCE'},
                {to: 'Ref', from: 'REF'},
                {to: 'Title', from: 'TITLE'},
                {to: 'Type', from: 'TYPE'},
                {to: 'LaunchDatetime', from: 'LAUNCH_DATETIME'},
                {to: 'Duration', from: 'DURATION'},
                {to: 'ProcessingPriority', from: 'PROCESSING_PRIORITY'},
                {to: 'Processed', from: 'PROCESSED'},
                {to: 'Status.State', from: 'STATUS.STATE'},
                {to: 'Status.SubState', from: 'STATUS.SUB_STATE'},
                {to: 'Schedule', from: 'SCHEDULE'},
                {to: 'Target', from: 'TARGET'},
                {to: 'AssetGroupTitle', from: 'ASSET_GROUP_TITLE_LIST.ASSET_GROUP_TITLE'},
                {to: 'DeafualtFlag', from: 'OPTION_PROFILE.DEFAULT_FLAG'},
                {to: 'UserLogin', from: 'USER_LOGIN'},
                {to: 'Duration', from: 'DURATION'}
            ],
        'endpoint': [
                {to: 'ID', from: 'ID'},
                {to: 'IP', from: 'IP'},
                {to: 'DNS', from: 'DNS'},
                {to: 'EC2InstanceID', from: 'EC2_INSTANCE_ID'},
                {to: 'NETBIOS', from: 'NETBIOS'},
                {to: 'OS', from: 'OS'},
                {to: 'AssetGroupIDs', from: 'ASSET_GROUP_IDS'},
                {to: 'NetworkID', from: 'NETWORK_ID'}
            ],
        'virtualEndpoint': [
                {to: 'IP', from: 'IP'},
                {to: 'Port', from: 'PORT'},
                {to: 'FQDN', from: 'FQDN'},
                {to: 'NetworkID', from: 'NETWORK_ID'}
            ],
        'assetGroup': [
                {to: 'ID', from: 'ID'},
                {to: 'Title', from: 'TITLE'},
                {to: 'OwnerID', from: 'OWNER_ID'},
                {to: 'UnitID', from: 'UNIT_ID'},
                {to: 'IP.Address', from: 'IP_SET.IP'},
                {to: 'IP.Range', from: 'IP_SET.IP_RANGE'},
                {to: 'NetworkID', from: 'NETWORK_ID'},
                {to: 'ApplianceIDS', from: 'APPLIANCE_IDS'},
                {to: 'DefaultApplianceID', from: 'DEFAULT_APPLIANCE_ID'}
                ],
        'IP': [
                {to: 'Address', from: 'IP'},
                {to: 'Range', from: 'IP_RANGE'},
                ]
};

var contextDict = {

    'reportList': { ContextPath: 'Qualys.Report(val.ID == obj.ID)',
                    ContentPath: ['REPORT_LIST_OUTPUT.RESPONSE','.REPORT_LIST.REPORT'],
                    entityType: 'report' },
    'reportCancel': { ContextPath: undefined,
                    ContentPath: ['SIMPLE_RETURN.RESPONSE','.ITEM_LIST.ITEM'],
                    entityType: 'report'
    },
    'reportDelete': { ContextPath: 'Qualys.Report(val.ID == obj.ID)',
                    ContentPath: ['SIMPLE_RETURN.RESPONSE','.ITEM_LIST.ITEM'],
                    entityType: 'report'
    },
    'scorecardLaunch':{ ContextPath: 'Qualys.Report(val.ID == obj.ID)',
                    ContentPath: ['SIMPLE_RETURN.RESPONSE','.ITEM_LIST.ITEM'],
                    entityType: 'report'
    },
    'pcScanList': { ContextPath: 'Qualys.Scan(val.ID == obj.ID)',
                    ContentPath: ['SCAN_LIST_OUTPUT.RESPONSE','.SCAN_LIST.SCAN'],
                    entityType: 'scan' },
    'reportFetch': '',
    'vmScanList': { ContextPath: 'Qualys.Scan(val.ID == obj.ID)',
                    ContentPath: ['SCAN_LIST_OUTPUT.RESPONSE','.SCAN_LIST.SCAN'],
                    entityType: 'scan' },
    'vmScanLaunch': { ContextPath: 'Qualys.Scan(val.ID == obj.ID)',
                    ContentPath: ['SIMPLE_RETURN.RESPONSE','.ITEM_LIST.ITEM'],
                    entityType: 'scan' },
    'vmScanAction': { ContextPath: undefined,
                    ContentPath: ['SIMPLE_RETURN.RESPONSE','.ITEM_LIST.ITEM'],
                     entityType: ''},
    'vmScanFetch': { ContextPath: 'Qualys.VM(val.QID==obj.QID)',
                      entityType: 'vm'},
    'scapScanList': { ContextPath: 'Qualys.Scan(val.ID == obj.ID)',
                    ContentPath: ['SCAN_LIST_OUTPUT.RESPONSE','.SCAN_LIST.SCAN'],
                    entityType: 'scan' },
    'pcScanManage': { ContextPath: undefined,
                    ContentPath: ['SIMPLE_RETURN.RESPONSE','.ITEM_LIST.ITEM'],
                    entityType: 'scan'
    },
    'pcScanFetch': { ContextPath: undefined,
                    ContentPath: ['COMPLIANCE_SCAN_RESULT_OUTPUT.RESPONSE','.COMPLIANCE_SCAN'],
                    entityType: ''
    },
    'pcScanLaunch': { ContextPath: 'Qualys.Scan(val.ID == obj.ID)',
                    ContentPath: ['SIMPLE_RETURN.RESPONSE','.ITEM_LIST.ITEM'],
                    entityType: 'scan' },
    'scheduleScanList': { ContextPath: 'Qualys.Scan(val.ID == obj.ID)',
                    ContentPath: ['SCHEDULE_SCAN_LIST_OUTPUT.RESPONSE','.SCHEDULE_SCAN_LIST.SCAN'],
                    entityType: 'scan' },
    'ipRestrictedList': '',
    'ipList': { ContextPath: 'IP',
                    ContentPath: ['IP_LIST_OUTPUT.RESPONSE','.IP_SET'],
                    entityType: 'IP'

    },
    'ipAdd': { ContextPath: undefined,
                ContentPath: ['SIMPLE_RETURN.RESPONSE','.ITEM_LIST.ITEM'] },
    'ipUpdate': { ContextPath: undefined,
                ContentPath: ['SIMPLE_RETURN.RESPONSE','.ITEM_LIST.ITEM'] },
    'hostList': { ContextPath: 'Qualys.Endpoint(val.ID == obj.ID)',
                    ContentPath: ['HOST_LIST_OUTPUT.RESPONSE','.HOST_LIST.HOST'],
                    entityType: 'endpoint' },
    'virtualHostList': { ContextPath: 'Qualys.VirtualEndpoint',
                    ContentPath: ['VIRTUAL_HOST_LIST_OUTPUT.RESPONSE','.VIRTUAL_HOST_LIST.VIRTUAL_HOST'],
                    entityType: 'virtualEndpoint'
    },
    'virtualHostManage': { ContextPath: undefined,
                    ContentPath: ['SIMPLE_RETURN.RESPONSE','.ITEM_LIST.ITEM'],
                    entityType: ''
    },
    'hostExcludedList': { ContextPath: 'Qualys.Excluded.Host',
                    ContentPath: ['IP_LIST_OUTPUT.RESPONSE','.IP_SET'],
                    entityType: 'IP'},
    'hostExcludedManage': { ContextPath: undefined,
                            ContentPath: ['SIMPLE_RETURN.RESPONSE','.ITEM_LIST.ITEM'],
                            entityType: ''
    },
    'scheduledReportList': { ContextPath: 'Qualys.Report(val.ID == obj.ID)',
                            ContentPath: ['SCHEDULE_REPORT_LIST_OUTPUT.RESPONSE','.SCHEDULE_REPORT_LIST.REPORT'],
                            entityType: 'report'
    },
    'scheduledReportLaunch': { ContextPath: 'Qualys.Report(val.ID == obj.ID)',
                            ContentPath: ['SIMPLE_RETURN.RESPONSE','.ITEM_LIST.ITEM'],
                            entityType: 'report'
    },
    'reportLaunchMap': { ContextPath: 'Qualys.Report(val.ID == obj.ID)',
                    ContentPath: ['SIMPLE_RETURN.RESPONSE','.ITEM_LIST.ITEM'],
                            entityType: 'report'
    },
    'reportLaunchScanBasedFindings': { ContextPath: 'Qualys.Report(val.ID == obj.ID)',
                    ContentPath: ['SIMPLE_RETURN.RESPONSE','.ITEM_LIST.ITEM'],
                            entityType: 'report'
    },
    'reportLaunchHostBasedFindings':{ ContextPath: 'Qualys.Report(val.ID == obj.ID)',
                    ContentPath: ['SIMPLE_RETURN.RESPONSE','.ITEM_LIST.ITEM'],
                    entityType: 'report'
    },
    'reportLaunchPatch':{ ContextPath: 'Qualys.Report(val.ID == obj.ID)',
                    ContentPath: ['SIMPLE_RETURN.RESPONSE','.ITEM_LIST.ITEM'],
                    entityType: 'report'
    },
    'reportLaunchRemediation':{ ContextPath: 'Qualys.Report(val.ID == obj.ID)',
                    ContentPath: ['SIMPLE_RETURN.RESPONSE','.ITEM_LIST.ITEM'],
                    entityType: 'report'
    },
    'reportLaunchCompliance':{ ContextPath: 'Qualys.Report(val.ID == obj.ID)',
                    ContentPath: ['SIMPLE_RETURN.RESPONSE','.ITEM_LIST.ITEM'],
                    entityType: 'report'
    },
    'reportLaunchCompliancePolicy':{ ContextPath: 'Qualys.Report(val.ID == obj.ID)',
                    ContentPath: ['SIMPLE_RETURN.RESPONSE','.ITEM_LIST.ITEM'],
                    entityType: 'report'
    },
    'vulnerabilityList': { ContextPath: undefined,
                           ContentPath: ['KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE','.VULN_LIST.VULN'],
                           entityType: ''},
    'groupList': { ContextPath: 'Qualys.AssetGroup(val.ID == obj.ID)',
                    ContentPath: ['ASSET_GROUP_LIST_OUTPUT.RESPONSE','.ASSET_GROUP_LIST.ASSET_GROUP'],
                    entityType: 'assetGroup'},
    'reportTemplateList': { ContextPath: 'Qualys.ReportTemplate(val.ID == obj.ID)',
                    ContentPath: ['REPORT_TEMPLATE_LIST.REPORT_TEMPLATE',''],
                    entityType: 'reportTemplate'}
    };

var  outputFunctionsDict = {
    'reportList': handleXMLWithTable,
    'reportCancel': handleSimpleReturnWithText,
    'reportDelete': handleReportDelete,
    'scorecardLaunch':handleSimpleReturnWithText,
    'pcScanList': handleXMLWithTable,
    'reportFetch': handleFetchReport,
    'vmScanList': handleXMLWithTable,
    'vmScanLaunch': handleSimpleReturnWithText,
    'vmScanAction': handleSimpleReturnWithText,
    'vmScanFetch': handleFetchScan,
    'scapScanList': handleXMLWithTable,
    'pcScanManage': handleSimpleReturnWithText,
    'pcScanFetch':handleFetchPCScan,
    'pcScanLaunch': handleSimpleReturnWithText,
    'scheduleScanList': handleXMLWithTable,
    'ipRestrictedList': '',
    'ipList': handleIPlist,
    'ipAdd': handleSimpleReturnWithText,
    'ipUpdate': handleSimpleReturnWithText,
    'hostList': handleXMLWithTable,
    'virtualHostList': handleXMLWithTable,
    'virtualHostManage': handleXMLWithTable,
    'hostExcludedList': handleIPlist,
    'hostExcludedManage': handleSimpleReturnWithText,
    'scheduledReportList': handleXMLWithTable,
    'scheduledReportLaunch': handleSimpleReturnWithText,
    'reportLaunchMap': handleSimpleReturnWithText,
    'reportLaunchScanBasedFindings': handleSimpleReturnWithText,
    'reportLaunchHostBasedFindings': handleSimpleReturnWithText,
    'reportLaunchPatch': handleSimpleReturnWithText,
    'reportLaunchRemediation': handleSimpleReturnWithText,
    'reportLaunchCompliance': handleSimpleReturnWithText,
    'reportLaunchCompliancePolicy': handleSimpleReturnWithText,
    'vulnerabilityList': handleXMLWithTable,
    'groupList': handleXMLWithTable,
    'reportTemplateList': handleXMLWithTable,
};

function getItemFromItemList(itemList, key){
    itemsMap = itemListToMap(itemList);
    if(itemsMap && itemsMap[key]) {
        return itemsMap[key];
    }
    return '';
}

function itemListToMap(itemList) {
    items = {};
    if (itemList instanceof Array){
        for (var i=0; i < itemList.length; i++) {
            items[itemList[i].KEY] = itemList[i].VALUE;
        }
    } else if(itemList && Object.keys(itemList).length === 2 && itemList.KEY){
         items[itemList.KEY] = itemList.VALUE;
    }
    //throw "itemList: "+ JSON.stringify(itemList) + "\n items: " + JSON.stringify(items);
    return items;
}

function objectArrayFromSet(key, Set) {
    Arr = [];
    if(Set[key]){
        if (Set[key] instanceof Array){
            for (var i=0; i < Set[key].length; i++) {
                var newObj = {};
                newObj[key] = Set[key][i];
                Arr[i] = newObj;
            }
        } else {
            var singleObj = {};
                singleObj[key] = Set[key];
                Arr[0] = singleObj;
        }
    }
    return Arr;
}
function createIPArrayFromIPSet(ipSet) {
    return objectArrayFromSet('IP', ipSet).concat(objectArrayFromSet('IP_RANGE',
ipSet)); }

function mapObjFunction(mapFields) {
        var transformSingleObj= function(obj) {
            var res = {};
            var fieldValue = '';
            mapFields.forEach(function(f) {
                fieldValue = dq(obj, f.from);
                if (fieldValue){
                    var keys = f.to.split('.');
                    switch (keys.length){
                        case 1:
                            res[keys[0]] = fieldValue;
                            break;
                        case 2:
                             if (!res[keys[0]]){
                                res[keys[0]] = {};
                            }
                            res[keys[0]][keys[1]] = fieldValue;
                            break;
                        default:
                        throw "context target field [" + f.to + "] must have 1-3
levels but have " + keys.length;
                    }
                }
            });
            return res;
        };
        return function(obj) {
            if (obj instanceof Array) {
                var res = [];
                for (var j=0; j < obj.length; j++) {
                    res.push(transformSingleObj(obj[j]));
                }
                return res;
            }
            return transformSingleObj(obj);
        };
    }



function getFormatedMethodParams(method) {
    var metodCommandJson = {};

    var fixedParmas = methodFixedParams[method];
    if (fixedParmas) {
            for (var i = 0; i < fixedParmas.length; i++) {
                metodCommandJson[fixedParmas[i][0]] = fixedParmas[i][1];
        }
    }

    var allArgs = methodArgs[method];
    for (var j = 0; j < allArgs.length; j++){
        if (args[allArgs[j]]){
          metodCommandJson[allArgs[j]] = args[allArgs[j]];
        }
    }

    if(Object.keys(metodCommandJson).length > 0){
        return encodeToURLQuery(metodCommandJson).substr(1);
    }
    else {
        return '';
    }
}


function parseAndCheckErrors (httpRes) {
    var rawResponse = JSON.parse(x2j(httpRes.Body));
    var simpleReturn = rawResponse ? dq(rawResponse, 'SIMPLE_RETURN.RESPONSE')
: undefined;
    if(simpleReturn && simpleReturn.CODE) {
        throw "\n" + simpleReturn.TEXT + "\nCode: " + simpleReturn.CODE + "\nHTTP
Status Code: " + httpRes.StatusCode;
    }
    if (httpRes.StatusCode < 200 || httpRes.StatusCode >= 300) {
        throw 'Request Failed.\nStatus code: ' + httpRes.StatusCode + '.\nBody:
' + JSON.stringify(httpRes) + '.';
    }
    return rawResponse;
}


function createStandartEntry(contextPath, returnObject, humanReadable, rawResponse) {
    var ec = {};
    if (contextPath) {
        ec[contextPath] = returnObject;
    }
    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: rawResponse,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: humanReadable,
        EntryContext: ec
    };
}


function parseXMLAndCheckErrors (httpRes) {
    var rawResponse = JSON.parse(x2j(httpRes.Body));
    var simpleReturn = rawResponse ? dq(rawResponse, 'SIMPLE_RETURN.RESPONSE')
: undefined;
    if(simpleReturn && simpleReturn.CODE) {
        throw "\n" + simpleReturn.TEXT + "\nCode: " + simpleReturn.CODE + "\nHTTP
Status Code: " + httpRes.StatusCode;
    }
    if (httpRes.StatusCode < 200 || httpRes.StatusCode >= 300) {
        throw 'Request Failed.\nStatus code: ' + httpRes.StatusCode + '.\nBody:
' + JSON.stringify(httpRes) + '.';
    }
    return rawResponse;
}

function nonXMLCheckErrors (httpRes) {
    var rawResponse;
    if (httpRes.StatusCode < 200 || httpRes.StatusCode >= 300) {
        try {
            rawResponse = JSON.parse(x2j(httpRes.Body));
            var simpleReturn = rawResponse ? dq(rawResponse, 'SIMPLE_RETURN.RESPONSE')
: undefined;
        }
        catch(err) {
            throw 'Request Failed.\nStatus code: ' + httpRes.StatusCode + '.\nBody:
' + JSON.stringify(httpRes) + '.';
        }
        if(simpleReturn && simpleReturn.CODE) {
        throw "\n" + simpleReturn.TEXT + "\nCode: " + simpleReturn.CODE + "\nHTTP
Status Code: " + httpRes.StatusCode;
        }
    }
    try {
            rawResponse = JSON.parse(x2j(httpRes.Body));
        }
        catch(err) {
            return
        }
        var simpleReturn = rawResponse ? dq(rawResponse, 'SIMPLE_RETURN.RESPONSE')
: undefined;
        if(simpleReturn && simpleReturn.CODE) {
        throw "\n" + simpleReturn.TEXT + "\nCode: " + simpleReturn.CODE + "\nHTTP
Status Code: " + httpRes.StatusCode;
        }
}


function isEmptyXMLRes(contextData, rawResponse) {
    var response = dq(rawResponse, contextData.ContentPath[0]);
    if (response && Object.keys(response).length === 1 && response.DATETIME){
        return "No Items Found";
    }
    return '';
}
function createStandartReturnObject(rawResponse, contextData) {
    if (!contextData.entityType) {
        return dq(rawResponse, contextData.ContentPath[0] + contextData.ContentPath[1]);
    }
    var entity = entityDict[contextData.entityType];
    return mapObjFunction(entity)(dq(rawResponse, contextData.ContentPath[0] +
contextData.ContentPath[1])); }

function createReturnObjectFromItemList(rawResponse, contextData) {
    if (!contextData.entityType) {
        return '';
    }
    var entity = entityDict[contextData.entityType];
    return mapObjFunction(entity)(
        itemListToMap(dq(rawResponse, contextData.ContentPath[0] + contextData.ContentPath[1])));
}

function createIPListReturnObject(rawResponse, contextData) {
    if (!contextData.entityType) {
        return dq(rawResponse, contextData.ContentPath[0] + contextData.ContentPath[1]);
    }
    var entity = entityDict[contextData.entityType];
    return mapObjFunction(entity)(createIPArrayFromIPSet(dq(rawResponse, contextData.ContentPath[0]
+ contextData.ContentPath[1]))); }

function getTextMsg(contextData, rawResponse){
    var res = dq(rawResponse, contextData.ContentPath[0]);
    if(res.TEXT) {
        return res.TEXT;
    }
    return '';
}


function createTableWithTitleOrText(rawResponse, returnObject, contextData, Title) {
    var text = getTextMsg(contextData, rawResponse);
    var title = (text) ? text : Title;
    return (returnObject) ? tableToMarkdown(title, returnObject) : title;
}

function handleXMLWithTable(httpRes, method) {
    var rawResponse = parseXMLAndCheckErrors(httpRes);
    var contextData = contextDict[method];
    isEmpty = isEmptyXMLRes(contextData, rawResponse);
    if(isEmpty) {
        return createStandartEntry('', '', isEmpty, rawResponse);
    }
    var returnObject = createStandartReturnObject(rawResponse, contextData);
    var humanReadable = createTableWithTitleOrText(rawResponse, returnObject ,contextData,
titleDict[method]);
    return createStandartEntry(contextData.ContextPath, returnObject, humanReadable,
rawResponse); }

function handleSimpleReturnWithText(httpRes, method) {
    var rawResponse = parseXMLAndCheckErrors(httpRes);

    var contextData = contextDict[method];
    var isEmpty = isEmptyXMLRes(contextData, rawResponse);
    if(isEmpty) {
        return createStandartEntry('', '', isEmpty, rawResponse);
    }
    var returnObject = createReturnObjectFromItemList(rawResponse, contextData);

    var humanReadable = createTableWithTitleOrText(rawResponse, returnObject,contextData,
titleDict[method]);
    return createStandartEntry(contextData.ContextPath, returnObject, humanReadable,
rawResponse); }

function handleIPlist(httpRes, method) {
    var rawResponse = parseXMLAndCheckErrors(httpRes);
    var contextData = contextDict[method];
    var isEmpty = isEmptyXMLRes(contextData, rawResponse);
    if(isEmpty) {
        return createStandartEntry('', '', isEmpty, rawResponse);
    }

    var returnObject = createIPListReturnObject(rawResponse, contextData);
    var humanReadable = createTableWithTitleOrText(rawResponse, returnObject ,contextData,
titleDict[method]);
    return createStandartEntry(contextData.ContextPath, returnObject, humanReadable,
rawResponse); }


function handleReportDelete(httpRes, method) {
    var rawResponse = parseXMLAndCheckErrors(httpRes);
    var contextData = contextDict[method];
    var isEmpty = isEmptyXMLRes(contextData, rawResponse);
    if(isEmpty) {
        return createStandartEntry('', '', isEmpty, rawResponse);
    }
    var returnObject = createReturnObjectFromItemList(rawResponse, contextData);
    returnObject['Deleted'] = true;
    var humanReadable = createTableWithTitleOrText(rawResponse, returnObject,contextData,
titleDict[method]);
    return createStandartEntry(contextData.ContextPath, returnObject, humanReadable,
rawResponse); }

function handleFetchReport(httpRes, method) {
    nonXMLCheckErrors(httpRes);
    fileName = "report_ID_" + args['id'];

    return {
        Type: entryTypes.file,
        FileID: saveFile(httpRes.Bytes),
        File: fileName,
        Contents: fileName
    }
}

function handleFetchScan(httpRes, method) {
    nonXMLCheckErrors(httpRes);
    rawResponse = JSON.parse(httpRes.Body);
    if(rawResponse.length === 0){
        return "There were no vulnerabilities detected";
    }
    rawResponseParsed =  Array(rawResponse.length);
    for (var i = 0; i <rawResponseParsed.length; i++) {
        rawResponseParsed[i] = {};
        rawResponseParsed[i]["Ip"] = rawResponse[i]["ip"];
        rawResponseParsed[i]["Dns"] = rawResponse[i]["dns"];
        rawResponseParsed[i]["Netbios"] = rawResponse[i]["netbios"];
        rawResponseParsed[i]["QID"] = rawResponse[i]["qid"];
        rawResponseParsed[i]["Instance"] = rawResponse[i]["instance"];
        rawResponseParsed[i]["Result"] = rawResponse[i]["result"];
    }
    var contextData = contextDict[method];
    entry_context = {};
    entry_context[contextData.ContextPath] = rawResponseParsed;
    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: rawResponseParsed,
        ReadableContentsFormat: formats.markdown,
        EntryContext: entry_context,
        HumanReadable: tableToMarkdown(titleDict[method], rawResponseParsed),
    };

}

function handleFetchPCScan(httpRes, method) {
    var rawResponse = parseXMLAndCheckErrors(httpRes);
    var contextData = contextDict[method];
    isEmpty = isEmptyXMLRes(contextData, rawResponse);
    if(isEmpty) {
        return createStandartEntry('', '', isEmpty, rawResponse);
    }
    return dq(rawResponse, contextData.ContentPath[0] + contextData.ContentPath[1]);
}



function handleRawRespose(httpRes, method) {
    rawResponse = parseXMLAndCheckErrors(httpRes);
    return rawResponse;
}


function sendRequest(cmd) {

    var method = commandToMethod[cmd];
    if(!method){
        throw 'Command \"' + cmd + '\"  is not supported';
    }
    var url = baseUrl;
    // handle '/' at the end of the url
    if (url[url.length - 1] === '/') {
        url = url.substring(0, url.length - 1);
    }

    // add method path
    var requestUrl = url + methodPath[method];

    var methodFormated = getFormatedMethodParams(method);

    if (methodFormated) {
        requestUrl = requestUrl + '?' + methodFormated;
    }
    var res = http(
        requestUrl,
        {
            Username: params.credentials.identifier,
            Password: params.credentials.password,
            Method: methodHttpMethod[method],
            Headers: {'X-Requested-With': ['Demisto']},
        },
        params.insecure,
        params.proxy
    );
    return outputFunctionsDict[method](res, method);

}


switch (command) {
        case 'test-module':
            try {
                sendRequest('qualys-report-list');
            } catch (err) {
                return 'Connection test failed with error: ' + err + '.';
            }
            return 'ok';
        default:
            return sendRequest(command);
}
