var url = params.server.replace(/[\/]+$/, '') +'/api';

commandDictionary = {
    //breaches
    'ds-get-breach-reviews': {
        url: '/data-breach-record/%breach_id%/reviews',
        method: 'GET',
        extended: true,
        translator: [
            {
                contextPath: 'DigitalShadows.BreachReviews',
                title: 'Digital Shadows Breach Reviews',
                data: [
                    {to: 'Note', from: 'note'},
                    {to: 'Version', from: 'version'},
                    {to: 'Status', from: 'status'},
                    {to: 'UserID', from: 'user.id'},
                    {to: 'UserRole', from: 'user.role'},
                    {to: 'UserPermissions', from: 'user.permissions'},
                    {to: 'UserEmail', from: 'user.emailAddress'},
                    {to: 'CreatedAt', from: 'created'}
                ]
            }
        ],
    },
    'ds-snapshot-breach-status': {
        url: '/data-breach-record/%breach_id%/reviews',
        method: 'POST',
        customMD: function(res){return 'Request successful';}
    },
    'ds-find-breach-records': {
        url: '/data-breach-record/find',
        method: 'POST',
        extended: true,
        translator: [
            {
                contextPath: 'DigitalShadows.BreachRecords(val.Id && val.Id==obj.Id)',
                innerPath: 'content',
                title: 'Digital Shadows Breach Records',
                data: [
                    {to: 'Content', from: 'content'},
                    {to: 'Id', from: 'id'},
                    {to: 'Password', from: 'password'},
                    {to: 'DomainNames', from: 'domainNames'},
                    {to: 'PriorRowTextBreachCount', from: 'priorRowTextBreachCount'},
                    {to: 'PriorUsernameBreachCount', from: 'priorUsernameBreachCount'},
                    {to: 'PriorUsernamePasswordBreachCount', from: 'priorUsernamePasswordBreachCount'},
                    {to: 'Published', from: 'published'},
                    {to: 'Review.Created', from: 'review.created'},
                    {to: 'Review.Status', from: 'review.status'},
                    {to: 'Review.User', from: 'review.user'},
                    {to: 'Username', from: 'username'},
                    {to: 'DataBreachId', from: 'dataBreach.id'}
                ]
            }
        ]
    },
    'ds-get-breach-summary': {
        url: '/data-breach-summary',
        method: 'GET',
        urlQueryArgs: ['published']
    },
    'ds-find-breach-usernames': {
        url: '/data-breach-usernames/find',
        method: 'POST',
        extended: true,
        translator: [
            {
                contextPath: 'DigitalShadows.Users(val.Username && val.Username==obj.Username)',
                title: 'Digital SHadows Breach Reviews',
                innerPath: 'content',
                data: [
                    {to: 'BreachCount', from: 'breachCount'},
                    {to: 'DistinctPasswordCount', from: 'distinctPasswordCount'},
                    {to: 'Username', from: 'username'}
                ]
            }
        ],
    },
    'ds-get-breach': {
        url: '/data-breach/%breach_id%',
        method: 'GET',
        extended: true,
        translator: [
            {
                contextPath: 'DigitalShadows.Breaches(val.Id && val.Id==obj.Id)',
                title: 'Digital Shadows Breaches',
                data: [
                    {to: 'DomainCount', from: 'domainCount'},
                    {to: 'DomainName', from: 'domainName'},
                    {to: 'DataClasses', from: 'dataClasses'},
                    {to: 'Id', from: 'id'},
                    {to: 'IncidentId', from: 'incident.id'},
                    {to: 'IncidentScope', from: 'incident.scope'},
                    {to: 'IncidentSeverity', from: 'incident.severity'},
                    {to: 'IncidentTitle', from: 'incident.title'},
                    {to: 'IncidentType', from: 'incident.type'},
                    {to: 'Occurred', from: 'occurred'},
                    {to: 'RecordCount', from: 'recordCount'},
                    {to: 'SourceUrl', from: 'sourceUrl'},
                    {to: 'Title', from: 'title'}
                ]
            }
        ]
    },
    //done
    'ds-get-breach-records': {
        url: '/data-breach/%breach_id%/records',
        method: 'POST',
        extended: true,
        translator: [
            {
                contextPath: 'DigitalShadows.BreachRecords(val.Id && val.Id==obj.Id)',
                innerPath: 'content',
                title: 'Digital Shadows Breach Records',
                data: [
                    {to: 'Id', from: 'id'},
                    {to: 'Password', from: 'password'},
                    {to: 'PriorRowTextBreachCount', from: 'priorRowTextBreachCount'},
                    {to: 'PriorUsernameBreachCount', from: 'priorUsernameBreachCount'},
                    {to: 'PriorUsernamePasswordBreachCount', from: 'priorUsernamePasswordBreachCount'},
                    {to: 'Published', from: 'published'},
                    {to: 'Review.Created', from: 'review.created'},
                    {to: 'Review.Status', from: 'review.status'},
                    {to: 'Review.User', from: 'review.user'},
                    {to: 'Username', from: 'username'}
                ]
            }
        ]
    },
    'ds-find-data-breaches': {
        url: '/data-breach/find',
        method: 'POST',
        extended: true,
        translator: [
            {
                contextPath: 'DigitalShadows.Breaches(val.Id && val.Id==obj.Id)',
                title: 'Digital Shadows Breaches',
                innerPath: 'content',
                data: [
                    {to: 'DomainCount', from: 'domainCount'},
                    {to: 'DomainName', from: 'domainName'},
                    {to: 'DataClasses', from: 'dataClasses'},
                    {to: 'Id', from: 'id'},
                    {to: 'IncidentId', from: 'incident.id'},
                    {to: 'IncidentScope', from: 'incident.scope'},
                    {to: 'IncidentSeverity', from: 'incident.severity'},
                    {to: 'IncidentTitle', from: 'incident.title'},
                    {to: 'IncidentType', from: 'incident.type'},
                    {to: 'Occurred', from: 'occurred'},
                    {to: 'Modified', from: 'modified'},
                    {to: 'RecordCount', from: 'recordCount'},
                    {to: 'SourceUrl', from: 'sourceUrl'},
                    {to: 'Title', from: 'title'},
                    {to: 'OrganisationUsernameCount', from: 'organisationUsernameCount'}
                ]
            }
        ]
    },
    //incidents
    'ds-get-incident': {
        url: '/incidents/%incident_id%',
        method: 'GET',
        extended: true,
        translator: [
            {
                contextPath: 'DigitalShadows.Incidents(val.Id && val.Id==obj.Id)',
                title: 'Digital Shadows Incidents',
                data: [
                    {to: 'Alerted', from: 'alerted'},
                    {to: 'Description', from: 'description'},
                    {to: 'ImpactDescription', from: 'impactDescription'},
                    {to: 'Id', from: 'id'},
                    {to: 'Internal', from: 'internal'},
                    {to: 'Mitigation', from: 'mitigation'},
                    {to: 'Occurred', from: 'occurred'},
                    {to: 'Modified', from: 'modified'},
                    {to: 'Scope', from: 'scope'},
                    {to: 'Type', from: 'type'},
                    {to: 'Title', from: 'title'},
                    {to: 'Review.Created', from: 'review.created'},
                    {to: 'Review.Status', from: 'review.status'},
                    {to: 'Review.User', from: 'review.user'},
                    {to: 'SubType', from: 'subType'},
                    {to: 'Severity', from: 'severity'}
                ]
            }
        ],
        urlQueryArgs: ['fulltext']
    },
    'ds-get-incident-reviews': {
        url: '/incidents/%incident_id%/reviews',
        method: 'GET',
        extended: true,
        translator: [
            {
                contextPath: 'DigitalShadows.IncidentReviews(val.Id && val.Id==obj.Id)',
                title: 'Digital Shadows Incident Reviews',
                data: [
                    {to: 'Note', from: 'note'},
                    {to: 'Created', from: 'created'},
                    {to: 'Status', from: 'status'},
                    {to: 'User.Id', from: 'user.id'},
                    {to: 'Version', from: 'version'},
                    {to: 'User.EmailAddress', from: 'user.emailAddress'},
                    {to: 'User.FullName', from: 'user.fullName'},
                    {to: 'User.Role', from: 'user.role'},
                    {to: 'User.Status', from: 'user.status'}
                ]
            }
        ]
    },
    'ds-snapshot-incident-review': {
        url: '/incidents/%incident_id%/reviews',
        method: 'POST',
        extended: true,
        customMD: function(res){return 'Snapshot successful';}
    },
    'ds-find-incidents-filtered': {
        url: '/incidents/find',
        method: 'POST',
        extended: true,
        translator: [
            {
                contextPath: 'DigitalShadows.Incidents(val.Id && val.Id==obj.Id)',
                title: 'Digital Shadows Incidents',
                innerPath: 'content',
                data: [
                    {to: 'Alerted', from: 'alerted'},
                    {to: 'Description', from: 'description'},
                    {to: 'Id', from: 'id'},
                    {to: 'Internal', from: 'internal'},
                    {to: 'Mitigation', from: 'mitigation'},
                    {to: 'Occurred', from: 'occurred'},
                    {to: 'Modified', from: 'modified'},
                    {to: 'Occurred', from: 'occurred'},
                    {to: 'Published', from: 'published'},
                    {to: 'RestrictedContent', from:'restrictedContent'},
                    {to: 'RecordCount', from: 'recordCount'},
                    {to: 'Scope', from: 'scope'},
                    {to: 'Severity', from: 'severity'},
                    {to: 'Type', from: 'type'},
                    {to: 'SubType', frm: 'subType'},
                    {to: 'Verified', frm: 'verified'},
                    {to: 'Version', frm: 'version'},
                    {to: 'Title', from: 'title'},
                    {to: 'Score', from: 'score'},
                    {to: 'Review.Created', from: 'review.created'},
                    {to: 'Review.Status', from: 'review.status'},
                    {to: 'Review.User', from: 'review.user'}
                ]
            }
        ]
    },
    //command not exposed
    'ds-get-incidents-pipeline': {
        url: '/incidents/pipeline',
        method: 'POST'
    },
    'ds-get-incidents-summary':{
        url: '/incidents/summary',
        method: 'POST'
    },
    //intelligence-apt reports
    'ds-get-apt-report': {
        url: '/apt-report/%report_id%',
        method: 'GET',
        extended: true,
        translator: [
            {
                contextPath: 'DigitalShadows.APTReports(val.Id && val.Id==obj.Id)',
                title: 'APT Report',
                data: [
                    {to: 'Id', from: 'id'},
                    {to: 'Name', from: 'name'},
                    {to: 'Published', from: 'published'},
                    {to: 'Report.Id', from: 'report.id'},
                    {to: 'Report.Link', from: 'report.link'},
                    {to: 'Preview.Id', from: 'preview.id'},
                    {to: 'Preview.Link', from: 'preview.link'}
                ]
            }
        ]
    },
    //intelligence-incidents
    'ds-get-intelligence-incident':{
        url: '/intel-incidents/%incident_id%',
        method: 'GET',
        extended: true,
        translator: [
            {
                contextPath: 'DigitalShadows.IntelligenceIncidents(val.Id && val.Id==obj.Id)',
                title: 'Digital Shadows Intelligence Incident',
                data: [
                    {to: 'Description', from: 'description'},
                    {to: 'Id', from: 'id'},
                    {to: 'IndicatorOfCompromiseCount', from: 'indicatorOfCompromiseCount'},
                    {to: 'Internal', from: 'internal'},
                    {to: 'LinkedContentIncidents', from: 'linkedContentIncidents.id'},
                    {to: 'RelatedIncidentId', from: 'relatedIncident.id'},
                    {to: 'Occurred', from: 'occurred'},
                    {to: 'Modified', from: 'modified'},
                    {to: 'Published', from: 'published'},
                    {to: 'Scope', from: 'scope'},
                    {to: 'Severity', from: 'severity'},
                    {to: 'RestrictedContent', from: 'restrictedContent'},
                    {to: 'SubType', from: 'subType'},
                    {to: 'Title', from: 'title'},
                    {to: 'Type', from: 'type'},
                    {to: 'Verified', from: 'verified'},
                    {to: 'Version', from: 'version'}
                ]
            }
        ]
    },
    'ds-get-intelligence-incident-iocs':{
        url: '/intel-incidents/%incident_id%/iocs',
        method: 'POST',
        extended: true,
        translator: [
            {
                contextPath: 'DigitalShadows.IntelligenceIncidentsIOCs(val.Id && val.Id==obj.Id)',
                title: 'Intelligence Incident IOCs',
                innerPath: 'content',
                data: [
                    {to: 'Id', from: 'id'},
                    {to: 'IntelIncident.Id', from: 'intelIncident.id'},
                    {to: 'IntelIncident.Scope', from: 'intelIncident.scope'},
                    {to: 'Type', from: 'type'},
                    {to: 'Value', from: 'value'},
                    {to: 'Source', from: 'source'},
                    {to: 'LastUpdated', from: 'lastUpdated'},
                    {to: 'AptReport.Id', from: 'aptReport.id'}
                ]
            }
        ]
    },
    'ds-find-intelligence-incidents':{
        url: '/intel-incidents/find',
        method: 'POST',
        extended: true,
        translator: [
            {
                contextPath: 'DigitalShadows.IntelligenceIncidents(val.Id && val.Id==obj.Id)',
                title: 'Digital Shadows Intelligence Incidents',
                innerPath: 'content',
                data: [
                    {to: 'Description', from: 'description'},
                    {to: 'Id', from: 'id'},
                    {to: 'IndicatorOfCompromiseCount', from: 'indicatorOfCompromiseCount'},
                    {to: 'Internal', from: 'internal'},
                    {to: 'LinkedContentIncidents', from: 'linkedContentIncidents.id'},
                    {to: 'RelatedIncidentId', from: 'relatedIncident.id'},
                    {to: 'Occurred', from: 'occurred'},
                    {to: 'Modified', from: 'modified'},
                    {to: 'Published', from: 'published'},
                    {to: 'Scope', from: 'scope'},
                    {to: 'Severity', from: 'severity'},
                    {to: 'RestrictedContent', from: 'restrictedContent'},
                    {to: 'SubType', from: 'subType'},
                    {to: 'Title', from: 'title'},
                    {to: 'Type', from: 'type'},
                    {to: 'Verified', from: 'verified'},
                    {to: 'Version', from: 'version'}
                ]
            }
        ]
    },
    'ds-find-intelligence-incidents-regional':{
        url: '/intel-incidents/regional',
        method: 'POST',
        extended: true,
        translator: [
            {
                contextPath: 'DigitalShadows.IntelligenceIncidentsRegional(val.CountryTag.Id && val.CountryTag.Id==obj.CountryTag.Id)',
                title: 'Digital Shadows Intelligence Incidents',
                innerPath: 'incidentsByCountry',
                data: [
                    {to: 'CountryTag.Id', from: 'countryTag.id'},
                    {to: 'CountryTag.Name', from: 'countryTag.name'},
                    {to: 'CountryTag.ParentId', from: 'countryTag.parent.id'},
                    {to: 'CountryTag.ThreatId', from: 'countryTag.threat.id'},
                    {to: 'CountryTag.Type', from: 'countryTag.type'},
                    {to: 'IncidentIds', from: 'incidents.id'}
                ]
            }
        ]
    },
    'ds-get-intelligence-threat':{
        url: '/intel-threats/%threat_id%',
        method: 'GET',
        extended: true,
        translator: [
            {
                contextPath: 'DigitalShadows.IntelligenceThreats(val.Id && val.Id==obj.Id)',
                title: 'Digital Shadows Intelligence Threat',
                data: [
                    {to: 'ActivityLevel', from: 'activityLevel'},
                    {to: 'Id', from: 'id'},
                    {to: 'ImageId', from: 'imageId'},
                    {to: 'LastActive', from: 'lastActive'},
                    {to: 'Type', from: 'type'},
                    {to: 'EndDate', from: 'endDate'},
                    {to: 'LatestIncident', from: 'latestIncident'},
                    {to: 'Tags.PrimaryTag', from: 'primaryTag', humanReadable: false},
                    {to: 'Recurring', from: 'recurring'},
                    {to: 'Tags.SourceGeographyTags', from: 'sourceGeographyTags', humanReadable: false},
                    {to: 'AptReportIDs', from: 'aptReports.id'},
                    {to: 'EndDate', from: 'endDate'},
                    {to: 'ImageThumbnailId', from: 'imageThumbnailId'},
                    {to: 'IndicatorOfCompromiseCount', from: 'indicatorOfCompromiseCount'},
                    {to: 'StartDate', from: 'startDate'},
                    {to: 'Tags.ActorTypeTags', from: 'actorTypeTags', humanReadable: false},
                    {to: 'AnnouncementIncidentIDs', from: 'announcementIncidentIDs'},
                    {to: 'Tags.AssociatedActorTags', from: 'associatedActorTags', humanReadable: false},
                    {to: 'Tags.AssociatedCampaignTags', from: 'associatedCampaignTags', humanReadable: false},
                    {to: 'AssociatedEventIDs', from: 'associatedEvents.id'},
                    {to: 'AttackEvidenceIncidentIDs', from: 'attackEvidenceIncidents.id'},
                    {to: 'Tags.ImpactEffectTags', from: 'impactEffectTags', humanReadable: false},
                    {to: 'Tags.IntendedEffectTags', from: 'intendedEffectTags', humanReadable: false},
                    {to: 'LatestIncidentID', from: 'latestIncident.id'},
                    {to: 'Tags.MotivationTags', from: 'motivationTags', humanReadable: false},
                    {to: 'Tags.OverviewTags', from: 'overviewTags', humanReadable: false},
                    {to: 'Tags.PrimaryLanguageTags', from: 'primaryLanguageTags', humanReadable: false},
                    {to: 'ThreatLevel', from: 'threatLevel.type'}
                ]
            }
        ],
        urlQueryArgs: ['opt']
    },
    'ds-get-intelligence-threat-iocs':{
        url: '/intel-threats/%threat_id%/iocs',
        method: 'POST',
        extended: true,
        translator: [
            {
                innerPath: 'content',
                contextPath: 'DigitalShadows.IntelligenceThreatIOCs',
                title: 'Digital Shadows Intelligence Threat IOCs',
                data: [
                    {to: 'APTReportId', from: 'aptReport.id'},
                    {to: 'Id', from: 'id'},
                    {to: 'IntelIncidentId', from: 'intelIncident.id'},
                    {to: 'LastUpdated', from: 'lastUpdated'},
                    {to: 'Source', from: 'source'},
                    {to: 'Type', from: 'type'},
                    {to: 'Value', from: 'value'}
                ]
            }
        ]
    },
    'ds-get-intelligence-threat-activity':{
        url: '/intel-threats/activity',
        method: 'POST'
    },
    'ds-find-intelligence-threats':{
        url: '/intel-threats/find',
        method: 'POST',
        extended: true,
        translator: [
            {
                contextPath: 'DigitalShadows.IntelligenceThreats(val.Id && val.Id==obj.Id)',
                title: 'Digital Shadows Intelligence Threats',
                innerPath: 'content',
                data: [
                    {to: 'ActivityLevel', from: 'activityLevel'},
                    {to: 'Id', from: 'id'},
                    {to: 'ImageId', from: 'imageId'},
                    {to: 'LastActive', from: 'lastActive'},
                    {to: 'Type', from: 'type'},
                    {to: 'ThreatLevelType', from: 'threatLevel.type'},
                    {to: 'Event', from: 'event'}
                ]
            }
        ]
    },
    'ds-find-intelligence-threats-regional':{
        url: '/intel-threats/regional',
        method: 'POST',
        extended: true,
        translator: [
            {
                contextPath: 'DigitalShadows.IntelligenceThreatsRegional(val.Id && val.Id==obj.Id)',
                title: 'Digital Shadows Regional Intelligence Threats',
                data: [
                    {to: 'ActivityLevel', from: 'activityLevel'},
                    {to: 'Id', from: 'id'},
                    {to: 'ImageId', from: 'imageId'},
                    {to: 'LastActive', from: 'lastActive'},
                    {to: 'Type', from: 'type'},
                    {to: 'ThreatLevelType', from: 'threatLevel.type'},
                    {to: 'Event', from: 'event'},
                    {to: 'OverviewTags', from: 'overviewTags', humanReadable: false}
                ]
            }
        ]
    },
    'ds-get-port-reviews':{
        url: '/ip-ports/%port%/reviews',
        method: 'GET',
        extended: true,
        translator: [
            {
                contextPath: 'DigitalShadows.IpPortReviews(val.Id && val.Id==obj.Id)',
                title: 'Digital Shadows Port Review',
                data: [
                    {to: 'Created', from: 'created'},
                    {to: 'Status', from: 'status'},
                    {to: 'Version', from: 'version'},
                    {to: 'Incident.Id', from: 'incident.id'},
                    {to: 'Incident.Scope', from: 'incident.scope'},
                    {to: 'User.Id', from: 'user.id'},
                    {to: 'User.FullName', from: 'user.fullName'}
                ]
            }
        ],
        urlQueryArgs: ['incidentId']
    },
    'ds-snapshot-port-review':{
        url: '/ip-ports/%port%/reviews',
        method: 'POST',
        customMD: function(res){return 'Success';}
    },
    'ds-find-ports':{
        url: '/ip-ports/find',
        method: 'POST',
        extended: true,
        translator: [
            {
                innerPath: 'content',
                contextPath: 'DigitalShadows.IpPorts(val.Id && val.Id==obj.Id)',
                title: 'Digital Shadows Ports',
                data: [
                    {to: 'DiscoveredOpen', from: 'discoveredOpen'},
                    {to: 'Id', from: 'id'},
                    {to: 'IpAddress', from: 'ipAddress'},
                    {to: 'PortNumber', from: 'portNumber'},
                    {to: 'Transport', from: 'transport'},
                    {to: 'Incident.Id', from: 'incident.id'},
                    {to: 'Incident.Scope', from: 'incident.scope'},
                    {to: 'Incident.Severity', from: 'incident.severity'},
                    {to: 'Incident.SubType', from: 'incident.subType'},
                    {to: 'Incident.Type', from: 'incident.type'},
                    {to: 'Incident.Title', from: 'incident.title'},
                    {to: 'Incident.Published', from: 'incident.published'},
                    {to: 'Review.Status', from: 'review.status'},
                    {to: 'Review.UserId', from: 'review.user.id'},
                    {to: 'Review.UserName', from: 'review.user.fullName'},
                    {to: 'Review.Version', from: 'review.version'}
                ]

            }
        ]
    },
    'ds-find-secure-sockets':{
        url: '/secure-socket/find',
        method: 'POST',
        extended: true,
        translator: [
            {
                innerPath: 'content',
                contextPath: 'DigitalShadows.SecureSockets(val.Id && val.Id==obj.Id)',
                title: 'Digital Shadows Secure Sockets',
                data: [
                    {to: 'Id', from: 'id'},
                    {to: 'Discovered', from: 'discovered'},
                    {to: 'DomainName', from: 'domainName'},
                    {to: 'Grade', from: 'grade'},
                    {to: 'IpAddress', from: 'ipAddress'},
                    {to: 'PortNumber', from: 'portNumber'},
                    {to: 'Transport', from: 'transport'},
                    {to: 'Issues', from: 'issues'},
                    {to: 'Review.Status', from: 'review.status'},
                    {to: 'Review.UserId', from: 'review.user.id'},
                    {to: 'Review.UserName', from: 'review.user.fullName'},
                    {to: 'Review.Version', from: 'review.version'},
                    {to: 'Incident.Id', from: 'incident.id'},
                    {to: 'Incident.Scope', from: 'incident.scope'},
                    {to: 'Incident.Severity', from: 'incident.severity'},
                    {to: 'Incident.SubType', from: 'incident.subType'},
                    {to: 'Incident.Type', from: 'incident.type'},
                    {to: 'Incident.Title', from: 'incident.title'},
                    {to: 'Incident.Published', from: 'incident.published'},
                    {to: 'CertificateCommonName', from: 'certificateCommonName'},
                    {to: 'ReverseDomainName', from: 'reverseDomainName'}
                ]
            }
        ]
    },
    'ds-find-vulnerabilities':{
        url: '/vulnerability/find',
        method: 'POST',
        extended: true,
        translator: [
            {
                innerPath: 'content',
                contextPath: 'DigitalShadows.Vulnerabilities(val.Id && val.Id==obj.Id)',
                title: 'Digital Shadows Vulnerabilities',
                data: [
                    {to: 'CveId', from: 'cveId'},
                    {to: 'Id', from: 'id'},
                    {to: 'Discovered', from: 'discovered'},
                    {to: 'IpAddress', from: 'ipAddress'},
                    {to: 'Review.Status', from: 'review.status'},
                    {to: 'Review.UserId', from: 'review.user.id'},
                    {to: 'Review.UserName', from: 'review.user.fullName'},
                    {to: 'Review.Version', from: 'review.version'},
                    {to: 'Incident.Id', from: 'incident.id'},
                    {to: 'Incident.Scope', from: 'incident.scope'},
                    {to: 'Incident.Severity', from: 'incident.severity'},
                    {to: 'Incident.SubType', from: 'incident.subType'},
                    {to: 'Incident.Type', from: 'incident.type'},
                    {to: 'Incident.Title', from: 'incident.title'},
                    {to: 'Incident.Published', from: 'incident.published'},
                ]
            }
        ]
    },
    'ds-search':{
        url: '/search/find',
        method: 'POST'
    },
    'ds-get-tags':{
        url: '/tags/batch',
        method: 'GET',
        urlQueryArgs: ['detailed', 'id']
    }
};

arrayArgs = {
    domainNames : true,
    reviewStatuses: true,
    statuses: true,
    domainNamesOnRecords: true,
    repostedCredentials: true,
    severities: true,
    types: true,
    subTypes: true
};

var createBody = function(args, arrayArgs) {
    var Body = {};
    var cur = Body;
    keys = Object.keys(args);
    keys.forEach(function(key){
        sub_keys = key.split('_');
        for(var i=0; i<sub_keys.length - 1; i++){
            if (!cur[sub_keys[i]]){
                cur[sub_keys[i]] = {};
                if(arrayArgs[sub_keys[i]]){
                    cur[sub_keys[i]] = [{}];
                }
            }
            cur = cur[sub_keys[i]];
            if(Array.isArray(cur)){
                cur = cur[0];
            }
        }
        last_sub_key = sub_keys[sub_keys.length - 1];
        cur[last_sub_key] = arrayArgs[last_sub_key] && !Array.isArray(args[key]) ? args[key].split(',') : args[key];
        cur = Body;
    });
    return Body;
};


var encodeToURLQueryByFilter = function(filter, args){
    if (!filter){
        return '';
    }
    var filtered = {};
    filter.forEach(function(key){
        if(args[key]){
            filtered[key] = args[key];
            delete args[key];
        }
    });
    return encodeToURLQuery(filtered);
};

var sendRequest = function(url, method, body) {
    var res = http(
        url,
        {
            Method: method,
            Headers: {
                'Content-Type': ['application/json']
            },
            Username: params.apikey,
            Password: params.secret,
            Body: JSON.stringify(body)
        },
        params.insecure,
        params.proxy
    );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }
    return res.Body;
};

var fetchCommandIncidents = function(comnd, bodyArgs, name){
    incidents = [];
    cmd = commandDictionary[comnd];
    res = sendRequest(url+cmd.url, cmd.method, createBody(bodyArgs, arrayArgs));
    parsed_res = JSON.parse(res);
    if (parsed_res && parsed_res.content){
        parsed_res.content.forEach(function(inc){
            inc['origin'] = name;
            incidents.push({
              name: name,
              rawJSON: JSON.stringify(inc)
            });
        });
    }
    return incidents;
};

var getIncidentsIds = function(incidents) {
    var ids = [];
    incidents.forEach(function(inc) {
        ids.push(JSON.parse(inc.rawJSON).id);
    });

    return ids;
};

var fetchIncidents = function(){
    var lastRun = getLastRun();
    nowDate = new Date();
    var now = nowDate.toISOString();
    if (!lastRun || !lastRun.value) {
        lastRun = {value: (new Date(nowDate.getTime() - 1*60*1000)).toISOString()};
    }

    // first API call - fetch PHISHING_ATTEMPT incidents only (within the date range)
    bodyArgs = {filter_types_type:'BRAND_PROTECTION', filter_types_subTypes:'PHISHING_ATTEMPT', filter_dateRange: lastRun.value + '/' + now};
    var incidents = fetchCommandIncidents('ds-find-incidents-filtered', bodyArgs, 'PHISHING_ATTEMPT');

    var ids = getIncidentsIds(incidents);

    // second API call - fetch all incidents (within the date range)
    bodyArgs = {filter_dateRange: lastRun.value + '/' + now};
    temp = fetchCommandIncidents('ds-find-incidents-filtered', bodyArgs, 'Client Incident');

    if (incidents) {
        // concatenate only new incident to list (filter the duplicates)
        filteredIncidents = temp.filter(function(inc) {
           incidentId = JSON.parse(inc.rawJSON).id;
           notDuplicatedIncident = (ids.indexOf(incidentId) == -1);
           return notDuplicatedIncident;
        });
        incidents = incidents.concat(filteredIncidents);
    }
    else {
        incidents = temp;
    }

    // third API call - fetch intelligence incidents (within the date range)
    incidents = incidents.concat(fetchCommandIncidents('ds-find-intelligence-incidents', bodyArgs, 'Intelligence Incident'));

    // fourth API call - fetch data breaches (within the date range)
    bodyArgs = {filter_published: lastRun.value + '/' + now};
    incidents = incidents.concat(fetchCommandIncidents('ds-find-data-breaches', bodyArgs, 'Data Breach'));

    setLastRun({value: now});
    return JSON.stringify(incidents);
};

switch (command) {
    case 'test-module':
        cmd = commandDictionary['ds-get-breach-summary'];
        sendRequest(url+cmd.url, cmd.method);
        return 'ok';
    case 'fetch-incidents':
        return fetchIncidents();
    default:
        cmd = commandDictionary[command];
        res = sendRequest(url+replaceInTemplatesAndRemove(cmd.url, args)+encodeToURLQueryByFilter(cmd.urlQueryArgs, args), cmd.method, createBody(args, arrayArgs));
        if (cmd.customMD){
            return cmd.customMD(res);
        }
        if(cmd.extended === true)
            return createEntry(JSON.parse(res), cmd.translator[0]);
        try{
            return JSON.parse(res);
        } catch(err) {
            return res;
        }
}
