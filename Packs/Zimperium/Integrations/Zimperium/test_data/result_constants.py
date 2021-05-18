EXPECTED_SEARCH_EVENTS = [
    {'eventId': 'c4220bdf-0c0b-489c-a915-7d71bba7197a', 'eventStateCode': 1, 'eventState': 'Pending',
     'typeDesc': 'ZIPS_EVENT', 'eventVector': '2', 'severity': 'IMPORTANT', 'eventName': 'THREAT_DETECTED',
     'eventFullName': 'host.vulnerable.ios', 'customerId': 'becky', 'customerContactName': 'becky',
     'customerContactPhone': '+1 415 1234567',
     'deviceHash': 'ae14a9f3359cc75f122c4b38f0a033503b82995e5ec4fe54d5a93df35f9b81',
     'deviceId': '37245C48-D3B9-474A-80BA-54E66DDF0D94', 'mdmId': None,
     'zdid': '0082956f-380c-4e91-baf6-6e36da54040a',
     'latitude': 32.925141094962385, 'longitude': -96.84469371892781, 'bssid': 'Unknown', 'ssid': 'Unknown',
     'deviceTime': '2019-01-08 18:39:56 +0000', 'queuedTime': '2019-01-08 18:39:56 +0000',
     'persistedTime': '2019-01-08 18:39:56 +0000', 'lastSeenTime': '2019-01-08 18:39:55 +0000',
     'mitigatedDate': None,
     'deviceModel': 'iPhone', 'osType': 'iOS', 'osVersion': '11.4.1', 'country': 'US',
     'userEmail': 'pat@example.com',
     'userPhoneNumber': '', 'firstName': 'anonymous', 'middleName': None, 'lastName': 'user',
     'locationDetail': {'previousLongitude': -96.84469371892781, 'previousLatitude': 32.925141094962385,
                        'exact': True,
                        'previousSampledTimeAsDate': 1546972781000, 'sampledTimeAsDate': 1546972796046},
     'bundleId': 'com.zimperium.zIPS.appstore', 'zipsVersion': '4.7.0', 'appName': 'zIPS', 'tag1': '',
     'tag2': '',
     'incidentSummary': 'The system has detected that the iOS version installed onyour device is not '
                        'up-to-date. The outdated operating system exposes the device to known vulnerabilities '
                        'and the threat of being exploited by malicious actors. It is advised to update your '
                        'operating system immediately.',
     'eventDetail': None},
    {'eventId': '8065749b-c12c-4ba5-995c-7efaa3eef254', 'eventStateCode': 1, 'eventState': 'Pending',
     'typeDesc': 'ZIPS_EVENT', 'eventVector': '2', 'severity': 'IMPORTANT', 'eventName': 'THREAT_DETECTED',
     'eventFullName': 'host.pin', 'customerId': 'becky', 'customerContactName': 'becky',
     'customerContactPhone': '+1 415 1234567',
     'deviceHash': 'ae14a9f3359cc75f122c4b38f0a033503b82995e5ec4fe54d5a93df35f9b81',
     'deviceId': '37245C48-D3B9-474A-80BA-54E66DDF0D94', 'mdmId': None,
     'zdid': '0082956f-380c-4e91-baf6-6e36da54040a',
     'latitude': 32.925141094962385, 'longitude': -96.84469371892781, 'bssid': '9c:5d:12:fa:b7:27',
     'ssid': 'z-Wifi',
     'deviceTime': '2019-01-08 18:39:43 +0000', 'queuedTime': '2019-01-08 18:39:43 +0000',
     'persistedTime': '2019-01-08 18:39:43 +0000', 'lastSeenTime': '2019-01-08 18:39:55 +0000',
     'mitigatedDate': None,
     'deviceModel': 'iPhone', 'osType': 'iOS', 'osVersion': '11.4.1', 'country': 'US',
     'userEmail': 'pat@example.com',
     'userPhoneNumber': '', 'firstName': 'Test', 'middleName': None, 'lastName': 'User',
     'locationDetail': {'previousLongitude': 0, 'previousLatitude': 0, 'exact': None,
                        'sampledTimeAsDate': 1546972783751}, 'bundleId': 'com.zimperium.zIPS.appstore',
     'zipsVersion': '4.7.0', 'appName': 'zIPS', 'tag1': '', 'tag2': '',
     'incidentSummary': 'Your device is not setup to use a PIN code, Password, or Pattern to lock your device. '
                        'By not using a PIN code, Password, or Pattern to lock your device, sensitive data on '
                        'the device could be exposed to attackers if your device is stolen or compromised. '
                        'It is advised that a PIN code, Password, or Pattern be enabled as a standard security '
                        'practice in securing your device and securing the sensitive data on the device.',
     'eventDetail': None}
]
EXPECTED_SEARCH_USERS = [
    {
        'objectId': '1B9182C7-8C12-4499-ADF0-A338DEFDFC33', 'lastLogin': '2019-02-01T17:12:35+0000',
        'email': 'zauto@example.com', 'alias': 'e7f4eb20-5433-42e0-8229-8910e342d4fc', 'firstName': 'zAuto',
        'middleName': 'Tool', 'lastName': 'QA', 'status': 1, 'dateJoined': '2019-02-01T17:12:35+0000',
        'agreedToTerms': True, 'pwdRecoveryRequest': False, 'role': 4, 'signupSteps': 1,
        'createdDate': '2019-02-01T17:12:35+0000', 'modifiedDate': '2019-02-01T17:12:35+0000',
        'roles': [{'roleId': 150061}],
        'activationTokenUrl': 'https://demo-device-api.zimperium.com',
        'superuser': False, 'staff': False, 'phoneNumberVerified': False, 'syncedFromMdm': False
    }
]
EXPECTED_USER_GET_BY_ID = {
    "objectId": "1B9182C7-8C12-4499-ADF0-A338DEFDFC33",
    "lastLogin": "2019-02-01T17:12:35+0000",
    "email": "zauto@example.com",
    "alias": "e7f4eb20-5433-42e0-8229-8910e342d4fc",
    "firstName": "zAuto",
    "middleName": "Tool",
    "lastName": "QA",
    "status": 1,
    "dateJoined": "2019-02-01T17:12:35+0000",
    "agreedToTerms": True,
    "pwdRecoveryRequest": False,
    "role": 4,
    "signupSteps": 1,
    "createdDate": "2019-02-01T17:12:35+0000",
    "modifiedDate": "2019-02-01T17:12:35+0000",
    "roles": [
        {
            "roleId": 150061
        }
    ],
    "activationTokenUrl": "https://demo-device-api.zimperium.com",
    "superuser": False,
    "staff": False,
    "phoneNumberVerified": False,
    "syncedFromMdm": False
}
EXPECTED_SEARCH_DEVICES = [
    {
        'zdid': '87a587de-283f-48c9-9ff2-047c8b025b6d', 'deviceId': '1dbf5a9e-b0e8-4625-9205-6d9df8750c3f',
        'deviceHash': '3dce52cf609b70d00865fa8a4bbc3ccb49cdd05ea88dd897fe98c6e510f0a3',
        'mdmId': '1dbf5a9e-b0e8-4625-9205-6d9df8750c3f', 'statusCode': 1, 'status': 'Active',
        'zipsVersion': '4.8.0', 'lastSeen': '2019-02-01 05:13:12 UTC', 'createdAt': '2019-02-01 05:13:12 UTC',
        'updatedDate': '2019-02-01 05:13:12 UTC', 'country': 'US', 'countryCode': '310',
        'operatorAlpha': 'AT&T', 'type': 'iPhone', 'zipsDistributionVersion': 'n/a', 'appName': 'zIPS',
        'bundleId': 'com.zimperium.vzips', 'externalTrackingId1': '', 'externalTrackingId2': '',
        'version': '4.8.0', 'osUpgradeable': False, 'osVulnerable': False, 'model': 'iPhoneXS Max',
        'osVersion': '12.0.0', 'osType': 'iOS', 'userId': '868CEA8B-7796-44B6-B249-724A325EDE78',
        'email': 'zauto@example.com', 'firstName': 'zAuto', 'middleName': 'Tool', 'lastName': 'QA',
        'systemToken': 'automation-rest', 'riskPostureCode': 0, 'riskPosture': 'Normal',
        'vulnerabilities': []
    }
]
EXPECTED_DEVICE_GET_BY_ID = {
    'zdid': '87a587de-283f-48c9-9ff2-047c8b025b6d', 'deviceId': '1dbf5a9e-b0e8-4625-9205-6d9df8750c3f',
    'deviceHash': '3dce52cf609b70d00865fa8a4bbc3ccb8c49cdd05ea88dd897fe98c6e510f0a3', 'statusCode': 1,
    'status': 'Active', 'zipsVersion': '4.8.0', 'lastSeen': '2019-02-01 05:13:12 UTC',
    'createdAt': '2019-02-01 05:13:12 UTC', 'updatedDate': '2019-02-01 05:13:12 UTC', 'country': 'US',
    'countryCode': '310', 'operatorAlpha': 'AT&T', 'type': 'iPhone', 'zipsDistributionVersion': 'n/a',
    'appName': 'zIPS', 'bundleId': 'com.zimperium.vzips', 'externalTrackingId1': '', 'externalTrackingId2': '',
    'version': '4.8.0', 'osUpgradeable': False, 'osVulnerable': False, 'model': 'iPhoneXS Max',
    'osVersion': '12.0.0', 'osType': 'iOS', 'userId': '868CEA8B-7796-44B6-B249-724A325EDE78',
    'email': 'zauto@example.com', 'firstName': 'zAuto', 'middleName': 'Tool', 'lastName': 'QA',
    'systemToken': 'automation-rest', 'riskPostureCode': 0, 'riskPosture': 'Normal', 'vulnerabilities': []
}
EXPECTED_APP_CLASSIFICATION_GET = {
    'objectId': 'd28bf74c-c978-488e-a7e4-e15f4d864927', 'systemToken': 'joseph',
    'hash': 'aad9b2fd4606467f06931d72048ee1dff137cbc9b601860a88ad6a2c092',
    'modifiedDate': '2018-12-14 12:37:52 UTC', 'classification': 'Legitimate', 'name': 'Test',
    'version': '2.1.3', 'score': 0.0, 'privacyEnum': 0, 'securityEnum': 1, 'processState': 'AVAILABLE',
    'deviceCount': 0, 'metadata': {'name': 'Test', 'bundleId': 'com.apple.Test', 'applicationSize': 10600448,
                                   'id': '045c470c-e6f4-3b86-9da6-5b1005c8459f', 'version': '2.1.3',
                                   'hash': 'aad9b2fd4606467f06931d72048ee1dff137cbc9b601860a88ad6a2c092',
                                   'platform': 'iOS'}, 'securityRisk': 'Medium', 'privacyRisk': 'Low'
}
EXPECTED_MULTIPLE_APP_CLASSIFICATION_GET = [
    {
        'classification': 'Legitimate', 'deviceCount': 1, 'hash': '85525e9c1fd30a20848812e417f3bb1a', 'metadata': {
        'activities': [
            'com.google.android.apps.tachyon.appupdate.HardBlockActivity',
            'com.google.android.apps.tachyon.call.feedback.BadCallRatingActivity',
            'com.google.android.apps.tachyon.call.history.ExportHistoryActivity',
            'com.google.android.apps.tachyon.call.oneonone.ui.OneOnOneCallActivity',
            'com.google.android.apps.tachyon.call.postcall.ui.PostCallActivity',
            'com.google.android.apps.tachyon.call.precall.OneOnOnePrecallActivity',
            'com.google.android.apps.tachyon.call.precall.fullhistory.FullHistoryActivity',
            'com.google.android.apps.tachyon.clips.share.ReceiveShareIntentActivity',
            'com.google.android.apps.tachyon.clips.ui.ClipsComposerActivity',
            'com.google.android.apps.tachyon.clips.ui.gallerypicker.GalleryPickerActivity',
            'com.google.android.apps.tachyon.clips.ui.viewclips.ViewClipsActivity',
            'com.google.android.apps.tachyon.externalcallactivity.ExternalCallActivity',
            'com.google.android.apps.tachyon.groupcalling.creategroup.EditGroupActivity',
            'com.google.android.apps.tachyon.groupcalling.creategroup.GroupCreationActivity',
            'com.google.android.apps.tachyon.groupcalling.incall.InGroupCallActivity',
            'com.google.android.apps.tachyon.groupcalling.incoming.IncomingGroupCallActivity',
            'com.google.android.apps.tachyon.groupcalling.precall.PrecallScreenGroupActivity',
            'com.google.android.apps.tachyon.groupcalling.precall.PrecallScreenGroupInviteActivity',
            'com.google.android.apps.tachyon.invites.externalinvite.ExternalInviteActivity',
            'com.google.android.apps.tachyon.invites.invitescreen.InviteScreenActivity',
            'com.google.android.apps.tachyon.registration.countrycode.CountryCodeActivity',
            'com.google.android.apps.tachyon.registration.enterphonenumber.PhoneRegistrationActivity',
            'com.google.android.apps.tachyon.registration.onboarding.OnboardingActivity',
            'com.google.android.apps.tachyon.settings.blockedusers.BlockedUsersActivity',
            'com.google.android.apps.tachyon.settings.knockknock.KnockKnockSettingActivity',
            'com.google.android.apps.tachyon.settings.notifications.NotificationSettingsActivity',
            'com.google.android.apps.tachyon.settings.v2.AccountSettingsActivity',
            'com.google.android.apps.tachyon.settings.v2.ApplicationSettingsActivity',
            'com.google.android.apps.tachyon.settings.v2.CallSettingsActivity',
            'com.google.android.apps.tachyon.settings.v2.MessageSettingsActivity',
            'com.google.android.apps.tachyon.ui.blockusers.BlockUsersActivity',
            'com.google.android.apps.tachyon.ui.duoprivacy.DuoPrivacyActivity',
            'com.google.android.apps.tachyon.ui.launcher.LauncherActivity',
            'com.google.android.apps.tachyon.ui.lockscreen.LockscreenTrampolineActivity',
            'com.google.android.apps.tachyon.ui.main.MainActivity',
            'com.google.android.apps.tachyon.ui.warningdialog.WarningDialogActivity',
            'com.google.android.gms.common.api.GoogleApiActivity',
            'com.google.android.libraries.social.licenses.LicenseActivity',
            'com.google.android.libraries.social.licenses.LicenseMenuActivity',
            'com.google.android.libraries.surveys.internal.view.SurveyActivity',
            'com.google.android.play.core.common.PlayCoreDialogWrapperActivity',
            'com.google.android.play.core.missingsplits.PlayCoreMissingSplitsActivity',
            'com.google.research.ink.annotate.AnnotateActivity'],
        'filename': '/data/app/com.google.android.apps.tachyon-5hQwDR1DIKxnBrAIkdNlmg==/base.apk',
        'package': 'com.google.android.apps.tachyon',
        'permissions': [
            'android.permission.ACCESS_NETWORK_STATE', 'android.permission.ACCESS_WIFI_STATE',
            'android.permission.AUTHENTICATE_ACCOUNTS', 'android.permission.BLUETOOTH',
            'android.permission.BROADCAST_STICKY', 'android.permission.CAMERA',
            'android.permission.CHANGE_NETWORK_STATE', 'android.permission.FOREGROUND_SERVICE',
            'android.permission.GET_ACCOUNTS', 'android.permission.GET_PACKAGE_SIZE',
            'android.permission.INTERNET', 'android.permission.MANAGE_ACCOUNTS',
            'android.permission.MODIFY_AUDIO_SETTINGS', 'android.permission.READ_APP_BADGE',
            'android.permission.READ_CONTACTS', 'android.permission.READ_PHONE_STATE',
            'android.permission.READ_PROFILE', 'android.permission.READ_SYNC_STATS',
            'android.permission.RECEIVE_BOOT_COMPLETED', 'android.permission.RECORD_AUDIO',
            'android.permission.VIBRATE', 'android.permission.WAKE_LOCK',
            'android.permission.WRITE_CALL_LOG', 'android.permission.WRITE_CONTACTS',
            'android.permission.WRITE_SYNC_SETTINGS', 'com.anddoes.launcher.permission.UPDATE_COUNT',
            'com.android.launcher.permission.INSTALL_SHORTCUT',
            'com.google.android.c2dm.permission.RECEIVE',
            'com.google.android.providers.gsf.permission.READ_GSERVICES',
            'com.htc.launcher.permission.READ_SETTINGS', 'com.htc.launcher.permission.UPDATE_SHORTCUT',
            'com.huawei.android.launcher.permission.CHANGE_BADGE',
            'com.huawei.android.launcher.permission.READ_SETTINGS',
            'com.huawei.android.launcher.permission.WRITE_SETTINGS',
            'com.majeur.launcher.permission.UPDATE_BADGE', 'com.oppo.launcher.permission.READ_SETTINGS',
            'com.oppo.launcher.permission.WRITE_SETTINGS',
            'com.samsung.android.app.telephonyui.permission.READ_SETTINGS_PROVIDER',
            'com.samsung.android.app.telephonyui.permission.WRITE_SETTINGS_PROVIDER',
            'com.samsung.android.aremoji.provider.permission.READ_STICKER_PROVIDER',
            'com.samsung.android.livestickers.provider.permission.READ_STICKER_PROVIDER',
            'com.samsung.android.provider.filterprovider.permission.READ_FILTER',
            'com.samsung.android.provider.stickerprovider.permission.READ_STICKER_PROVIDER',
            'com.sec.android.provider.badge.permission.READ',
            'com.sec.android.provider.badge.permission.WRITE',
            'com.sonyericsson.home.permission.BROADCAST_BADGE',
            'com.sonymobile.home.permission.PROVIDER_INSERT_BADGE'],
        'receivers': [
            'androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryChargingProxy',
            'androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryNotLowProxy',
            'androidx.work.impl.background.systemalarm.ConstraintProxy$NetworkStateProxy',
            'androidx.work.impl.background.systemalarm.ConstraintProxy$StorageNotLowProxy',
            'androidx.work.impl.background.systemalarm.ConstraintProxyUpdateReceiver',
            'androidx.work.impl.background.systemalarm.RescheduleReceiver',
            'androidx.work.impl.diagnostics.DiagnosticsReceiver',
            'androidx.work.impl.utils.ForceStopRunnable$BroadcastReceiver',
            'com.google.android.apps.tachyon.call.notification.CallRetryNotifierReceiver',
            'com.google.android.apps.tachyon.call.notification.InCallNotificationIntentReceiver',
            'com.google.android.apps.tachyon.call.notification.MissedCallNotificationIntentReceiver',
            'com.google.android.apps.tachyon.clips.notification.MessagesNotificationIntentReceiver',
            'com.google.android.apps.tachyon.common.applifecycle.AppInstallReceiver',
            'com.google.android.apps.tachyon.common.applifecycle.AppUpdateReceiver',
            'com.google.android.apps.tachyon.common.applifecycle.BootReceiver',
            'com.google.android.apps.tachyon.common.applifecycle.LocaleChangeReceiver',
            'com.google.android.apps.tachyon.groupcalling.incall.InGroupCallNotificationIntentReceiver',
            'com.google.android.apps.tachyon.groupcalling.incoming.IncomingGroupCallIntentReceiver',
            'com.google.android.apps.tachyon.groupcalling.incoming.IncomingGroupCallNotificationIntentReceiver',
            'com.google.android.apps.tachyon.groupcalling.notification.GroupUpdateNotificationReceiver',
            'com.google.android.apps.tachyon.invites.invitehelper.IntentChooserCallbackReceiver',
            'com.google.android.apps.tachyon.net.fcm.CjnNotificationIntentReceiver',
            'com.google.android.apps.tachyon.net.fcm.GenericFcmEventHandlerNotificationIntentReceiver',
            'com.google.android.apps.tachyon.notifications.engagement.EngagementNotificationIntentReceiver',
            'com.google.android.apps.tachyon.notifications.receiver.BasicNotificationIntentReceiver',
            'com.google.android.apps.tachyon.phenotype.PhenotypeBroadcastReceiver',
            'com.google.android.apps.tachyon.ping.notification.PingNotificationIntentReceiver',
            'com.google.android.apps.tachyon.registration.SystemAccountChangedReceiver',
            'com.google.android.apps.tachyon.registration.notification.RegistrationNotificationIntentReceiver',
            'com.google.android.apps.tachyon.simdetection.SimStateBroadcastReceiver',
            'com.google.firebase.iid.FirebaseInstanceIdReceiver'],
        'services': [
            'androidx.work.impl.background.systemalarm.SystemAlarmService',
            'androidx.work.impl.background.systemjob.SystemJobService',
            'androidx.work.impl.foreground.SystemForegroundService',
            'com.google.android.apps.tachyon.call.service.CallService',
            'com.google.android.apps.tachyon.clientapi.ClientApiService',
            'com.google.android.apps.tachyon.contacts.reachability.ReachabilityService',
            'com.google.android.apps.tachyon.contacts.sync.DuoAccountService',
            'com.google.android.apps.tachyon.contacts.sync.SyncService',
            'com.google.android.apps.tachyon.net.fcm.CallConnectingForegroundService',
            'com.google.android.apps.tachyon.net.fcm.FcmReceivingService',
            'com.google.android.apps.tachyon.telecom.TachyonTelecomConnectionService',
            'com.google.android.apps.tachyon.telecom.TelecomFallbackService',
            'com.google.android.libraries.internal.growth.growthkit.internal.jobs.impl.'
            'GrowthKitBelowLollipopJobService',
            'com.google.android.libraries.internal.growth.growthkit.internal.jobs.impl.GrowthKitJobService',
            'com.google.apps.tiktok.concurrent.InternalForegroundService',
            'com.google.firebase.components.ComponentDiscoveryService',
            'com.google.firebase.messaging.FirebaseMessagingService'],
        'signature': '6c22867349d7e4b05b7ebb333056236f',
        'subject': {
            'commonName': 'corp_tachyon', 'countryName': 'US', 'localityName': 'Mountain View',
            'organizationName': 'Google Inc.', 'organizationalUnitName': 'Android',
            'stateOrProvinceName': 'California'
        }
    },
        'modifiedDate': '2020-06-10 10:07:22 UTC', 'name': 'Duo',
        'namespace': 'com.google.android.apps.tachyon', 'objectId': 'ebdfed24-951e-45f5-845a-2c163c53fc47',
        'privacyEnum': 0, 'privacyRisk': 'Unavailable', 'processState': 'UNAVAILABLE', 'score': 0,
        'securityEnum': 0, 'securityRisk': 'Unavailable', 'systemToken': 'paxsoar', 'type': 0,
        'version': '91.0.315322534.DR91_RC03'},
    {
        'classification': 'Legitimate', 'deviceCount': 1, 'hash': 'f26cf1135f9d2ea60532a5a13c6fbed5', 'metadata':
        {
            'activities': [
                'com.google.android.apps.tachyon.appupdate.HardBlockActivity',
                'com.google.android.apps.tachyon.call.feedback.BadCallRatingActivity',
                'com.google.android.apps.tachyon.call.history.ExportHistoryActivity',
                'com.google.android.apps.tachyon.call.oneonone.ui.OneOnOneCallActivity',
                'com.google.android.apps.tachyon.call.postcall.ui.PostCallActivity',
                'com.google.android.apps.tachyon.call.precall.OneOnOnePrecallActivity',
                'com.google.android.apps.tachyon.call.precall.fullhistory.FullHistoryActivity',
                'com.google.android.apps.tachyon.clips.share.ReceiveShareIntentActivity',
                'com.google.android.apps.tachyon.clips.ui.ClipsComposerActivity',
                'com.google.android.apps.tachyon.clips.ui.gallerypicker.GalleryPickerActivity',
                'com.google.android.apps.tachyon.clips.ui.viewclips.ViewClipsActivity',
                'com.google.android.apps.tachyon.externalcallactivity.ExternalCallActivity',
                'com.google.android.apps.tachyon.groupcalling.creategroup.EditGroupActivity',
                'com.google.android.apps.tachyon.groupcalling.creategroup.GroupCreationActivity',
                'com.google.android.apps.tachyon.groupcalling.incall.InGroupCallActivity',
                'com.google.android.apps.tachyon.groupcalling.incoming.IncomingGroupCallActivity',
                'com.google.android.apps.tachyon.groupcalling.precall.PrecallScreenGroupActivity',
                'com.google.android.apps.tachyon.groupcalling.precall.PrecallScreenGroupInviteActivity',
                'com.google.android.apps.tachyon.invites.externalinvite.ExternalInviteActivity',
                'com.google.android.apps.tachyon.invites.invitescreen.InviteScreenActivity',
                'com.google.android.apps.tachyon.registration.countrycode.CountryCodeActivity',
                'com.google.android.apps.tachyon.registration.enterphonenumber.PhoneRegistrationActivity',
                'com.google.android.apps.tachyon.registration.onboarding.OnboardingActivity',
                'com.google.android.apps.tachyon.settings.blockedusers.BlockedUsersActivity',
                'com.google.android.apps.tachyon.settings.knockknock.KnockKnockSettingActivity',
                'com.google.android.apps.tachyon.settings.notifications.NotificationSettingsActivity',
                'com.google.android.apps.tachyon.settings.v2.AccountSettingsActivity',
                'com.google.android.apps.tachyon.settings.v2.ApplicationSettingsActivity',
                'com.google.android.apps.tachyon.settings.v2.CallSettingsActivity',
                'com.google.android.apps.tachyon.settings.v2.MessageSettingsActivity',
                'com.google.android.apps.tachyon.ui.blockusers.BlockUsersActivity',
                'com.google.android.apps.tachyon.ui.duoprivacy.DuoPrivacyActivity',
                'com.google.android.apps.tachyon.ui.launcher.LauncherActivity',
                'com.google.android.apps.tachyon.ui.lockscreen.LockscreenTrampolineActivity',
                'com.google.android.apps.tachyon.ui.main.MainActivity',
                'com.google.android.apps.tachyon.ui.warningdialog.WarningDialogActivity',
                'com.google.android.gms.common.api.GoogleApiActivity',
                'com.google.android.libraries.social.licenses.LicenseActivity',
                'com.google.android.libraries.social.licenses.LicenseMenuActivity',
                'com.google.android.libraries.surveys.internal.view.SurveyActivity',
                'com.google.android.play.core.common.PlayCoreDialogWrapperActivity',
                'com.google.android.play.core.missingsplits.PlayCoreMissingSplitsActivity',
                'com.google.research.ink.annotate.AnnotateActivity'],
            'filename': '/data/app/com.google.android.apps.tachyon-tPZVegxYyWlY3qYsaqXeUQ==/base.apk',
            'package': 'com.google.android.apps.tachyon',
            'permissions': ['android.permission.ACCESS_NETWORK_STATE', 'android.permission.ACCESS_WIFI_STATE',
                            'android.permission.AUTHENTICATE_ACCOUNTS', 'android.permission.BLUETOOTH',
                            'android.permission.BROADCAST_STICKY', 'android.permission.CAMERA',
                            'android.permission.CHANGE_NETWORK_STATE', 'android.permission.FOREGROUND_SERVICE',
                            'android.permission.GET_ACCOUNTS', 'android.permission.GET_PACKAGE_SIZE',
                            'android.permission.INTERNET', 'android.permission.MANAGE_ACCOUNTS',
                            'android.permission.MODIFY_AUDIO_SETTINGS', 'android.permission.READ_APP_BADGE',
                            'android.permission.READ_CONTACTS', 'android.permission.READ_PHONE_STATE',
                            'android.permission.READ_PROFILE', 'android.permission.READ_SYNC_STATS',
                            'android.permission.RECEIVE_BOOT_COMPLETED', 'android.permission.RECORD_AUDIO',
                            'android.permission.VIBRATE', 'android.permission.WAKE_LOCK',
                            'android.permission.WRITE_CALL_LOG', 'android.permission.WRITE_CONTACTS',
                            'android.permission.WRITE_SYNC_SETTINGS',
                            'com.anddoes.launcher.permission.UPDATE_COUNT',
                            'com.android.launcher.permission.INSTALL_SHORTCUT',
                            'com.google.android.c2dm.permission.RECEIVE',
                            'com.google.android.providers.gsf.permission.READ_GSERVICES',
                            'com.htc.launcher.permission.READ_SETTINGS',
                            'com.htc.launcher.permission.UPDATE_SHORTCUT',
                            'com.huawei.android.launcher.permission.CHANGE_BADGE',
                            'com.huawei.android.launcher.permission.READ_SETTINGS',
                            'com.huawei.android.launcher.permission.WRITE_SETTINGS',
                            'com.majeur.launcher.permission.UPDATE_BADGE',
                            'com.oppo.launcher.permission.READ_SETTINGS',
                            'com.oppo.launcher.permission.WRITE_SETTINGS',
                            'com.samsung.android.app.telephonyui.permission.READ_SETTINGS_PROVIDER',
                            'com.samsung.android.app.telephonyui.permission.WRITE_SETTINGS_PROVIDER',
                            'com.samsung.android.aremoji.provider.permission.READ_STICKER_PROVIDER',
                            'com.samsung.android.livestickers.provider.permission.READ_STICKER_PROVIDER',
                            'com.samsung.android.provider.filterprovider.permission.READ_FILTER',
                            'com.samsung.android.provider.stickerprovider.permission.READ_STICKER_PROVIDER',
                            'com.sec.android.provider.badge.permission.READ',
                            'com.sec.android.provider.badge.permission.WRITE',
                            'com.sonyericsson.home.permission.BROADCAST_BADGE',
                            'com.sonymobile.home.permission.PROVIDER_INSERT_BADGE'],
            'receivers': [
                'androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryChargingProxy',
                'androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryNotLowProxy',
                'androidx.work.impl.background.systemalarm.ConstraintProxy$NetworkStateProxy',
                'androidx.work.impl.background.systemalarm.ConstraintProxy$StorageNotLowProxy',
                'androidx.work.impl.background.systemalarm.ConstraintProxyUpdateReceiver',
                'androidx.work.impl.background.systemalarm.RescheduleReceiver',
                'androidx.work.impl.diagnostics.DiagnosticsReceiver',
                'androidx.work.impl.utils.ForceStopRunnable$BroadcastReceiver',
                'com.google.android.apps.tachyon.call.notification.CallRetryNotifierReceiver',
                'com.google.android.apps.tachyon.call.notification.InCallNotificationIntentReceiver',
                'com.google.android.apps.tachyon.call.notification.MissedCallNotificationIntentReceiver',
                'com.google.android.apps.tachyon.clips.notification.MessagesNotificationIntentReceiver',
                'com.google.android.apps.tachyon.common.applifecycle.AppInstallReceiver',
                'com.google.android.apps.tachyon.common.applifecycle.AppUpdateReceiver',
                'com.google.android.apps.tachyon.common.applifecycle.BootReceiver',
                'com.google.android.apps.tachyon.common.applifecycle.LocaleChangeReceiver',
                'com.google.android.apps.tachyon.groupcalling.incall.InGroupCallNotificationIntentReceiver',
                'com.google.android.apps.tachyon.groupcalling.incoming.IncomingGroupCallIntentReceiver',
                'com.google.android.apps.tachyon.groupcalling.incoming.IncomingGroupCallNotificationIntentReceiver',
                'com.google.android.apps.tachyon.groupcalling.notification.GroupUpdateNotificationReceiver',
                'com.google.android.apps.tachyon.invites.invitehelper.IntentChooserCallbackReceiver',
                'com.google.android.apps.tachyon.net.fcm.CjnNotificationIntentReceiver',
                'com.google.android.apps.tachyon.net.fcm.GenericFcmEventHandlerNotificationIntentReceiver',
                'com.google.android.apps.tachyon.notifications.engagement.EngagementNotificationIntentReceiver',
                'com.google.android.apps.tachyon.notifications.receiver.BasicNotificationIntentReceiver',
                'com.google.android.apps.tachyon.phenotype.PhenotypeBroadcastReceiver',
                'com.google.android.apps.tachyon.ping.notification.PingNotificationIntentReceiver',
                'com.google.android.apps.tachyon.registration.SystemAccountChangedReceiver',
                'com.google.android.apps.tachyon.registration.notification.RegistrationNotificationIntentReceiver',
                'com.google.android.apps.tachyon.simdetection.SimStateBroadcastReceiver',
                'com.google.firebase.iid.FirebaseInstanceIdReceiver'],
            'services': [
                'androidx.work.impl.background.systemalarm.SystemAlarmService',
                'androidx.work.impl.background.systemjob.SystemJobService',
                'androidx.work.impl.foreground.SystemForegroundService',
                'com.google.android.apps.tachyon.call.service.CallService',
                'com.google.android.apps.tachyon.clientapi.ClientApiService',
                'com.google.android.apps.tachyon.contacts.reachability.ReachabilityService',
                'com.google.android.apps.tachyon.contacts.sync.DuoAccountService',
                'com.google.android.apps.tachyon.contacts.sync.SyncService',
                'com.google.android.apps.tachyon.net.fcm.CallConnectingForegroundService',
                'com.google.android.apps.tachyon.net.fcm.FcmReceivingService',
                'com.google.android.apps.tachyon.telecom.TachyonTelecomConnectionService',
                'com.google.android.apps.tachyon.telecom.TelecomFallbackService',
                'com.google.android.libraries.internal.growth.growthkit.internal.jobs.impl.GrowthKitJobService',
                'com.google.apps.tiktok.concurrent.InternalForegroundService',
                'com.google.firebase.components.ComponentDiscoveryService',
                'com.google.firebase.messaging.FirebaseMessagingService'],
            'signature': '6c22867349d7e4b05b7ebb333056236f',
            'subject': {'commonName': 'corp_tachyon', 'countryName': 'US', 'localityName': 'Mountain View',
                        'organizationName': 'Google Inc.', 'organizationalUnitName': 'Android',
                        'stateOrProvinceName': 'California'}}, 'modifiedDate': '2020-06-10 09:37:22 UTC',
        'name': 'Duo',
        'namespace': 'com.google.android.apps.tachyon', 'objectId': '02a0ed2d-b22f-4b25-834f-232c7e1b4914',
        'privacyEnum': 0, 'privacyRisk': 'Unavailable', 'processState': 'UNAVAILABLE', 'score': 0,
        'securityEnum': 0,
        'securityRisk': 'Unavailable', 'systemToken': 'paxsoar', 'type': 0, 'version': '91.0.314224792.DR91_RC01'
    }
]
EXPECTED_GET_LAST_UPDATED_DEVICES = [
    {
        'appName': 'zIPS', 'bundleId': 'com.zimperium.zIPS', 'country': '454', 'countryCode': '454',
        'createdAt': '2020-06-03 02:02:45 UTC', 'deviceGroupName': None,
        'deviceHash': 'dcbe063072cf31387339ed13efc076043e8b172995e71a653f08f07b36ab3b3f',
        'deviceId': '000834174047969', 'email': 'ztester1982@gmail.com', 'externalTrackingId1': None,
        'externalTrackingId2': None, 'firstName': 'Fname', 'lastName': 'Lname',
        'lastSeen': '2020-06-03 02:04:03 UTC', 'mdmId': None, 'middleName': None, 'model': 'iPhone',
        'operatorAlpha': 'SMC HK', 'osBuild': None, 'osSecurityPatch': None, 'osType': 'iOS',
        'osUpgradeable': False, 'osVersion': '11.0.2', 'osVulnerable': False, 'phoneNumber': '',
        'processor': None,
        'riskPosture': 'Critical', 'riskPostureCode': 3, 'status': 'Inactive', 'statusCode': 2,
        'systemToken': 'paxsoar', 'type': 'iPhone5,2', 'updatedDate': '2020-06-06 02:04:57 UTC',
        'userId': '3d588112-6467-4c2d-932a-b728f866163d', 'version': '4.9.21',
        'vulnerabilities': ['Jailbroken/Rooted', 'Screen Lock Disabled'],
        'zdid': '71bd5388-f2f4-44e8-9235-6ecd973da589', 'zipsDistributionVersion': 'n/a',
        'zipsVersion': '4.9.21'},
    {
        'appName': 'zIPS', 'bundleId': 'com.zimperium.zips', 'country': 'us', 'countryCode': 'us',
        'createdAt': '2020-06-03 02:04:25 UTC', 'deviceGroupName': None,
        'deviceHash': 'd3a5f56726ea39341ca19a534b8d5bc0cac07484b3032148857118f31b72bf01',
        'deviceId': '198280699673142', 'email': 'ztester1982@gmail.com', 'externalTrackingId1': None,
        'externalTrackingId2': None, 'firstName': 'Fname', 'lastName': 'Lname',
        'lastSeen': '2020-06-03 02:05:19 UTC', 'mdmId': None, 'middleName': None, 'model': 'SM-G900H',
        'operatorAlpha': 'AT&T', 'osBuild': 'LRX21T.G900HXXS1BPC8', 'osSecurityPatch': '2016-03-01',
        'osType': 'Android', 'osUpgradeable': False, 'osVersion': '4.4.2', 'osVulnerable': False,
        'phoneNumber': '', 'processor': 'armeabi-v7a', 'riskPosture': 'Low', 'riskPostureCode': 1,
        'status': 'Inactive', 'statusCode': 2, 'systemToken': 'paxsoar', 'type': 'k3gxx',
        'updatedDate': '2020-06-06 02:05:57 UTC', 'userId': '3d588112-6467-4c2d-932a-b728f866163d',
        'version': '4.9.19',
        'vulnerabilities': ['Jailbroken/Rooted', 'USB Debug Mode', 'Stagefright', 'Device Encryption Disabled',
                            'Developer Mode', 'Screen Lock Disabled', '3rd Party App Store'],
        'zdid': 'c728a9f1-dbcc-4b0f-84b2-5dc07e80b6e5', 'zipsDistributionVersion': 'n/a',
        'zipsVersion': '4.9.19'},
    {
        'appName': 'zIPS', 'bundleId': 'com.zimperium.zips', 'country': None, 'countryCode': None,
        'createdAt': '2020-06-10 08:50:32 UTC', 'deviceGroupName': None,
        'deviceHash': 'f5b42533a5cd2e4452a954b62a5bbab7ac2147d5bf1ade726a48f1f1d111c9',
        'deviceId': 'c3e39cf6-97aa-38df-86eb-60a8a2cafbc1', 'email': 'ztester1982@gmail.com',
        'externalTrackingId1': '', 'externalTrackingId2': '', 'firstName': 'Fname', 'lastName': 'Lname',
        'lastSeen': '2020-06-11 08:43:58 UTC', 'mdmId': None, 'middleName': None, 'model': None,
        'operatorAlpha': None, 'osBuild': None, 'osSecurityPatch': None, 'osType': None, 'osUpgradeable': False,
        'osVersion': None, 'osVulnerable': False, 'phoneNumber': '', 'processor': None,
        'riskPosture': 'Critical',
        'riskPostureCode': 3, 'status': 'Active', 'statusCode': 1, 'systemToken': 'paxsoar', 'type': None,
        'updatedDate': '2020-06-11 08:44:35 UTC', 'userId': '3d588112-6467-4c2d-932a-b728f866163d',
        'version': '4.13.3', 'vulnerabilities': ['USB Debug Mode', 'Developer Mode', 'Screen Lock Disabled'],
        'zdid': '2a086e00-32f3-4c03-90b2-b9fd4ea836e5', 'zipsDistributionVersion': 'n/a',
        'zipsVersion': '4.13.3'}
]
EXPECTED_REPORT_GET_ITUNESID = {'app_analysis': {'analysis': {
    'Address Book': [{
        'description': 'The app implement a functionality to fetch, enumerate and save contacts to/from the Address Book.',
        'imp': 'L', 'privacy': 1, 'security': 0}, {
        'description': 'The app implements the AddressBook.framework which enables the app to gain access to the Address Book.',
        'imp': 'L', 'privacy': 1, 'security': 0}], 'Analytics': [{
        'description': "Urban Airship is a mobile engagement platform and digital wallet solution that enables the developer to send messages such as advertisements to the user and monitor the user's engagement to those messages. This information is used to improve user retention and grow customers.",
        'imp': 'L', 'privacy': 1,
        'security': 0}, {
        'description': 'The app implements the Plausible Labs Crash analytic framework. The company develops and markets a platform for analyzing consumer interactions with mobile apps, solutions for marketers to advertise in-apps, as well as a service for applying monetization structures to mobile apps.',
        'imp': 'L', 'privacy': 1,
        'security': 0}, {
        'description': 'The app implements the Apteligent (Crittercism) analytics framework. Crittercism will monitor, prioritize, troubleshoot, and trend your mobile app performance to accelerate your mobile business.',
        'imp': 'L', 'privacy': 1,
        'security': 0}],
    'App Package': [{'description': 'The debug dump did not succeed.', 'imp': 'L', 'privacy': 0, 'security': 1}],
    'Backup': [{
        'description': 'This app has disabled the backup feature in iOS. This can assist in protecting sensitive information from being exposed in the backup location.',
        'imp': 'N', 'privacy': 1, 'security': 0}], 'Billing': [
        {'description': 'The app implements the StoreKit framework which enables the app to provide in-app purchases.',
         'imp': 'L', 'privacy': 1, 'security': 0}], 'Binary Protections Testing': [
        {'description': 'Source Code Reverse Engineering Exposure', 'imp': 'N', 'privacy': 0, 'security': 1},
        {'description': 'Function Names Exposure', 'imp': 'N', 'privacy': 0, 'security': 1},
        {'description': 'Data Symbols Exposure', 'imp': 'N', 'privacy': 0, 'security': 1}], 'Camera': [{
        'description': 'The app implements the MobileCoreServices framework which enables the app to gain access to the camera.',
        'imp': 'L',
        'privacy': 1,
        'security': 0},
        {
            'description': 'The app uses Album Image Picker functionality.',
            'imp': 'L',
            'privacy': 1,
            'security': 0},
        {
            'description': 'The app has access to the Camera API.',
            'imp': 'L',
            'privacy': 1,
            'security': 0}],
    'Capabilities': [{
        'description': 'This application has the functionality to take screenshots of the full UI, enabling an attacker to understand everything from installed apps to credentials.',
        'imp': 'H', 'privacy': 1, 'security': 0}], 'Cloud Services': [{
        'description': 'This app is implementing the iOS Hand-Off functionality which allow app data to be shared and process via the cloud.',
        'imp': 'L', 'privacy': 1,
        'security': 0}],
    'Code Analysis': [{
        'description': 'This app is using RNCryptor as an  Encryptor/Decryptor. RNCryptor provides an easy-to-use, Objective-C interface to the AES functionality of CommonCrypto. Simplifies correct handling of password stretching (PBKDF2), salting, and IV.',
        'imp': 'L', 'privacy': 0, 'security': 1}], 'Data Leakage': [
        {'description': 'This app writes data to iOS file system.', 'imp': 'L', 'privacy': 1, 'security': 0}, {
            'description': 'The app implements functionality that logs data to the system console. System log files are accessible to any app and could included PII data. The log files may also be shared with Apple.',
            'imp': 'M', 'privacy': 1, 'security': 0}, {
            'description': 'This app has enabled input field masking on some UI fields. This can assist to ensure sensitive information is not exposed.',
            'imp': 'L', 'privacy': 1, 'security': 0}], 'Fingerprint': [
        {'description': 'The app is implementing a Touch ID or Face ID biometric authentication functionality.',
         'imp': 'L', 'privacy': 1, 'security': 0}], 'Identity': [{
        'description': 'The app implements a device identification call which returns a unique identifier for the device and the vendor. This could be used to track the user across multiple apps developed by the same company and installed on a single device.',
        'imp': 'L', 'privacy': 1, 'security': 0}, {
        'description': 'The app implements a device identification call which returns a unique identifier for the device. This could be used to track the user across multiple apps.',
        'imp': 'L', 'privacy': 1, 'security': 0}],
    'KeyChain Sharing': [{
        'description': 'This app has the functionality to share passwords from its keychain with other apps made by the same team.',
        'imp': 'L', 'privacy': 0, 'security': 1}], 'Keychain': [
        {'description': 'This app writes data to the Keychain. This is an informational finding.', 'imp': 'L',
         'privacy': 0, 'security': 1},
        {'description': 'The app accesses the Keychain using the Keychain framework. This is an informational finding.',
         'imp': 'L', 'privacy': 0, 'security': 1}, {
            'description': 'The app implements the Security framework which enables the app to gain access to keychain data.This is an informational finding.',
            'imp': 'L', 'privacy': 1, 'security': 0}], 'Load Command': [{
        'description': 'Defines a segment of this file to be mapped into the address space of the process that loads this file. It also includes all the sections contained by the segment.',
        'imp': 'L', 'privacy': 0, 'security': 1}, {
        'description': 'Specifies the symbol table for this file. This information is used by both static and dynamic linkers when linking the file, and also by debuggers to map symbols to the original source code files from which the symbols were generated.',
        'imp': 'L', 'privacy': 0, 'security': 1}],
    'Location': [{
        'description': 'The app implements the CoreLocation framework which enables the app to gain access to GPS data.',
        'imp': 'L', 'privacy': 1, 'security': 0}, {
        'description': 'The app implements a 10 meter accuracy location functionality from CoreLocation framework. This is the recommended CoreLocation call for non-navigation apps.',
        'imp': 'L', 'privacy': 1, 'security': 0}, {
        'description': "The app implements a one kilometer fuzzy location functionality from CoreLocation framework which enables the app to gain access to the user's general whereabouts.",
        'imp': 'L', 'privacy': 1, 'security': 0}, {
        'description': 'The app implements a location functionality from CoreLocation framework which enables the app to gain access to the user locations with a precision of 100 meters.',
        'imp': 'L', 'privacy': 1, 'security': 0},
        {'description': 'The app invokes CoreLocation framework tracking functions.', 'imp': 'L', 'privacy': 1,
         'security': 0}], 'Logging': [{
        'description': 'This app is using NSLOG or console.log to write app or user data to the Apple System Log (ASL). This information will be accessible to all other apps allowing an attacker to easily dump device logs and retrieve any logged sensitive information.',
        'imp': 'M', 'privacy': 1, 'security': 0}], 'Maps': [{
        'description': 'This app is using Map Kit, which can create routes, provide specific directions, subway routes, hiking trails, or bike paths.',
        'imp': 'L',
        'privacy': 1,
        'security': 0}],
    'Media': [{
        'description': 'The app implements the AVFoundation framework which enables app to gain access to microphone and speaker.',
        'imp': 'L', 'privacy': 1, 'security': 0}], 'Mobile Advertising': [{
        'description': 'The app implements the iAd advertising framework. This is the approved Apple advertising platform. https://developer.apple.com/iad/monetize/',
        'imp': 'L', 'privacy': 1,
        'security': 0}, {
        'description': 'The app implements low-level API call to retrieve the device global Ad identifier key.',
        'imp': 'M', 'privacy': 1,
        'security': 0}], 'Network': [
        {'description': 'This app transfers data over the Internet using a custom header. ', 'imp': 'L', 'privacy': 0,
         'security': 1},
        {'description': 'The app contains the communication classes required to transfer data across the Internet.',
         'imp': 'L', 'privacy': 0, 'security': 1},
        {'description': 'This app is using a LocalHost address for communication.', 'imp': 'L', 'privacy': 0,
         'security': 1},
        {'description': 'The app backend may be vulnerable to OWASP Web Top 10 Mobile weaknesses.', 'imp': 'L',
         'privacy': 0, 'security': 1},
        {'description': 'The app will create a paired socket on the network.', 'imp': 'M', 'privacy': 0, 'security': 1},
        {'description': 'The app is implementing network sockets. This is an informational finding.', 'imp': 'M',
         'privacy': 0, 'security': 1},
        {'description': 'The app is implementing a direct call to network sockets. This is an informational finding.',
         'imp': 'L', 'privacy': 0, 'security': 1},
        {'description': 'kCFProxyTypeSOCKS specifies a SOCKS proxy.', 'imp': 'L', 'privacy': 0, 'security': 1},
        {'description': 'Specifies that the stream is providing VoIP service.', 'imp': 'N', 'privacy': 1,
         'security': 0},
        {'description': 'This app will open a resource identified by URL.', 'imp': 'L', 'privacy': 0, 'security': 1}, {
            'description': 'NSHTTPCookieSecure is an NSString object indicating that the cookie should be transmitted only over secure channels.',
            'imp': 'L', 'privacy': 1, 'security': 0},
        {'description': 'Application implements a Listening Server over TCP Sockets', 'imp': 'M', 'privacy': 0,
         'security': 1},
        {'description': 'The app is creating network sockets using bind.', 'imp': 'L', 'privacy': 0, 'security': 1}],
    'Network Security': [
        {'description': 'The app can use non-encrypted HTTP connections.', 'imp': 'M', 'privacy': 1, 'security': 0}, {
            'description': "The authentication method 'NSURLAuthenticationMethodServerTrust' is being implemented. This authentication method can be used to override SSL and TLS chain validation.",
            'imp': 'H', 'privacy': 0, 'security': 1}, {
            'description': 'This app has functionality that allows it to connect to and transmit data through https proxies.',
            'imp': 'L', 'privacy': 1, 'security': 0},
        {'description': 'This app has functionality that allows it to communicate over non-secure http proxies.',
         'imp': 'M', 'privacy': 0, 'security': 1},
        {'description': 'This app is attempting SSL Certificate pinning against a local certificate.', 'imp': 'N',
         'privacy': 0, 'security': 1}, {
            'description': "This app references the proxy API's in the CFNetwork Framework which can allow it to connect to a proxy or host a proxy service.",
            'imp': 'M', 'privacy': 0, 'security': 1}, {
            'description': 'This app is using API implementations that fail to properly validate SSL certificates. When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by using a Man-In-The-Middle (MITM) attack.',
            'imp': 'M', 'privacy': 0, 'security': 1}, {
            'description': 'Contains URLs that do not have a valid SSL certificate and/or fails the chain of trust validation.',
            'imp': 'M', 'privacy': 0, 'security': 1}], 'Payment': [
        {'description': 'The app is processing payments using the PassKit framework.', 'imp': 'L', 'privacy': 0,
         'security': 1},
        {'description': 'The app has the ability to processing payments.', 'imp': 'L', 'privacy': 0, 'security': 1}],
    'Security': [
        {'description': 'The app implements the Common Cryptographic library using Ccrypt for encryption features.',
         'imp': 'N', 'privacy': 0, 'security': 1},
        {'description': 'The app implements the Common Cryptographic library using CHmac for encryption features.',
         'imp': 'N', 'privacy': 0, 'security': 1},
        {'description': 'The app implements the Common Cryptographic library using MD5 for encryption features.',
         'imp': 'N', 'privacy': 0, 'security': 1},
        {'description': 'The app implements the Common Cryptographic library using SHA256 for encryption features.',
         'imp': 'N', 'privacy': 0, 'security': 1},
        {'description': 'The app can dynamic load external binaries and system frameworks.', 'imp': 'L', 'privacy': 0,
         'security': 1},
        {'description': 'The app implements the Common Cryptographic library using SHA1 for encryption features.',
         'imp': 'N', 'privacy': 0, 'security': 1},
        {'description': 'The app has the ability to execute other tasks in the background. ', 'imp': 'L', 'privacy': 0,
         'security': 1}, {
            'description': "'Bearer' related oAuth (Open Authorization) tokens were found. An adversary could potentially gain access to these tokens if they are not encrypted.",
            'imp': 'M', 'privacy': 0, 'security': 1}, {
            'description': 'The app accesses frameworks that are located in PrivateFrameworks. PrivateFramework access is prohibited by Apple.',
            'imp': 'L', 'privacy': 0, 'security': 1}], 'System': [{
        'description': 'This app has additional compiled libraries embedded in the app which could unintentionally introduce additional security or privacy risks because the compiled code is from another developer.',
        'imp': 'M', 'privacy': 0, 'security': 1}, {
        'description': 'The app implements calls that directly interact with system sounds (such as Shutter sound). This could indicate trojan activity by silencing systems sounds.',
        'imp': 'L', 'privacy': 1, 'security': 0}, {
        'description': "The app implements Swizzling API calls. This may impact the app's ability to trust security decisions that are based on untrusted inputs or manipulated/swizzled output.",
        'imp': 'M', 'privacy': 0, 'security': 1}, {
        'description': 'The app implements a call to enumerate information about the user-specific configuration of the paired Apple Watch.',
        'imp': 'L', 'privacy': 1, 'security': 0}, {
        'description': 'The app implement functionality that facilitates communication between a WatchKit extension and its companion iOS app.',
        'imp': 'L', 'privacy': 1, 'security': 0}, {
        'description': 'The app implements Apple ForceTouch recognition functionality',
        'imp': 'L', 'privacy': 1, 'security': 0}, {
        'description': 'This application is actively monitoring and retrieving data from the iOS Pasteboard which can lead to the exposure of sensitive data which could potentially include credentials.',
        'imp': 'H', 'privacy': 1, 'security': 0}, {
        'description': 'The app implements an API call to the device battery monitoring functionality.',
        'imp': 'L', 'privacy': 1, 'security': 0}, {
        'description': 'The app implements low-level Mach port manipulation.',
        'imp': 'L', 'privacy': 0, 'security': 1}, {
        'description': 'The app uses the Spotlight Search to provide queries and get results through the CoreSpotlight framework.',
        'imp': 'L', 'privacy': 0, 'security': 1}, {
        'description': 'The app implements low level file-system API calls.',
        'imp': 'L', 'privacy': 0, 'security': 1}, {
        'description': "This app contains method's to detect if the device is jailbroken",
        'imp': 'N', 'privacy': 0, 'security': 1}],
    'Telephony': [{
        'description': "The app implements a call to '_getifaddrs'. This enables the application to retrieve the physical device MAC address. This information can then be used by advertising frameworks that clandestinely collect information about the user, the device and the app.",
        'imp': 'L', 'privacy': 1, 'security': 0}]}, 'application_type': 'iOS', 'engine_version': '4.8.27',
    'frameworks': {
        'APIGuard': {
            'description': 'No additional data available',
            'path': '@rpath/APIGuard.framework'},
        'AVFoundation': {
            'description': 'Application Record, edit, and play audio and video, configure the audio session, and respond to changes in the device audio environment utilizing the AVFoundation framework.',
            'path': '/System/Library/Frameworks/AVFoundation.framework'},
        'Accelerate': {
            'description': 'Contains accelerated math and DSP functions',
            'path': '/System/Library/Frameworks/Accelerate.framework'},
        'Accounts': {
            'description': "Application Manage the user's external accounts using the Accounts framework. You can also use this framework to simplify the authorization process when using external APIs, such as the Twitter API.",
            'path': '/System/Library/Frameworks/Accounts.framework'},
        'AdSupport': {
            'description': 'Application Access the advertising identifier and a flag indicating whether the user has chosen to limit ad tracking.',
            'path': '/System/Library/Frameworks/AdSupport.framework'},
        'AddressBook': {
            'description': "Application Use the Address Book framework to gain access to the centralized database for storing a user's contacts. The database, known as Address Book, is used by applications such as Mail and Messages to present information about known and unknown persons.",
            'path': '/System/Library/Frameworks/AddressBook.framework'},
        'AirshipKit': {
            'description': "We Power Mobile Engagement For The World's Leading Brands.Connect mobile data to any business system with the industry’s first user-centric data streaming platform that delivers real-time mobile information.",
            'path': '@rpath/AirshipKit.framework'},
        'Apptentive': {
            'description': 'No additional data available',
            'path': '@rpath/Apptentive.framework'},
        'Apptimize': {
            'description': 'No additional data available',
            'path': '@rpath/Apptimize.framework'},
        'AudioToolbox': {
            'description': 'Contains the interfaces for handling audio stream data and for playing and recording audio',
            'path': '/System/Library/Frameworks/AudioToolbox.framework'},
        'Branch': {
            'description': 'The Branch Metrics iOS SDK for deferred and contextual mobile deep linking. Branch helps mobile apps grow with deep links / deeplinks that power referral systems, sharing links and invites with full attribution and analytics. https://dev.branch.io/references/ios_sdk/',
            'path': '@rpath/Branch.framework'},
        'CFNetwork': {
            'description': 'Application Use the CFNetwork framework to gain access to network services and handle changes in network configurations. The CFNetwork framework provides a library of abstractions for network protocols. These abstractions make it easy to perform a variety of network tasks, such as working with BSD sockets, working with HTTP and FTP servers, and managing Bonjour services.',
            'path': '/System/Library/Frameworks/CFNetwork.framework'},
        'ChasePay': {
            'description': 'No additional data available',
            'path': '@rpath/ChasePay.framework'},
        'ClockKit': {
            'description': 'No additional data available',
            'path': '/System/Library/Frameworks/ClockKit.framework'},
        'Contacts': {
            'description': "Application Use the Contacts framework to gain access to the centralized database for storing a user's contacts. The database is used by apps such as Mail and Messages to present information about known and unknown persons.",
            'path': '/System/Library/Frameworks/Contacts.framework'},
        'ContactsUI': {
            'description': 'The Contacts UI framework provides controllers that facilitate displaying, editing, selecting, and creating contacts in your app.',
            'path': '/System/Library/Frameworks/ContactsUI.framework'},
        'CoreData': {
            'description': 'Application Use the Core Data framework for generalized and automated solutions to common tasks associated with object life-cycle and object graph management, including persistence.',
            'path': '/System/Library/Frameworks/CoreData.framework'},
        'CoreFoundation': {
            'description': 'Application Use the Core Foundation framework for system services fundamental to all iOS applications. Core Foundation provides abstractions for common data types, it facilitates internationalization with Unicode string storage, and it offers a suite of utilities such as plug-in support, XML property lists, URL resource access, and preferences.',
            'path': '/System/Library/Frameworks/CoreFoundation.framework'},
        'CoreGraphics': {
            'description': 'Application Handle 2D rendering tasks using the Core Graphics framework. Use this C-based API, which is based on the Quartz drawing engine, for path-based drawing, anti-aliased rendering, gradients, images, color management, and PDF document handling.',
            'path': '/System/Library/Frameworks/CoreGraphics.framework'},
        'CoreImage': {
            'description': 'Application Perform image processing and video image manipulation utilizing the Core Image framework.',
            'path': '/System/Library/Frameworks/CoreImage.framework'},
        'CoreLocation': {
            'description': "Application Use the Core Location framework to determine the current latitude and longitude of a device and to configure and schedule the delivery of location-related events. The framework uses the available hardware to triangulate the user's position based on nearby signal information.",
            'path': '/System/Library/Frameworks/CoreLocation.framework'},
        'CoreMedia': {
            'description': 'Application Represent time-based audio-visual assets utilizing the essential data types in the Core Media framework.',
            'path': '/System/Library/Frameworks/CoreMedia.framework'},
        'CoreMotion': {
            'description': 'Application Receive and handle accelerometer and other motion events utilizing the Core Motion framework.',
            'path': '/System/Library/Frameworks/CoreMotion.framework'},
        'CoreSpotlight': {
            'description': 'Application Index the content in the app and enable users to deep-link to that content from Spotlight and Safari search results utilizing the Core Spotlight framework. Core Spotlight is designed for apps that handle persistent user data, such as documents, photos, and other types of content created by or on behalf of users. Use Core Spotlight APIs to add, retrieve, update, and delete items that represent searchable app content.',
            'path': '/System/Library/Frameworks/CoreSpotlight.framework'},
        'CoreTelephony': {
            'description': 'Application Gain access to cellular telephone call status and cellular service provider information utilizing the Core Telephony framework.',
            'path': '/System/Library/Frameworks/CoreTelephony.framework'},
        'CoreText': {
            'description': 'Layout text and perform font handling utilizing the Core Text framework. The text layout API provides high-quality typesetting, including character-to-glyph conversion and positioning of glyphs in lines and paragraphs. The complementary font technology provides features such as automatic font substitution (cascading), font descriptors and collections, and easy access to font metrics and glyph data.',
            'path': '/System/Library/Frameworks/CoreText.framework'},
        'CoreVideo': {
            'description': 'Application Playback and process movies, with access to individual frames, utilizing the Core Video framework. This C-based framework provides a low-level, pipeline-based API for working with movies. You can use it to work with pixel buffers, OpenGL buffers, and OpenGL textures.',
            'path': '/System/Library/Frameworks/CoreVideo.framework'},
        'Foundation': {
            'description': 'Application Use the Foundation framework for the "nuts and bolts" classes for Objective-C programming. This framework provides essential Objective-C classes, most importantly the root class, NSObject, which defines basic object behavior. It includes classes for objects representing basic data types, collections, and operating-system services. Foundation also introduces several design patterns and mechanisms that contribute to the robustness and efficiency of Objective-C programs. Along with UIKit, the Foundation framework provides the basic tools and infrastructure you need to implement graphical, event-driven iOS applications.',
            'path': '/System/Library/Frameworks/Foundation.framework'},
        'FraudForce': {
            'description': 'No additional data available',
            'path': '@rpath/FraudForce.framework'},
        'GameplayKit': {
            'description': 'Application Implement common game play behaviors using the GameplayKit framework. GameplayKit provides random number generation with characteristics that are appropriate for games and provides infrastructure for implementing behavior for entities within the game.',
            'path': '/System/Library/Frameworks/GameplayKit.framework'},
        'ImageIO': {
            'description': 'Application Read and write most image file formats utilizing the Image I/O framework. This C-based framework also supports color management and access to image metadata.',
            'path': '/System/Library/Frameworks/ImageIO.framework'},
        'Intents': {
            'description': 'No additional data available',
            'path': '/System/Library/Frameworks/Intents.framework'},
        'IntentsUI': {
            'description': 'No additional data available',
            'path': '/System/Library/Frameworks/IntentsUI.framework'},
        'LocalAuthentication': {
            'description': 'Application Request authentication from users through passphrases or biometrics utilizing the Local Authentication framework.',
            'path': '/System/Library/Frameworks/LocalAuthentication.framework'},
        'MapKit': {
            'description': 'Application Display map or satellite imagery from the windows and views of the custom applications utilizing the MapKit framework. You can also use the framework to annotate the maps with points of interest and other custom information.',
            'path': '/System/Library/Frameworks/MapKit.framework'},
        'MessageUI': {
            'description': 'Application reate a view-controller-based user interface for composing email messages. Use it in cases where you want the user to be able to create email messages without leaving the application.',
            'path': '/System/Library/Frameworks/MessageUI.framework'},
        'Metal': {
            'description': 'Application Render hardware-accelerated advanced 3D graphics and perform data-parallel computation workloads by using the Metal framework. Metal gives fine-grain access to the graphics processor while minimizing CPU overhead.',
            'path': '/System/Library/Frameworks/Metal.framework'},
        'MobileCoreServices': {
            'description': 'Application Gain access to standard types and constants utilizing the Mobile Core Services framework. Use it in conjunction with other frameworks that rely on UTI type information.',
            'path': '/System/Library/Frameworks/MobileCoreServices.framework'},
        'OpenGLES': {
            'description': 'Application Use a compact, efficient subset of the OpenGL API for 2D and 3D drawing on mobile devices. The OpenGL ES framework includes EAGL, a C-based API that supports the integration of OpenGL ES rendering with Core Animation layers and UIKit views. You can also use EAGL to render to pixel buffers',
            'path': '/System/Library/Frameworks/OpenGLES.framework'},
        'PassKit': {
            'description': "Application Create, distribute, and update passes utilizing the PassKit framework. You can also use this framework to interact utilizing the user's pass library.",
            'path': '/System/Library/Frameworks/PassKit.framework'},
        'Photos': {
            'description': 'Application Work with image and video assets and collections managed by the Photos app, including iCloud Photos, using the Photos framework. This API supports asynchronously fetching and caching thumbnails or full-sized assets, as well as making edits to asset content that a user can later resume working with.',
            'path': '/System/Library/Frameworks/Photos.framework'},
        'QuartzCore': {
            'description': 'Application Use the Quartz Core framework to configure animations and effects that are then rendered in hardware for optimal performance. This framework contains the advanced animation and compositing technology known as Core Animation.',
            'path': '/System/Library/Frameworks/QuartzCore.framework'},
        'QuickLook': {
            'description': 'Contains interfaces for previewing files',
            'path': '/System/Library/Frameworks/QuickLook.framework'},
        'SBXFeatureKit': {
            'description': 'No additional data available',
            'path': '@rpath/SBXFeatureKit.framework'},
        'SBXFoundation': {
            'description': 'No additional data available',
            'path': '@rpath/SBXFoundation.framework'},
        'SBXServices': {
            'description': 'No additional data available',
            'path': '@rpath/SBXServices.framework'},
        'SBXStrings': {
            'description': 'No additional data available',
            'path': '@rpath/SBXStrings.framework'},
        'SBXUIKit': {
            'description': 'No additional data available',
            'path': '@rpath/SBXUIKit.framework'},
        'SafariServices': {
            'description': 'Application Use the Safari Services framework to enable web-based views and services in the app.',
            'path': '/System/Library/Frameworks/SafariServices.framework'},
        'Security': {
            'description': 'Application Use the Security framework to secure the data the application manages. This framework defines C interfaces for protecting information and controlling access to software.',
            'path': '/System/Library/Frameworks/Security.framework'},
        'SockPuppetGizmo': {
            'description': 'No additional data available',
            'path': '/System/Library/PrivateFrameworks/SockPuppetGizmo.framework'},
        'SpriteKit': {
            'description': 'Application Create 2D sprite-based games using the SpriteKit framework. This Objective-C framework provides an optimized animation system, physics simulation, and event-handling support.',
            'path': '/System/Library/Frameworks/SpriteKit.framework'},
        'StoreKit': {
            'description': 'Application Embed a store in the app using the StoreKit framework. Use it to process the financial transactions associated utilizing the purchase of content and services from the application.',
            'path': '/System/Library/Frameworks/StoreKit.framework'},
        'SystemConfiguration': {
            'description': 'Application Use the System Configuration framework to determine network availability and state on a device. The System Configuration framework declares the functions, types, and constants related to network reachability.',
            'path': '/System/Library/Frameworks/SystemConfiguration.framework'},
        'UIKit': {
            'description': "Application Construct and manage the application's user interface utilizing the UIKit framework. This Objective-C framework provides an application object, event handling support, drawing support, windows, views, and controls designed specifically for the Multi-Touch interface.",
            'path': '/System/Library/Frameworks/UIKit.framework'},
        'UserNotifications': {
            'description': 'Urban Airship iOS SDK',
            'path': '/System/Library/Frameworks/UserNotifications.framework'},
        'WatchConnectivity': {
            'description': 'Application Use the Watch Connectivity framework to coordinate activities between the iOS app and the corresponding Watch app.',
            'path': '/System/Library/Frameworks/WatchConnectivity.framework'},
        'WatchKit': {
            'description': 'The WatchKit framework (WatchKit.framework) contains the classes that a WatchKit extension uses to manipulate the interface of a Watch app. A Watch app contains one or more interface controllers, each of which can have tables, buttons, sliders, and other types of visual elements. The WatchKit extension uses the classes of this framework to configure those visual elements and to respond to user interactions.',
            'path': '/System/Library/Frameworks/WatchKit.framework'},
        'WebKit': {
            'description': 'Application Use the WebKit framework to display web content in windows and to implement browser features such as following links when clicked by the user, managing a back-forward list, and managing a history of pages recently visited.',
            'path': '/System/Library/Frameworks/WebKit.framework'},
        'iAd': {
            'description': 'Application Place full-screen advertisements or banner advertisements in the application utilizing the iAd framework.',
            'path': '/System/Library/Frameworks/iAd.framework'},
        'libSystem.B.dylib': {
            'description': 'This library contains system dependent declarations.',
            'path': '/usr/lib'},
        'libc++.1.dylib': {
            'description': 'The Objective-C and Objective-C++ runtime library.',
            'path': '/usr/lib'},
        'libicucore.A.dylib': {
            'description': 'libicucore is a C/C++ library providing Unicode support.',
            'path': '/usr/lib'},
        'libobjc.A.dylib': {
            'description': 'This is the standard C libraries.',
            'path': '/usr/lib'},
        'libsqlite3.dylib': {
            'description': 'The SQLite library lets you embed a lightweight SQL database into your app without running a separate remote database server process.',
            'path': '/usr/lib'},
        'libswiftCore.dylib': {
            'description': 'The Swift library supporting Core framework.',
            'path': '@rpath'},
        'libswiftCoreData.dylib': {
            'description': 'Swift implementation of the Apple Core Data Framework',
            'path': '@rpath'},
        'libswiftCoreFoundation.dylib': {
            'description': 'No additional data available',
            'path': '@rpath'},
        'libswiftCoreGraphics.dylib': {
            'description': 'The Swift library supporting Core Graphics framework.',
            'path': '@rpath'},
        'libswiftCoreImage.dylib': {
            'description': 'The Swift library supporting Core Image framework.',
            'path': '@rpath'},
        'libswiftCoreLocation.dylib': {
            'description': 'Swift implementation of the Apple Core Location Framework',
            'path': '@rpath'},
        'libswiftDarwin.dylib': {
            'description': 'The Swift library supporting Darwin framework.',
            'path': '@rpath'},
        'libswiftDispatch.dylib': {
            'description': 'Dispatch library for swift similar to GCD Grand Central Dispatch.',
            'path': '@rpath'},
        'libswiftFoundation.dylib': {
            'description': 'The Swift library supporting Foundation Framework.',
            'path': '@rpath'},
        'libswiftIntents.dylib': {
            'description': 'This is included in the package distribution that provides Xamarin applications support for Swift3 ',
            'path': '@rpath'},
        'libswiftMetal.dylib': {
            'description': 'No additional data available',
            'path': '@rpath'},
        'libswiftObjectiveC.dylib': {
            'description': 'The Swift library for implementing Objective C alongside Swift code.',
            'path': '@rpath'},
        'libswiftQuartzCore.dylib': {
            'description': 'This is included in the package distribution that provides Xamarin applications support for Swift3 ',
            'path': '@rpath'},
        'libswiftUIKit.dylib': {
            'description': 'The Swift library supporting the UIKit framework (UIKit.framework) which provides the crucial infrastructure needed to construct and manage iOS apps. This framework provides the window and view architecture needed to manage an app s user interface, the event handling infrastructure needed to respond to user input, and the app model needed to drive the main run loop and interact with the system.',
            'path': '@rpath'},
        'libswiftos.dylib': {
            'description': 'This is included in the package distribution that provides Xamarin applications support for Swift3 ',
            'path': '@rpath'},
        'libz.1.dylib': {
            'description': "interface of the 'zlib' general purpose compression library",
            'path': '/usr/lib'},
        'mParticle_Apple_SDK': {
            'description': 'No additional data available',
            'path': '@rpath/mParticle_Apple_SDK.framework'}},
    'network': {
        'emails': [],
        'schemes': [
            'itms://itunes.apple.com/us/app/spotify-music/id324684580?mt=8#',
            'itms-apps://itunes.apple.com/app/id%@?action=write-review',
            'sbux331177714',
            'starbucks://pay/addcard',
            'starbucks://pay/addCard',
            'starbucks://pay/addcard?number=',
            'starbucks://pay/reload',
            'starbucks://home',
            'starbucks://pay',
            'starbucks://pay/barcode',
            'wss://plank.apptimize.com/websocket',
            'wss://staging-plank.apptimize.co/websocket'],
        'urls': [{
            'source': [],
            'url': 'https://gwsol.chase.com',
            'url_info': {
                'exp_check': 0,
                'freak_vulnerability': False,
                'has_problem': 0,
                'hb': 0,
                'hb_tm': '07 Jun 2020',
                'mcafee_gti_reputation': {
                    'cat': [
                        114],
                    'rep': -45,
                    'ufg': 2},
                'robot': 0,
                'robot_vulnerability': False,
                'server': {
                    'BGP_Prefix': '159.53.96.0/19',
                    'allocated_date': '1992-03-06',
                    'as_name': 'AS-7743, US',
                    'as_number': '7743',
                    'city': '',
                    'country': 'United States',
                    'ip': '159.53.113.232',
                    'latitude': '37.751',
                    'longitude': '-97.822',
                    'region': ''},
                'site': {
                    'domain': 'chase.com'},
                'site_reputation': 'No reputation violations discovered',
                'valid_chain_of_trust': True,
                'whois': []}},
            {
                'source': [],
                'url': 'https://secure.chase.com',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            114],
                        'rep': -45,
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '159.53.232.0/24',
                        'allocated_date': '1992-03-06',
                        'as_name': 'AS10934, US',
                        'as_number': '10934',
                        'city': '',
                        'country': 'United States',
                        'ip': '159.53.232.13',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'chase.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': []}},
            {
                'source': [],
                'url': 'http://mparticle.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': '',
                        'ufg': ''},
                    'server': {
                        'BGP_Prefix': '34.192.0.0/12',
                        'allocated_date': '2016-09-12',
                        'as_name': 'AMAZON-AES, US',
                        'as_number': '14618',
                        'city': 'Ashburn',
                        'country': 'United States',
                        'ip': '34.194.207.225',
                        'latitude': '39.0481',
                        'longitude': '-77.4728',
                        'region': 'Virginia'},
                    'site': {
                        'domain': 'mparticle.com',
                        'http_server_type': 'Cowboy'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '2012-07-02',
                        'name_server': 'ns-1447.awsdns-52.org,ns-1796.awsdns-32.co.uk,ns-206.awsdns-25.com,ns-553.awsdns-05.net',
                        'registrant_email': 'Select Contact Domain Holder link at https://www.godaddy.com/whois/results.aspx?domain=MPARTICLE.COM',
                        'registrant_organization': 'mParticle, inc'}}},
            {
                'source': [],
                'url': 'https://test.openapi.starbucks.com/v1/assets/1dbd4fc6e3b94cb98909b1046ef3ada4.png',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '03 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '107.23.0.0/17',
                        'allocated_date': '2011-05-03',
                        'as_name': 'AMAZON-AES, US',
                        'as_number': '14618',
                        'city': 'Ashburn',
                        'country': 'United States',
                        'ip': '107.23.127.116',
                        'latitude': '39.0481',
                        'longitude': '-77.4728',
                        'region': 'Virginia'},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://content-cert-live.cert.starbucks.com/binary/v2/asset/cert.digitalcontent.starbucks.com/udp/us/en/assets/incomplete-background_tcm125-28751.jpg',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.94.64.0/20',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.94.71.126',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://content-cert-live.cert.starbucks.com/binary/v2/asset/cert.digitalcontent.starbucks.com/udp/us/en/assets/onboarding_pay_400_tcm125-28756.jpg',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.94.64.0/20',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.94.71.126',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://assets.starbucks.prod.takt.com/8204daa7c541b13ed0d353029e7eb800-1534895479.png',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': '',
                        'ufg': 8},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '13.225.48.0/21',
                        'allocated_date': '2018-07-11',
                        'as_name': 'AMAZON-02, US',
                        'as_number': '16509',
                        'city': 'Seattle',
                        'country': 'United States',
                        'ip': '13.225.54.41',
                        'latitude': '47.6348',
                        'longitude': '-122.3451',
                        'region': 'Washington'},
                    'site': {
                        'domain': 'takt.com',
                        'http_server_type': 'AmazonS3'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2002-08-25',
                        'name_server': 'luke.ns.cloudflare.com,olga.ns.cloudflare.com',
                        'registrant_email': 'admin@formation.ai',
                        'registrant_name': 'FORMATION INC',
                        'registrant_organization': 'FORMATION INC'}}},
            {
                'source': [],
                'url': 'https://test.openapi.starbucks.com/v1/assets/0fa50d4cfbfc458d8e3f53261e0e0acb.png',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '03 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '107.23.0.0/17',
                        'allocated_date': '2011-05-03',
                        'as_name': 'AMAZON-AES, US',
                        'as_number': '14618',
                        'city': 'Ashburn',
                        'country': 'United States',
                        'ip': '107.23.127.116',
                        'latitude': '39.0481',
                        'longitude': '-77.4728',
                        'region': 'Virginia'},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://www.starbucks.com/account/signin/sso/',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '09 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.97.192.0/19',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.97.219.142',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://cdn.branch.io/sdk/uriskiplist_v%ld.json',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': -2,
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '13.225.48.0/21',
                        'allocated_date': '2018-07-11',
                        'as_name': 'AMAZON-02, US',
                        'as_number': '16509',
                        'city': 'Seattle',
                        'country': 'United States',
                        'ip': '13.225.54.26',
                        'latitude': '47.6348',
                        'longitude': '-122.3451',
                        'region': 'Washington'},
                    'site': {
                        'domain': 'branch.io',
                        'http_server_type': 'AmazonS3'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'name_server': 'ns-1091.awsdns-08.org,ns-1809.awsdns-34.co.uk,ns-236.awsdns-29.com,ns-991.awsdns-59.net'}}},
            {
                'source': [],
                'url': 'https://<yourapp>.app.link/NdJ6nFzRbK?bnc_validate=True',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': None,
                    'mcafee_gti_reputation': {
                        'cat': [
                            107,
                            140],
                        'rep': 12,
                        'ufg': ''},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '',
                        'allocated_date': '',
                        'as_name': '',
                        'as_number': '',
                        'city': '',
                        'country': '',
                        'ip': 'Unavailable',
                        'latitude': '',
                        'longitude': '',
                        'region': ''},
                    'site': {
                        'domain': ''},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': None}},
            {
                'source': [],
                'url': 'https://app.adjust.io/yv3y8r?campaign=starbucksapp&deeplink=spotify:user:starbucks:playlist:0LPsYH4hIRjLUKXuZd2vAt',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '08 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': 18,
                        'ufg': 34},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '185.151.204.0/24',
                        'allocated_date': '2016-05-12',
                        'as_name': 'ADJUST-NL, DE',
                        'as_number': '61273',
                        'city': '',
                        'country': 'Germany',
                        'ip': '185.151.204.1',
                        'latitude': '51.2993',
                        'longitude': '9.491',
                        'region': ''},
                    'site': {
                        'domain': 'adjust.io'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'name_server': 'dns1.p09.nsone.net,dns2.p09.nsone.net,dns3.p09.nsone.net,dns4.p09.nsone.net'}}},
            {
                'source': [],
                'url': 'http://test.openapi.starbucks.com/xop/v1/assets/7f1c84aee6a64be18f400103176fc396.png',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '107.23.0.0/17',
                        'allocated_date': '2011-05-03',
                        'as_name': 'AMAZON-AES, US',
                        'as_number': '14618',
                        'city': 'Ashburn',
                        'country': 'United States',
                        'ip': '107.23.127.116',
                        'latitude': '39.0481',
                        'longitude': '-77.4728',
                        'region': 'Virginia'},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'http://is1.mzstatic.com/image/thumb/Music7/v4/35/0e/73/350e73c1-792e-81e3-26bd-bd5703de1c46/dj.phawrgln.jpg/100x100bb-85.jpg',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            105,
                            107],
                        'rep': -89,
                        'ufg': 4},
                    'server': {
                        'BGP_Prefix': '23.43.60.0/22',
                        'allocated_date': '2011-05-16',
                        'as_name': 'AKAMAI-ASN1, EU',
                        'as_number': '20940',
                        'city': 'Astoria',
                        'country': 'United States',
                        'ip': '23.43.62.99',
                        'latitude': '40.7579',
                        'longitude': '-73.9332',
                        'region': 'New York'},
                    'site': {
                        'domain': 'mzstatic.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '2010-07-12',
                        'name_server': 'a.ns.apple.com,b.ns.apple.com,c.ns.apple.com,d.ns.apple.com',
                        'registrant_email': 'domains@apple.com',
                        'registrant_name': 'Domain Administrator',
                        'registrant_organization': 'Apple Inc.'}}},
            {
                'source': [],
                'url': 'http://crl.apple.com/root.crl',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            105,
                            107],
                        'rep': -49,
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '17.253.2.0/23',
                        'allocated_date': '1990-04-16',
                        'as_name': 'APPLE-AUSTIN, US',
                        'as_number': '6185',
                        'city': 'Dallas',
                        'country': 'United States',
                        'ip': '17.253.3.207',
                        'latitude': '32.7787',
                        'longitude': '-96.8217',
                        'region': 'Texas'},
                    'site': {
                        'domain': 'apple.com',
                        'http_server_type': 'ATS/8.0.6'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': []}},
            {
                'source': [],
                'url': 'https://www.starbucks.com/starbucks-rewards/credit-card',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '09 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.97.192.0/19',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.97.219.142',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://openapi.starbucks.com/v1/',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '08 May 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '34.224.0.0/12',
                        'allocated_date': '2016-09-12',
                        'as_name': 'AMAZON-AES, US',
                        'as_number': '14618',
                        'city': 'Ashburn',
                        'country': 'United States',
                        'ip': '34.237.118.73',
                        'latitude': '39.0481',
                        'longitude': '-77.4728',
                        'region': 'Virginia'},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://test7.openapi.starbucks.com',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 1,
                    'hb': 0,
                    'hb_tm': '27 May 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '107.23.0.0/17',
                        'allocated_date': '2011-05-03',
                        'as_name': 'AMAZON-AES, US',
                        'as_number': '14618',
                        'city': 'Ashburn',
                        'country': 'United States',
                        'ip': '107.23.127.45',
                        'latitude': '39.0481',
                        'longitude': '-77.4728',
                        'region': 'Virginia'},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': False,
                    'valid_cot_msg': 'Certificate has expired',
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://www.starbucks.com/card/card-terms-and-conditions',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '09 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.97.192.0/19',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.97.219.142',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://www.starbucks.ca/card/card-terms-and-conditions',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 6},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.4.48.0/20',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.4.57.35',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.ca'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2000-11-01',
                        'expiration': '2017-03-05',
                        'name_server': 'a4.nstld.com,f4.nstld.com,l4.nstld.com'}}},
            {
                'source': [],
                'url': 'https://combine.urbanairship.com',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': 11,
                        'ufg': 6},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '35.190.0.0/16',
                        'allocated_date': '2016-10-11',
                        'as_name': 'GOOGLE, US',
                        'as_number': '15169',
                        'city': 'Mountain View',
                        'country': 'United States',
                        'ip': '35.190.53.75',
                        'latitude': '37.4043',
                        'longitude': '-122.0748',
                        'region': 'California'},
                    'site': {
                        'domain': 'urbanairship.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2009-04-13',
                        'name_server': 'ns-cloud-d1.googledomains.com,ns-cloud-d2.googledomains.com,ns-cloud-d3.googledomains.com,ns-cloud-d4.googledomains.com'}}},
            {
                'source': [],
                'url': 'https://api.spotify.com/v1/users/ldowlingstarbucks/playlists/0UQ4rAWSXMHjsamcCS3dc1/tracks',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            129,
                            147],
                        'rep': -40,
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '35.186.0.0/16',
                        'allocated_date': '2016-10-11',
                        'as_name': 'GOOGLE, US',
                        'as_number': '15169',
                        'city': 'Mountain View',
                        'country': 'United States',
                        'ip': '35.186.224.25',
                        'latitude': '37.4043',
                        'longitude': '-122.0748',
                        'region': 'California'},
                    'site': {
                        'domain': 'spotify.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2006-04-23',
                        'name_server': 'dns1.p07.nsone.net,dns2.p07.nsone.net,dns3.p07.nsone.net,dns4.p07.nsone.net,ns1.p23.dynect.net,ns2.p23.dynect.net,ns3.p23.dynect.net,ns4.p23.dynect.net'}}},
            {
                'source': [],
                'url': 'http://www.starbucks.com/mobilenotification',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '104.97.192.0/19',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.97.219.142',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://www.starbucks.ca/customer-service',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 6},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.4.48.0/20',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.4.57.35',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.ca'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2000-11-01',
                        'expiration': '2017-03-05',
                        'name_server': 'a4.nstld.com,f4.nstld.com,l4.nstld.com'}}},
            {
                'source': [],
                'url': 'https://fr.starbucks.ca/customer-service',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 8},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.4.48.0/20',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.4.57.35',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.ca',
                        'http_server_type': 'IIS'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2000-11-01',
                        'expiration': '2017-03-05',
                        'name_server': 'a4.nstld.com,f4.nstld.com,l4.nstld.com'}}},
            {
                'source': [],
                'url': 'http://merchant.com.cashstar.starbucks.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '',
                        'allocated_date': '',
                        'as_name': '',
                        'as_number': '',
                        'city': '',
                        'country': '',
                        'ip': 'Unavailable',
                        'latitude': '',
                        'longitude': '',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'http://localhost:3000/analytics-event',
                'url_info': {
                    'has_problem': 0,
                    'server': {
                        'BGP_Prefix': 'NA',
                        'allocated_date': '',
                        'as_name': 'NA',
                        'as_number': 'NA',
                        'city': '',
                        'country': '',
                        'ip': '127.0.0.1',
                        'latitude': '',
                        'longitude': '',
                        'region': ''},
                    'site': {
                        'domain': 'localhost'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': []}},
            {
                'source': [],
                'url': 'https://www.starbucks.ca/rewards/terms',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 6},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.4.48.0/20',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.4.57.35',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.ca'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2000-11-01',
                        'expiration': '2017-03-05',
                        'name_server': 'a4.nstld.com,f4.nstld.com,l4.nstld.com'}}},
            {
                'source': [],
                'url': 'https://www.starbucks.co.uk/card/card-terms-and-conditions',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '03 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 6},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.50.140.0/22',
                        'allocated_date': '2011-05-16',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.50.143.85',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.co.uk',
                        'http_server_type': 'IIS'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1997-07-15',
                        'name_server': 'a4.nstld.com,j4.nstld.com,l4.nstld.com'}}},
            {
                'source': [],
                'url': 'https://tycho.apptimize.com',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '07 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': '',
                        'ufg': 8},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '13.225.48.0/21',
                        'allocated_date': '2018-07-11',
                        'as_name': 'AMAZON-02, US',
                        'as_number': '16509',
                        'city': 'Seattle',
                        'country': 'United States',
                        'ip': '13.225.54.19',
                        'latitude': '47.6348',
                        'longitude': '-122.3451',
                        'region': 'Washington'},
                    'site': {
                        'domain': 'apptimize.com',
                        'http_server_type': 'AmazonS3'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2006-09-21',
                        'name_server': 'ns-1129.awsdns-13.org,ns-1883.awsdns-43.co.uk,ns-473.awsdns-59.com,ns-685.awsdns-21.net',
                        'registrant_address': '85260 Scottsdale, US',
                        'registrant_email': 'APPTIMIZE.COM@domainsbyproxy.com',
                        'registrant_name': 'Registration Private',
                        'registrant_organization': 'Domains By Proxy, LLC'}}},
            {
                'source': [],
                'url': 'https://staging-mapi.apptimize.co',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '07 Jun 2020',
                    'mcafee_gti_reputation': {
                        'rep': 15,
                        'ufg': ''},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '54.200.0.0/15',
                        'allocated_date': '2013-06-19',
                        'as_name': 'AMAZON-02, US',
                        'as_number': '16509',
                        'city': 'Boardman',
                        'country': 'United States',
                        'ip': '54.200.104.92',
                        'latitude': '45.8491',
                        'longitude': '-119.7143',
                        'region': 'Oregon'},
                    'site': {
                        'domain': 'apptimize.co',
                        'http_server_type': 'openresty/1.13.6.2'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2000-02-22',
                        'name_server': 'ns-1935.awsdns-49.co.uk,ns-805.awsdns-36.net,ns-1048.awsdns-03.org,ns-150.awsdns-18.com'}}},
            {
                'source': [],
                'url': 'https://md-i-d.apptimize.com/api/metadata/v4/',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '07 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': '',
                        'ufg': 4},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '52.10.0.0/15',
                        'allocated_date': '1991-12-19',
                        'as_name': 'AMAZON-02, US',
                        'as_number': '16509',
                        'city': 'Boardman',
                        'country': 'United States',
                        'ip': '52.11.186.135',
                        'latitude': '45.8491',
                        'longitude': '-119.7143',
                        'region': 'Oregon'},
                    'site': {
                        'domain': 'apptimize.com',
                        'http_server_type': 'openresty/1.13.6.2'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2006-09-21',
                        'name_server': 'ns-1129.awsdns-13.org,ns-1883.awsdns-43.co.uk,ns-473.awsdns-59.com,ns-685.awsdns-21.net',
                        'registrant_address': '85260 Scottsdale, US',
                        'registrant_email': 'APPTIMIZE.COM@domainsbyproxy.com',
                        'registrant_name': 'Registration Private',
                        'registrant_organization': 'Domains By Proxy, LLC'}}},
            {
                'source': [],
                'url': 'http://itunes.apple.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            112,
                            129],
                        'rep': '',
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '23.199.248.0/22',
                        'allocated_date': '2013-07-12',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.199.248.27',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'apple.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': []}},
            {
                'source': [],
                'url': 'https://go.urbanairship.com/',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': '',
                        'ufg': 32},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.112.64.0/19',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.112.72.14',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'urbanairship.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2009-04-13',
                        'name_server': 'ns-cloud-d1.googledomains.com,ns-cloud-d2.googledomains.com,ns-cloud-d3.googledomains.com,ns-cloud-d4.googledomains.com'}}},
            {
                'source': [],
                'url': 'https://device-api.urbanairship.com',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': 11,
                        'ufg': 6},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '35.244.0.0/14',
                        'allocated_date': '2017-09-29',
                        'as_name': 'GOOGLE, US',
                        'as_number': '15169',
                        'city': 'Mountain View',
                        'country': 'United States',
                        'ip': '35.244.184.98',
                        'latitude': '37.4043',
                        'longitude': '-122.0748',
                        'region': 'California'},
                    'site': {
                        'domain': 'urbanairship.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2009-04-13',
                        'name_server': 'ns-cloud-d1.googledomains.com,ns-cloud-d2.googledomains.com,ns-cloud-d3.googledomains.com,ns-cloud-d4.googledomains.com'}}},
            {
                'source': [],
                'url': 'https://remote-data.urbanairship.com',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': '',
                        'ufg': 6},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '35.200.0.0/14',
                        'allocated_date': '2017-03-21',
                        'as_name': 'GOOGLE, US',
                        'as_number': '15169',
                        'city': '',
                        'country': '',
                        'ip': '35.201.74.116',
                        'latitude': '35',
                        'longitude': '105',
                        'region': ''},
                    'site': {
                        'domain': 'urbanairship.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2009-04-13',
                        'name_server': 'ns-cloud-d1.googledomains.com,ns-cloud-d2.googledomains.com,ns-cloud-d3.googledomains.com,ns-cloud-d4.googledomains.com'}}},
            {
                'source': [],
                'url': 'https://device-api.asnapieu.com',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': 4,
                        'ufg': 8},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '130.211.0.0/16',
                        'allocated_date': '2014-05-12',
                        'as_name': 'GOOGLE, US',
                        'as_number': '15169',
                        'city': 'Mountain View',
                        'country': 'United States',
                        'ip': '130.211.7.30',
                        'latitude': '37.4043',
                        'longitude': '-122.0748',
                        'region': 'California'},
                    'site': {
                        'domain': 'asnapieu.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2019-05-15',
                        'name_server': 'ns-cloud-e1.googledomains.com,ns-cloud-e2.googledomains.com,ns-cloud-e3.googledomains.com,ns-cloud-e4.googledomains.com'}}},
            {
                'source': [],
                'url': 'http://chase.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            114],
                        'rep': -45,
                        'ufg': 3},
                    'server': {
                        'BGP_Prefix': '159.53.96.0/19',
                        'allocated_date': '1992-03-06',
                        'as_name': 'AS-7743, US',
                        'as_number': '7743',
                        'city': '',
                        'country': 'United States',
                        'ip': '159.53.116.62',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'chase.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': []}},
            {
                'source': [],
                'url': 'http://nativesdks.mparticle.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': '',
                        'ufg': ''},
                    'server': {
                        'BGP_Prefix': '151.101.192.0/22',
                        'allocated_date': '2016-02-01',
                        'as_name': 'FASTLY, US',
                        'as_number': '54113',
                        'city': '',
                        'country': 'United States',
                        'ip': '151.101.194.133',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'mparticle.com',
                        'http_server_type': 'Kestrel'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '2012-07-02',
                        'name_server': 'ns-1447.awsdns-52.org,ns-1796.awsdns-32.co.uk,ns-206.awsdns-25.com,ns-553.awsdns-05.net',
                        'registrant_email': 'Select Contact Domain Holder link at https://www.godaddy.com/whois/results.aspx?domain=MPARTICLE.COM',
                        'registrant_organization': 'mParticle, inc'}}},
            {
                'source': [],
                'url': 'http://www.google-analytics.com/collect',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': '',
                        'ufg': 8},
                    'server': {
                        'BGP_Prefix': '172.217.1.0/24',
                        'allocated_date': '2012-04-16',
                        'as_name': 'GOOGLE, US',
                        'as_number': '15169',
                        'city': '',
                        'country': 'United States',
                        'ip': '172.217.1.238',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'google-analytics.com',
                        'http_server_type': 'sffe'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': []}},
            {
                'source': [],
                'url': 'https://eapi-ct.starbucks.com/content/v3/pages/125-42626-64',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '01 May 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '107.23.0.0/17',
                        'allocated_date': '2011-05-03',
                        'as_name': 'AMAZON-AES, US',
                        'as_number': '14618',
                        'city': 'Ashburn',
                        'country': 'United States',
                        'ip': '107.23.127.102',
                        'latitude': '39.0481',
                        'longitude': '-77.4728',
                        'region': 'Virginia'},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://content-cert-live.cert.starbucks.com/binary/v2/asset/125-29184.jpg',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.94.64.0/20',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.94.71.126',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://assets.starbucks.prod.takt.com/7806ad81ff8ae98be9f78b41606c1e51-1534895479.png',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': '',
                        'ufg': 8},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '13.225.48.0/21',
                        'allocated_date': '2018-07-11',
                        'as_name': 'AMAZON-02, US',
                        'as_number': '16509',
                        'city': 'Seattle',
                        'country': 'United States',
                        'ip': '13.225.54.41',
                        'latitude': '47.6348',
                        'longitude': '-122.3451',
                        'region': 'Washington'},
                    'site': {
                        'domain': 'takt.com',
                        'http_server_type': 'AmazonS3'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2002-08-25',
                        'name_server': 'luke.ns.cloudflare.com,olga.ns.cloudflare.com',
                        'registrant_email': 'admin@formation.ai',
                        'registrant_name': 'FORMATION INC',
                        'registrant_organization': 'FORMATION INC'}}},
            {
                'source': [],
                'url': 'https://assets.starbucks.prod.takt.com/a0d241e153a6336f05abf9581bb36b89-1534272146.png',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': '',
                        'ufg': 8},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '13.225.48.0/21',
                        'allocated_date': '2018-07-11',
                        'as_name': 'AMAZON-02, US',
                        'as_number': '16509',
                        'city': 'Seattle',
                        'country': 'United States',
                        'ip': '13.225.54.41',
                        'latitude': '47.6348',
                        'longitude': '-122.3451',
                        'region': 'Washington'},
                    'site': {
                        'domain': 'takt.com',
                        'http_server_type': 'AmazonS3'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2002-08-25',
                        'name_server': 'luke.ns.cloudflare.com,olga.ns.cloudflare.com',
                        'registrant_email': 'admin@formation.ai',
                        'registrant_name': 'FORMATION INC',
                        'registrant_organization': 'FORMATION INC'}}},
            {
                'source': [],
                'url': 'http://www.apptentive.com/',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': -3,
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '151.101.64.0/22',
                        'allocated_date': '2016-02-01',
                        'as_name': 'FASTLY, US',
                        'as_number': '54113',
                        'city': '',
                        'country': 'United States',
                        'ip': '151.101.66.159',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'apptentive.com',
                        'http_server_type': 'Flywheel/4.1.0'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '2011-03-16',
                        'name_server': 'ns-103.awsdns-12.com,ns-1266.awsdns-30.org,ns-1873.awsdns-42.co.uk,ns-933.awsdns-52.net',
                        'registrant_email': 'Select Contact Domain Holder link at https://www.godaddy.com/whois/results.aspx?domain=APPTENTIVE.COM',
                        'registrant_organization': 'Apptentive'}}},
            {
                'source': [],
                'url': 'https://api.apptentive.com/',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '34.192.0.0/12',
                        'allocated_date': '2016-09-12',
                        'as_name': 'AMAZON-AES, US',
                        'as_number': '14618',
                        'city': 'Ashburn',
                        'country': 'United States',
                        'ip': '34.204.136.24',
                        'latitude': '39.0481',
                        'longitude': '-77.4728',
                        'region': 'Virginia'},
                    'site': {
                        'domain': 'apptentive.com',
                        'http_server_type': 'nginx'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2011-03-16',
                        'name_server': 'ns-103.awsdns-12.com,ns-1266.awsdns-30.org,ns-1873.awsdns-42.co.uk,ns-933.awsdns-52.net',
                        'registrant_email': 'Select Contact Domain Holder link at https://www.godaddy.com/whois/results.aspx?domain=APPTENTIVE.COM',
                        'registrant_organization': 'Apptentive'}}},
            {
                'source': [],
                'url': 'https://dev.branch.io/getting-started/sdk-integration-guide/guide/ios/#configure-xcode-project',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': -2,
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '13.226.200.0/21',
                        'allocated_date': '2018-07-11',
                        'as_name': 'AMAZON-02, US',
                        'as_number': '16509',
                        'city': 'Seattle',
                        'country': 'United States',
                        'ip': '13.226.205.71',
                        'latitude': '47.6348',
                        'longitude': '-122.3451',
                        'region': 'Washington'},
                    'site': {
                        'domain': 'branch.io'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'name_server': 'ns-1091.awsdns-08.org,ns-1809.awsdns-34.co.uk,ns-236.awsdns-29.com,ns-991.awsdns-59.net'}}},
            {
                'source': [],
                'url': 'http://test.openapi.starbucks.com/xop/v1/assets/654dac376d2b4d6daf165d6c7f656058.png',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '107.23.0.0/17',
                        'allocated_date': '2011-05-03',
                        'as_name': 'AMAZON-AES, US',
                        'as_number': '14618',
                        'city': 'Ashburn',
                        'country': 'United States',
                        'ip': '107.23.127.116',
                        'latitude': '39.0481',
                        'longitude': '-77.4728',
                        'region': 'Virginia'},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://i.scdn.co/image//38d76bf7f7b9e42e1e99a9f3968654f67180009c',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '07 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': '',
                        'ufg': 8},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '151.101.48.0/22',
                        'allocated_date': '2016-02-01',
                        'as_name': 'FASTLY, US',
                        'as_number': '54113',
                        'city': 'Dallas',
                        'country': 'United States',
                        'ip': '151.101.50.248',
                        'latitude': '32.7787',
                        'longitude': '-96.8217',
                        'region': 'Texas'},
                    'site': {
                        'domain': 'scdn.co'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2000-08-20',
                        'name_server': 'dns3.p07.nsone.net,ns3.p23.dynect.net,ns1.p23.dynect.net,dns1.p07.nsone.net,ns4.p23.dynect.net,ns2.p23.dynect.net,dns2.p07.nsone.net,dns4.p07.nsone.net'}}},
            {
                'source': [],
                'url': 'http://open.spotify.com/user/ldowlingstarbucks/playlist/0UQ4rAWSXMHjsamcCS3dc1',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            129,
                            147],
                        'rep': '',
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '35.186.0.0/16',
                        'allocated_date': '2016-10-11',
                        'as_name': 'GOOGLE, US',
                        'as_number': '15169',
                        'city': 'Mountain View',
                        'country': 'United States',
                        'ip': '35.186.224.25',
                        'latitude': '37.4043',
                        'longitude': '-122.0748',
                        'region': 'California'},
                    'site': {
                        'domain': 'spotify.com',
                        'http_server_type': 'envoy'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '2006-04-23',
                        'name_server': 'dns1.p07.nsone.net,dns2.p07.nsone.net,dns3.p07.nsone.net,dns4.p07.nsone.net,ns1.p23.dynect.net,ns2.p23.dynect.net,ns3.p23.dynect.net,ns4.p23.dynect.net'}}},
            {
                'source': [],
                'url': 'https://privacy-policy.truste.com/certified-policy/mobile/app/en/StarbucksUK.com/index.html',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '20 May 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': 16,
                        'ufg': 42},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '13.226.200.0/21',
                        'allocated_date': '2018-07-11',
                        'as_name': 'AMAZON-02, US',
                        'as_number': '16509',
                        'city': 'Seattle',
                        'country': 'United States',
                        'ip': '13.226.207.72',
                        'latitude': '47.6348',
                        'longitude': '-122.3451',
                        'region': 'Washington'},
                    'site': {
                        'domain': 'truste.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1997-06-12',
                        'name_server': 'ns-1063.awsdns-04.org,ns-2018.awsdns-60.co.uk,ns-470.awsdns-58.com,ns-562.awsdns-06.net'}}},
            {
                'source': [],
                'url': 'http://starbucks.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '23.4.48.0/20',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.4.57.35',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'http://www.starbucks.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '104.97.192.0/19',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.97.219.142',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://www.starbucks.com/starbucks-rewards/prepaid-benefits',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '09 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.97.192.0/19',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.97.219.142',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://www.starbucks.com/cardbenefits',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '09 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.97.192.0/19',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.97.219.142',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'http://mobile-crash.newrelic.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            105,
                            107],
                        'rep': -3,
                        'ufg': 6},
                    'server': {
                        'BGP_Prefix': '162.247.242.0/24',
                        'allocated_date': '2014-04-29',
                        'as_name': 'NEWRELIC-AS-1, US',
                        'as_number': '23467',
                        'city': '',
                        'country': 'United States',
                        'ip': '162.247.242.6',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'newrelic.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '2006-04-19',
                        'name_server': 'dns1.p07.nsone.net,dns2.p07.nsone.net,dns3.p07.nsone.net,dns4.p07.nsone.net,ns1.p29.dynect.net,ns2.p29.dynect.net,ns3.p29.dynect.net,ns4.p29.dynect.net'}}},
            {
                'source': [],
                'url': 'http://ocsp.apple.com/ocsp03-aipca040',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            105,
                            107],
                        'rep': -49,
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '17.253.2.0/23',
                        'allocated_date': '1990-04-16',
                        'as_name': 'APPLE-AUSTIN, US',
                        'as_number': '6185',
                        'city': 'Dallas',
                        'country': 'United States',
                        'ip': '17.253.3.201',
                        'latitude': '32.7787',
                        'longitude': '-96.8217',
                        'region': 'Texas'},
                    'site': {
                        'domain': 'apple.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': []}},
            {
                'source': [],
                'url': 'http://ocsp.apple.com/ocsp03-applerootca0.',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            105,
                            107],
                        'rep': -49,
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '17.253.2.0/23',
                        'allocated_date': '1990-04-16',
                        'as_name': 'APPLE-AUSTIN, US',
                        'as_number': '6185',
                        'city': 'Dallas',
                        'country': 'United States',
                        'ip': '17.253.3.201',
                        'latitude': '32.7787',
                        'longitude': '-96.8217',
                        'region': 'Texas'},
                    'site': {
                        'domain': 'apple.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': []}},
            {
                'source': [],
                'url': 'https://www.apple.com/appleca/0',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105,
                            107],
                        'rep': -49,
                        'ufg': 3},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.0.240.0/23',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.0.241.60',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'apple.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': []}},
            {
                'source': [],
                'url': 'https://test7.openapi.starbucks.com/v1/',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 1,
                    'hb': 0,
                    'hb_tm': '27 May 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '107.23.0.0/17',
                        'allocated_date': '2011-05-03',
                        'as_name': 'AMAZON-AES, US',
                        'as_number': '14618',
                        'city': 'Ashburn',
                        'country': 'United States',
                        'ip': '107.23.127.45',
                        'latitude': '39.0481',
                        'longitude': '-77.4728',
                        'region': 'Virginia'},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': False,
                    'valid_cot_msg': 'Certificate has expired',
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://mapi.apptimize.com',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '07 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': '',
                        'ufg': 4},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '54.148.0.0/15',
                        'allocated_date': '2014-10-23',
                        'as_name': 'AMAZON-02, US',
                        'as_number': '16509',
                        'city': 'Boardman',
                        'country': 'United States',
                        'ip': '54.148.254.217',
                        'latitude': '45.8491',
                        'longitude': '-119.7143',
                        'region': 'Oregon'},
                    'site': {
                        'domain': 'apptimize.com',
                        'http_server_type': 'openresty/1.13.6.2'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2006-09-21',
                        'name_server': 'ns-1129.awsdns-13.org,ns-1883.awsdns-43.co.uk,ns-473.awsdns-59.com,ns-685.awsdns-21.net',
                        'registrant_address': '85260 Scottsdale, US',
                        'registrant_email': 'APPTIMIZE.COM@domainsbyproxy.com',
                        'registrant_name': 'Registration Private',
                        'registrant_organization': 'Domains By Proxy, LLC'}}},
            {
                'source': [],
                'url': 'https://local.apptimize.co',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '07 Jun 2020',
                    'mcafee_gti_reputation': {
                        'rep': 15,
                        'ufg': ''},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '',
                        'allocated_date': '',
                        'as_name': '',
                        'as_number': '',
                        'city': '',
                        'country': '',
                        'ip': 'Unavailable',
                        'latitude': '',
                        'longitude': '',
                        'region': ''},
                    'site': {
                        'domain': 'apptimize.co'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2000-02-22',
                        'name_server': 'ns-1935.awsdns-49.co.uk,ns-805.awsdns-36.net,ns-1048.awsdns-03.org,ns-150.awsdns-18.com'}}},
            {
                'source': [],
                'url': 'https://md-i-s.apptimize.com/api/metadata/v4/',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '07 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': '',
                        'ufg': 4},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '54.148.0.0/15',
                        'allocated_date': '2014-10-23',
                        'as_name': 'AMAZON-02, US',
                        'as_number': '16509',
                        'city': 'Boardman',
                        'country': 'United States',
                        'ip': '54.148.254.217',
                        'latitude': '45.8491',
                        'longitude': '-119.7143',
                        'region': 'Oregon'},
                    'site': {
                        'domain': 'apptimize.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2006-09-21',
                        'name_server': 'ns-1129.awsdns-13.org,ns-1883.awsdns-43.co.uk,ns-473.awsdns-59.com,ns-685.awsdns-21.net',
                        'registrant_address': '85260 Scottsdale, US',
                        'registrant_email': 'APPTIMIZE.COM@domainsbyproxy.com',
                        'registrant_name': 'Registration Private',
                        'registrant_organization': 'Domains By Proxy, LLC'}}},
            {
                'source': [],
                'url': 'http://phobos.apple.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            105,
                            107],
                        'rep': -46,
                        'ufg': 34},
                    'server': {
                        'BGP_Prefix': '17.152.0.0/14',
                        'allocated_date': '1990-04-16',
                        'as_name': 'APPLE-ENGINEERING, US',
                        'as_number': '714',
                        'city': '',
                        'country': 'United States',
                        'ip': '17.154.66.38',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'apple.com',
                        'http_server_type': 'Apache'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': []}},
            {
                'source': [],
                'url': 'http://www.youtube.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            140,
                            147],
                        'rep': -98,
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '216.58.192.0/22',
                        'allocated_date': '2012-01-27',
                        'as_name': 'GOOGLE, US',
                        'as_number': '15169',
                        'city': 'Mountain View',
                        'country': 'United States',
                        'ip': '216.58.194.110',
                        'latitude': '37.3861',
                        'longitude': '-122.0839',
                        'region': 'California'},
                    'site': {
                        'domain': 'youtube.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': []}},
            {
                'source': [],
                'url': 'https://ssl.google-analytics.com/collect',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '18 May 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': -91,
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '216.58.192.0/22',
                        'allocated_date': '2012-01-27',
                        'as_name': 'GOOGLE, US',
                        'as_number': '15169',
                        'city': 'Bluffdale',
                        'country': 'United States',
                        'ip': '216.58.194.136',
                        'latitude': '40.4953',
                        'longitude': '-111.9439',
                        'region': 'Utah'},
                    'site': {
                        'domain': 'google-analytics.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': []}},
            {
                'source': [],
                'url': 'http://www.apple.com/certificateauthority0',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            105,
                            107],
                        'rep': -49,
                        'ufg': 3},
                    'server': {
                        'BGP_Prefix': '23.0.240.0/23',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.0.241.60',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'apple.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': []}},
            {
                'source': [],
                'url': 'https://s3-us-west-2.amazonaws.com/stx-apollo-asset-store/mobile-general/fy2016/General/star-dash-525x525.png',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '52.218.224.0/24',
                        'allocated_date': '2015-09-02',
                        'as_name': 'AMAZON-02, US',
                        'as_number': '16509',
                        'city': 'Boardman',
                        'country': 'United States',
                        'ip': '52.218.224.56',
                        'latitude': '45.8491',
                        'longitude': '-119.7143',
                        'region': 'Oregon'},
                    'site': {
                        'domain': 'amazonaws.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2005-08-17',
                        'name_server': 'r1.amazonaws.com,r2.amazonaws.com,u1.amazonaws.com,u2.amazonaws.com'}}},
            {
                'source': [],
                'url': 'https://eapi-ct.starbucks.com/content/v3/content/125-42634',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '01 May 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '107.23.0.0/17',
                        'allocated_date': '2011-05-03',
                        'as_name': 'AMAZON-AES, US',
                        'as_number': '14618',
                        'city': 'Ashburn',
                        'country': 'United States',
                        'ip': '107.23.127.102',
                        'latitude': '39.0481',
                        'longitude': '-77.4728',
                        'region': 'Virginia'},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://content-cert-live.cert.starbucks.com/binary/v2/asset/cert.digitalcontent.starbucks.com/udp/us/en/assets/onboarding_addmoney_complete_400_tcm125-28753.jpg',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.94.64.0/20',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.94.71.126',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://content-cert-live.cert.starbucks.com/binary/v2/asset/cert.digitalcontent.starbucks.com/udp/us/en/assets/onboarding_mop_complete_400_tcm125-28755.jpg',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.94.64.0/20',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.94.71.126',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://content-cert-live.cert.starbucks.com/binary/v2/asset/cert.digitalcontent.starbucks.com/udp/us/en/assets/success%20background_tcm125-28759.jpg',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.94.64.0/20',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.94.71.126',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://content-cert-live.cert.starbucks.com/binary/v2/asset/cert.digitalcontent.starbucks.com/udp/gb/en/assets/rewards_still_here_tcm124-28746.jpg',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.94.64.0/20',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.94.71.126',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://open.spotify.com/playlist/7DcE2Xbwxg47xYl1oVzVAh?si=v9PPkxXMSuCCXaSDS_ac9Q',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            129,
                            147],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '35.186.0.0/16',
                        'allocated_date': '2016-10-11',
                        'as_name': 'GOOGLE, US',
                        'as_number': '15169',
                        'city': 'Mountain View',
                        'country': 'United States',
                        'ip': '35.186.224.25',
                        'latitude': '37.4043',
                        'longitude': '-122.0748',
                        'region': 'California'},
                    'site': {
                        'domain': 'spotify.com',
                        'http_server_type': 'envoy'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2006-04-23',
                        'name_server': 'dns1.p07.nsone.net,dns2.p07.nsone.net,dns3.p07.nsone.net,dns4.p07.nsone.net,ns1.p23.dynect.net,ns2.p23.dynect.net,ns3.p23.dynect.net,ns4.p23.dynect.net'}}},
            {
                'source': [],
                'url': 'https://content-prod-live.cert.starbucks.com/binary/v2/asset/digitalcontent.starbucks.com/udp/us/en/assets/POD5_CC-4500_AppCard_1376x736_tcm121-46905.jpg',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.94.64.0/20',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.94.71.126',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://itunes.apple.com/us/app/starbucks/id331177714?mt=8&amp;uo=4\\',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '23 May 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            112,
                            129],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.199.248.0/22',
                        'allocated_date': '2013-07-12',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.199.248.27',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'apple.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': []}},
            {
                'source': [],
                'url': 'https://assets.starbucks.staging.takt.com/a01ba5c7e70429537d9bdc1b996f6832-1540841854.jpg',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': '',
                        'ufg': 8},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '13.249.68.0/22',
                        'allocated_date': '2016-08-09',
                        'as_name': 'AMAZON-02, US',
                        'as_number': '16509',
                        'city': 'Seattle',
                        'country': 'United States',
                        'ip': '13.249.71.123',
                        'latitude': '47.6348',
                        'longitude': '-122.3451',
                        'region': 'Washington'},
                    'site': {
                        'domain': 'takt.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2002-08-25',
                        'name_server': 'luke.ns.cloudflare.com,olga.ns.cloudflare.com',
                        'registrant_email': 'admin@formation.ai',
                        'registrant_name': 'FORMATION INC',
                        'registrant_organization': 'FORMATION INC'}}},
            {
                'source': [],
                'url': 'https://www.starbucks.ca/account/signin/sso/',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 6},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.4.48.0/20',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.4.57.35',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.ca'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2000-11-01',
                        'expiration': '2017-03-05',
                        'name_server': 'a4.nstld.com,f4.nstld.com,l4.nstld.com'}}},
            {
                'source': [],
                'url': 'https://en-gb.dev.starbucks.com/account/signin/sso/',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.34.112.0/20',
                        'allocated_date': '2011-05-16',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.34.116.161',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com',
                        'http_server_type': 'AkamaiGHost'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://apps.apple.com/us/app/spotify-music-and-podcasts/id324684580',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105,
                            107],
                        'rep': -49,
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.0.240.0/23',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.0.240.35',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'apple.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': []}},
            {
                'source': [],
                'url': 'https://globalassets.starbucks.com/images/mobilev3/card_Coffee_Aroma_Card_FY11_270.png',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.10.112.0/20',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.10.112.183',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com',
                        'http_server_type': 'IIS'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://globalassets.starbucks.com/images/mobilev3/card_Coffee_Aroma_Card_FY11_thumb_82.png',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.10.112.0/20',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.10.112.183',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com',
                        'http_server_type': 'IIS'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://test.openapi.starbucks.com/v1/',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '03 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '107.23.0.0/17',
                        'allocated_date': '2011-05-03',
                        'as_name': 'AMAZON-AES, US',
                        'as_number': '14618',
                        'city': 'Ashburn',
                        'country': 'United States',
                        'ip': '107.23.127.116',
                        'latitude': '39.0481',
                        'longitude': '-77.4728',
                        'region': 'Virginia'},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://openapi.starbucks.com',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '08 May 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '34.224.0.0/12',
                        'allocated_date': '2016-09-12',
                        'as_name': 'AMAZON-AES, US',
                        'as_number': '14618',
                        'city': 'Ashburn',
                        'country': 'United States',
                        'ip': '34.237.118.73',
                        'latitude': '39.0481',
                        'longitude': '-77.4728',
                        'region': 'Virginia'},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://fr.starbucks.ca/about-us/company-information/online-policies/privacy-statement',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 8},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.4.48.0/20',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.4.57.35',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.ca',
                        'http_server_type': 'IIS'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2000-11-01',
                        'expiration': '2017-03-05',
                        'name_server': 'a4.nstld.com,f4.nstld.com,l4.nstld.com'}}},
            {
                'source': [],
                'url': 'https://branch.app.link/link-settings-page',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107,
                            140],
                        'rep': 12,
                        'ufg': ''},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '143.204.160.0/21',
                        'allocated_date': '2018-01-05',
                        'as_name': 'AMAZON-02, US',
                        'as_number': '16509',
                        'city': 'Seattle',
                        'country': 'United States',
                        'ip': '143.204.166.50',
                        'latitude': '47.6348',
                        'longitude': '-122.3451',
                        'region': 'Washington'},
                    'site': {
                        'domain': 'app.link'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'name_server': 'ns-1249.awsdns-28.org,ns-1578.awsdns-05.co.uk,ns-158.awsdns-19.com,ns-758.awsdns-30.net'}}},
            {
                'source': [],
                'url': 'https://bnc.lt',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '18 May 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': 4,
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '13.249.72.0/21',
                        'allocated_date': '2016-08-09',
                        'as_name': 'AMAZON-02, US',
                        'as_number': '16509',
                        'city': 'Seattle',
                        'country': 'United States',
                        'ip': '13.249.72.73',
                        'latitude': '47.6348',
                        'longitude': '-122.3451',
                        'region': 'Washington'},
                    'site': {
                        'domain': 'bnc.lt'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2016-11-14',
                        'name_server': 'ns-1241.awsdns-27.org,ns-1925.awsdns-48.co.uk,ns-20.awsdns-02.com,ns-819.awsdns-38.net',
                        'registrant_email': 'ecf8bdba5d9a89d879b0661a7296843f-5049847@contact.gandi.net',
                        'registrant_organization': 'Branch'}}},
            {
                'source': [],
                'url': 'http://www.spotify.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            129,
                            147],
                        'rep': -40,
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '35.186.0.0/16',
                        'allocated_date': '2016-10-11',
                        'as_name': 'GOOGLE, US',
                        'as_number': '15169',
                        'city': 'Mountain View',
                        'country': 'United States',
                        'ip': '35.186.224.25',
                        'latitude': '37.4043',
                        'longitude': '-122.0748',
                        'region': 'California'},
                    'site': {
                        'domain': 'spotify.com',
                        'http_server_type': 'envoy'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '2006-04-23',
                        'name_server': 'dns1.p07.nsone.net,dns2.p07.nsone.net,dns3.p07.nsone.net,dns4.p07.nsone.net,ns1.p23.dynect.net,ns2.p23.dynect.net,ns3.p23.dynect.net,ns4.p23.dynect.net'}}},
            {
                'source': [],
                'url': 'https://i.scdn.co/image/70d540d899fdde03897518c1dce61fccbbf25e07',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '07 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': '',
                        'ufg': 8},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '151.101.48.0/22',
                        'allocated_date': '2016-02-01',
                        'as_name': 'FASTLY, US',
                        'as_number': '54113',
                        'city': 'Dallas',
                        'country': 'United States',
                        'ip': '151.101.50.248',
                        'latitude': '32.7787',
                        'longitude': '-96.8217',
                        'region': 'Texas'},
                    'site': {
                        'domain': 'scdn.co'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2000-08-20',
                        'name_server': 'dns3.p07.nsone.net,ns3.p23.dynect.net,ns1.p23.dynect.net,dns1.p07.nsone.net,ns4.p23.dynect.net,ns2.p23.dynect.net,dns2.p07.nsone.net,dns4.p07.nsone.net'}}},
            {
                'source': [],
                'url': 'https://i.scdn.co/image/1700539edd8be96ea13bb3861a57c159ae6b43da',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '07 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': '',
                        'ufg': 8},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '151.101.48.0/22',
                        'allocated_date': '2016-02-01',
                        'as_name': 'FASTLY, US',
                        'as_number': '54113',
                        'city': 'Dallas',
                        'country': 'United States',
                        'ip': '151.101.50.248',
                        'latitude': '32.7787',
                        'longitude': '-96.8217',
                        'region': 'Texas'},
                    'site': {
                        'domain': 'scdn.co'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2000-08-20',
                        'name_server': 'dns3.p07.nsone.net,ns3.p23.dynect.net,ns1.p23.dynect.net,dns1.p07.nsone.net,ns4.p23.dynect.net,ns2.p23.dynect.net,dns2.p07.nsone.net,dns4.p07.nsone.net'}}},
            {
                'source': [],
                'url': 'https://i.scdn.co/image/8e1885ce8a283124953a34625b6881d232e3e0fb',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '07 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': '',
                        'ufg': 8},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '151.101.48.0/22',
                        'allocated_date': '2016-02-01',
                        'as_name': 'FASTLY, US',
                        'as_number': '54113',
                        'city': 'Dallas',
                        'country': 'United States',
                        'ip': '151.101.50.248',
                        'latitude': '32.7787',
                        'longitude': '-96.8217',
                        'region': 'Texas'},
                    'site': {
                        'domain': 'scdn.co'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2000-08-20',
                        'name_server': 'dns3.p07.nsone.net,ns3.p23.dynect.net,ns1.p23.dynect.net,dns1.p07.nsone.net,ns4.p23.dynect.net,ns2.p23.dynect.net,dns2.p07.nsone.net,dns4.p07.nsone.net'}}},
            {
                'source': [],
                'url': 'http://com.starbucks.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '',
                        'allocated_date': '',
                        'as_name': '',
                        'as_number': '',
                        'city': '',
                        'country': '',
                        'ip': 'Unavailable',
                        'latitude': '',
                        'longitude': '',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'http://sbuxguest.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'rep': 15,
                        'ufg': ''},
                    'server': {
                        'BGP_Prefix': '',
                        'allocated_date': '',
                        'as_name': '',
                        'as_number': '',
                        'city': '',
                        'country': '',
                        'ip': 'Unavailable',
                        'latitude': '',
                        'longitude': '',
                        'region': ''},
                    'site': {
                        'domain': 'sbuxguest.com',
                        'http_server_type': 'nginx/1.14.2'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '2017-08-24',
                        'expiration': '2020-08-24',
                        'name_server': 'a4.nstld.com,f4.nstld.com,g4.nstld.com'}}},
            {
                'source': [],
                'url': 'https://www.starbucks.com/about-us/company-information/online-policies/terms-of-use/card',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '09 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.97.192.0/19',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.97.219.142',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://www.starbucks.ca/card/manage/starbucks-card-ts-and-cs',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 6},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.4.48.0/20',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.4.57.35',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.ca'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2000-11-01',
                        'expiration': '2017-03-05',
                        'name_server': 'a4.nstld.com,f4.nstld.com,l4.nstld.com'}}},
            {
                'source': [],
                'url': 'https://www.starbucks.com/about-us/company-information/online-policies/terms-of-use',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '09 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.97.192.0/19',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.97.219.142',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'http://mobile-collector.newrelic.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            105,
                            107],
                        'rep': -3,
                        'ufg': 6},
                    'server': {
                        'BGP_Prefix': '151.101.0.0/22',
                        'allocated_date': '2016-02-01',
                        'as_name': 'FASTLY, US',
                        'as_number': '54113',
                        'city': '',
                        'country': 'United States',
                        'ip': '151.101.2.110',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'newrelic.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '2006-04-19',
                        'name_server': 'dns1.p07.nsone.net,dns2.p07.nsone.net,dns3.p07.nsone.net,dns4.p07.nsone.net,ns1.p29.dynect.net,ns2.p29.dynect.net,ns3.p29.dynect.net,ns4.p29.dynect.net'}}},
            {
                'source': [],
                'url': 'https://www.starbucks.ca/about-us/company-information/online-policies/privacy-statement',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 6},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.4.48.0/20',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.4.57.35',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.ca'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2000-11-01',
                        'expiration': '2017-03-05',
                        'name_server': 'a4.nstld.com,f4.nstld.com,l4.nstld.com'}}},
            {
                'source': [],
                'url': 'https://www.starbucks.co.uk/about-us/company-information/online-policies/privacy-statement',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '03 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 6},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.50.140.0/22',
                        'allocated_date': '2011-05-16',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.50.143.85',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.co.uk',
                        'http_server_type': 'IIS'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1997-07-15',
                        'name_server': 'a4.nstld.com,j4.nstld.com,l4.nstld.com'}}},
            {
                'source': [],
                'url': 'https://local.apptimize.co/api/metadata/v4/',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '07 Jun 2020',
                    'mcafee_gti_reputation': {
                        'rep': 15,
                        'ufg': ''},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '',
                        'allocated_date': '',
                        'as_name': '',
                        'as_number': '',
                        'city': '',
                        'country': '',
                        'ip': 'Unavailable',
                        'latitude': '',
                        'longitude': '',
                        'region': ''},
                    'site': {
                        'domain': 'apptimize.co'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2000-02-22',
                        'name_server': 'ns-1935.awsdns-49.co.uk,ns-805.awsdns-36.net,ns-1048.awsdns-03.org,ns-150.awsdns-18.com'}}},
            {
                'source': [],
                'url': 'https://md-i-c.apptimize.com/api/metadata/v4/',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '07 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': '',
                        'ufg': 4},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '13.225.48.0/21',
                        'allocated_date': '2018-07-11',
                        'as_name': 'AMAZON-02, US',
                        'as_number': '16509',
                        'city': 'Seattle',
                        'country': 'United States',
                        'ip': '13.225.54.19',
                        'latitude': '47.6348',
                        'longitude': '-122.3451',
                        'region': 'Washington'},
                    'site': {
                        'domain': 'apptimize.com',
                        'http_server_type': 'AmazonS3'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2006-09-21',
                        'name_server': 'ns-1129.awsdns-13.org,ns-1883.awsdns-43.co.uk,ns-473.awsdns-59.com,ns-685.awsdns-21.net',
                        'registrant_address': '85260 Scottsdale, US',
                        'registrant_email': 'APPTIMIZE.COM@domainsbyproxy.com',
                        'registrant_name': 'Registration Private',
                        'registrant_organization': 'Domains By Proxy, LLC'}}},
            {
                'source': [],
                'url': 'https://apptimize.com/docs/installation/ios-installation.html',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': '',
                        'ufg': 4},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '35.160.0.0/13',
                        'allocated_date': '2016-08-09',
                        'as_name': 'AMAZON-02, US',
                        'as_number': '16509',
                        'city': 'Boardman',
                        'country': 'United States',
                        'ip': '35.162.44.242',
                        'latitude': '45.8491',
                        'longitude': '-119.7143',
                        'region': 'Oregon'},
                    'site': {
                        'domain': 'apptimize.com',
                        'http_server_type': 'openresty/1.13.6.2'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2006-09-21',
                        'name_server': 'ns-1129.awsdns-13.org,ns-1883.awsdns-43.co.uk,ns-473.awsdns-59.com,ns-685.awsdns-21.net',
                        'registrant_address': '85260 Scottsdale, US',
                        'registrant_email': 'APPTIMIZE.COM@domainsbyproxy.com',
                        'registrant_name': 'Registration Private',
                        'registrant_organization': 'Domains By Proxy, LLC'}}},
            {
                'source': [],
                'url': 'https://combine.asnapieu.com',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': 4,
                        'ufg': 8},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '35.244.0.0/14',
                        'allocated_date': '2017-09-29',
                        'as_name': 'GOOGLE, US',
                        'as_number': '15169',
                        'city': 'Mountain View',
                        'country': 'United States',
                        'ip': '35.244.242.208',
                        'latitude': '37.4043',
                        'longitude': '-122.0748',
                        'region': 'California'},
                    'site': {
                        'domain': 'asnapieu.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2019-05-15',
                        'name_server': 'ns-cloud-e1.googledomains.com,ns-cloud-e2.googledomains.com,ns-cloud-e3.googledomains.com,ns-cloud-e4.googledomains.com'}}},
            {
                'source': [],
                'url': 'https://remote-data.asnapieu.com',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': 4,
                        'ufg': 8},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '34.96.0.0/14',
                        'allocated_date': '2018-09-28',
                        'as_name': 'GOOGLE, US',
                        'as_number': '15169',
                        'city': '',
                        'country': 'United States',
                        'ip': '34.96.96.216',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'asnapieu.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2019-05-15',
                        'name_server': 'ns-cloud-e1.googledomains.com,ns-cloud-e2.googledomains.com,ns-cloud-e3.googledomains.com,ns-cloud-e4.googledomains.com'}}},
            {
                'source': [],
                'url': 'https://pwc.chase.com/pwc',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '08 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            114],
                        'rep': -45,
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '159.53.32.0/19',
                        'allocated_date': '1992-03-06',
                        'as_name': 'AS-7743, US',
                        'as_number': '7743',
                        'city': 'New York',
                        'country': 'United States',
                        'ip': '159.53.44.92',
                        'latitude': '40.7145',
                        'longitude': '-74.0029',
                        'region': 'New York'},
                    'site': {
                        'domain': 'chase.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': []}},
            {
                'source': [],
                'url': 'https://www.chase.com',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            114],
                        'rep': -45,
                        'ufg': 3},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '159.53.64.0/19',
                        'allocated_date': '1992-03-06',
                        'as_name': 'AS-7743, US',
                        'as_number': '7743',
                        'city': '',
                        'country': 'United States',
                        'ip': '159.53.84.126',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'chase.com',
                        'http_server_type': ''},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': []}},
            {
                'source': [],
                'url': 'http://identity.mparticle.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': '',
                        'ufg': ''},
                    'server': {
                        'BGP_Prefix': '151.101.0.0/22',
                        'allocated_date': '2016-02-01',
                        'as_name': 'FASTLY, US',
                        'as_number': '54113',
                        'city': '',
                        'country': 'United States',
                        'ip': '151.101.2.133',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'mparticle.com',
                        'http_server_type': 'Kestrel'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '2012-07-02',
                        'name_server': 'ns-1447.awsdns-52.org,ns-1796.awsdns-32.co.uk,ns-206.awsdns-25.com,ns-553.awsdns-05.net',
                        'registrant_email': 'Select Contact Domain Holder link at https://www.godaddy.com/whois/results.aspx?domain=MPARTICLE.COM',
                        'registrant_organization': 'mParticle, inc'}}},
            {
                'source': [],
                'url': 'http://baseduser@starbucks.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '23.4.48.0/20',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.4.57.35',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'http://www.apple.com/appleca/root.crl',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            105,
                            107],
                        'rep': -49,
                        'ufg': 3},
                    'server': {
                        'BGP_Prefix': '23.0.240.0/23',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.0.241.60',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'apple.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': []}},
            {
                'source': [],
                'url': 'https://content-cert-live.cert.starbucks.com/binary/v2/asset/125-39047.jpg',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.94.64.0/20',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.94.71.126',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://eapi-ct.starbucks.com/content/v3/content/125-42635',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '01 May 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '107.23.0.0/17',
                        'allocated_date': '2011-05-03',
                        'as_name': 'AMAZON-AES, US',
                        'as_number': '14618',
                        'city': 'Ashburn',
                        'country': 'United States',
                        'ip': '107.23.127.102',
                        'latitude': '39.0481',
                        'longitude': '-77.4728',
                        'region': 'Virginia'},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://globalassets.starbucks.com/assets/1a8789bf1a9c4513bd02d0d83e751128.png',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.10.112.0/20',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.10.112.183',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com',
                        'http_server_type': 'IIS'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://content-cert-live.cert.starbucks.com/binary/v2/asset/cert.digitalcontent.starbucks.com/udp/us/en/assets/onboarding_mop_400_tcm125-28754.jpg',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.94.64.0/20',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.94.71.126',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://content-prod-live.cert.starbucks.com/binary/v2/asset/digitalcontent.starbucks.com/udp/us/en/assets/Happy_Birthday_feedCard_tcm121-50795.jpg',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.94.64.0/20',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.94.71.126',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://content-prod-live.cert.starbucks.com/binary/v2/asset/digitalcontent.starbucks.com/udp/us/en/assets/Spotify-Tile-GuestDJLadyGaga-Pride_tcm121-53074.jpg',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.94.64.0/20',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.94.71.126',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://creditcards.chase.com/a1/Starbuckscreditcard/App4',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '07 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            114],
                        'rep': -80,
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '159.53.32.0/19',
                        'allocated_date': '1992-03-06',
                        'as_name': 'AS-7743, US',
                        'as_number': '7743',
                        'city': '',
                        'country': 'United States',
                        'ip': '159.53.53.3',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'chase.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': []}},
            {
                'source': [],
                'url': 'https://test.openapi.starbucks.com/v1/assets/488bfc5ca8df41e9909ff7fb1db1e71d.png',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '03 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '107.23.0.0/17',
                        'allocated_date': '2011-05-03',
                        'as_name': 'AMAZON-AES, US',
                        'as_number': '14618',
                        'city': 'Ashburn',
                        'country': 'United States',
                        'ip': '107.23.127.116',
                        'latitude': '39.0481',
                        'longitude': '-77.4728',
                        'region': 'Virginia'},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://en-us.dev.starbucks.com/account/signin/sso/',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.34.112.0/20',
                        'allocated_date': '2011-05-16',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.34.116.161',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://learn.apptentive.com/knowledge-base/ios-integration-reference/#push-notifications.',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': -3,
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '151.101.64.0/22',
                        'allocated_date': '2016-02-01',
                        'as_name': 'FASTLY, US',
                        'as_number': '54113',
                        'city': '',
                        'country': 'United States',
                        'ip': '151.101.66.159',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'apptentive.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2011-03-16',
                        'name_server': 'ns-103.awsdns-12.com,ns-1266.awsdns-30.org,ns-1873.awsdns-42.co.uk,ns-933.awsdns-52.net',
                        'registrant_email': 'Select Contact Domain Holder link at https://www.godaddy.com/whois/results.aspx?domain=APPTENTIVE.COM',
                        'registrant_organization': 'Apptentive'}}},
            {
                'source': [],
                'url': 'http://support@apptentive.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': -3,
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '151.101.64.0/22',
                        'allocated_date': '2016-02-01',
                        'as_name': 'FASTLY, US',
                        'as_number': '54113',
                        'city': '',
                        'country': 'United States',
                        'ip': '151.101.66.159',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'apptentive.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '2011-03-16',
                        'name_server': 'ns-103.awsdns-12.com,ns-1266.awsdns-30.org,ns-1873.awsdns-42.co.uk,ns-933.awsdns-52.net',
                        'registrant_email': 'Select Contact Domain Holder link at https://www.godaddy.com/whois/results.aspx?domain=APPTENTIVE.COM',
                        'registrant_organization': 'Apptentive'}}},
            {
                'source': [],
                'url': 'https://<yourapp>.app.link/NdJ6nFzRbK',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': None,
                    'mcafee_gti_reputation': {
                        'cat': [
                            107,
                            140],
                        'rep': 12,
                        'ufg': ''},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '',
                        'allocated_date': '',
                        'as_name': '',
                        'as_number': '',
                        'city': '',
                        'country': '',
                        'ip': 'Unavailable',
                        'latitude': '',
                        'longitude': '',
                        'region': ''},
                    'site': {
                        'domain': ''},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': None}},
            {
                'source': [],
                'url': 'https://api2.branch.io',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': -2,
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '143.204.160.0/21',
                        'allocated_date': '2018-01-05',
                        'as_name': 'AMAZON-02, US',
                        'as_number': '16509',
                        'city': 'Seattle',
                        'country': 'United States',
                        'ip': '143.204.166.24',
                        'latitude': '47.6348',
                        'longitude': '-122.3451',
                        'region': 'Washington'},
                    'site': {
                        'domain': 'branch.io'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'name_server': 'ns-1091.awsdns-08.org,ns-1809.awsdns-34.co.uk,ns-236.awsdns-29.com,ns-991.awsdns-59.net'}}},
            {
                'source': [],
                'url': 'https://api.spotify.com/v1/users/ldowlingstarbucks',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            129,
                            147],
                        'rep': -40,
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '35.186.0.0/16',
                        'allocated_date': '2016-10-11',
                        'as_name': 'GOOGLE, US',
                        'as_number': '15169',
                        'city': 'Mountain View',
                        'country': 'United States',
                        'ip': '35.186.224.25',
                        'latitude': '37.4043',
                        'longitude': '-122.0748',
                        'region': 'California'},
                    'site': {
                        'domain': 'spotify.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2006-04-23',
                        'name_server': 'dns1.p07.nsone.net,dns2.p07.nsone.net,dns3.p07.nsone.net,dns4.p07.nsone.net,ns1.p23.dynect.net,ns2.p23.dynect.net,ns3.p23.dynect.net,ns4.p23.dynect.net'}}},
            {
                'source': [],
                'url': 'http://mtestwww2.starbucks.com/payPalCancelled',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '107.162.133.0/24',
                        'allocated_date': '2013-12-19',
                        'as_name': 'DEFENSE-NET, US',
                        'as_number': '55002',
                        'city': '',
                        'country': 'United States',
                        'ip': '107.162.133.207',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'http://mtestwww2.starbucks.com/payPalSuccess',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '107.162.133.0/24',
                        'allocated_date': '2013-12-19',
                        'as_name': 'DEFENSE-NET, US',
                        'as_number': '55002',
                        'city': '',
                        'country': 'United States',
                        'ip': '107.162.133.207',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'http://www.starbucks.com/payPalCancelled',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '104.97.192.0/19',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.97.219.142',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'http://www.starbucks.com/payPalSuccess',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '104.97.192.0/19',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.97.219.142',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'http://en-us.test.starbucks.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '23.34.8.0/21',
                        'allocated_date': '2011-05-16',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.34.10.146',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com',
                        'http_server_type': 'AkamaiGHost'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://customerservice.starbucks.com/',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '74.117.200.0/23',
                        'allocated_date': '2009-09-15',
                        'as_name': 'NETDYNAMICS, US',
                        'as_number': '7160',
                        'city': 'Elk Grove Village',
                        'country': 'United States',
                        'ip': '74.117.200.136',
                        'latitude': '42.0048',
                        'longitude': '-87.9954',
                        'region': 'Illinois'},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://www.starbucks.co.uk/customer-service',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '03 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 6},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.50.140.0/22',
                        'allocated_date': '2011-05-16',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.50.143.85',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.co.uk',
                        'http_server_type': 'IIS'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1997-07-15',
                        'name_server': 'a4.nstld.com,j4.nstld.com,l4.nstld.com'}}},
            {
                'source': [],
                'url': 'https://fr.starbucks.ca/card/manage/starbucks-card-ts-and-cs',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 8},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.4.48.0/20',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.4.57.35',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.ca',
                        'http_server_type': 'IIS'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2000-11-01',
                        'expiration': '2017-03-05',
                        'name_server': 'a4.nstld.com,f4.nstld.com,l4.nstld.com'}}},
            {
                'source': [],
                'url': 'https://www.starbucks.com/starbucks-rewards/credit-card?cell=6cr2&spid=g2nw&utm_campaign=6500&utm_medium=email&utm_source=exacttarget',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '09 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.97.192.0/19',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.97.219.142',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://test14.openapi.starbucks.com/v1/',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '34.224.0.0/12',
                        'allocated_date': '2016-09-12',
                        'as_name': 'AMAZON-AES, US',
                        'as_number': '14618',
                        'city': 'Ashburn',
                        'country': 'United States',
                        'ip': '34.237.118.220',
                        'latitude': '39.0481',
                        'longitude': '-77.4728',
                        'region': 'Virginia'},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://test.openapi.starbucks.com',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '03 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '107.23.0.0/17',
                        'allocated_date': '2011-05-03',
                        'as_name': 'AMAZON-AES, US',
                        'as_number': '14618',
                        'city': 'Ashburn',
                        'country': 'United States',
                        'ip': '107.23.127.116',
                        'latitude': '39.0481',
                        'longitude': '-77.4728',
                        'region': 'Virginia'},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'http://maps.google.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            108],
                        'rep': '',
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '172.217.9.0/24',
                        'allocated_date': '2012-04-16',
                        'as_name': 'GOOGLE, US',
                        'as_number': '15169',
                        'city': '',
                        'country': 'United States',
                        'ip': '172.217.9.14',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'google.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': []}},
            {
                'source': [],
                'url': 'https://mfasapwc.chase.com/auth',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '20 May 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            114],
                        'rep': -45,
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '159.53.32.0/19',
                        'allocated_date': '1992-03-06',
                        'as_name': 'AS-7743, US',
                        'as_number': '7743',
                        'city': 'New York',
                        'country': 'United States',
                        'ip': '159.53.44.91',
                        'latitude': '40.7145',
                        'longitude': '-74.0029',
                        'region': 'New York'},
                    'site': {
                        'domain': 'chase.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': []}},
            {
                'source': [],
                'url': 'https://chaseonline.chase.com',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '08 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            114],
                        'rep': -22,
                        'ufg': 71},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '159.53.64.0/19',
                        'allocated_date': '1992-03-06',
                        'as_name': 'AS-7743, US',
                        'as_number': '7743',
                        'city': '',
                        'country': 'United States',
                        'ip': '159.53.85.76',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'chase.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': []}},
            {
                'source': [],
                'url': 'https://pwc.chase.com/mps',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '08 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            114],
                        'rep': -45,
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '159.53.32.0/19',
                        'allocated_date': '1992-03-06',
                        'as_name': 'AS-7743, US',
                        'as_number': '7743',
                        'city': 'New York',
                        'country': 'United States',
                        'ip': '159.53.44.92',
                        'latitude': '40.7145',
                        'longitude': '-74.0029',
                        'region': 'New York'},
                    'site': {
                        'domain': 'chase.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': []}},
            {
                'source': [],
                'url': 'https://example.com/?%@',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': 9,
                        'ufg': 6},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '93.184.216.0/24',
                        'allocated_date': '2008-06-02',
                        'as_name': 'EDGECAST, US',
                        'as_number': '15133',
                        'city': 'Norwell',
                        'country': 'United States',
                        'ip': '93.184.216.34',
                        'latitude': '42.1596',
                        'longitude': '-70.8217',
                        'region': 'Massachusetts'},
                    'site': {
                        'domain': 'example.com',
                        'http_server_type': 'ECS (nyb/1D07)'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1995-08-13'}}},
            {
                'source': [],
                'url': 'http://config2.mparticle.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': '',
                        'ufg': ''},
                    'server': {
                        'BGP_Prefix': '151.101.192.0/22',
                        'allocated_date': '2016-02-01',
                        'as_name': 'FASTLY, US',
                        'as_number': '54113',
                        'city': '',
                        'country': 'United States',
                        'ip': '151.101.194.133',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'mparticle.com',
                        'http_server_type': 'Kestrel'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '2012-07-02',
                        'name_server': 'ns-1447.awsdns-52.org,ns-1796.awsdns-32.co.uk,ns-206.awsdns-25.com,ns-553.awsdns-05.net',
                        'registrant_email': 'Select Contact Domain Holder link at https://www.godaddy.com/whois/results.aspx?domain=MPARTICLE.COM',
                        'registrant_organization': 'mParticle, inc'}}},
            {
                'source': [],
                'url': 'http://crl.apple.com/codesigning.crl',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            105,
                            107],
                        'rep': -49,
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '17.253.2.0/23',
                        'allocated_date': '1990-04-16',
                        'as_name': 'APPLE-AUSTIN, US',
                        'as_number': '6185',
                        'city': 'Dallas',
                        'country': 'United States',
                        'ip': '17.253.3.207',
                        'latitude': '32.7787',
                        'longitude': '-96.8217',
                        'region': 'Texas'},
                    'site': {
                        'domain': 'apple.com',
                        'http_server_type': 'ATS/8.0.6'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': []}},
            {
                'source': [],
                'url': 'https://open.spotify.com',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            129,
                            147],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '35.186.0.0/16',
                        'allocated_date': '2016-10-11',
                        'as_name': 'GOOGLE, US',
                        'as_number': '15169',
                        'city': 'Mountain View',
                        'country': 'United States',
                        'ip': '35.186.224.25',
                        'latitude': '37.4043',
                        'longitude': '-122.0748',
                        'region': 'California'},
                    'site': {
                        'domain': 'spotify.com',
                        'http_server_type': 'envoy'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2006-04-23',
                        'name_server': 'dns1.p07.nsone.net,dns2.p07.nsone.net,dns3.p07.nsone.net,dns4.p07.nsone.net,ns1.p23.dynect.net,ns2.p23.dynect.net,ns3.p23.dynect.net,ns4.p23.dynect.net'}}},
            {
                'source': [],
                'url': 'https://content-prod-live.cert.starbucks.com/binary/v2/asset/digitalcontent.starbucks.com/udp/us/en/assets/Spotify_Tile_1280x1280_GuestDJLadyGaga_Pride_tcm121-52994.jpg',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.94.64.0/20',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.94.71.126',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://cert-assets.digital.starbucksassets.com/binary/v2/asset/cert.digitalcontent.starbucks.com/udp/us/en/assets/1_9-BlondeVL-1376x736_tcm125-29037.jpg',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105],
                        'rep': '',
                        'ufg': 12},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '184.31.96.0/19',
                        'allocated_date': '2010-10-11',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '184.31.127.133',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucksassets.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2016-10-19',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Domain Admin',
                        'registrant_organization': 'Starbucks Corporation'}}},
            {
                'source': [],
                'url': 'https://content-cert-live.cert.starbucks.com/binary/v2/asset/cert.digitalcontent.starbucks.com/udp/us/en/assets/onboarding_addmoney_400_tcm125-28752.jpg',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.94.64.0/20',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.94.71.126',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://content-cert-live.cert.starbucks.com/binary/v2/asset/cert.digitalcontent.starbucks.com/udp/us/en/assets/onboarding_pay_complete_400_tcm125-28757.jpg',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.94.64.0/20',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.94.71.126',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://test14host.openapi.starbucks.com/content/v1/assets/6e97c616213747d28ff02bb3b3e5641c.jpg',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '98.99.248.0/24',
                        'allocated_date': '2008-03-06',
                        'as_name': 'STARBUCKS, US',
                        'as_number': '62566',
                        'city': 'Chandler',
                        'country': 'United States',
                        'ip': '98.99.248.17',
                        'latitude': '33.2727',
                        'longitude': '-111.8278',
                        'region': 'Arizona'},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://content-prod-live.cert.starbucks.com/binary/v2/asset/digitalcontent.starbucks.com/udp/us/en/assets/Cocoa-Cloud-Macchiato-FINAL060519_tcm121-53268.jpg',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.94.64.0/20',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.94.71.126',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://en-us.test.starbucks.com/account/signin/sso/',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.34.8.0/21',
                        'allocated_date': '2011-05-16',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.34.10.146',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com',
                        'http_server_type': 'AkamaiGHost'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://en-ca.dev.starbucks.com/account/signin/sso/',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.34.112.0/20',
                        'allocated_date': '2011-05-16',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.34.116.161',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://en-ca.test.starbucks.com/account/signin/sso/',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.34.8.0/21',
                        'allocated_date': '2011-05-16',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.34.10.146',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://www.starbucks.co.uk/account/signin/sso/',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '03 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 6},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.50.140.0/22',
                        'allocated_date': '2011-05-16',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.50.143.85',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.co.uk',
                        'http_server_type': 'IIS'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1997-07-15',
                        'name_server': 'a4.nstld.com,j4.nstld.com,l4.nstld.com'}}},
            {
                'source': [],
                'url': 'https://en-gb.test.starbucks.com/account/signin/sso/',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.34.8.0/21',
                        'allocated_date': '2011-05-16',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.34.10.146',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'http://wwww.starbucks.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '',
                        'allocated_date': '',
                        'as_name': '',
                        'as_number': '',
                        'city': '',
                        'country': '',
                        'ip': 'Unavailable',
                        'latitude': '',
                        'longitude': '',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'http://www.apptentive.com/privacy/',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': -3,
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '151.101.64.0/22',
                        'allocated_date': '2016-02-01',
                        'as_name': 'FASTLY, US',
                        'as_number': '54113',
                        'city': '',
                        'country': 'United States',
                        'ip': '151.101.66.159',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'apptentive.com',
                        'http_server_type': 'Flywheel/4.1.0'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '2011-03-16',
                        'name_server': 'ns-103.awsdns-12.com,ns-1266.awsdns-30.org,ns-1873.awsdns-42.co.uk,ns-933.awsdns-52.net',
                        'registrant_email': 'Select Contact Domain Holder link at https://www.godaddy.com/whois/results.aspx?domain=APPTENTIVE.COM',
                        'registrant_organization': 'Apptentive'}}},
            {
                'source': [],
                'url': 'https://d3rt1990lpmkn.cloudfront.net/640/38d76bf7f7b9e42e1e99a9f3968654f67180009c',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '13.226.200.0/21',
                        'allocated_date': '2018-07-11',
                        'as_name': 'AMAZON-02, US',
                        'as_number': '16509',
                        'city': 'Seattle',
                        'country': 'United States',
                        'ip': '13.226.204.164',
                        'latitude': '47.6348',
                        'longitude': '-122.3451',
                        'region': 'Washington'},
                    'site': {
                        'domain': 'cloudfront.net'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2008-04-25',
                        'name_server': 'ns-1306.awsdns-35.org,ns-1597.awsdns-07.co.uk,ns-418.awsdns-52.com,ns-666.awsdns-19.net'}}},
            {
                'source': [],
                'url': 'https://i.scdn.co/image/d3e2370607288b578180006702f27c39aa1250ae',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '07 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            107],
                        'rep': '',
                        'ufg': 8},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '151.101.48.0/22',
                        'allocated_date': '2016-02-01',
                        'as_name': 'FASTLY, US',
                        'as_number': '54113',
                        'city': 'Dallas',
                        'country': 'United States',
                        'ip': '151.101.50.248',
                        'latitude': '32.7787',
                        'longitude': '-96.8217',
                        'region': 'Texas'},
                    'site': {
                        'domain': 'scdn.co'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2000-08-20',
                        'name_server': 'dns3.p07.nsone.net,ns3.p23.dynect.net,ns1.p23.dynect.net,dns1.p07.nsone.net,ns4.p23.dynect.net,ns2.p23.dynect.net,dns2.p07.nsone.net,dns4.p07.nsone.net'}}},
            {
                'source': [],
                'url': 'https://itunes.apple.com/us/album/the-disney-afternoon/id988013003?i=988013004&uo=4',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '23 May 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            112,
                            129],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.199.248.0/22',
                        'allocated_date': '2013-07-12',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.199.248.27',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'apple.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': []}},
            {
                'source': [],
                'url': 'http://open.spotify.com/user/ldowlingstarbucks',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            129,
                            147],
                        'rep': '',
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '35.186.0.0/16',
                        'allocated_date': '2016-10-11',
                        'as_name': 'GOOGLE, US',
                        'as_number': '15169',
                        'city': 'Mountain View',
                        'country': 'United States',
                        'ip': '35.186.224.25',
                        'latitude': '37.4043',
                        'longitude': '-122.0748',
                        'region': 'California'},
                    'site': {
                        'domain': 'spotify.com',
                        'http_server_type': 'envoy'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '2006-04-23',
                        'name_server': 'dns1.p07.nsone.net,dns2.p07.nsone.net,dns3.p07.nsone.net,dns4.p07.nsone.net,ns1.p23.dynect.net,ns2.p23.dynect.net,ns3.p23.dynect.net,ns4.p23.dynect.net'}}},
            {
                'source': [],
                'url': 'https://api.spotify.com/v1/users/ldowlingstarbucks/playlists/0UQ4rAWSXMHjsamcCS3dc1',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '06 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            129,
                            147],
                        'rep': -40,
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '35.186.0.0/16',
                        'allocated_date': '2016-10-11',
                        'as_name': 'GOOGLE, US',
                        'as_number': '15169',
                        'city': 'Mountain View',
                        'country': 'United States',
                        'ip': '35.186.224.25',
                        'latitude': '37.4043',
                        'longitude': '-122.0748',
                        'region': 'California'},
                    'site': {
                        'domain': 'spotify.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2006-04-23',
                        'name_server': 'dns1.p07.nsone.net,dns2.p07.nsone.net,dns3.p07.nsone.net,dns4.p07.nsone.net,ns1.p23.dynect.net,ns2.p23.dynect.net,ns3.p23.dynect.net,ns4.p23.dynect.net'}}},
            {
                'source': [],
                'url': 'http://starbucksstore.com',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': -42,
                        'ufg': 2},
                    'server': {
                        'BGP_Prefix': '107.150.136.0/21',
                        'allocated_date': '2013-12-13',
                        'as_name': 'INTERNAP-2BLK, US',
                        'as_number': '12179',
                        'city': '',
                        'country': 'United States',
                        'ip': '107.150.141.160',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucksstore.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': {
                        'creation': '2004-05-03',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Starbucks Coffee Company',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://www.starbucks.com',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '09 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.97.192.0/19',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.97.219.142',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://customerservice.starbucks.com/app/answers/list/p/148',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '74.117.200.0/23',
                        'allocated_date': '2009-09-15',
                        'as_name': 'NETDYNAMICS, US',
                        'as_number': '7160',
                        'city': 'Elk Grove Village',
                        'country': 'United States',
                        'ip': '74.117.200.136',
                        'latitude': '42.0048',
                        'longitude': '-87.9954',
                        'region': 'Illinois'},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://s00293apim0certegift.azure-api.net/v21/proxyv21/api/PaymentTokenRemoval',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            105,
                            107],
                        'rep': -3,
                        'ufg': 4},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '52.160.0.0/11',
                        'allocated_date': '2015-11-24',
                        'as_name': 'MICROSOFT-CORP-MSN-AS-BLOCK, US',
                        'as_number': '8075',
                        'city': 'Washington',
                        'country': 'United States',
                        'ip': '52.186.10.31',
                        'latitude': '38.7095',
                        'longitude': '-78.1539',
                        'region': 'Virginia'},
                    'site': {
                        'domain': 'azure-api.net'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'name_server': 'bayan.ns.cloudflare.com,dolly.ns.cloudflare.com'}}},
            {
                'source': [],
                'url': 'http://www.apple.com/DTDs/PropertyList-1.0.dtd',
                'url_info': {
                    'has_problem': 0,
                    'mcafee_gti_reputation': {
                        'cat': [
                            105,
                            107],
                        'rep': -49,
                        'ufg': 3},
                    'server': {
                        'BGP_Prefix': '23.0.240.0/23',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.0.241.60',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'apple.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'whois': []}},
            {
                'source': [],
                'url': 'https://www.starbucks.com/rewards/terms',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '09 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.97.192.0/19',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.97.219.142',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}},
            {
                'source': [],
                'url': 'https://www.starbucks.co.uk/card/rewards/rewards-program-ts-and-cs',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '03 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 6},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.50.140.0/22',
                        'allocated_date': '2011-05-16',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.50.143.85',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.co.uk',
                        'http_server_type': 'IIS'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1997-07-15',
                        'name_server': 'a4.nstld.com,j4.nstld.com,l4.nstld.com'}}},
            {
                'source': [],
                'url': 'https://fr.starbucks.ca/recompenses/modalites',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 8},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.4.48.0/20',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.4.57.35',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.ca',
                        'http_server_type': 'IIS'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2000-11-01',
                        'expiration': '2017-03-05',
                        'name_server': 'a4.nstld.com,f4.nstld.com,l4.nstld.com'}}},
            {
                'source': [],
                'url': 'https://fr.starbucks.ca/card/card-terms-and-conditions',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '28 Apr 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 8},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '23.4.48.0/20',
                        'allocated_date': '2010-12-17',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '23.4.57.35',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.ca',
                        'http_server_type': 'IIS'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '2000-11-01',
                        'expiration': '2017-03-05',
                        'name_server': 'a4.nstld.com,f4.nstld.com,l4.nstld.com'}}},
            {
                'source': [],
                'url': 'https://www.starbucks.com/about-us/company-information/online-policies/privacy-policy',
                'url_info': {
                    'exp_check': 0,
                    'freak_vulnerability': False,
                    'has_problem': 0,
                    'hb': 0,
                    'hb_tm': '09 Jun 2020',
                    'mcafee_gti_reputation': {
                        'cat': [
                            136],
                        'rep': '',
                        'ufg': 2},
                    'robot': 0,
                    'robot_vulnerability': False,
                    'server': {
                        'BGP_Prefix': '104.97.192.0/19',
                        'allocated_date': '2014-04-22',
                        'as_name': 'AKAMAI-AS, US',
                        'as_number': '16625',
                        'city': '',
                        'country': 'United States',
                        'ip': '104.97.219.142',
                        'latitude': '37.751',
                        'longitude': '-97.822',
                        'region': ''},
                    'site': {
                        'domain': 'starbucks.com'},
                    'site_reputation': 'No reputation violations discovered',
                    'valid_chain_of_trust': True,
                    'whois': {
                        'creation': '1993-10-24',
                        'name_server': 'udns1.cscdns.net,udns2.cscdns.uk',
                        'registrant_email': 'inethost@starbucks.com',
                        'registrant_name': 'Internet Hostmaster',
                        'registrant_organization': 'Starbucks Coffee Company'}}}]},
    'owasp': [{
        'description': 'M1: Improper Platform Usage',
        'found': False,
        'name': 'm1',
        'risks': []},
        {
            'description': 'M2: Insecure Data Storage',
            'found': True,
            'name': 'm2',
            'risks': {
                'Data Leakage': [
                    {
                        'desc': [
                            'The app implements functionality that logs data to the system console. System log files are accessible to any app and could included PII data. The log files may also be shared with Apple.'],
                        'found_in': None}]}},
        {
            'description': 'M3: Insecure Communications',
            'found': True,
            'name': 'm3',
            'risks': {
                'Network Security': [
                    {
                        'desc': [
                            'The app can use non-encrypted HTTP connections.'],
                        'found_in': None},
                    {
                        'desc': [
                            "The authentication method 'NSURLAuthenticationMethodServerTrust' is being implemented. This authentication method can be used to override SSL and TLS chain validation."],
                        'found_in': None}]}},
        {
            'description': 'M4: Insecure Authentication',
            'found': False,
            'name': 'm4',
            'risks': []},
        {
            'description': 'M5: Insufficient Cryptography',
            'found': True,
            'name': 'm5',
            'risks': {
                'Network Security': [
                    {
                        'desc': [
                            'Contains URLs that do not have a valid SSL certificate and/or fails the chain of trust validation.'],
                        'found_in': None}]}},
        {
            'description': 'M6: Insecure Authorization',
            'found': False,
            'name': 'm6',
            'risks': []},
        {
            'description': 'M7: Client Code Quality',
            'found': False,
            'name': 'm7',
            'risks': []},
        {
            'description': 'M8: Code Tampering',
            'found': True,
            'name': 'm8',
            'risks': {
                'System': [
                    {
                        'desc': [
                            "The app implements Swizzling API calls. This may impact the app's ability to trust security decisions that are based on untrusted inputs or manipulated/swizzled output."],
                        'found_in': None}]}},
        {
            'description': 'M9: Reverse Engineering',
            'found': True,
            'name': 'm9',
            'risks': {
                'Binary Protections Testing': [
                    {
                        'desc': [
                            'Source Code Reverse Engineering Exposure'],
                        'found_in': None},
                    {
                        'desc': [
                            'Function Names Exposure'],
                        'found_in': None},
                    {
                        'desc': [
                            'Data Symbols Exposure'],
                        'found_in': None}]}},
        {
            'description': 'M10: Extraneous Functionality',
            'found': False,
            'name': 'm10',
            'risks': []}],
    'rules_version': '7a6caf93636c59b592c7330bf068ade0',
    'scan_timestamp': 1591685904,
    'status': 'N/A'},
    'distribution': {'file_share': [{
        'app_name': 'Starbucks Pocket Coffee Master  ipa free .ipa',
        'file_size': '296.49 KB',
        'site_name': 'Getwapi',
        'url': 'http://getwapi.com/software/download/mobile/cIDjiYvvce/Starbucks_Pocket_Coffee_Master.html'},
        {
            'app_name': 'Find Nearest Starbucks  ipa for free.ipa',
            'file_size': '282.91 KB',
            'site_name': 'Getwapi',
            'url': 'http://getwapi.com/software/download/mobile/2RRLSKl4ba/download_Find_Nearest_Starbuck.html'},
        {
            'app_name': 'Starbucks Coffee Master for iPad  ipa for free.ipa',
            'file_size': '296.42 KB',
            'site_name': 'Getwapi',
            'url': 'http://getwapi.com/software/download/mobile/Sh89V2_Eba/download_Starbucks_Coffee_Mast.html'},
        {
            'app_name': 'free Starbucks Pocket Coffee Master  torrent ipa .ipa',
            'file_size': '296.49 KB',
            'site_name': 'Getwapi',
            'url': 'http://getwapi.com/software/download/mobile/Qmtu5ARGba/free_Starbucks_Pocket_Coffee_M.html'}],
        'market_data': {
            'advisories': [],
            'appletvScreenshotUrls': [],
            'artistId': 331177718,
            'artistName': 'Starbucks Coffee Company',
            'artistViewUrl': 'https://apps.apple.com/us/developer/starbucks-coffee-company/id331177718?uo=4',
            'artworkUrl100': 'https://is3-ssl.mzstatic.com/image/thumb/Purple113/v4/a3/5f/61/a35f6148-c8c0-c0a9-d513-3a92dd08485e/source/100x100bb.jpg',
            'artworkUrl512': 'https://is3-ssl.mzstatic.com/image/thumb/Purple113/v4/a3/5f/61/a35f6148-c8c0-c0a9-d513-3a92dd08485e/source/512x512bb.jpg',
            'artworkUrl60': 'https://is3-ssl.mzstatic.com/image/thumb/Purple113/v4/a3/5f/61/a35f6148-c8c0-c0a9-d513-3a92dd08485e/source/60x60bb.jpg',
            'averageUserRating': 4.83274,
            'averageUserRatingForCurrentVersion': 4.83274,
            'bundleId': 'com.starbucks.mystarbucks',
            'contentAdvisoryRating': '4+',
            'currency': 'USD',
            'currentVersionReleaseDate': '2020-06-08T17:00:37Z',
            'description': 'The Starbucks® app is a convenient way to pay in store or order ahead for pickup. Rewards are built right in, so you’ll collect Stars and start earning free drinks and food with every purchase.\n\nPay in store\nSave time and earn Rewards when you pay with the Starbucks® app at many stores in the U.S.\n\nMobile Order & Pay\nCustomize and place your order, and pick up from a nearby store without waiting in line.\n\nRewards\nTrack your Stars and redeem Rewards for a free food or drink of your choosing. Receive custom offers as a Starbucks Rewards™ member.\n\nSend a gift\nSay thanks with a digital Starbucks Card. It’s easy to redeem a gift from email or in the Starbucks® app.\n\nManage cards\nCheck your Starbucks Card balance, add money, view past purchases and transfer balances between cards.\n\nFind a store\nSee stores near you, get directions, hours and view store amenities before you make the trip.\n\nMusic \nDiscover what songs are playing at your local store.\n\nTip your barista \nLeave a tip on purchases made with the app at many stores in the U.S.',
            'features': [],
            'fileSizeBytes': '193733632',
            'formattedPrice': 'Free',
            'genreIds': [
                '6023',
                '6012'],
            'genres': [
                'Food & Drink',
                'Lifestyle'],
            'ipadScreenshotUrls': [],
            'isGameCenterEnabled': False,
            'isVppDeviceBasedLicensingEnabled': True,
            'kind': 'software',
            'languageCodesISO2A': [
                'EN',
                'FR'],
            'minimumOsVersion': '11.0',
            'price': 0,
            'primaryGenreId': 6023,
            'primaryGenreName': 'Food & Drink',
            'releaseDate': '2009-09-23T05:33:59Z',
            'releaseNotes': 'We made some changes to make things run smoothly.',
            'screenshotUrls': [
                'https://is1-ssl.mzstatic.com/image/thumb/Purple123/v4/df/ae/97/dfae9744-4a5c-47ec-622a-5388de19083b/pr_source.png/392x696bb.png',
                'https://is3-ssl.mzstatic.com/image/thumb/Purple113/v4/3f/5b/54/3f5b5405-c056-04e9-4d24-d6c1909d796a/pr_source.png/392x696bb.png',
                'https://is3-ssl.mzstatic.com/image/thumb/Purple123/v4/35/ad/09/35ad0966-60a5-5d30-7ae2-8039653c259f/pr_source.png/392x696bb.png',
                'https://is2-ssl.mzstatic.com/image/thumb/Purple123/v4/95/d9/72/95d97296-d67f-a87e-a721-07b84f1ecb29/pr_source.png/392x696bb.png',
                'https://is3-ssl.mzstatic.com/image/thumb/Purple123/v4/b9/82/30/b9823049-c520-3696-7816-e7c990d1739c/pr_source.png/392x696bb.png',
                'https://is5-ssl.mzstatic.com/image/thumb/Purple123/v4/26/23/16/26231698-a156-7b24-d835-4f3e35b430fc/pr_source.png/392x696bb.png',
                'https://is4-ssl.mzstatic.com/image/thumb/Purple113/v4/88/fb/d1/88fbd13c-a3ff-265f-d6af-f30b52d4d840/pr_source.png/392x696bb.png'],
            'sellerName': 'Starbucks Coffee Company',
            'sellerUrl': 'http://www.starbucks.com/coffeehouse/mobile-apps/mystarbucks',
            'supportedDevices': [
                'iPadAir-iPadAir',
                'iPhoneX-iPhoneX',
                'iPadSeventhGen-iPadSeventhGen',
                'iPad76-iPad76',
                'iPad611-iPad611',
                'iPadMini5Cellular-iPadMini5Cellular',
                'iPhone11Pro-iPhone11Pro',
                'iPodTouchSixthGen-iPodTouchSixthGen',
                'iPad856-iPad856',
                'iPadMiniRetina-iPadMiniRetina',
                'iPadProFourthGenCellular-iPadProFourthGenCellular',
                'iPhone6s-iPhone6s',
                'iPad74-iPad74',
                'iPad612-iPad612',
                'iPadProCellular-iPadProCellular',
                'iPadProSecondGenCellular-iPadProSecondGenCellular',
                'iPadAir3-iPadAir3',
                'iPadAir2-iPadAir2',
                'Watch4-Watch4',
                'iPadMiniRetinaCellular-iPadMiniRetinaCellular',
                'iPadProSecondGen-iPadProSecondGen',
                'iPhone7-iPhone7',
                'iPad73-iPad73',
                'iPad878-iPad878',
                'iPadMini4Cellular-iPadMini4Cellular',
                'iPadMini4-iPadMini4',
                'iPhone11-iPhone11',
                'iPad834-iPad834',
                'iPodTouchSeventhGen-iPodTouchSeventhGen',
                'iPhone6-iPhone6',
                'iPhoneSESecondGen-iPhoneSESecondGen',
                'iPadPro-iPadPro',
                'iPadAir2Cellular-iPadAir2Cellular',
                'iPhone5s-iPhone5s',
                'iPad72-iPad72',
                'iPhoneXR-iPhoneXR',
                'iPad75-iPad75',
                'iPad812-iPad812',
                'iPhone7Plus-iPhone7Plus',
                'iPadPro97-iPadPro97',
                'iPadProFourthGen-iPadProFourthGen',
                'iPhone6Plus-iPhone6Plus',
                'iPadMini5-iPadMini5',
                'iPadMini3Cellular-iPadMini3Cellular',
                'iPadAir3Cellular-iPadAir3Cellular',
                'iPad71-iPad71',
                'iPadSeventhGenCellular-iPadSeventhGenCellular',
                'iPhoneXSMax-iPhoneXSMax',
                'iPhone8Plus-iPhone8Plus',
                'iPhoneXS-iPhoneXS',
                'iPhone8-iPhone8',
                'iPadAirCellular-iPadAirCellular',
                'iPadPro97Cellular-iPadPro97Cellular',
                'iPhoneSE-iPhoneSE',
                'iPhone6sPlus-iPhone6sPlus',
                'iPadMini3-iPadMini3',
                'iPhone11ProMax-iPhone11ProMax'],
            'trackCensoredName': 'Starbucks',
            'trackContentRating': '4+',
            'trackId': 331177714,
            'trackName': 'Starbucks',
            'trackViewUrl': 'https://apps.apple.com/us/app/starbucks/id331177714?uo=4',
            'userRatingCount': 3279169,
            'userRatingCountForCurrentVersion': 3279169,
            'version': '5.19',
            'wrapperType': 'software'},
        'torrents': [
            'Information not available.']},
    'properties': {
        'app_short_version': '5.19',
        'app_version': '5.19',
        'bundle_id': 'com.starbucks.mystarbucks',
        'dd_version': None,
        'info_property_list': {
            'BuildMachineOSBuild': '19E287',
            'CFBundleDevelopmentRegion': 'en',
            'CFBundleDisplayName': 'Starbucks',
            'CFBundleExecutable': 'Starbucks',
            'CFBundleIcons': {
                'CFBundlePrimaryIcon': {
                    'CFBundleIconFiles': [
                        'AppIcon60x60'],
                    'CFBundleIconName': 'AppIcon'}},
            'CFBundleIcons~ipad': {
                'CFBundlePrimaryIcon': {
                    'CFBundleIconFiles': [
                        'AppIcon60x60',
                        'AppIcon76x76'],
                    'CFBundleIconName': 'AppIcon'}},
            'CFBundleIdentifier': 'com.starbucks.mystarbucks',
            'CFBundleInfoDictionaryVersion': '6.0',
            'CFBundleName': 'Starbucks',
            'CFBundlePackageType': 'APPL',
            'CFBundleShortVersionString': '5.19',
            'CFBundleSignature': '????',
            'CFBundleSupportedPlatforms': [
                'iPhoneOS'],
            'CFBundleURLTypes': [{
                'CFBundleTypeRole': 'Editor',
                'CFBundleURLName': 'com.starbucks.appId',
                'CFBundleURLSchemes': [
                    'sbux331177714']},
                {
                    'CFBundleTypeRole': 'Editor',
                    'CFBundleURLName': 'com.starbucks.deep-linking',
                    'CFBundleURLSchemes': [
                        'starbucks']},
                {
                    'CFBundleTypeRole': 'Editor',
                    'CFBundleURLSchemes': [
                        'prefs']}],
            'CFBundleVersion': '11331',
            'DTAppStoreToolsBuild': '11E608a',
            'DTCompiler': 'com.apple.compilers.llvm.clang.1_0',
            'DTPlatformBuild': '17E8258',
            'DTPlatformName': 'iphoneos',
            'DTPlatformVersion': '13.4',
            'DTSDKBuild': '17E8258',
            'DTSDKName': 'iphoneos13.4',
            'DTXcode': '1141',
            'DTXcodeBuild': '11E503a',
            'IOVSubKey': 'LK4xkQ2wt8IO-g3cfkuITqPdbkyEHSIWTU1FAg7rK9A',
            'ITSAppUsesNonExemptEncryption': False,
            'LSApplicationQueriesSchemes': [
                'spotify',
                'spotify-action',
                'starbucks'],
            'LSRequiresIPhoneOS': True,
            'MinimumOSVersion': '11.0',
            'NSAppTransportSecurity': {
                'NSAllowsArbitraryLoads': False,
                'NSAllowsLocalNetworking': False,
                'NSExceptionDomains': {
                    'akamaihd*net': {
                        'NSIncludesSubdomains': True,
                        'NSThirdPartyExceptionAllowsInsecureHTTPLoads': True,
                        'NSThirdPartyExceptionRequiresForwardSecrecy': False},
                    'assets*starbucks*com': {
                        'NSExceptionAllowsInsecureHTTPLoads': True},
                    'bcassets*starbucks*com': {
                        'NSExceptionAllowsInsecureHTTPLoads': True},
                    'cloudfront*net': {
                        'NSIncludesSubdomains': True,
                        'NSThirdPartyExceptionAllowsInsecureHTTPLoads': True,
                        'NSThirdPartyExceptionRequiresForwardSecrecy': False},
                    'facebook*com': {
                        'NSIncludesSubdomains': True,
                        'NSThirdPartyExceptionRequiresForwardSecrecy': False},
                    'fbcdn*net': {
                        'NSIncludesSubdomains': True,
                        'NSThirdPartyExceptionRequiresForwardSecrecy': False},
                    'mzstatic*com': {
                        'NSIncludesSubdomains': True,
                        'NSThirdPartyExceptionAllowsInsecureHTTPLoads': True,
                        'NSThirdPartyExceptionRequiresForwardSecrecy': False},
                    'scdn*co': {
                        'NSIncludesSubdomains': True,
                        'NSThirdPartyExceptionAllowsInsecureHTTPLoads': True,
                        'NSThirdPartyExceptionRequiresForwardSecrecy': False},
                    'starbucks*ca': {
                        'NSExceptionAllowsInsecureHTTPLoads': True,
                        'NSExceptionRequiresForwardSecrecy': False,
                        'NSIncludesSubdomains': True},
                    'starbucks*co*uk': {
                        'NSExceptionAllowsInsecureHTTPLoads': True,
                        'NSExceptionRequiresForwardSecrecy': False,
                        'NSIncludesSubdomains': True},
                    'starbucks*com': {
                        'NSExceptionAllowsInsecureHTTPLoads': True,
                        'NSExceptionRequiresForwardSecrecy': False,
                        'NSIncludesSubdomains': True}}},
            'NSCameraUsageDescription': 'Starbucks can scan some Starbucks Cards to add them to your account',
            'NSContactsUsageDescription': 'Used to auto-populate recipient information',
            'NSFaceIDUsageDescription': 'Used to authenticate for reloads and logging in.',
            'NSLocationWhenInUseUsageDescription': 'To easily order ahead, get directions and see what’s available at nearby stores.',
            'NSUserActivityTypes': [
                'SBAOrderItemIntent',
                'com.starbucks.myStarbucks.watchappLaunch'],
            'SBUXBuildSHA': '0000000',
            'UIAppFonts': ['Avenir.ttc',
                           'AvenirNext.ttc',
                           'SoDoSans-Regular.otf',
                           'HelveticaNeue.ttc'],
            'UIBackgroundModes': [
                'remote-notification'],
            'UIDeviceFamily': [1],
            'UILaunchImages': [{
                'UILaunchImageMinimumOSVersion': '7.0',
                'UILaunchImageName': 'LaunchImage-700',
                'UILaunchImageOrientation': 'Portrait',
                'UILaunchImageSize': '{320, 480}'},
                {
                    'UILaunchImageMinimumOSVersion': '7.0',
                    'UILaunchImageName': 'LaunchImage-700-568h',
                    'UILaunchImageOrientation': 'Portrait',
                    'UILaunchImageSize': '{320, 568}'}],
            'UILaunchStoryboardName': 'LaunchScreen',
            'UIPrerenderedIcon': True,
            'UIRequiredDeviceCapabilities': [
                'arm64'],
            'UIStatusBarHidden': False,
            'UIStatusBarStyle': 'UIStatusBarStyleLightContent',
            'UISupportedInterfaceOrientations': [
                'UIInterfaceOrientationPortrait'],
            'UIUserInterfaceStyle': 'Light',
            'UIViewControllerBasedStatusBarAppearance': True,
            'branch_app_domain': 'starbucks.app.link'},
        'itunes_app_id': '331177714',
        'name': 'Starbucks'},
    'risk_profile': {
        'overall_risk': 'Out',
        'privacy_risk': 64,
        'security_risk': 63}
}
