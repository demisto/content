''' TESTS ARGUMENTS '''

# test_users_to_entry #

response_test_users_to_entry = [
    {'kind': 'admin#directory#user',
        'id': '000000000000000000000',
        'etag': '“XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX”',
        'primaryEmail': 'johndoe@test.com',
        'name': {'givenName': 'john',
                 'familyName': 'doe',
                 'fullName': 'john doe'},
        'isAdmin': True,
        'isDelegatedAdmin': False,
        'lastLoginTime': '2021-09-21T08:52:17.000Z',
        'creationTime': '2019-12-30T14:32:18.000Z',
        'agreedToTerms': True,
        'suspended': False,
        'archived': False,
        'changePasswordAtNextLogin': False,
        'ipWhitelisted': False,
        'emails': [
                {'address': 'johndoe@test.com', 'primary': True}],
        'languages': [{'languageCode': 'en', 'preference': 'preferred'}],
        'nonEditableAliases': ['johndoe@test.com'],
        'customerId': 'Cxxxxxxxx',
        'orgUnitPath': '/',
        'isMailboxSetup': True,
        'isEnrolledIn2Sv': False,
        'isEnforcedIn2Sv': False,
        'includeInGlobalAddressList': True,
        'recoveryEmail': 'johndoe@test.com',
        'recoveryPhone': '+972500000000'}]
expected_outputs = [{'Type': 'Google',
                     'ID': '000000000000000000000',
                     'UserName': 'john',
                     'Username': 'john',  # adding to fit the new context standard
                     'DisplayName': 'john doe',
                     'Email': {'Address': 'johndoe@test.com'},
                     'Gmail': {'Address': 'johndoe@test.com'},
                     'Group': 'admin#directory#user',
                     'Groups': 'admin#directory#user',  # adding to fit the new context standard
                     'CustomerId': 'Cxxxxxxxx',
                     'Domain': 'test.com',
                     'VisibleInDirectory': True}]
expected_human_readable = "### User 000000000000000000000:\n\
|Type|ID|Username|DisplayName|Groups|CustomerId|Domain|Email|VisibleInDirectory|\n\
|---|---|---|---|---|---|---|---|---|\n\
| Google | 000000000000000000000 | john | john doe |\
 admin#directory#user |\
 Cxxxxxxxx | test.com |\
 Address: johndoe@test.com | true |\n"
expected_result_test_users_to_entry = {"expected_human_readable": expected_human_readable,
                                       "expected_outputs": expected_outputs,
                                       "expected_raw_response": response_test_users_to_entry}


# test_autoreply_to_entry #

get_auto_replay_result = {'enableAutoReply': True,
                          'responseSubject': 'subject_test',
                          'responseBodyPlainText': 'body_test',
                          'restrictToContacts': False,
                          'restrictToDomain': False}
expected_raw_response_test_autoreply_to_entry = [{'EnableAutoReply': True,
                                                  'ResponseBody': 'body_test',
                                                  'ResponseSubject': 'subject_test',
                                                  'RestrictToContact': False,
                                                  'RestrictToDomain': False,
                                                  'StartTime': None,
                                                  'EndTime': None,
                                                  'ResponseBodyHtml': None}]
expected_human_readable_test_autoreply_to_entry = '### User johndoe@test.com:\n|EnableAutoReply|ResponseBody|ResponseSubject\
|RestrictToContact|RestrictToDomain|EnableAutoReply|\n|---|---|---|---|---|---|\n| true | body_test |\
 subject_test | false | false | true |\n'
expected_outputs_test_autoreply_to_entry = {"Address": "johndoe@test.com",
                                            "AutoReply": [{'EnableAutoReply': True,
                                                           'ResponseBody': 'body_test',
                                                           'ResponseSubject': 'subject_test',
                                                           'RestrictToContact': False,
                                                           'RestrictToDomain': False,
                                                           'StartTime': None, 'EndTime': None,
                                                           'ResponseBodyHtml': None}]}

expected_result_test_autoreply_to_entry = {"expected_human_readable": expected_human_readable_test_autoreply_to_entry,
                                           "expected_outputs": expected_outputs_test_autoreply_to_entry,
                                           "expected_raw_response": expected_raw_response_test_autoreply_to_entry}


# test_user_role_to_entry #
role_test_role_to_entry = {'kind': 'admin#directory#role',
                           'etag': '"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"',
                           'roleId': '00000000000000000',
                           'roleName': 'ADMIN',
                           'roleDescription': 'Administrator',
                           'rolePrivileges': [{'privilegeName': 'ADMIN', 'serviceId': '00upglbi0qz687j'},
                                              {'privilegeName': 'ADMIN', 'serviceId': '03j2qqm31d4j55e'}],
                           'isSystemRole': True, 'isSuperAdminRole': True}


expected_outputstest_role_to_entry = {'ETag': 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
                                      'IsSuperAdminRole': True,
                                      'IsSystemRole': True,
                                      'Kind': 'admin#directory#role',
                                      'Description': 'Administrator',
                                      'ID': '00000000000000000',
                                      'Name': 'ADMIN',
                                      'Privilege': [{'ServiceID': '00upglbi0qz687j', 'Name': 'ADMIN'},
                                                    {'ServiceID': '03j2qqm31d4j55e', 'Name': 'ADMIN'}]}
expected_privileges_hr = '### Role 00000000000000000 privileges:\n|ServiceID|Name|\n|---|---|\n| 00upglbi0qz687j | ADMIN |\n| \
03j2qqm31d4j55e | ADMIN |\n'
expected_details_hr = '### Role 00000000000000000 details:\n|ETag|IsSuperAdminRole|IsSystemRole|Kind|Description|ID|Name|\n|---|\
---|---|---|---|---|---|\n| XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX | true | true |\
 admin#directory#role | Administrator | 00000000000000000 | ADMIN |\n'
expected_human_readable_test_role_to_entry = expected_details_hr + expected_privileges_hr
expected_result_test_role_to_entry = {"expected_human_readable": expected_human_readable_test_role_to_entry,
                                      "expected_outputs": expected_outputstest_role_to_entry,
                                      "expected_raw_response": expected_outputstest_role_to_entry}


# test_user_roles_to_entry #

get_user_role_mock_result = [{'kind': 'admin#directory#roleAssignment',
                              'etag': '"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"',
                              'roleAssignmentId': '00000000000000000',
                              'roleId': '11111111111111111',
                              'assignedTo': '222222222222222222222',
                              'scopeType': 'CUSTOMER'}]
expected_human_readable_test_user_roles_to_entry = '### User Roles of 222222222222222222222:\n|ID|RoleAssignmentId|ScopeType|Kind|\n\
|---|---|---|---|\n| 11111111111111111 | 00000000000000000 | CUSTOMER | admin#directory#roleAssignment |\n'
expected_raw_response_user_roles_to_entry = [{'ID': '11111111111111111',
                                              'AssignedTo': '222222222222222222222',
                                              'RoleAssignmentId': '00000000000000000',
                                              'ScopeType': 'CUSTOMER',
                                              'Kind': 'admin#directory#roleAssignment',
                                              'OrgUnitId': '',
                                              }]
expected_outputs_test_user_roles_to_entry = expected_raw_response_user_roles_to_entry
expected_result_user_roles_to_entry = {"expected_human_readable": expected_human_readable_test_user_roles_to_entry,
                                       "expected_outputs": expected_outputs_test_user_roles_to_entry,
                                       "expected_raw_response": expected_raw_response_user_roles_to_entry}


# test_tokens_to_entry #

get_user_tokens_mock_result = [{'kind': 'admin#directory#token',
                                'etag': '"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"',
                                'clientId': '000000000000.apps.googleusercontent.com',
                                'displayText': 'iOS Account Manager',
                                'anonymous': False,
                                'nativeApp': False,
                                'userKey': '999999999999999999999',
                                'scopes': ['openid']}]

expected_human_readable_test_tokens_to_entry = '### Tokens:\n|DisplayText|ClientId|Kind|Scopes|UserKey|\n\
|---|---|---|---|---|\n\
| iOS Account Manager | 000000000000.apps.googleusercontent.com | admin#directory#token |\
 openid | 999999999999999999999 |\n'

expected_raw_response_test_tokens_to_entry = [{'DisplayText': 'iOS Account Manager',
                                               'ClientId': '000000000000.apps.googleusercontent.com',
                                               'Kind': 'admin#directory#token',
                                               'Scopes': ['openid'],
                                               'UserKey': '999999999999999999999'}]
expected_outputs_test_tokens_to_entry = expected_raw_response_test_tokens_to_entry
expected_result_test_tokens_to_entry = {"expected_human_readable": expected_human_readable_test_tokens_to_entry,
                                        "expected_outputs": expected_outputs_test_tokens_to_entry,
                                        "expected_raw_response": expected_raw_response_test_tokens_to_entry}


# test_sent_mail_to_entry #

send_mail_mock_result = {'id': '11111', 'threadId': '11111', 'labelIds': ['SENT']}

expected_human_readable_test_sent_mail_to_entry = '### Email sent:\n|Type|ID|To|From|Subject|Labels|ThreadId|\n\
|---|---|---|---|---|---|---|\n|\
 Gmail | 11111 | helloworld@gmail.com | test@gmail.com | ls | SENT | 11111 |\n'

expected_raw_response_test_sent_mail_to_entry = [{'id': '11111', 'threadId': '11111', 'labelIds': ['SENT']}]
expected_outputs_test_sent_mail_to_entry = [{'Type': 'Gmail',
                                             'ID': '11111',
                                             'Labels': ['SENT'],
                                             'ThreadId': '11111',
                                             'To': 'helloworld@gmail.com',
                                             'From': 'test@gmail.com',
                                             'Cc': None,
                                             'Bcc': None,
                                             'Subject': 'ls',
                                             'Body': None,
                                             'Mailbox': 'helloworld@gmail.com'}]
expected_result_test_sent_mail_to_entry = {"expected_human_readable": expected_human_readable_test_sent_mail_to_entry,
                                           "expected_outputs": expected_outputs_test_sent_mail_to_entry,
                                           "expected_raw_response": expected_raw_response_test_sent_mail_to_entry}


# test_filters_to_entry #
list_filters_mock_result = [{'id': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'criteria': {'from': 'test1@gmail.com'},
                             'action': {'addLabelIds': ['TRASH']}},
                            {'id': 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', 'criteria': {'from': 'test2@gmail.com'},
                             'action': {'addLabelIds': ['TRASH']}}]
except_contents = [{'ID': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'Mailbox': '1111111',
                    'Criteria': {'from': 'test1@gmail.com'}, 'Action': {'addLabelIds': ['TRASH']}},
                   {'ID': 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', 'Mailbox': '1111111',
                   'Criteria': {'from': 'test2@gmail.com'}, 'Action': {'addLabelIds': ['TRASH']}}]
expected_human_readable_test_filters_to_entry = '### filters:\n|ID|Criteria|Action|\n\
|---|---|---|\n| AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA | from: test1@gmail.com | addLabelIds: TRASH |\n|\
 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB | from: test2@gmail.com | addLabelIds: TRASH |\n'

expected_result_test_filters_to_entry = {"expected_human_readable": expected_human_readable_test_filters_to_entry,
                                         "except_contents": except_contents}


# test_mailboxes_to_entry #

list_mailboxes = [{'Mailbox': 'test1@gmail.com', 'q': ''},
                  {'Mailbox': 'test2@gmail.com', 'q': ''},
                  {'Mailbox': 'test3@gmail.com', 'q': ''},
                  {'Mailbox': 'test4@gmail.com', 'q': ''},
                  {'Mailbox': 'test5@gmail.com', 'q': ''}]
except_contents_test_mailboxes_to_entry = list_mailboxes
expected_human_readable_test_mailboxes_to_entry = '### Query: \n|Mailbox|\n|---|\n| test1@gmail.com |\n| test2@gmail.com |\n|\
 test3@gmail.com |\n| test4@gmail.com |\n| test5@gmail.com |\n'

expected_result_test_mailboxes_to_entry = {"expected_human_readable": expected_human_readable_test_mailboxes_to_entry,
                                           "except_contents": except_contents_test_mailboxes_to_entry}


# test_emails_to_entry #

expected_human_readable_test_emails_to_entry = '### Search in 11111:\nquery: "subject:helloworld"\n\
|Mailbox|ID|Labels|\n|---|---|---|\n| 11111 | 183c702bfdbb3fc2 | UNREAD, IMPORTANT, CATEGORY_PERSONAL, INBOX |\n'
mails = [{'id': '183c702bfdbb3fc2',
          'threadId': '183c702bfdbb3fc2',
          'labelIds': ['UNREAD', 'IMPORTANT', 'CATEGORY_PERSONAL', 'INBOX'],
          'snippet': 'helloworld',
          'payload': {'partId': '',
                      'mimeType': 'multipart/alternative',
                      'filename': '',
                      'headers': [{'name': 'Delivered-To', 'value': 'test@gmail.com'}],
                      'body': {'size': 0},
                      'parts': [{'partId': '0',
                                 'mimeType':
                                 'text/plain',
                                 'filename': '',
                                 'headers': [{'name': 'Content-Type', 'value': 'text/plain; charset="UTF-8"'}],
                                 'body': {'size': 12, 'data': 'aGVsbG93b3JsZA0K'}}]},
          'sizeEstimate': 7514,
          'historyId': '72166',
          'internalDate': '1665491175000'}]

except_contents_test_emails_to_entry = [{'id': '183c702bfdbb3fc2',
                                         'threadId': '183c702bfdbb3fc2',
                                         'labelIds': ['UNREAD', 'IMPORTANT', 'CATEGORY_PERSONAL', 'INBOX'],
                                         'snippet': 'helloworld',
                                         'payload': {'partId': '',
                                                     'mimeType': 'multipart/alternative',
                                                     'filename': '',
                                                     'headers': [{'name': 'Delivered-To',
                                                                  'value': 'test@gmail.com'}],
                                                     'body': {'size': 0},
                                                     'parts': [{'partId': '0',
                                                                'mimeType':
                                                                'text/plain',
                                                                'filename': '',
                                                                'headers': [{'name': 'Content-Type',
                                                                             'value': 'text/plain; charset="UTF-8"'}],
                                                                'body': {'size': 12, 'data': 'aGVsbG93b3JsZA0K'}}]},
                                         'sizeEstimate': 7514,
                                         'historyId': '72166',
                                         'internalDate': '1665491175000'}]
expected_result_test_emails_to_entry = {"expected_human_readable": expected_human_readable_test_emails_to_entry,
                                        "except_contents": except_contents_test_emails_to_entry}
