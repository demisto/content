import json

RAW_RESPONSE_ADD_USER = {"authenticationMethod": ["AuthTypePass"],
                             "businessAddress": {"workCity": "", "workCountry": "", "workState": "", "workStreet": "",
                                                 "workZip": ""}, "changePassOnNextLogon": True, "componentUser": False,
                             "description": "new user for test", "distinguishedName": "", "enableUser": True,
                             "expiryDate": -62135578800, "groupsMembership": [], "id": 123,
                             "internet": {"businessEmail": "usertest@test.com", "homeEmail": "", "homePage": "",
                                          "otherEmail": ""}, "lastSuccessfulLoginDate": 1594756313, "location": "\\",
                             "passwordNeverExpires": False,
                             "personalDetails": {"city": "", "country": "", "department": "", "firstName": "user",
                                                 "lastName": "test", "middleName": "", "organization": "",
                                                 "profession": "testing integrations", "state": "", "street": "",
                                                 "title": "", "zip": ""},
                             "phones": {"businessNumber": "", "cellularNumber": "", "faxNumber": "", "homeNumber": "",
                                        "pagerNumber": ""}, "source": "CyberArk", "suspended": False,
                             "unAuthorizedInterfaces": [], "userType": "EPVUser", "username": "TestUser",
                             "vaultAuthorization": []}
RAW_RESPONSE_UPDATE_USER = {"authenticationMethod": ["AuthTypePass"],
                            "businessAddress": {"workCity": "", "workCountry": "", "workState": "", "workStreet": "",
                                                "workZip": ""},
                            "changePassOnNextLogon": True, "componentUser": False, "description": "updated description",
                            "distinguishedName": "", "enableUser": True, "expiryDate": -62135578800,
                            "groupsMembership": [], "id": 123,
                            "internet": {"businessEmail": "update@test.com", "homeEmail": "", "homePage": "",
                                         "otherEmail": ""},
                            "lastSuccessfulLoginDate": 1594756313, "location": "\\", "passwordNeverExpires": False,
                            "personalDetails": {"city": "", "country": "", "department": "", "firstName": "test1",
                                                "lastName": "updated-name",
                                                "middleName": "", "organization": "", "profession": "test1",
                                                "state": "", "street": "",
                                                "title": "", "zip": ""},
                            "phones": {"businessNumber": "", "cellularNumber": "", "faxNumber": "", "homeNumber": "",
                                       "pagerNumber": ""},
                            "source": "CyberArk", "suspended": False, "unAuthorizedInterfaces": [],
                            "userType": "EPVUser",
                            "username": "TestUser1", "vaultAuthorization": []}

RAW_RESPONSE_GET_USERS = [{"componentUser": False, "id": 2, "location": "\\",
                           "personalDetails": {"firstName": "", "lastName": "", "middleName": ""}, "source": "CyberArk",
                           "userType": "Built-InAdmins", "username": "Administrator",
                           "vaultAuthorization": ["AddUpdateUsers", "AddSafes", "AddNetworkAreas",
                                                  "ManageDirectoryMapping",
                                                  "ManageServerFileCategories", "AuditUsers", "BackupAllSafes",
                                                  "RestoreAllSafes",
                                                  "ResetUsersPasswords", "ActivateUsers"]},
                          {"componentUser": True, "id": 76, "location": "\\",
                           "personalDetails": {"firstName": "", "lastName": "", "middleName": ""}, "source": "CyberArk",
                           "userType": "AppProvider", "username": "Sync_COMP01", "vaultAuthorization": ["AuditUsers"]},
                          {"componentUser": True, "id": 83, "location": "\\Applications",
                           "personalDetails": {"firstName": "", "lastName": "", "middleName": ""}, "source": "CyberArk",
                           "userType": "AppProvider", "username": "Prov_nexpose",
                           "vaultAuthorization": ["AddSafes", "AuditUsers"]}]




def test1():


    print(json.dumps(RAW_RESPONSE_ADD_USER, indent=4, sort_keys=True))
