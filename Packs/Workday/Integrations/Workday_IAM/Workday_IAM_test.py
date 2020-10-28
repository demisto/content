import demistomock as demisto  # noqa: F401
import pytest


from Workday_IAM import Client, fetch_incidents, get_all_user_profiles

total_client_response = {'Report_Entry': [{'Employee_Type': 'Regular', 'Leadership': 'Yes-HQ', 'Work_Country_Code': '840',
                                         'Street_Address': '3000 Tannery Way', 'Employment_Status': 'Active',
                                         'VP_Flag': 'N', 'Mgr_ID': '115069', 'Cost_Center_Description': 'Channel Sales',
                                         'GDPR_Country_Flag': '0', 'Director_Flag': 'Y',
                                         'Email_-_Primary_Home': 'ronnyrahardjo@gmail.com', 'First_Name': 'Ronny',
                                         'Last_Hire_Date': '10/05/2020', 'People_Manager_Flag': 'N',
                                         'Department': 'Sales NAM:NAM Channel Sales',
                                         'Workday_ID': '5aa443c785ff10461ac83e5a6be32e1e', 'Postal_Code': '95054',
                                         'Rehired_Employee': 'Yes', 'Org_Level_1': 'Sales',
                                         'Org_Level_3': 'NAM Channel Sales', 'Country_Name': 'United States Of America',
                                         'Org_Level_2': 'Sales NAM', 'Emp_ID': '100122',
                                         'Job_Family': 'Product Management',
                                         'User_Name': 'rrahardjo@paloaltonetworks.com',
                                         'Preferred_Name_-_First_Name': 'Ronny', 'Hide_from_GAL': 'False',
                                         'Management_Level_1': 'Nikesh Arora', 'Work_Country_Abbrev': 'US',
                                         'Management_Level_2': 'Timmy Turner',
                                         'Email_Address': 'rrahardjo@paloaltonetworks.com',
                                         'Title': 'Dir, Product Line Manager', 'City': 'Santa Clara',
                                         'Work_State_US_Only': 'California', 'Job_Code': '2245',
                                         'PAN_CF_Okta_Location_Region': 'Americas', 'Last_Name': 'Rahardjo',
                                         'Job_Function': 'Product Management Function', 'State': 'California',
                                         'Exec_Admin_Flag': 'N', 'Preferred_Name': 'Ronny Rahardjo',
                                         'Regular_Employee_Flag': 'Y', 'Preferred_Name_-_Last_Name': 'Rahardjo',
                                         'Cost_Center_Code': '120100', 'Location': 'Office - USA - CA - Headquarters'},
                                    {'Employee_Type': 'Regular', 'Leadership': 'No', 'Work_Country_Code': '840',
                                         'Street_Address': 'WeWork Embarcadero Center', 'Employment_Status': 'Active',
                                         'VP_Flag': 'N', 'Mgr_ID': '115069',
                                         'Cost_Center_Description': 'Magnifier Sales Inc', 'GDPR_Country_Flag': '0',
                                         'Public_Work_Mobile_Phone_Number': '+44  7900-160-819', 'Director_Flag': 'N',
                                         'Email_-_Primary_Home': 'stevearnoldtstc@hotmail.com', 'First_Name': 'Stephen',
                                         'Last_Hire_Date': '10/01/2020', 'People_Manager_Flag': 'N',
                                         'Department': 'WW Sales Functions:Cortex Sales',
                                         'Workday_ID': '5aa443c785ff10461a941c31a173e459', 'Postal_Code': '94111',
                                         'Rehired_Employee': 'Yes', 'Org_Level_1': 'Sales',
                                         'Org_Level_3': 'Cortex Sales', 'Country_Name': 'United States Of America',
                                         'Org_Level_2': 'WW Sales Functions', 'Emp_ID': '101351',
                                         'Job_Family': 'Software Engineering',
                                         'User_Name': 'sarnold@paloaltonetworks.com',
                                         'Preferred_Name_-_First_Name': 'Stephen', 'Hide_from_GAL': 'False',
                                         'Management_Level_1': 'Nikesh Arora', 'Work_Country_Abbrev': 'US',
                                         'Management_Level_2': 'Timmy Turner',
                                         'Email_Address': 'sarnold@paloaltonetworks.com',
                                         'Title': 'Mgr, SW Engineering', 'City': 'San Francisco',
                                         'Work_State_US_Only': 'California', 'Job_Code': '2163',
                                         'PAN_CF_Okta_Location_Region': 'Americas', 'Last_Name': 'Arnold',
                                         'Job_Function': 'Engineering Function', 'State': 'California',
                                         'Exec_Admin_Flag': 'N', 'Preferred_Name': 'Stephen Arnold',
                                         'Regular_Employee_Flag': 'Y', 'Preferred_Name_-_Last_Name': 'Arnold',
                                         'Cost_Center_Code': '101100', 'Location': 'Office - USA - CA - San Francisco'},
                                    {'Employee_Type': 'Regular', 'Leadership': 'No', 'Work_Country_Code': '840',
                                         'Street_Address': '3000 Tannery Way', 'Employment_Status': 'Active',
                                         'VP_Flag': 'N', 'Mgr_ID': '115069',
                                         'Cost_Center_Description': 'IoT - Engineering', 'GDPR_Country_Flag': '0',
                                         'Director_Flag': 'N', 'Email_-_Primary_Home': 'test37@aporeto.com',
                                         'First_Name': 'Tooth', 'Last_Hire_Date': '06/15/2020',
                                         'People_Manager_Flag': 'N', 'Department': 'Enterprise R&D:FWaaP',
                                         'Workday_ID': '9aa7e309929e01ebec7923080803461b', 'Postal_Code': '95054',
                                         'Rehired_Employee': 'No', 'Org_Level_1': 'All R&D', 'Org_Level_3': 'FWaaP',
                                         'Country_Name': 'United States Of America', 'Org_Level_2': 'Enterprise R&D',
                                         'Emp_ID': '115104', 'Job_Family': 'Software Engineering',
                                         'Preferred_Name_-_First_Name': 'Tooth', 'Hide_from_GAL': 'False',
                                         'Management_Level_1': 'Nikesh Arora', 'Work_Country_Abbrev': 'US',
                                         'Management_Level_2': 'Timmy Turner',
                                         'Email_Address': 'tfairy@paloaltonetworks.com', 'Title': 'Staff Engineer SW',
                                         'City': 'Santa Clara', 'Work_State_US_Only': 'California', 'Job_Code': '5162',
                                         'PAN_CF_Okta_Location_Region': 'Americas', 'Last_Name': 'Fairy_Updated',
                                         'Job_Function': 'Engineering Function', 'State': 'California',
                                         'Exec_Admin_Flag': 'N', 'Preferred_Name': 'Tooth Fairy_Updated',
                                         'Regular_Employee_Flag': 'Y', 'Preferred_Name_-_Last_Name': 'Fairy_Updated',
                                         'Cost_Center_Code': '613116', 'Location': 'Office - USA - CA - Headquarters'}
                                    ]}
client_response = {'Report_Entry': [{'Employee_Type': 'Regular', 'Leadership': 'Yes-HQ', 'Work_Country_Code': '840',
                                         'Street_Address': '3000 Tannery Way', 'Employment_Status': 'Active',
                                         'VP_Flag': 'N', 'Mgr_ID': '115069', 'Cost_Center_Description': 'Channel Sales',
                                         'GDPR_Country_Flag': '0', 'Director_Flag': 'Y',
                                         'Email_-_Primary_Home': 'ronnyrahardjo@gmail.com', 'First_Name': 'Ronny',
                                         'Last_Hire_Date': '10/05/2020', 'People_Manager_Flag': 'N',
                                         'Department': 'Sales NAM:NAM Channel Sales',
                                         'Workday_ID': '5aa443c785ff10461ac83e5a6be32e1e', 'Postal_Code': '95054',
                                         'Rehired_Employee': 'Yes', 'Org_Level_1': 'Sales',
                                         'Org_Level_3': 'NAM Channel Sales', 'Country_Name': 'United States Of America',
                                         'Org_Level_2': 'Sales NAM', 'Emp_ID': '100122',
                                         'Job_Family': 'Product Management',
                                         'User_Name': 'rrahardjo@paloaltonetworks.com',
                                         'Preferred_Name_-_First_Name': 'Ronny', 'Hide_from_GAL': 'False',
                                         'Management_Level_1': 'Nikesh Arora', 'Work_Country_Abbrev': 'US',
                                         'Management_Level_2': 'Timmy Turner',
                                         'Email_Address': 'rrahardjo@paloaltonetworks.com',
                                         'Title': 'Dir, Product Line Manager', 'City': 'Santa Clara',
                                         'Work_State_US_Only': 'California', 'Job_Code': '2245',
                                         'PAN_CF_Okta_Location_Region': 'Americas', 'Last_Name': 'Rahardjo',
                                         'Job_Function': 'Product Management Function', 'State': 'California',
                                         'Exec_Admin_Flag': 'N', 'Preferred_Name': 'Ronny Rahardjo',
                                         'Regular_Employee_Flag': 'Y', 'Preferred_Name_-_Last_Name': 'Rahardjo',
                                         'Cost_Center_Code': '120100', 'Location': 'Office - USA - CA - Headquarters'}

                                    ]}
events = [{
    'rawJSON': '{"Employee_Type": "Regular", "Leadership": "Yes-HQ", "Work_Country_Code": "840", "Street_Address": "3000 Tannery Way", "Employment_Status": "Active", "VP_Flag": "N", "Mgr_ID": "115069", "Cost_Center_Description": "Channel Sales", "GDPR_Country_Flag": "0", "Director_Flag": "Y", "Email_-_Primary_Home": "ronnyrahardjo@gmail.com", "First_Name": "Ronny", "Last_Hire_Date": "10/05/2020", "People_Manager_Flag": "N", "Department": "Sales NAM:NAM Channel Sales", "Workday_ID": "5aa443c785ff10461ac83e5a6be32e1e", "Postal_Code": "95054", "Rehired_Employee": "Yes", "Org_Level_1": "Sales", "Org_Level_3": "NAM Channel Sales", "Country_Name": "United States Of America", "Org_Level_2": "Sales NAM", "Emp_ID": "100122", "Job_Family": "Product Management", "User_Name": "rrahardjo@paloaltonetworks.com", "Preferred_Name_-_First_Name": "Ronny", "Hide_from_GAL": "False", "Management_Level_1": "Nikesh Arora", "Work_Country_Abbrev": "US", "Management_Level_2": "Timmy Turner", "Email_Address": "rrahardjo@paloaltonetworks.com", "Title": "Dir, Product Line Manager", "City": "Santa Clara", "Work_State_US_Only": "California", "Job_Code": "2245", "PAN_CF_Okta_Location_Region": "Americas", "Last_Name": "Rahardjo", "Job_Function": "Product Management Function", "State": "California", "Exec_Admin_Flag": "N", "Preferred_Name": "Ronny Rahardjo", "Regular_Employee_Flag": "Y", "Preferred_Name_-_Last_Name": "Rahardjo", "Cost_Center_Code": "120100", "Location": "Office - USA - CA - Headquarters", "UserProfile": {"city": "Santa Clara", "cost_center_code": "120100", "cost_center_description": "Channel Sales", "country_name": "United States Of America", "department": "Sales NAM:NAM Channel Sales", "director_flag": "Y", "email_-_primary_home": "ronnyrahardjo@gmail.com", "email_address": "rrahardjo@paloaltonetworks.com", "emp_id": "100122", "employee_type": "Regular", "employment_status": "Active", "exec_admin_flag": "N", "first_name": "Ronny", "gdpr_country_flag": "0", "hide_from_gal": "False", "job_code": "2245", "job_family": "Product Management", "job_function": "Product Management Function", "last_hire_date": "10/05/2020", "last_name": "Rahardjo", "leadership": "Yes-HQ", "location": "Office - USA - CA - Headquarters", "management_level_1": "Nikesh Arora", "management_level_2": "Timmy Turner", "mgr_id": "115069", "org_level_1": "Sales", "org_level_2": "Sales NAM", "org_level_3": "NAM Channel Sales", "pan_cf_okta_location_region": "Americas", "people_manager_flag": "N", "postal_code": "95054", "preferred_name": "Ronny Rahardjo", "preferred_name_-_first_name": "Ronny", "preferred_name_-_last_name": "Rahardjo", "regular_employee_flag": "Y", "rehired_employee": "Yes", "state": "California", "street_address": "3000 Tannery Way", "title": "Dir, Product Line Manager", "user_name": "rrahardjo@paloaltonetworks.com", "vp_flag": "N", "work_country_abbrev": "US", "work_country_code": "840", "work_state_us_only": "California", "workday_id": "5aa443c785ff10461ac83e5a6be32e1e"}}',
    'details': 'Profile changed. Changed fields: False'}, {
    'rawJSON': '{"Employee_Type": "Regular", "Leadership": "No", "Work_Country_Code": "840", "Street_Address": "WeWork Embarcadero Center", "Employment_Status": "Active", "VP_Flag": "N", "Mgr_ID": "115069", "Cost_Center_Description": "Magnifier Sales Inc", "GDPR_Country_Flag": "0", "Public_Work_Mobile_Phone_Number": "+44  7900-160-819", "Director_Flag": "N", "Email_-_Primary_Home": "stevearnoldtstc@hotmail.com", "First_Name": "Stephen", "Last_Hire_Date": "10/01/2020", "People_Manager_Flag": "N", "Department": "WW Sales Functions:Cortex Sales", "Workday_ID": "5aa443c785ff10461a941c31a173e459", "Postal_Code": "94111", "Rehired_Employee": "Yes", "Org_Level_1": "Sales", "Org_Level_3": "Cortex Sales", "Country_Name": "United States Of America", "Org_Level_2": "WW Sales Functions", "Emp_ID": "101351", "Job_Family": "Software Engineering", "User_Name": "sarnold@paloaltonetworks.com", "Preferred_Name_-_First_Name": "Stephen", "Hide_from_GAL": "False", "Management_Level_1": "Nikesh Arora", "Work_Country_Abbrev": "US", "Management_Level_2": "Timmy Turner", "Email_Address": "sarnold@paloaltonetworks.com", "Title": "Mgr, SW Engineering", "City": "San Francisco", "Work_State_US_Only": "California", "Job_Code": "2163", "PAN_CF_Okta_Location_Region": "Americas", "Last_Name": "Arnold", "Job_Function": "Engineering Function", "State": "California", "Exec_Admin_Flag": "N", "Preferred_Name": "Stephen Arnold", "Regular_Employee_Flag": "Y", "Preferred_Name_-_Last_Name": "Arnold", "Cost_Center_Code": "101100", "Location": "Office - USA - CA - San Francisco", "UserProfile": {"city": "San Francisco", "cost_center_code": "101100", "cost_center_description": "Magnifier Sales Inc", "country_name": "United States Of America", "department": "WW Sales Functions:Cortex Sales", "director_flag": "N", "email_-_primary_home": "stevearnoldtstc@hotmail.com", "email_address": "sarnold@paloaltonetworks.com", "emp_id": "101351", "employee_type": "Regular", "employment_status": "Active", "exec_admin_flag": "N", "first_name": "Stephen", "gdpr_country_flag": "0", "hide_from_gal": "False", "job_code": "2163", "job_family": "Software Engineering", "job_function": "Engineering Function", "last_hire_date": "10/01/2020", "last_name": "Arnold", "leadership": "No", "location": "Office - USA - CA - San Francisco", "management_level_1": "Nikesh Arora", "management_level_2": "Timmy Turner", "mgr_id": "115069", "org_level_1": "Sales", "org_level_2": "WW Sales Functions", "org_level_3": "Cortex Sales", "pan_cf_okta_location_region": "Americas", "people_manager_flag": "N", "postal_code": "94111", "preferred_name": "Stephen Arnold", "preferred_name_-_first_name": "Stephen", "preferred_name_-_last_name": "Arnold", "public_work_mobile_phone_number": "+44  7900-160-819", "regular_employee_flag": "Y", "rehired_employee": "Yes", "state": "California", "street_address": "WeWork Embarcadero Center", "title": "Mgr, SW Engineering", "user_name": "sarnold@paloaltonetworks.com", "vp_flag": "N", "work_country_abbrev": "US", "work_country_code": "840", "work_state_us_only": "California", "workday_id": "5aa443c785ff10461a941c31a173e459"}}',
    'details': 'Profile changed. Changed fields: False'}]

mapped_user = {'Employee_Type': 'Regular', 'Leadership': 'Yes-HQ', 'Work_Country_Code': '840',
                                         'Street_Address': '3000 Tannery Way', 'Employment_Status': 'Active',
                                         'VP_Flag': 'N', 'Mgr_ID': '115069', 'Cost_Center_Description': 'Channel Sales',
                                         'GDPR_Country_Flag': '0', 'Director_Flag': 'Y',
                                         'Email_-_Primary_Home': 'ronnyrahardjo@gmail.com', 'First_Name': 'Ronny',
                                         'Last_Hire_Date': '10/05/2020', 'People_Manager_Flag': 'N',
                                         'Department': 'Sales NAM:NAM Channel Sales',
                                         'Workday_ID': '5aa443c785ff10461ac83e5a6be32e1e', 'Postal_Code': '95054',
                                         'Rehired_Employee': 'Yes', 'Org_Level_1': 'Sales',
                                         'Org_Level_3': 'NAM Channel Sales', 'Country_Name': 'United States Of America',
                                         'Org_Level_2': 'Sales NAM', 'Emp_ID': '100122',
                                         'Job_Family': 'Product Management',
                                         'User_Name': 'rrahardjo@paloaltonetworks.com',
                                         'Preferred_Name_-_First_Name': 'Ronny', 'Hide_from_GAL': 'False',
                                         'Management_Level_1': 'Nikesh Arora', 'Work_Country_Abbrev': 'US',
                                         'Management_Level_2': 'Timmy Turner',
                                         'Email_Address': 'rrahardjo@paloaltonetworks.com',
                                         'Title': 'Dir, Product Line Manager', 'City': 'Santa Clara',
                                         'Work_State_US_Only': 'California', 'Job_Code': '2245',
                                         'PAN_CF_Okta_Location_Region': 'Americas', 'Last_Name': 'Rahardjo',
                                         'Job_Function': 'Product Management Function', 'State': 'California',
                                         'Exec_Admin_Flag': 'N', 'Preferred_Name': 'Ronny Rahardjo',
                                         'Regular_Employee_Flag': 'Y', 'Preferred_Name_-_Last_Name': 'Rahardjo',
                                         'Cost_Center_Code': '120100', 'Location': 'Office - USA - CA - Headquarters'}
events_result = [{'name': 'None None', 'rawJSON': '{"Employee_Type": "Regular", "Leadership": "Yes-HQ", "Work_Country_Code": "840", "Street_Address": "3000 Tannery Way", "Employment_Status": "Active", "VP_Flag": "N", "Mgr_ID": "115069", "Cost_Center_Description": "Channel Sales", "GDPR_Country_Flag": "0", "Director_Flag": "Y", "Email_-_Primary_Home": "ronnyrahardjo@gmail.com", "First_Name": "Ronny", "Last_Hire_Date": "10/05/2020", "People_Manager_Flag": "N", "Department": "Sales NAM:NAM Channel Sales", "Workday_ID": "5aa443c785ff10461ac83e5a6be32e1e", "Postal_Code": "95054", "Rehired_Employee": "Yes", "Org_Level_1": "Sales", "Org_Level_3": "NAM Channel Sales", "Country_Name": "United States Of America", "Org_Level_2": "Sales NAM", "Emp_ID": "100122", "Job_Family": "Product Management", "User_Name": "rrahardjo@paloaltonetworks.com", "Preferred_Name_-_First_Name": "Ronny", "Hide_from_GAL": "False", "Management_Level_1": "Nikesh Arora", "Work_Country_Abbrev": "US", "Management_Level_2": "Timmy Turner", "Email_Address": "rrahardjo@paloaltonetworks.com", "Title": "Dir, Product Line Manager", "City": "Santa Clara", "Work_State_US_Only": "California", "Job_Code": "2245", "PAN_CF_Okta_Location_Region": "Americas", "Last_Name": "Rahardjo", "Job_Function": "Product Management Function", "State": "California", "Exec_Admin_Flag": "N", "Preferred_Name": "Ronny Rahardjo", "Regular_Employee_Flag": "Y", "Preferred_Name_-_Last_Name": "Rahardjo", "Cost_Center_Code": "120100", "Location": "Office - USA - CA - Headquarters", "UserProfile": {"employee_type": "Regular", "leadership": "Yes-HQ", "work_country_code": "840", "street_address": "3000 Tannery Way", "employment_status": "Active", "vp_flag": "N", "mgr_id": "115069", "cost_center_description": "Channel Sales", "gdpr_country_flag": "0", "director_flag": "Y", "email_-_primary_home": "ronnyrahardjo@gmail.com", "first_name": "Ronny", "last_hire_date": "10/05/2020", "people_manager_flag": "N", "department": "Sales NAM:NAM Channel Sales", "workday_id": "5aa443c785ff10461ac83e5a6be32e1e", "postal_code": "95054", "rehired_employee": "Yes", "org_level_1": "Sales", "org_level_3": "NAM Channel Sales", "country_name": "United States Of America", "org_level_2": "Sales NAM", "emp_id": "100122", "job_family": "Product Management", "user_name": "rrahardjo@paloaltonetworks.com", "preferred_name_-_first_name": "Ronny", "hide_from_gal": "False", "management_level_1": "Nikesh Arora", "work_country_abbrev": "US", "management_level_2": "Timmy Turner", "email_address": "rrahardjo@paloaltonetworks.com", "title": "Dir, Product Line Manager", "city": "Santa Clara", "work_state_us_only": "California", "job_code": "2245", "pan_cf_okta_location_region": "Americas", "last_name": "Rahardjo", "job_function": "Product Management Function", "state": "California", "exec_admin_flag": "N", "preferred_name": "Ronny Rahardjo", "regular_employee_flag": "Y", "preferred_name_-_last_name": "Rahardjo", "cost_center_code": "120100", "location": "Office - USA - CA - Headquarters"}}', 'details': 'Profile changed. Changed fields: []'}]


def test_fetch_incidents(mocker):
    """Unit test
    Given
    - raw response of the http request
    When
    - mock the http request result as 5 results that are sorted from the newest to the oldest
    Then
    - as defined in the demisto params - show only 2, those should be the oldest 2 available
    - validate the incidents values
    """

    mocker.patch.object(Client, 'get_full_report', return_value=client_response)
    mocker.patch('Workday_IAM.get_all_user_profiles', return_value=("id", "mail"))
    mocker.patch.object(demisto, 'mapObject', return_value=mapped_user)
    client = Client(base_url="", verify="verify", headers={}, proxy=False, ok_codes=(200, 204), auth=None)

    fetch_events = fetch_incidents(client, {}, "")
    assert fetch_events == events_result


