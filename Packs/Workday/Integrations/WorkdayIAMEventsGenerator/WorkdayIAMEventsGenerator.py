# noqa: F401
from flask import Flask, jsonify
from gevent.pywsgi import WSGIServer
from CommonServerPython import *

FIRST_RUN_REPORT = {
    "Report_Entry": [
        {
            "Employee_Type": "Regular",
            "Leadership": "Yes-HQ",
            "Work_Country_Code": "840",
            "Street_Address": "3000 Tannery Way",
            "Employment_Status": "Active",
            "VP_Flag": "N",
            "Mgr_ID": "115069",
            "Cost_Center_Description": "Channel Sales",
            "GDPR_Country_Flag": "0",
            "Director_Flag": "Y",
            "Email_-_Primary_Home": "ronnyrahardjo@test.com",
            "First_Name": "Ronny",
            "Last_Hire_Date": "10/05/2020",
            "People_Manager_Flag": "N",
            "Department": "Sales NAM:NAM Channel Sales",
            "Workday_ID": "5aa443c785ff10461ac83e5a6be32e1e",
            "Postal_Code": "95054",
            "Rehired_Employee": "Yes",
            "Org_Level_1": "Sales",
            "Org_Level_3": "NAM Channel Sales",
            "Country_Name": "United States Of America",
            "Org_Level_2": "Sales NAM",
            "Emp_ID": "100122",
            "Job_Family": "Product Management",
            "User_Name": "rrahardjo@test.com",
            "Preferred_Name_-_First_Name": "Ronny",
            "Prehire_Flag": "False",
            "Management_Level_1": "Nikesh Arora",
            "Work_Country_Abbrev": "US",
            "Management_Level_2": "Timmy Turner",
            "Email_Address": "rrahardjo@test.com",
            "Title": "Dir, Product Line Manager",
            "City": "Santa Clara",
            "Work_State_US_Only": "California",
            "Job_Code": "2245",
            "PAN_CF_Okta_Location_Region": "Americas",
            "Last_Name": "Rahardjo",
            "Job_Function": "Product Management Function",
            "State": "California",
            "Exec_Admin_Flag": "N",
            "Preferred_Name": "Ronny Rahardjo",
            "Regular_Employee_Flag": "Y",
            "Preferred_Name_-_Last_Name": "Rahardjo",
            "Cost_Center_Code": "120100",
            "Location": "Office - USA - CA - Headquarters",
            "Last_Day_of_Work": "02/15/2021",
            "Termination_Date": "02/15/2021",
            "Hire_Date": "01/01/2010"
        },
        {
            "Employee_Type": "Regular",
            "Leadership": "No",
            "Work_Country_Code": "840",
            "Street_Address": "WeWork Embarcadero Center",
            "Employment_Status": "Active",
            "VP_Flag": "N",
            "Mgr_ID": "115069",
            "Cost_Center_Description": "Magnifier Sales Inc",
            "GDPR_Country_Flag": "0",
            "Public_Work_Mobile_Phone_Number": "+44  7900-160-819",
            "Director_Flag": "N",
            "Email_-_Primary_Home": "stevearnoldtstc@test.com",
            "First_Name": "Stephen",
            "Last_Hire_Date": "10/01/2020",
            "People_Manager_Flag": "N",
            "Department": "WW Sales Functions:Cortex Sales",
            "Workday_ID": "5aa443c785ff10461a941c31a173e459",
            "Postal_Code": "94111",
            "Rehired_Employee": "Yes",
            "Org_Level_1": "Sales",
            "Org_Level_3": "Cortex Sales",
            "Country_Name": "United States Of America",
            "Org_Level_2": "WW Sales Functions",
            "Emp_ID": "101351",
            "Job_Family": "Software Engineering",
            "User_Name": "sarnold@test.com",
            "Preferred_Name_-_First_Name": "Stephen",
            "Prehire_Flag": "False",
            "Management_Level_1": "Nikesh Arora",
            "Work_Country_Abbrev": "US",
            "Management_Level_2": "Timmy Turner",
            "Email_Address": "sarnold@test.com",
            "Title": "Mgr, SW Engineering",
            "City": "San Francisco",
            "Work_State_US_Only": "California",
            "Job_Code": "2163",
            "PAN_CF_Okta_Location_Region": "Americas",
            "Last_Name": "Arnold",
            "Job_Function": "Engineering Function",
            "State": "California",
            "Exec_Admin_Flag": "N",
            "Preferred_Name": "Stephen Arnold",
            "Regular_Employee_Flag": "Y",
            "Preferred_Name_-_Last_Name": "Arnold",
            "Cost_Center_Code": "101100",
            "Location": "Office - USA - CA - San Francisco",
            "Last_Day_of_Work": "02/15/2021",
            "Termination_Date": "02/15/2021",
            "Hire_Date": "01/01/2010"
        },
        {
            "Employee_Type": "Regular",
            "Leadership": "No",
            "Work_Country_Code": "840",
            "Street_Address": "3000 Tannery Way",
            "Employment_Status": "Active",
            "VP_Flag": "N",
            "Mgr_ID": "115069",
            "Cost_Center_Description": "IoT - Engineering",
            "GDPR_Country_Flag": "0",
            "Director_Flag": "N",
            "Email_-_Primary_Home": "test37@testing.com",
            "First_Name": "Tooth",
            "Last_Hire_Date": "06/15/2020",
            "People_Manager_Flag": "N",
            "Department": "Enterprise R&D:FWaaP",
            "Workday_ID": "9aa7e309929e01ebec7923080803461b",
            "Postal_Code": "95054",
            "Rehired_Employee": "No",
            "Org_Level_1": "All R&D",
            "Org_Level_3": "FWaaP",
            "Country_Name": "United States Of America",
            "Org_Level_2": "Enterprise R&D",
            "Emp_ID": "115104",
            "Job_Family": "Software Engineering",
            "Preferred_Name_-_First_Name": "Tooth",
            "Prehire_Flag": "False",
            "Management_Level_1": "Nikesh Arora",
            "Work_Country_Abbrev": "US",
            "Management_Level_2": "Timmy Turner",
            "Email_Address": "tfairy@test.com",
            "Title": "Staff Engineer SW",
            "City": "Santa Clara",
            "Work_State_US_Only": "California",
            "Job_Code": "5162",
            "PAN_CF_Okta_Location_Region": "Americas",
            "Last_Name": "Fairy_Updated",
            "Job_Function": "Engineering Function",
            "State": "California",
            "Exec_Admin_Flag": "N",
            "Preferred_Name": "Tooth Fairy_Updated",
            "Regular_Employee_Flag": "Y",
            "Preferred_Name_-_Last_Name": "Fairy_Updated",
            "Cost_Center_Code": "613116",
            "Location": "Office - USA - CA - Headquarters",
            "Last_Day_of_Work": "02/15/2021",
            "Termination_Date": "02/15/2021",
            "Hire_Date": "01/01/2010"
        },
        {
            "Employee_Type": "Regular",
            "Leadership": "No",
            "Work_Country_Code": "840",
            "Street_Address": "3000 Tannery Way",
            "Employment_Status": "Active",
            "VP_Flag": "N",
            "Mgr_ID": "115069",
            "Cost_Center_Description": "Consulting Systems Engineering",
            "GDPR_Country_Flag": "0",
            "Director_Flag": "N",
            "Email_-_Primary_Home": "test26@testing.com",
            "First_Name": "Remy",
            "Last_Hire_Date": "06/15/2020",
            "People_Manager_Flag": "N",
            "Department": "WW Sales Functions:WW SE Sales",
            "Workday_ID": "9aa7e309929e01830c041f1c08039323",
            "Postal_Code": "95054",
            "Rehired_Employee": "No",
            "Org_Level_1": "Sales",
            "Org_Level_3": "WW SE Sales",
            "Country_Name": "United States Of America",
            "Org_Level_2": "WW Sales Functions",
            "Emp_ID": "115094",
            "Job_Family": "Software Engineering",
            "User_Name": "rbuxaplenty@test.com",
            "Preferred_Name_-_First_Name": "Remy",
            "Prehire_Flag": "False",
            "Management_Level_1": "Nikesh Arora",
            "Work_Country_Abbrev": "US",
            "Management_Level_2": "Timmy Turner",
            "Email_Address": "rbuxaplenty@test.com",
            "Title": "Staff Engineer Software",
            "City": "Santa Clara",
            "Work_State_US_Only": "California",
            "Job_Code": "5162",
            "PAN_CF_Okta_Location_Region": "Americas",
            "Last_Name": "Buxaplenty",
            "Job_Function": "Engineering Function",
            "State": "California",
            "Exec_Admin_Flag": "N",
            "Preferred_Name": "Remy Buxaplenty",
            "Regular_Employee_Flag": "Y",
            "Preferred_Name_-_Last_Name": "Buxaplenty",
            "Cost_Center_Code": "310100",
            "Location": "Office - USA - CA - Headquarters",
            "Last_Day_of_Work": "02/15/2021",
            "Termination_Date": "02/15/2021",
            "Hire_Date": "01/01/2010"
        },
        {
            "Employee_Type": "Regular",
            "Leadership": "No",
            "Work_Country_Code": "840",
            "Street_Address": "3000 Tannery Way",
            "Employment_Status": "Active",
            "VP_Flag": "N",
            "Mgr_ID": "115069",
            "Cost_Center_Description": "IoT - PM",
            "GDPR_Country_Flag": "0",
            "Director_Flag": "N",
            "Email_-_Primary_Home": "test24@testing.com",
            "First_Name": "Norm",
            "Last_Hire_Date": "06/15/2020",
            "People_Manager_Flag": "N",
            "Department": "Enterprise R&D:FWaaP",
            "Workday_ID": "9aa7e309929e0125823a032108030b25",
            "Postal_Code": "95054",
            "Rehired_Employee": "No",
            "Org_Level_1": "All R&D",
            "Org_Level_3": "FWaaP",
            "Country_Name": "United States Of America",
            "Org_Level_2": "Enterprise R&D",
            "Emp_ID": "115092",
            "Job_Family": "Product Management",
            "User_Name": "ngenie@test.com",
            "Preferred_Name_-_First_Name": "Norm",
            "Prehire_Flag": "False",
            "Management_Level_1": "Nikesh Arora",
            "Work_Country_Abbrev": "US",
            "Management_Level_2": "Timmy Turner",
            "Email_Address": "ngenie@test.com",
            "Title": "Sr Prod Mgr",
            "City": "Santa Clara",
            "Work_State_US_Only": "California",
            "Job_Code": "5224",
            "PAN_CF_Okta_Location_Region": "Americas",
            "Last_Name": "Genie",
            "Job_Function": "Product Management Function",
            "State": "California",
            "Exec_Admin_Flag": "N",
            "Preferred_Name": "Norm Genie",
            "Regular_Employee_Flag": "Y",
            "Preferred_Name_-_Last_Name": "Genie",
            "Cost_Center_Code": "651116",
            "Location": "Office - USA - CA - Headquarters",
            "Last_Day_of_Work": "02/15/2021",
            "Termination_Date": "02/15/2021",
            "Hire_Date": "01/01/2010"
        },
        {
            "Employee_Type": "Regular",
            "Leadership": "No",
            "Work_Country_Code": "840",
            "Street_Address": "3000 Tannery Way",
            "Employment_Status": "Active",
            "VP_Flag": "N",
            "Mgr_ID": "115069",
            "Cost_Center_Description": "IoT - PM",
            "GDPR_Country_Flag": "0",
            "Director_Flag": "N",
            "Email_-_Primary_Home": "test23@testing.com",
            "First_Name": "Santa",
            "Last_Hire_Date": "06/15/2020",
            "People_Manager_Flag": "N",
            "Department": "Enterprise R&D:FWaaP",
            "Workday_ID": "9aa7e309929e01b392c9a5220803c825",
            "Postal_Code": "95054",
            "Rehired_Employee": "No",
            "Org_Level_1": "All R&D",
            "Org_Level_3": "FWaaP",
            "Country_Name": "United States Of America",
            "Org_Level_2": "Enterprise R&D",
            "Emp_ID": "115091",
            "Job_Family": "Technical Writing",
            "Preferred_Name_-_First_Name": "Santa",
            "Prehire_Flag": "False",
            "Management_Level_1": "Nikesh Arora",
            "Work_Country_Abbrev": "US",
            "Management_Level_2": "Timmy Turner",
            "Email_Address": "sclaus@test.com",
            "Title": "Sr Technical Writer",
            "City": "Santa Clara",
            "Work_State_US_Only": "California",
            "Job_Code": "5314",
            "PAN_CF_Okta_Location_Region": "Americas",
            "Last_Name": "Claus",
            "Job_Function": "Product Management Function",
            "State": "California",
            "Exec_Admin_Flag": "N",
            "Preferred_Name": "Santa Claus",
            "Regular_Employee_Flag": "Y",
            "Preferred_Name_-_Last_Name": "Claus",
            "Cost_Center_Code": "651116",
            "Location": "Office - USA - CA - Headquarters",
            "Last_Day_of_Work": "02/15/2021",
            "Termination_Date": "02/15/2021",
            "Hire_Date": "01/01/2010"
        },
        {
            "Employee_Type": "Regular",
            "Leadership": "No",
            "Work_Country_Code": "840",
            "Street_Address": "3000 Tannery Way",
            "Employment_Status": "Active",
            "VP_Flag": "N",
            "Mgr_ID": "115069",
            "Cost_Center_Description": "IoT - PM",
            "GDPR_Country_Flag": "0",
            "Director_Flag": "N",
            "Email_-_Primary_Home": "test20@testing.com",
            "First_Name": "Dolores",
            "Last_Hire_Date": "06/15/2020",
            "People_Manager_Flag": "N",
            "Department": "Enterprise R&D:FWaaP",
            "Workday_ID": "9aa7e309929e0188f4eb6b2a08031228",
            "Postal_Code": "95054",
            "Rehired_Employee": "No",
            "Org_Level_1": "All R&D",
            "Org_Level_3": "FWaaP",
            "Country_Name": "United States Of America",
            "Org_Level_2": "Enterprise R&D",
            "Emp_ID": "115088",
            "Job_Family": "Software Engineering",
            "Preferred_Name_-_First_Name": "Dolores",
            "Prehire_Flag": "False",
            "Management_Level_1": "Nikesh Arora",
            "Work_Country_Abbrev": "US",
            "Management_Level_2": "Timmy Turner",
            "Email_Address": "dcrocker@test.com",
            "Title": "Sr Mgr, UX Design",
            "City": "Santa Clara",
            "Work_State_US_Only": "California",
            "Job_Code": "2164",
            "PAN_CF_Okta_Location_Region": "Americas",
            "Last_Name": "Crocker",
            "Job_Function": "Engineering Function",
            "State": "California",
            "Exec_Admin_Flag": "N",
            "Preferred_Name": "Dolores Crocker",
            "Regular_Employee_Flag": "Y",
            "Preferred_Name_-_Last_Name": "Crocker",
            "Cost_Center_Code": "651116",
            "Location": "Office - USA - CA - Headquarters",
            "Last_Day_of_Work": "02/15/2021",
            "Termination_Date": "02/15/2021",
            "Hire_Date": "01/01/2010"
        },
        {
            "Employee_Type": "Regular",
            "Leadership": "No",
            "Work_Country_Code": "840",
            "Street_Address": "3000 Tannery Way",
            "Employment_Status": "Active",
            "VP_Flag": "N",
            "Mgr_ID": "115069",
            "Cost_Center_Description": "IoT - Engineering",
            "GDPR_Country_Flag": "0",
            "Director_Flag": "N",
            "Email_-_Primary_Home": "test19@testing.com",
            "First_Name": "Crash",
            "Last_Hire_Date": "06/15/2020",
            "People_Manager_Flag": "N",
            "Department": "Enterprise R&D:FWaaP",
            "Workday_ID": "9aa7e309929e014a0d78ca2c08030629",
            "Postal_Code": "95054",
            "Rehired_Employee": "No",
            "Org_Level_1": "All R&D",
            "Org_Level_3": "FWaaP",
            "Country_Name": "United States Of America",
            "Org_Level_2": "Enterprise R&D",
            "Emp_ID": "115087",
            "Job_Family": "Software Engineering",
            "Preferred_Name_-_First_Name": "Crash",
            "Prehire_Flag": "False",
            "Management_Level_1": "Nikesh Arora",
            "Work_Country_Abbrev": "US",
            "Management_Level_2": "Timmy Turner",
            "Email_Address": "cnebula@test.com",
            "Title": "Staff Engineer Software",
            "City": "Santa Clara",
            "Work_State_US_Only": "California",
            "Job_Code": "5162",
            "PAN_CF_Okta_Location_Region": "Americas",
            "Last_Name": "Nebula",
            "Job_Function": "Engineering Function",
            "State": "California",
            "Exec_Admin_Flag": "N",
            "Preferred_Name": "Crash Nebula",
            "Regular_Employee_Flag": "Y",
            "Preferred_Name_-_Last_Name": "Nebula",
            "Cost_Center_Code": "613116",
            "Location": "Office - USA - CA - Headquarters",
            "Last_Day_of_Work": "02/15/2021",
            "Termination_Date": "02/15/2021",
            "Hire_Date": "01/01/2010"
        },
        {
            "Employee_Type": "Regular",
            "Leadership": "No",
            "Work_Country_Code": "840",
            "Street_Address": "3000 Tannery Way",
            "Employment_Status": "Active",
            "VP_Flag": "N",
            "Mgr_ID": "115069",
            "Cost_Center_Description": "IoT - Engineering",
            "GDPR_Country_Flag": "0",
            "Director_Flag": "N",
            "Email_-_Primary_Home": "test18@testing.com",
            "First_Name": "Trixie",
            "Last_Hire_Date": "06/15/2020",
            "People_Manager_Flag": "N",
            "Department": "Enterprise R&D:FWaaP",
            "Workday_ID": "9aa7e309929e01eb443ce92e08031f2a",
            "Postal_Code": "95054",
            "Rehired_Employee": "No",
            "Org_Level_1": "All R&D",
            "Org_Level_3": "FWaaP",
            "Country_Name": "United States Of America",
            "Org_Level_2": "Enterprise R&D",
            "Emp_ID": "115086",
            "Job_Family": "Software Engineering",
            "Preferred_Name_-_First_Name": "Trixie",
            "Prehire_Flag": "False",
            "Management_Level_1": "Nikesh Arora",
            "Work_Country_Abbrev": "US",
            "Management_Level_2": "Timmy Turner",
            "Email_Address": "ttang@test.com",
            "Title": "Principal Engineer Software",
            "City": "Santa Clara",
            "Work_State_US_Only": "California",
            "Job_Code": "5164",
            "PAN_CF_Okta_Location_Region": "Americas",
            "Last_Name": "Tang",
            "Job_Function": "Engineering Function",
            "State": "California",
            "Exec_Admin_Flag": "N",
            "Preferred_Name": "Trixie Tang",
            "Regular_Employee_Flag": "Y",
            "Preferred_Name_-_Last_Name": "Tang",
            "Cost_Center_Code": "613116",
            "Location": "Office - USA - CA - Headquarters",
            "Last_Day_of_Work": "02/15/2021",
            "Termination_Date": "02/15/2021",
            "Hire_Date": "01/01/2010"
        }
    ]
}

NEW_HIRE_REPORT = {
    "Report_Entry": [
        {
            "Employee_Type": "Regular",
            "Leadership": "No",
            "Work_Country_Code": "840",
            "Street_Address": "3000 Tannery Way",
            "Employment_Status": "Active",
            "VP_Flag": "N",
            "Mgr_ID": "115069",
            "Cost_Center_Description": "IoT - PM",
            "GDPR_Country_Flag": "0",
            "Director_Flag": "N",
            "Email_-_Primary_Home": "test6@testing.com",
            "First_Name": 'first_name',
            "Last_Hire_Date": "06/15/2020",
            "People_Manager_Flag": "N",
            "Department": "Enterprise R&D:FWaaP",
            "Workday_ID": "9aa7e309929e013ff3c6e3440803b833",
            "Postal_Code": "95054",
            "Rehired_Employee": "No",
            "Org_Level_1": "All R&D",
            "Org_Level_3": "FWaaP",
            "Country_Name": "United States Of America",
            "Org_Level_2": "Enterprise R&D",
            "Emp_ID": "115074",
            "Job_Family": "Product Management",
            "Preferred_Name_-_First_Name": 'first_name',
            "Nikesh Arora": "False",
            "Management_Level_1": "Nikesh Arora",
            "Work_Country_Abbrev": "US",
            "Management_Level_2": "Timmy Turner",
            "Email_Address": 'user_email',
            "Title": "Product Line Manager",
            "City": "Santa Clara",
            "Work_State_US_Only": "California",
            "Job_Code": "5225",
            "PAN_CF_Okta_Location_Region": "Americas",
            "Last_Name": 'lsat_name',
            "Job_Function": "Product Management Function",
            "State": "California",
            "Exec_Admin_Flag": "N",
            "Preferred_Name": "Chester McBadbat",
            "Regular_Employee_Flag": "Y",
            "Preferred_Name_-_Last_Name": 'last_name',
            "Cost_Center_Code": "651116",
            "Location": "Office - USA - CA - Headquarters",
            "Last_Day_of_Work": "02/15/2021",
            "Termination_Date": "02/15/2021",
            "Hire_Date": "01/01/2010"
        }
    ]
}


APP: Flask = Flask('xsoar-workday')


@APP.route('/', methods=['GET'])
def get_full_reports():
    integration_context = get_integration_context()
    return jsonify(integration_context)


def get_full_report():
    set_integration_context(FIRST_RUN_REPORT)
    integration_context = get_integration_context()
    return integration_context['Report_Entry'][0]


def test_module():
    if int(demisto.params().get('longRunningPort', '')) and demisto.params().get("longRunning"):
        user_report = get_full_report()
        if user_report:
            demisto.results('ok')
        else:
            return_error('Could not connect to the long running server. Please make sure everything is configured.')
    else:
        return_error('Please make sure the long running port is filled and the long running checkbox is marked.')


def get_employee_id():
    """
    Get the maximum employee id number and increase it by one.
    This function is used to avoid duplication while creating a new hire report.
    Returns: (int) Employee ID number.

    """
    integration_context = get_integration_context()
    employee_ids = []
    for report in integration_context['Report_Entry']:
        employee_id = int(report.get('Emp_ID'))
        employee_ids.append(employee_id)
    max_employee_id = int(max(employee_ids)) + 1

    return str(max_employee_id)


def generate_new_hire_reports():
    user_email = demisto.args().get('user_email')
    first_name = demisto.args().get('first_name', '')
    last_name = demisto.args().get('last_name', '')
    integration_context = get_integration_context()

    new_report = NEW_HIRE_REPORT['Report_Entry'][0]
    for report in integration_context['Report_Entry']:
        email_address = report.get('Email_Address')
        if user_email == email_address:
            raise Exception(f'User "{user_email}" already exist. Please try another user email.')

    new_report['Email_Address'] = user_email
    new_report['First_Name'] = first_name
    new_report['Last_Name'] = last_name
    new_report['Preferred_Name'] = f'{first_name} {last_name}'
    new_report['Preferred_Name_-_First_Name'] = first_name
    new_report['Preferred_Name_-_Last_Name'] = last_name
    new_report['Emp_ID'] = get_employee_id()
    integration_context['Report_Entry'].append(new_report)
    set_integration_context(integration_context)

    return_results('Successfully generated the new hire event.')


def generate_terminate_report():
    user_email = demisto.args().get('user_email')
    integration_context = get_integration_context()
    now = datetime.now()
    current_date = now.strftime("%m/%d/%Y")
    user_report = None
    for report in integration_context['Report_Entry']:
        if report['Email_Address'] == user_email:
            user_report = report
    if not user_report:
        raise Exception(f'The user email {user_email} does not exist. Please try one  of the followings: '
                        f'ttang@test.com, rrahardjo@test.com, sarnold@test.com')

    is_terminated = user_report.get('Employment_Status')
    rehired_status = user_report.get('Rehired_Employee')
    if is_terminated == 'Terminated' and rehired_status == 'No':
        raise Exception(f'The user {user_email} is already terminated.')

    user_report['Employment_Status'] = 'Terminated'
    user_report['Last_Day_of_Work'] = demisto.args().get('last_day_of_work', str(current_date))
    user_report['Termination_Date'] = demisto.args().get('termination_date', str(current_date))
    set_integration_context(integration_context)
    return_results('Successfully generated the Terminate user event.')


def generate_update_report():
    user_email = demisto.args().get('user_email')
    integration_context = get_integration_context()
    title = demisto.args().get('title')
    city = demisto.args().get('city')
    street_address = demisto.args().get('street_address')
    last_day_of_work = demisto.args().get('last_day_of_work')
    user_report = None
    for report in integration_context['Report_Entry']:
        if report['Email_Address'] == user_email:
            user_report = report
    if not user_report:
        raise Exception(f'The user email {user_email} does not exist. Please try one  of the followings: '
                        f'ttang@test.com, rrahardjo@test.com, sarnold@test.com')
    if title:
        user_report['Title'] = title
    if city:
        user_report['City'] = city
    if street_address:
        user_report['Street_Address'] = street_address
    if last_day_of_work:
        user_report['Last_Day_of_Work'] = last_day_of_work
    set_integration_context(integration_context)
    return_results('Successfully generated the Update user event.')


def generate_rehire_report():
    user_email = demisto.args().get('user_email')
    integration_context = get_integration_context()
    user_report = None
    for report in integration_context['Report_Entry']:
        if report['Email_Address'] == user_email:
            user_report = report
    if not user_report:
        raise Exception(f'The user email {user_email} does not exist. Please try one  of the followings: '
                        f'ttang@test.com, rrahardjo@test.com, sarnold@test.com')

    is_terminated = user_report.get('Employment_Status')
    rehired_status = user_report.get('Rehired_Employee')
    if is_terminated == 'Active' or rehired_status == 'Yes':
        raise Exception(f'The user {user_email} is not terminated. Either he is still active or was already '
                        f'rehired.')

    user_report['Rehired_Employee'] = 'Yes'
    user_report['Prehire_Flag'] = 'True'
    set_integration_context(integration_context)
    return_results('Successfully generated the rehire user event.')


def main():

    if demisto.command() == 'test-module':
        test_module()

    elif demisto.command() == 'long-running-execution':
        integration_context = get_integration_context()
        if not integration_context:
            set_integration_context(FIRST_RUN_REPORT)
        while True:
            port = int(demisto.params().get('longRunningPort', ''))
            server = WSGIServer(('0.0.0.0', port), APP)
            server.serve_forever()

    elif demisto.command() == 'workday-generate-hire-event':
        generate_new_hire_reports()

    elif demisto.command() == 'workday-generate-update-event':
        generate_update_report()

    elif demisto.command() == 'workday-generate-rehire-event':
        generate_rehire_report()

    elif demisto.command() == 'workday-generate-terminate-event':
        generate_terminate_report()

    elif demisto.command() == 'initialize-context':
        set_integration_context(FIRST_RUN_REPORT)
        return_results('The integration context has been initialized.')


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
