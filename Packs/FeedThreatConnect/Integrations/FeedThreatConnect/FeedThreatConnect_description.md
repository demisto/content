## ThreatConnect Feed
This integration fetches indicators from ThreatConnect and indicators could be filtered by indicator owner.\

Genrating credentials:\
    1. On the top navigation bar, hover the cursor over the Settings icon and select Org Settings from the dropdown menu.\
    2. Click the Create API User button on the Membership tab of the Organization Settings screen, and the API User Administration window will be displayed.\
    3. Fill up the following parts of the form:\
        - First Name: Enter the API user’s first name.\
        - Last Name: Enter the API user’s last name.\
        - Organization Role: Use the dropdown menu to select an Organization role for the user.\
        - Include in Observations and False Positives: Check this box to allow data provided by the API user to be included in observation and false-positive counts.\
        - Disabled: Click the checkbox to disable an API user’s account in the event that the Administrator wishes to retain log integrity when the API user no longer requires ThreatConnect access.\
    4. Record the Secret Key, as it will not be accessible after the window is closed.\
    5. Click the SAVE button to create the API user account.\
    