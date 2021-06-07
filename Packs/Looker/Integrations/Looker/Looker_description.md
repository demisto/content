#### Generate an API3 key for a Looker user:
1. Log in to the looker web interface with an account that is permitted to manage users.
2. At the top of the page, click on the "Admin" drop down and select "Users"
3. Select the user you would like to generate the API3 key for.
4. Go to "API3 Keys" and select "Edit Keys"
5. Click on "New API3 Key"

#### Get a look ID:
**Usages:** 
- "Look name or ID to fetch incidents from" integration parameter
- Look ID command arguments
- Uniquely identify a Look (the name is not unique).

**Option A:** Looker Web Interface
1. Click on the desired look.
2. Look at the URL - it should end with a number - that is the ID of the look.

**Option B:** Cortex XSOAR commands
1. Configure looker without fetching incidents or filling in the parameter.
2. Run looker-search-queries or looker-search-looks
3. The ID will be part of the results (among other look details).

#### Get model and view names from an explore's URL:
1. Navigate to the desired explore.
2. The URL will be formatted like so: `https://<looker server>/explore/<model>/<view>`

#### Get a field's SQL name (for command arguments):
1. Navigate to the desired explore.
2. Click on the desired field.
3. In the "DATA" tab, Click on "SQL".

You will see the field name in the following format: "object_name.field_name"