# Fetching Incidents

## Overview
Demisto can pull events from 3rd party tools and convert them into actionable incidents. There are a few important parts that are necessary to keep in mind while doing so and they are outlined below.

## ```fetch-incidents``` Command
The ```fetch incidents``` command is the function that Demisto calls every minute to import new incidents and is triggered by the "Fetches incidents" parameter in the integration configuration. It is not necessary to configure the ```fetch-incidents``` command in the Integration Settings.

![screen shot 2019-01-07 at 15 35 01](https://user-images.githubusercontent.com/42912128/50771147-6aedb800-1292-11e9-833f-b5dd13e3507b.png)


Let's walk through the example below:

First we open up the command called "fetch-incidents". Make sure that the command is also referenced in the execution block as well.

```python
def fetch_incidents():

```

### Last Run
demisto.getLastRun() is how we retrieve the previous run time. When we are fetching incidents, it's important to only the events which have occured since the last time the function has ran. This helps to prevent incidents from being duplicated.

```python
    # demisto.getLastRun() will returns an obj with the previous run in it.
    last_run = demisto.getLastRun()
```

### Query and Parameters
    # usually there will be some kind of query based on event creation date, 
    # or get all the events with id greater than X id and their status is New
    query = 'status=New'

    day_ago = datetime.now() - timedelta(days=1) 
    start_time = day_ago.time()
    if last_run and last_run.has_key('start_time'):
        start_time = last_run.get('start_time')

    # execute the query and get the events
    events = query_events(query, start_time)

    # convert the events to demisto incident 
    incidents = []
    for event in events:
        incident = {
            'name': event['name'],        # name is required field, must be set
            'occurred': event['create_time'], # occurred is optional date
            'rawJSON': json.dumps(event)  # set the original event to rawJSON, this will allow mapping of the event. Don't forget to `json.dumps`
        }
        incident.append(incident)

    # save your data from this run, to continue the next run
    demisto.setLastRun({
        'start_time': datetime.now()
    })

    # this command will create incidents in Demisto
    demisto.incidents(incidents)
```