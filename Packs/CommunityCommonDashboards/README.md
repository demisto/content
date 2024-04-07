# Community Common Dashboards
This content pack contains two dashboards:

* CISO Metrics
* XSOAR Value Metrics

## CISO Metrics Dashboard

This dashboard uses OOTB widgets configured to present a consistent overview of XSOAR operation.

## XSOAR Value Metrics Dashboard

This dashboard provides XSOAR value metrics for the XSOAR implementation:

* Time to respond to alerts
* Cost to respond to alerts

Time to respond metrics are measured by overall incident duration and SLA timers that have been implemented. Cost to respond is based on per XSOAR incident type estimates of the effort it would take to respond to an alert without use of XSOAR compared to the time to respond to the alert with XSOAR and the quantity of alerts processed by XSOAR.  The mix of alerts and the relative costs of handling different types of alerts factor into the overall cost to respond.  An automation is ran periodically to collect incident statistics and stores the results in XSOAR lists.  This allows monitoring metrics over years without the requirement of incidents being retained - for long term trending within the XSOAR console.  The automation manages the current year metrics and previous year metrics. Dashboard widgets retreive data from these lists for display. Additional functionality is available through adding lists and customization of the automation and script arguments to use these lists.

There are three XSOAR lists used by the automations and dashboard:

* Incident effort - user provided estimates for each incident type
* This year metrics - populated by **XSOARValueMetrics**
* Last year metrics - populated by **XSOARValueMetrics**

### Setup and Use

After installing this content pack, setup the **XSOAR Value Metrics** dashboard as follows:

* Run the **XSOARValueMetrics** automation in the playground and identify the incident types found
* Create the **IncidentEffort** XSOAR list (default list name) and provide the manual and automated effort to respond estimates for each incident type
* Review the **XSOAR Value Metrics** dashboard

The **XSOARValueMetrics** automation is executed periodically to collect incident statistics, monthly or quarterly for example.  You may want to wait a month before executing the automation to allow incident closure to occur.  For example, for a windows Jan 1st - Mar 31st, execute this automation May 1st. The expected duration of incidents determines if this delay makes sense. If incident open duration is days, then delaying a month may make sense. If incidents are close within a day the are created in XSOAR, then executing this on April 1st for a Q1 window is reasonable.

### XSOAR Lists Used

The dashboard and widgets can be customized and extended by using additional lists as needed. The **XSOARValueMetrics** automation and the **XSOAR Value Metrics** dashboard by default are configured to use the following list names:

* **IncidentEffort**
* **MetricsThisYear**
* **MetricsLastYear**

#### Incident Effort XSOAR List

The incident effort list is a JSON dictonary with two values for each XSOAR incident type with a format of:  **incident_type_name: [Manual_effort, Automated_effort]**

* **Manual_effort**: average analyst minutes per incident if the incident is responded to without XSOAR
* **Automated_effort**: average analyst minutes per incident if the incident is responded to with XSOAR

Example:
```
    {
	    "Malware": [20, 2],
	    "CloudAccess": [10, 0],
	    "Phishing": [45, 7]
    }
```

#### This Years Metric and Last Years Metric XSOAR Lists

The **XSOARValueMetrics** automation updates JSON dictionaries stored in these lists containing the monthly metrics collected. The dashboard widgets pull data from these lists for display.

Example:
```
    {
        "YEAR": "2023", 
        "Incidents": {
            "TestMalware": {"Jan": "0", "Feb": "0", "Mar": "0", "Apr": "0", "May": "0", "Jun": "0", "Jul": "0", "Aug": "0", "Sep": "0", "Oct": "0", "Nov": "672", "Dec": "455"}, 
            "CloudAccess": {"Jan": "0", "Feb": "0", "Mar": "0", "Apr": "0", "May": "0", "Jun": "0", "Jul": "0", "Aug": "0", "Sep": "0", "Oct": "0", "Nov": "1", "Dec": "0"} 
        }, 
        "Closed Incidents": {
            "TestMalware": {"Jan": "0", "Feb": "0", "Mar": "0", "Apr": "0", "May": "0", "Jun": "0", "Jul": "0", "Aug": "0", "Sep": "0", "Oct": "0", "Nov": "672", "Dec": "60"}, 
            "CloudAccess": {"Jan": "0", "Feb": "0", "Mar": "0", "Apr": "0", "May": "0", "Jun": "0", "Jul": "0", "Aug": "0", "Sep": "0", "Oct": "0", "Nov": "0", "Dec": "0"} 
        }, 
        "Incident Open Duration": {
            "TestMalware": {"Jan": "0", "Feb": "0", "Mar": "0", "Apr": "0", "May": "0", "Jun": "0", "Jul": "0", "Aug": "0", "Sep": "0", "Oct": "0", "Nov": "2849292", "Dec": "8166"}, 
            "CloudAccess": {"Jan": "0", "Feb": "0", "Mar": "0", "Apr": "0", "May": "0", "Jun": "0", "Jul": "0", "Aug": "0", "Sep": "0", "Oct": "0", "Nov": "0", "Dec": "0"} 
        }, 
        "SLA Metrics": {
            "contime": {"Jan": "0", "Feb": "0", "Mar": "0", "Apr": "0", "May": "0", "Jun": "0", "Jul": "0", "Aug": "0", "Sep": "0", "Oct": "0", "Nov": "0", "Dec": "0"}, 
            "dettime": {"Jan": "0", "Feb": "0", "Mar": "0", "Apr": "0", "May": "0", "Jun": "0", "Jul": "0", "Aug": "0", "Sep": "0", "Oct": "0", "Nov": "0", "Dec": "0"}, 
            "remtime": {"Jan": "0", "Feb": "0", "Mar": "0", "Apr": "0", "May": "0", "Jun": "0", "Jul": "0", "Aug": "0", "Sep": "0", "Oct": "0", "Nov": "0", "Dec": "0"}, 
            "asstime": {"Jan": "0", "Feb": "0", "Mar": "0", "Apr": "0", "May": "0", "Jun": "0", "Jul": "0", "Aug": "0", "Sep": "0", "Oct": "0", "Nov": "28", "Dec": "36"}, 
            "tritime": {"Jan": "0", "Feb": "0", "Mar": "0", "Apr": "0", "May": "0", "Jun": "0", "Jul": "0", "Aug": "0", "Sep": "0", "Oct": "0", "Nov": "0", "Dec": "0"}
        }
    }
```

### Automations

#### XSOARValueMetrics

This automation collects metrics for a specified time window and generates metrics for the top 20 incident types in that time period. The automation creates a small CSV with four tables in the war room as well as storing the metrics in JSON dictionaries in two XSOAR lists specified in the "thisyearlist" and "lastyearlist" arguments. The four tables in the war room CSV contain annual data for:

* All Incidents
* Closed Incidents
* Open Duration
* SLA Timer Durations  

The time window is expected to be a complete month specified by the "firstday" and "lastday" arguments. If partial months are used, the open durations and SLA metrics is the average of the last set of incidents found, while incident counts are incremented. For more details on how the data is updated, see the "mode" argument for different options.

##### Inputs
* firstday - required argument to set the start day for searching incidents

Example:
    ```firstday=2024-01-01```

* lastday - required argument to set the last day for searching incidents

Example:
    ```lastday=2024-03-31```

* thisyearlist - required argument for XSOAR list where current year results are stored

Example:
    ```thisyearlist=MetricsThisYear```

* lastyearlist - required argument for XSOAR list when the year rolls, "thisyearslist" is copied here

Example:
    ```lastyearlist=MetricsLastYear```

* mode -  argument controls saving monthly statistics in this year's XSOAR list (a JSON object) as specified in the "thisyearlist" argument:  
    * increment
    * noupdate
    * initialize

The default mode is "mode=increment" and expects the time windows for each query to be contiguous months with no gaps or overlaps in the time window specified by the "firstday" and "lastday" arguments. If the time windows overlap, then incidents will be double counted. If there are gaps between time windows, then incidents may be missed.  If the query needs to run and not update the saved statistics, use "mode=noupdate".  In the event a month with saved statistics needs to be rebuilt, use "mode=initialize" with the first day and the last day of the month to reset the values.

* slatimers - optional argument for a CSV list of custom SLA timer fields to include in the metrics 

Example:
    ```slatimers="customsla1,customsla2,customsla3"```

* filters - optional argument is a CSV list thats support the following field names to filter incidents on:
    * severity              
        * unknown
        * information
        * low
        * medium
        * high
        * critical
    * status or notstatus
        * pending
        * active
        * done
        * archive
    * type
        * is the name of a single incident type
    * owner
        * is the name of a single incident owner

Example: 
    ```filters="type=typea,status=done,severity=high"```

* query - if this parameter is passed, the "filters" argument is ignored. The "query" parameter is a Lucene/Bleve search string the same as is used in the incidents search box in the XSOAR console.  The "query" string is used to select which incidents - you do not specify any dates. These are controlled by the "firstday" and  "lastday" parameters.

* windowstart and windowend - if these parameters are passed with the name of timer fields as values, the duration is calculated from **windowend.endDate** - **windowstart.startDate** for the "UserWindow" synthetic SLA metric

* esflag - If using Elasticsearch, you may need to set this to "true" if more than 10000 incidents in a two day period.  Elasticsearch has a 10000 incident search limit and this flag reduces the search windows from 2 days to to 4 hours

#### XMetrics

Dashboard widget script that presents monthly values over the year from the metrics list

##### Inputs

* listname - the XSOAR list with stored metrics for the year
* efflistname - XSOAR incident effort list with manual and automated effort estimates by incident type
* metrictype - type of metric to display in the dashboard widget
    * SLA Metrics
    * Closed Incidents
    * Incidents
    * Incident Open Duration
    * Effort Reduction

Example: 
    ```XMetrics listname=MetricsThisYear efflistname=IncidentEffort metrictype="SLA Metrics"```

#### XMetricsTotal

Dashboard widget script that presents annual totals over the current year from the metrics list

##### Inputs

* listname - the XSOAR metrics list with stored metrics for the year
* efflistname - XSOAR incident effort list with manual and automated effort estimates by incident type
* metrictype - type of metric to display in the dashboard widget
    * SLA Metrics
    * Closed Incidents
    * Incidents
    * Incident Open Duration
    * Effort Reduction

Example: 
    ```XMetricsTotal listname=MetricsThisYear efflistname=IncidentEffort metrictype="Effort Reduction"```

#### XMetricsYear

Dashboard widget script that reads the year from a metric list

##### Inputs

* listname - the XSOAR metrics list with stored metrics for the year

Example: 
    ```XMetricsYear listname=MetricsLastYear```


