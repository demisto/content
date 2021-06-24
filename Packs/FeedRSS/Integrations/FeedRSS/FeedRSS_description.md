
Configure the integration: If you want to fetch from several feeds, you need to configured an instance to each one of them.

The main part of RSS Feed integration is to use the *RSS Create Indicators From Report* playbook. Playbook tasks:
1. Extract indicators from article content.
2. Create relationships between the extracted indicators and the Report.
3. Run reputation commands on the extracted indicators. 

We recommend configuring a job that will execute this playbook. Recommended frequency - once a day. 

1. Configure a job that will run *RSS Create Indicators From Report* playbook. 
2. Configure Input to the *RSS Create Indicators From Report* playbook:
   
    2.1 From context data input: Tag name- indicator will be tagged with this value when the playbook finished process him, when all indicators were extracted and relationships were created.
   
    2.2 From indicators: Query to include only new report indicators that we have not processed them yet. Recommended query: "type:Report -tags:
   {Tag name configure on 2.1} -tags:in_process". One playbook start running he tags all indicators with "in_process" tag, and it removed when the playbook gets to an end.
   If you want the playbook to run on a specific instance (a specific feed) you should add to the query this filter: *sourceInstances:
   "{the selected instance}"*.

Popular security news feeds you can use: 

[https://threatpost.com/feed/](https://threatpost.com/feed/)

[https://feeds.feedburner.com/TheHackersNews](https://feeds.feedburner.com/TheHackersNews)

[https://www.securitymagazine.com/rss/articles](https://www.securitymagazine.com/rss/articles)

[https://www.darkreading.com/rss_feeds.asp](https://www.darkreading.com/rss_feeds.asp)

