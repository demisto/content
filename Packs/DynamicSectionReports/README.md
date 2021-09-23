Dynamic sections allow you to populate content into indicator and incident layouts using an automation script.
The `DisplayIndicatorReputationContent` automation contained in this pack makes it easy to display all reputation information collected for a particular indicator directly on its layout.

<img src="https://github.com/demisto/content/raw/0ab37a70cd964e903a8fae02501bff3577c1fc67/Packs/DynamicSectionReports/doc_files/indicator_report.png" width="500px" />

The `DisplayTaggedWarroomEntries` automation allows for a tab on an incident layout to be populated with a dynamic section which grabs warroom entries that are tagged with the "report" tag.

You can add the "report" tag directly on entries in the warroom


<img src="https://github.com/demisto/content/raw/0bc8b78953fc735f29224735f9a6bf8a804c5539/Packs/DynamicSectionReports/doc_files/tag-warroom.png" width="500px" />

or tags can be automatically applied on each task in the playbook editor

<img src="https://github.com/demisto/content/raw/0bc8b78953fc735f29224735f9a6bf8a804c5539/Packs/DynamicSectionReports/doc_files/tag-playbook.png" width="500px" />

An incident level report can then be generated from this tab in the layout.

<img src="https://github.com/demisto/content/raw/0ab37a70cd964e903a8fae02501bff3577c1fc67/Packs/DynamicSectionReports/doc_files/incident_report.png" width="500px" />
