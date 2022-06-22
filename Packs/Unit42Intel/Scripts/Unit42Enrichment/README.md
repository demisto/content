# Automation - Unit42Enrichment
This automation can be used to enrich indicators using Unit42 Source. 
Requires Demisto REST API integration enabled.  

Created by Abel Santamarina, Verified on 6.2.0 b1578666, 6.6.0 b2585049

  ## How to Use
  1. Download from Github
  2. Upload to XSOAR Automations
  3. Can invoke from a playbook task, CLI, other automation or as an action button on the indicator layout.  

  ### Parameters
  1. indicator - Indicator value to enrich. 
  
  ### Prerequisites
  Demisto REST API
    
  ## Example   
  1. Used in the CLI:
  `!Unit42Enrichment indicator="145.5.56.3"`
    
  2. Used as an action button in the indicator layout
  ![2022-04-25 23_40_27-92 255 85 135](https://user-images.githubusercontent.com/89417559/165372440-96eecc01-eeb2-4d1b-9b15-2ee1910b85ce.png)
