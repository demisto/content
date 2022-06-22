# Automation - Unit42Enrichment
This automation can be used to enrich indicators using Unit42 Source. 
Requires XSOAR REST API integration enabled.  


  ## How to Use
  1. Download from Github
  2. Upload to XSOAR Automations
  3. Can invoke from a playbook task, CLI, other automation or as an action button on the indicator layout.  

  ### Parameters
  1. indicator - Indicator value to enrich. 
  
  ### Prerequisites
  XSOAR REST API
    
  ## Example   
  1. Used in the CLI:
  `!Unit42Enrichment indicator="145.5.56.3"`
