### Group-IB Digital Risk Protection  

- This section explains how to configure the **Digital Risk Protection** instance in **Cortex XSOAR**.  

#### Step 1: Open the Group-IB TI Web Interface  
1.1 Go to [https://drp.group-ib.com](https://drp.group-ib.com).  

#### Step 2: Generate an API Key  
2.1 In the new interface:  
  - Log in to your account on DRP: [drp.group-ib.com](drp.group-ib.com)
  - Go to the Help Center / API [direct link](https://drp.group-ib.com/p/info/api).
  - Click the big blue button **Generate API key** at the top of the page. Then an API key will show up nearby.

#### Step 3: Set Up Connection Details  
3.1 **Server URL:** Use your **DRP web interface URL**.  
3.2 **Username:** The email address used to log in to the web interface.  

#### Step 4: Configure Classifier and Mapper  
4.1 Set the **Classifier** and **Mapper** using the **Group-IB Digital Risk Protection** classifier and mapper.  
Note: Alternatively, you may configure your own setup if needed.  

#### Step 5: Configure Pre-Processing Rules  
5.1 Navigate to **Settings → Integrations → Pre-Processing Rules** and create a new rule:  
   - **Condition**: `"gibdrpid" is not empty (General)`.  
   - **Action**: `"Run a script"`.  
   - **Script**: `"GIBDRPIncidentUpdate"` – Updates existing incidents without reopening those that were previously closed.  

#### Step 6: Whitelist Your Cortex XSOAR IP  
6.1 Contact **Group-IB support** to add your **Cortex XSOAR IP** or the **proxy public IP** used with Cortex to the allowlist.  
