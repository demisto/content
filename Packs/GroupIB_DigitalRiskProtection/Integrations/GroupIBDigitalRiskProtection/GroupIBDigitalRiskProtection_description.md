### Group-IB Digital Risk Protection  

- This section explains how to configure the **Digital Risk Protection** instance in **Cortex XSOAR**.  

#### Step 1: Open the Group-IB TI Web Interface  
1. Go to [https://drp.group-ib.com](https://drp.group-ib.com).  

#### Step 2: Generate an API Key (Password)  
2.1 In the new interface:  
   - Click on your name in the upper-right corner.  
   - Select **Profile**.  
   - Navigate to the **Security and Access** tab.  
   - Click **Personal Token** and follow the instructions to generate an API token.  

#### Step 3: Set Up Connection Details  
3. Your **server URL** is the same as your **DRP web interface URL**.  
4. Your **username** is the email address you use to log in to the web interface.  

#### Step 4: Configure Classifier and Mapper  
5. Set the **Classifier** and **Mapper** using the **Group-IB Digital Risk Protection** classifier and mapper.  
   - Alternatively, you can use your own configuration if needed.  

#### Step 5: Configure Pre-Processing Rules  
6. Navigate to **Settings → Integrations → Pre-Processing Rules** and create a new rule:  
   - **Condition**: `"gibdrpid" is not empty (General)`.  
   - **Action**: `"Run a script"`.  
   - **Script**: `"GIBDRPIncidentUpdate"` – Updates existing incidents without reopening those that were previously closed.  

#### Step 6: Whitelist Your Cortex XSOAR IP  
7. Contact **Group-IB** to add your **Cortex XSOAR IP** or the **public IP** of the proxy used with Cortex to the allowlist.  

