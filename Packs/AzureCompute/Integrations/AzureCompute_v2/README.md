<p>
Create and Manage Azure Virtual Machines
<br/>
This integration was integrated and tested with Azure Compute API Version: 2017-12-01.
</p>
<h2>Authentication</h2>
For more details about the authentication used in this integration, see <a href="https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication">Microsoft Integrations - Authentication</a>.

<ul>
<li>After authorizing the Demisto app, you will get an ID, Token, and Key, which should be inserted in the integration instance configuration's corresponding fields. After giving consent, the application has to have a role assigned so it can access the relevant resources per subscription. </li>
<li>In order to assign a role to the application after consent was given: 
  <ul>
    <li>Go to the Azure Portal UI.</li>
    <li>Go to Subscriptions, and then Access Control (IAM).</li>
    <li>Click Add.</li>
    <li>Select a role that includes the following permissions:
    <ul>
      <li>Microsoft.Compute/virtualMachines/*</li>
      <li>Microsoft.Network/networkInterfaces/read</li>
      <li>Microsoft.Resources/subscriptions/resourceGroups/read</li>
    </ul> </li>
    <li>Select the Azure Compute application.</li>
  </ul>
</li>
</ul>
<h2>Configure Azure Compute v2 on Demisto</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for Azure Compute v2.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>Host URL (e.g. https://management.azure.com)</strong></li>
   <li><strong>ID (received from the admin consent - see Detailed Instructions (?)</strong></li>
   <li><strong>Token (received from the admin consent - see Detailed Instructions (?) section)</strong></li>
   <li><strong>Key (received from the admin consent - see Detailed Instructions (?)</strong></li>
   <li><strong>Default Subscription ID</strong></li>
   <li><strong>Use system proxy</strong></li>
   <li><strong>Trust any certificate (not secure)</strong></li>
   <li><strong>Use a self-deployed Azure Application</strong></li>
    </ul>
  </li>
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>

<div class="cl-preview-section">
  <h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section">
  <p>
    You can execute these commands from the Demisto CLI, as part of an automation,
    or in a playbook. After you successfully execute a command, a DBot message
    appears in the War Room with the command details.
  </p>
</div>
<div class="cl-preview-section">
  <ol>
    <li>
      <a href="#list-vm-instances-for-a-resource-group" target="_self">List VM instances for a resource group: azure-vm-list-instances</a>
    </li>
    <li>
      <a href="#power-on-a-vm" target="_self">Power on a VM: azure-vm-start-instance</a>
    </li>
    <li>
      <a href="#power-off-a-vm" target="_self">Power off a VM: azure-vm-poweroff-instance</a>
    </li>
    <li>
      <a href="#get-details-for-a-vm" target="_self">Get details for a VM: azure-vm-get-instance-details</a>
    </li>
    <li>
      <a href="#create-a-vm-instance" target="_self">Create a VM instance: azure-vm-create-instance</a>
    </li>
    <li>
      <a href="#list-all-subscriptions-for-the-application" target="_self">List all subscriptions for the application: azure-list-subscriptions</a>
    </li>
    <li>
      <a href="#list-all-resource-groups-for-the-azure-subscription" target="_self">List all resource groups for the Azure subscription: azure-list-resource-groups</a>
    </li>
    <li>
      <a href="#delete-a-vm-instance" target="_self">Delete a VM instance: azure-vm-delete-instance</a>
    </li>
  </ol>
</div>
<div class="cl-preview-section">
  <h3 id="list-vm-instances-for-a-resource-group">1. List VM instances for a resource group</h3>
</div>
<div class="cl-preview-section">
  <hr>
</div>
<div class="cl-preview-section">
  <p>List the VM instances in the specified Resource Group.</p>
</div>
<div class="cl-preview-section">
  <h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
  <p>
    <code>azure-vm-list-instances</code>
  </p>
</div>
<div class="cl-preview-section">
  <h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:747px">
      <thead>
        <tr>
          <th style="width:130px">
            <strong>Argument Name</strong>
          </th>
          <th style="width:539px">
            <strong>Description</strong>
          </th>
          <th style="width:71px">
            <strong>Required</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:130px">resource_group</td>
          <td style="width:539px">
            Resource Group of the VMs. To see all the resource groups
            associated with your subscription try executing the&nbsp;<code>azure-list-resource-groups</code>&nbsp;command.
            If none are present then please visit the Azure Web Portal
            to create resource groups.
          </td>
          <td style="width:71px">Required</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h5 id="context-output">Context Output</h5>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:748px">
      <thead>
        <tr>
          <th style="width:329px">
            <strong>Path</strong>
          </th>
          <th style="width:45px">
            <strong>Type</strong>
          </th>
          <th style="width:366px">
            <strong>Description</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:329px">Azure.Compute.Name</td>
          <td style="width:45px">string</td>
          <td style="width:366px">Name of the VM</td>
        </tr>
        <tr>
          <td style="width:329px">Azure.Compute.Location</td>
          <td style="width:45px">string</td>
          <td style="width:366px">Location of the VM</td>
        </tr>
        <tr>
          <td style="width:329px">Azure.Compute.ProvisioningState</td>
          <td style="width:45px">string</td>
          <td style="width:366px">Provisioning State of the VM</td>
        </tr>
        <tr>
          <td style="width:329px">Azure.Compute.ResourceGroup</td>
          <td style="width:45px">string</td>
          <td style="width:366px">Resource group where the VM resides in</td>
        </tr>
        <tr>
          <td style="width:329px">Azure.Compute.ID</td>
          <td style="width:45px">string</td>
          <td style="width:366px">ID of the VM</td>
        </tr>
        <tr>
          <td style="width:329px">Azure.Compute.Size</td>
          <td style="width:45px">number</td>
          <td style="width:366px">Size of the deployed VM (in GB)</td>
        </tr>
        <tr>
          <td style="width:329px">Azure.Compute.OS</td>
          <td style="width:45px">string</td>
          <td style="width:366px">OS running on the VM</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h5 id="command-example">Command Example</h5>
</div>
<div class="cl-preview-section">
  <pre>!azure-vm-list-instances resource_group=compute-integration</pre>
</div>
<div class="cl-preview-section">
  <h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
  <pre>{
    "Azure.Compute": [
        {
            "Name": "TestOAuth", 
            "ResourceGroup": "compute-integration", 
            "Location": "westeurope", 
            "Size": 32, 
            "OS": "Linux", 
            "ID": "a050ff2e-85ab-44d9-b822-3bc3111739e0", 
            "ProvisioningState": "Succeeded"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
  <h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
  <h3 id="microsoft-azure---list-of-virtual-machines-in-resource-group-compute-integration">
    Microsoft Azure - List of Virtual Machines in Resource Group “compute-integration”
  </h3>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:641px">
      <thead>
        <tr>
          <th style="width:55px">Name</th>
          <th style="width:187px">ID</th>
          <th style="width:10px">Size</th>
          <th style="width:20px">OS</th>
          <th style="width:82px">Location</th>
          <th style="width:167px">ProvisioningState</th>
          <th style="width:112px">ResourceGroup</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:55px">TestOAuth</td>
          <td style="width:187px">a050ff2e-85ab-44d9-b822-3bc3111739e0</td>
          <td style="width:10px">32</td>
          <td style="width:20px">Linux</td>
          <td style="width:82px">westeurope</td>
          <td style="width:167px">Succeeded</td>
          <td style="width:112px">compute-integration</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h3 id="power-on-a-vm">2. Power on a VM</h3>
</div>
<div class="cl-preview-section">
  <hr>
</div>
<div class="cl-preview-section">
  <p>Powers-on a specified VM.</p>
</div>
<div class="cl-preview-section">
  <h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
  <p>
    <code>azure-vm-start-instance</code>
  </p>
</div>
<div class="cl-preview-section">
  <h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:745px">
      <thead>
        <tr>
          <th style="width:130px">
            <strong>Argument Name</strong>
          </th>
          <th style="width:556px">
            <strong>Description</strong>
          </th>
          <th style="width:54px">
            <strong>Required</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:130px">resource_group</td>
          <td style="width:556px">
            Resource Group to which the virtual machine belongs.<br>
            To see all the resource groups associated with your subscription
            try executing the&nbsp;<code>azure-list-resource-groups</code>&nbsp;command.
            If none are present visit the Azure Web Portal to create
            resource groups.
          </td>
          <td style="width:54px">Required</td>
        </tr>
        <tr>
          <td style="width:130px">virtual_machine_name</td>
          <td style="width:556px">
            Name of the virtual machine to power-on.<br>
            To see all the VMs with their associated names for a specific
            resource group try executing the&nbsp;<code>azure-vm-list-instances</code>&nbsp;command.
          </td>
          <td style="width:54px">Required</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h5 id="context-output-1">Context Output</h5>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:748px">
      <thead>
        <tr>
          <th style="width:295px">
            <strong>Path</strong>
          </th>
          <th style="width:36px">
            <strong>Type</strong>
          </th>
          <th style="width:409px">
            <strong>Description</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:295px">Azure.Compute.Name</td>
          <td style="width:36px">string</td>
          <td style="width:409px">Name of the VM that was started</td>
        </tr>
        <tr>
          <td style="width:295px">Azure.Compute.ResourceGroup</td>
          <td style="width:36px">string</td>
          <td style="width:409px">Resource group the VM resides in</td>
        </tr>
        <tr>
          <td style="width:295px">Azure.Compute.PowerState</td>
          <td style="width:36px">string</td>
          <td style="width:409px">Whether the VM instance is powered on or off</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h5 id="command-example-1">Command Example</h5>
</div>
<div class="cl-preview-section">
  <pre>!azure-vm-start-instance resource_group=compute-integration virtual_machine_name=TestOAuth</pre>
</div>
<div class="cl-preview-section">
  <h5 id="context-example-1">Context Example</h5>
</div>
<div class="cl-preview-section">
  <pre>{
    "Azure.Compute": {
        "ResourceGroup": "compute-integration", 
        "PowerState": "VM starting", 
        "Name": "TestOAuth"
    }
}
</pre>
</div>
<div class="cl-preview-section">
  <h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
  <h3 id="power-on-of-virtual-machine-testoauth-successfully-initiated">
    Power-on of Virtual Machine “TestOAuth” Successfully Initiated
  </h3>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:750px">
      <thead>
        <tr>
          <th style="width:175px">ResourceGroup</th>
          <th style="width:100px">PowerState</th>
          <th style="width:108px">Name</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:175px">compute-integration</td>
          <td style="width:100px">VM starting</td>
          <td style="width:108px">TestOAuth</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h3 id="power-off-a-vm">3. Power off a VM</h3>
</div>
<div class="cl-preview-section">
  <hr>
</div>
<div class="cl-preview-section">
  <p>Powers-off a specified VM.</p>
</div>
<div class="cl-preview-section">
  <h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
  <p>
    <code>azure-vm-poweroff-instance</code>
  </p>
</div>
<div class="cl-preview-section">
  <h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:746px">
      <thead>
        <tr>
          <th style="width:107px">
            <strong>Argument Name</strong>
          </th>
          <th style="width:587px">
            <strong>Description</strong>
          </th>
          <th style="width:46px">
            <strong>Required</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:107px">resource_group</td>
          <td style="width:587px">
            Resource Group to which the virtual machine belongs.<br>
            To see all the resource groups associated with your subscription
            try executing the&nbsp;<code>azure-list-resource-groups</code>&nbsp;command.
            If none are present then please visit the Azure Web Portal
            to create resource groups.
          </td>
          <td style="width:46px">Required</td>
        </tr>
        <tr>
          <td style="width:107px">virtual_machine_name</td>
          <td style="width:587px">
            Name of the virtual machine to power-off.<br>
            To see all the VMs with their associated names for a specific
            resource group try executing the&nbsp;<code>azure-vm-list-instances</code>&nbsp;command.
          </td>
          <td style="width:46px">Required</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h5 id="context-output-2">Context Output</h5>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:748px">
      <thead>
        <tr>
          <th style="width:292px">
            <strong>Path</strong>
          </th>
          <th style="width:39px">
            <strong>Type</strong>
          </th>
          <th style="width:409px">
            <strong>Description</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:292px">Azure.Compute.Name</td>
          <td style="width:39px">string</td>
          <td style="width:409px">Name of the VM that was powered down</td>
        </tr>
        <tr>
          <td style="width:292px">Azure.Compute.ResourceGroup</td>
          <td style="width:39px">string</td>
          <td style="width:409px">Resource group the VM resides in</td>
        </tr>
        <tr>
          <td style="width:292px">Azure.Compute.PowerState</td>
          <td style="width:39px">string</td>
          <td style="width:409px">Whether the VM instance is powered on or off</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h5 id="command-example-2">Command Example</h5>
</div>
<div class="cl-preview-section">
  <pre>!azure-vm-poweroff-instance resource_group=compute-integration virtual_machine_name=TestOAuth</pre>
</div>
<div class="cl-preview-section">
  <h5 id="context-example-2">Context Example</h5>
</div>
<div class="cl-preview-section">
  <pre>{
    "Azure.Compute": {
        "ResourceGroup": "compute-integration", 
        "PowerState": "VM stopping", 
        "Name": "TestOAuth"
    }
}
</pre>
</div>
<div class="cl-preview-section">
  <h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
  <h3 id="power-off-of-virtual-machine-testoauth-successfully-initiated">
    Power-off of Virtual Machine “TestOAuth” Successfully Initiated
  </h3>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:429px">
      <thead>
        <tr>
          <th style="width:216px">ResourceGroup</th>
          <th style="width:133px">PowerState</th>
          <th style="width:73px">Name</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:216px">compute-integration</td>
          <td style="width:133px">VM stopping</td>
          <td style="width:73px">TestOAuth</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h3 id="get-details-for-a-vm">4. Get details for a VM</h3>
</div>
<div class="cl-preview-section">
  <hr>
</div>
<div class="cl-preview-section">
  <p>Gets the properties of a specified VM.</p>
</div>
<div class="cl-preview-section">
  <h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
  <p>
    <code>azure-vm-get-instance-details</code>
  </p>
</div>
<div class="cl-preview-section">
  <h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:749px">
      <thead>
        <tr>
          <th style="width:185px">
            <strong>Argument Name</strong>
          </th>
          <th style="width:484px">
            <strong>Description</strong>
          </th>
          <th style="width:71px">
            <strong>Required</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:185px">resource_group</td>
          <td style="width:484px">
            Resource Group to which the virtual machine belongs.<br>
            To see all the resource groups associated with your subscription
            try executing the&nbsp;<code>azure-list-resource-groups</code>&nbsp;command.
            If none are present then please visit the Azure Web Portal
            to create resource groups.
          </td>
          <td style="width:71px">Required</td>
        </tr>
        <tr>
          <td style="width:185px">virtual_machine_name</td>
          <td style="width:484px">
            Name of the virtual machine you wish to view the details
            of.<br>
            To see all the VMs with their associated names for a specific
            resource group try executing the&nbsp;<code>azure-vm-list-instances</code>&nbsp;command.
          </td>
          <td style="width:71px">Required</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h5 id="context-output-3">Context Output</h5>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:748px">
      <thead>
        <tr>
          <th style="width:303px">
            <strong>Path</strong>
          </th>
          <th style="width:45px">
            <strong>Type</strong>
          </th>
          <th style="width:392px">
            <strong>Description</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:303px">Azure.Compute.Name</td>
          <td style="width:45px">string</td>
          <td style="width:392px">Name of the VM whose details were requested</td>
        </tr>
        <tr>
          <td style="width:303px">Azure.Compute.ID</td>
          <td style="width:45px">string</td>
          <td style="width:392px">ID of the VM</td>
        </tr>
        <tr>
          <td style="width:303px">Azure.Compute.Size</td>
          <td style="width:45px">number</td>
          <td style="width:392px">Size of the deployed VM in gigabytes</td>
        </tr>
        <tr>
          <td style="width:303px">Azure.Compute.OS</td>
          <td style="width:45px">string</td>
          <td style="width:392px">OS running in the specified VM</td>
        </tr>
        <tr>
          <td style="width:303px">Azure.Compute.ProvisioningState</td>
          <td style="width:45px">string</td>
          <td style="width:392px">Provisioning state of the deployed VM</td>
        </tr>
        <tr>
          <td style="width:303px">Azure.Compute.Location</td>
          <td style="width:45px">string</td>
          <td style="width:392px">Region in which the VM is hosted</td>
        </tr>
        <tr>
          <td style="width:303px">Azure.Compute.PowerState</td>
          <td style="width:45px">string</td>
          <td style="width:392px">Whether the VM instance is powered on or off</td>
        </tr>
        <tr>
          <td style="width:303px">Azure.Compute.ResourceGroup</td>
          <td style="width:45px">string</td>
          <td style="width:392px">Resource group in which the VM belongs</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h5 id="command-example-3">Command Example</h5>
</div>
<div class="cl-preview-section">
  <pre>!azure-vm-get-instance-details resource_group=compute-integration virtual_machine_name=TestOAuth</pre>
</div>
<div class="cl-preview-section">
  <h5 id="context-example-3">Context Example</h5>
</div>
<div class="cl-preview-section">
  <pre>{
    "Azure.Compute": {
        "PowerState": "VM starting", 
        "Name": "TestOAuth", 
        "ResourceGroup": "compute-integration", 
        "Location": "westeurope", 
        "Size": 32, 
        "OS": "Linux", 
        "ID": "a050ff2e-85ab-44d9-b822-3bc3111739e0", 
        "ProvisioningState": "Updating"
    }
}
</pre>
</div>
<div class="cl-preview-section">
  <h5 id="human-readable-output-3">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
  <h3 id="properties-of-vm-testoauth">Properties of VM “TestOAuth”</h3>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:750px">
      <thead>
        <tr>
          <th style="width:49px">Name</th>
          <th style="width:359px">ID</th>
          <th style="width:30px">Size</th>
          <th style="width:10px">OS</th>
          <th style="width:152px">ProvisioningState</th>
          <th style="width:57px">Location</th>
          <th style="width:105px">PowerState</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:49px">TestOAuth</td>
          <td style="width:359px">a050ff2e-85ab-44d9-b822-3bc3111739e0</td>
          <td style="width:30px">32</td>
          <td style="width:10px">Linux</td>
          <td style="width:152px">Updating</td>
          <td style="width:57px">westeurope</td>
          <td style="width:105px">VM starting</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h3 id="create-a-vm-instance">5. Create a VM instance</h3>
</div>
<div class="cl-preview-section">
  <hr>
</div>
<div class="cl-preview-section">
  <p>
    Creates a virtual machine instance with the specified OS image.
  </p>
</div>
<div class="cl-preview-section">
  <h5 id="base-command-4">Base Command</h5>
</div>
<div class="cl-preview-section">
  <p>
    <code>azure-vm-create-instance</code>
  </p>
</div>
<div class="cl-preview-section">
  <h5 id="input-4">Input</h5>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:785px">
      <thead>
        <tr>
          <th style="width:167px">
            <strong>Argument Name</strong>
          </th>
          <th style="width:534px">
            <strong>Description</strong>
          </th>
          <th style="width:75px">
            <strong>Required</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:167px">resource_group</td>
          <td style="width:534px">
            Resource group to which the new VM will belong.<br>
            To see all the resource groups associated with your subscription
            try executing the&nbsp;<code>azure-list-resource-groups</code>&nbsp;command.
            If none are present then please visit the Azure Web Portal
            to create resource groups.
          </td>
          <td style="width:75px">Required</td>
        </tr>
        <tr>
          <td style="width:167px">virtual_machine_name</td>
          <td style="width:534px">Name of the virtual machine to create</td>
          <td style="width:75px">Required</td>
        </tr>
        <tr>
          <td style="width:167px">virtual_machine_location</td>
          <td style="width:534px">Location to create the VM</td>
          <td style="width:75px">Required</td>
        </tr>
        <tr>
          <td style="width:167px">nic_name</td>
          <td style="width:534px">
            The name of the Network Interface to link the VM with. A
            Network Interface has to be created from within the Azure
            Portal. Note that the vm’s location property must match that
            of the Network Interface you choose to link it to.<br>
            To see a list of available Network Interfaces visit the Azure
            Web Portal, navigate to the search bar at the top of the
            page, type in ‘network interfaces’ and in the drop-down menu
            that appears as you type, click on the ‘Network interfaces’
            option that appears under the ‘Services’ category. If none
            are present, you will need to create a new Network Interface
            which you can do by clicking the ‘+Add’ button towards the
            top left of the page and following the instructions.<br>
            For more information regarding Network Interfaces see the&nbsp;<a href="https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-network-interface" target="_self">Microsoft API documentation</a>.
          </td>
          <td style="width:75px">Required</td>
        </tr>
        <tr>
          <td style="width:167px">vm_size</td>
          <td style="width:534px">
            The name of a VirtualMachineSize which determines the size
            of the deployed vm.<br>
            For more information see the&nbsp;<a href="https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines/listavailablesizes#virtualmachinesize" target="_self">Microsoft API documentation</a>.
          </td>
          <td style="width:75px">Required</td>
        </tr>
        <tr>
          <td style="width:167px">os_image</td>
          <td style="width:534px">Choose the base operating system image of the vm</td>
          <td style="width:75px">Optional</td>
        </tr>
        <tr>
          <td style="width:167px">sku</td>
          <td style="width:534px">
            SKU of the OS image to be used.<br>
            To see a list of available SKUs, visit your Azure Web Portal,
            click the symbol that looks similar to a ‘&gt;’ along the
            top bar of the page which should open a cloud shell. Make
            sure it is a bash shell.<br>
            At the command prompt enter&nbsp;<code>az vm image list-skus</code>&nbsp;along
            with the appropriate arguments that it will prompt you with
            to display the list of VM image SKUs available in the Azure
            Marketplace.
          </td>
          <td style="width:75px">Optional</td>
        </tr>
        <tr>
          <td style="width:167px">publisher</td>
          <td style="width:534px">
            Name of the publisher of the OS image.<br>
            To see a list of available publishers, visit your Azure Web
            Portal, click the symbol that looks similar to a ‘&gt;’ along
            the top bar of the page which should open a cloud shell.
            Make sure it is a bash shell.<br>
            At the command prompt enter&nbsp;<code>az vm image list-publishers</code>&nbsp;along
            with the appropriate arguments that it will prompt you with
            to display the list of VM image publishers available in the
            Azure Marketplace.
          </td>
          <td style="width:75px">Optional</td>
        </tr>
        <tr>
          <td style="width:167px">version</td>
          <td style="width:534px">
            Version of the image to use.<br>
            The allowed formats are Major.Minor.Build or ‘latest’. Major,
            Minor, and Build are decimal numbers.<br>
            Specify ‘latest’ to use the latest version of an image available
            at deploy time.
          </td>
          <td style="width:75px">Optional</td>
        </tr>
        <tr>
          <td style="width:167px">offer</td>
          <td style="width:534px">
            Specifies the offer of the platform image or marketplace
            image used to create the virtual machine.<br>
            To see a list of available offers, visit your Azure Web Portal,
            click the symbol that looks similar to a ‘&gt;’ along the
            top bar of the page which should open a cloud shell. Make
            sure it is a bash shell.<br>
            At the command prompt enter&nbsp;<code>az vm image list-offers</code>&nbsp;along
            with the appropriate arguments that it will prompt you with
            to display the list of VM image offers available in the Azure
            Marketplace.
          </td>
          <td style="width:75px">Optional</td>
        </tr>
        <tr>
          <td style="width:167px">admin_username</td>
          <td style="width:534px">Admin Username to be used when creating the VM</td>
          <td style="width:75px">Optional</td>
        </tr>
        <tr>
          <td style="width:167px">admin_password</td>
          <td style="width:534px">Admin Password to be used when creating the VM</td>
          <td style="width:75px">Optional</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h5 id="context-output-4">Context Output</h5>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:746px">
      <thead>
        <tr>
          <th style="width:310px">
            <strong>Path</strong>
          </th>
          <th style="width:41px">
            <strong>Type</strong>
          </th>
          <th style="width:389px">
            <strong>Description</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:310px">Azure.Compute.Name</td>
          <td style="width:41px">string</td>
          <td style="width:389px">Name of the created VM instance</td>
        </tr>
        <tr>
          <td style="width:310px">Azure.Compute.ResourceGroup</td>
          <td style="width:41px">string</td>
          <td style="width:389px">Resource group the VM resides in</td>
        </tr>
        <tr>
          <td style="width:310px">Azure.Compute.ID</td>
          <td style="width:41px">string</td>
          <td style="width:389px">ID of the VM</td>
        </tr>
        <tr>
          <td style="width:310px">Azure.Compute.Size</td>
          <td style="width:41px">number</td>
          <td style="width:389px">Size of the deployed VM in gigabytes</td>
        </tr>
        <tr>
          <td style="width:310px">Azure.Compute.OS</td>
          <td style="width:41px">string</td>
          <td style="width:389px">OS running in the specified VM</td>
        </tr>
        <tr>
          <td style="width:310px">Azure.Compute.ProvisioningState</td>
          <td style="width:41px">string</td>
          <td style="width:389px">Provisioning state of the deployed VM</td>
        </tr>
        <tr>
          <td style="width:310px">Azure.Compute.Location</td>
          <td style="width:41px">string</td>
          <td style="width:389px">Region in which the VM is hosted</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h5 id="command-example-4">Command Example</h5>
</div>
<div class="cl-preview-section">
  <pre>!azure-vm-create-instance resource_group=compute-integration nic_name=compute-integration-nic1 virtual_machine_location=westeurope vm_size=Standard_D1_v2 virtual_machine_name=DemoVM os_image="Ubuntu Server 18.04 LTS"</pre>
</div>
<div class="cl-preview-section">
  <h5 id="context-example-4">Context Example</h5>
</div>
<div class="cl-preview-section">
  <pre>{
    "Azure.Compute": {
        "Name": "DemoVM", 
        "ResourceGroup": "compute-integration", 
        "Location": "westeurope", 
        "Size": "NA", 
        "OS": "Linux", 
        "ID": "106a46b3-e999-44fd-be41-270a76e722fa", 
        "ProvisioningState": "Creating"
    }
}
</pre>
</div>
<div class="cl-preview-section">
  <h5 id="human-readable-output-4">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
  <h3 id="created-virtual-machine-demovm">Created Virtual Machine “DemoVM”</h3>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:643px">
      <thead>
        <tr>
          <th style="width:46px">Name</th>
          <th style="width:182px">ResourceGroup</th>
          <th style="width:21px">Location</th>
          <th style="width:38px">Size</th>
          <th style="width:41px">OS</th>
          <th style="width:160px">ID</th>
          <th style="width:140px">ProvisioningState</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:46px">DemoVM</td>
          <td style="width:182px">compute-integration</td>
          <td style="width:21px">westeurope</td>
          <td style="width:38px">NA</td>
          <td style="width:41px">Linux</td>
          <td style="width:160px">106a46b3-e999-44fd-be41-270a76e722fa</td>
          <td style="width:140px">Creating</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h3 id="list-all-subscriptions-for-the-application">6. Lists the subscriptions for this application.</h3>
</div>
<div class="cl-preview-section">
  <hr>
</div>
<div class="cl-preview-section">
  <p>
    Lists the subscriptions for this application.
  </p>
</div>
<div class="cl-preview-section">
  <h5 id="base-command-5">Base Command</h5>
</div>
<div class="cl-preview-section">
  <p>
    <code>azure-list-subscriptions</code>
  </p>
</div>
<div class="cl-preview-section">
  <h5 id="input-6">Input</h5>
</div>
<div class="cl-preview-section">
  No inputs for this command.
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h5 id="context-output-5">Context Output</h5>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:747px">
      <thead>
        <tr>
          <th style="width:303px">
            <strong>Path</strong>
          </th>
          <th style="width:33px">
            <strong>Type</strong>
          </th>
          <th style="width:404px">
            <strong>Description</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:303px">Azure.Subscription.Name</td>
          <td style="width:33px">string</td>
          <td style="width:404px">Subscription Name</td>
        </tr>
        <tr>
          <td style="width:303px">Azure.Subscription.ID</td>
          <td style="width:33px">string</td>
          <td style="width:404px">Subscription ID</td>
        </tr>
        <td style="width:303px">Azure.Subscription.State</td>
          <td style="width:33px">string</td>
          <td style="width:404px">Subscription State</td>
      </tbody>
    </table>
  </div>
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h5 id="command-example-5">Command Example</h5>
</div>
<div class="cl-preview-section">
  <pre>!azure-list-subscriptions</pre>
</div>
<div class="cl-preview-section">
  <h5 id="context-example-5">Context Example</h5>
</div>
<div class="cl-preview-section">
  <pre>{
    "Azure.Subscription": [
        {
            "Name": "My subscription", 
            "ID": "/subscriptions/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/resourceGroups/cloud-shell-storage-eastus", 
            "State": "Enabled"
        }, 
    ]
}
</pre>
</div>
<div class="cl-preview-section">
  <h5 id="human-readable-output-5">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
  <h3 id="list-of-resource-groups">List of Resource Groups</h3>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:1036px">
      <thead>
        <tr>
          <th style="width:67px">ID</th>
          <th style="width:279px">Name</th>
          <th style="width:523px">State</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:523px">
            /subscriptions/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/resourceGroups/cloud-shell-storage-eastus
          </td>
          <td style="width:67px">My subscription</td>
          <td style="width:155px">Enabled</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
<div class="cl-preview-section">
  <h3 id="list-all-resource-groups-for-the-azure-subscription">6. List all resource groups for the Azure subscription</h3>
</div>
<div class="cl-preview-section">
  <hr>
</div>
<div class="cl-preview-section">
  <p>
    Lists all resource groups belonging to your Azure subscription.
  </p>
</div>
<div class="cl-preview-section">
  <h5 id="base-command-5">Base Command</h5>
</div>
<div class="cl-preview-section">
  <p>
    <code>azure-list-resource-groups</code>
  </p>
</div>
<div class="cl-preview-section">
  <h5 id="input-6">Input</h5>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:748px">
      <thead>
        <tr>
          <th style="width:162px">
            <strong>Argument Name</strong>
          </th>
          <th style="width:507px">
            <strong>Description</strong>
          </th>
          <th style="width:71px">
            <strong>Required</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:162px">subscription_id</td>
          <td style="width:507px">
            Subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions
            command. If not specified, the default subscripton ID will be used.
          </td>
          <td style="width:71px">Required</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h5 id="context-output-5">Context Output</h5>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:747px">
      <thead>
        <tr>
          <th style="width:303px">
            <strong>Path</strong>
          </th>
          <th style="width:33px">
            <strong>Type</strong>
          </th>
          <th style="width:404px">
            <strong>Description</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:303px">Azure.ResourceGroup.Name</td>
          <td style="width:33px">string</td>
          <td style="width:404px">Name of the Resource Group</td>
        </tr>
        <tr>
          <td style="width:303px">Azure.ResourceGroup.ID</td>
          <td style="width:33px">string</td>
          <td style="width:404px">ID of the Resource Group</td>
        </tr>
        <tr>
          <td style="width:303px">Azure.ResourceGroup.Location</td>
          <td style="width:33px">string</td>
          <td style="width:404px">Location of the Resource Group</td>
        </tr>
        <tr>
          <td style="width:303px">Azure.ResourceGroup.ProvisioningState</td>
          <td style="width:33px">string</td>
          <td style="width:404px">Provisioning State of the Resource Group</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h5 id="command-example-5">Command Example</h5>
</div>
<div class="cl-preview-section">
  <pre>!azure-list-resource-groups</pre>
</div>
<div class="cl-preview-section">
  <h5 id="context-example-5">Context Example</h5>
</div>
<div class="cl-preview-section">
  <pre>{
    "Azure.ResourceGroup": [
        {
            "Name": "cloud-shell-storage-eastus", 
            "ProvisioningState": "Succeeded", 
            "ID": "/subscriptions/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/resourceGroups/cloud-shell-storage-eastus", 
            "Location": "eastus"
        }, 
        {
            "Name": "compute-integration", 
            "ProvisioningState": "Succeeded", 
            "ID": "/subscriptions/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/resourceGroups/compute-integration", 
            "Location": "eastus"
        }, 
        {
            "Name": "NetworkWatcherRG", 
            "ProvisioningState": "Succeeded", 
            "ID": "/subscriptions/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/resourceGroups/NetworkWatcherRG", 
            "Location": "westeurope"
        }, 
        {
            "Name": "us-east-rg", 
            "ProvisioningState": "Succeeded", 
            "ID": "/subscriptions/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/resourceGroups/us-east-rg", 
            "Location": "eastus"
        }, 
        {
            "Name": "us-east-rg-backups", 
            "ProvisioningState": "Succeeded", 
            "ID": "/subscriptions/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/resourceGroups/us-east-rg-backups", 
            "Location": "westus"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
  <h5 id="human-readable-output-5">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
  <h3 id="list-of-resource-groups">List of Resource Groups</h3>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:1036px">
      <thead>
        <tr>
          <th style="width:67px">Location</th>
          <th style="width:155px">ProvisioningState</th>
          <th style="width:279px">Name</th>
          <th style="width:523px">ID</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:67px">eastus</td>
          <td style="width:155px">Succeeded</td>
          <td style="width:279px">cloud-shell-storage-eastus</td>
          <td style="width:523px">
            /subscriptions/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/resourceGroups/cloud-shell-storage-eastus
          </td>
        </tr>
        <tr>
          <td style="width:67px">eastus</td>
          <td style="width:155px">Succeeded</td>
          <td style="width:279px">compute-integration</td>
          <td style="width:523px">
            /subscriptions/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/resourceGroups/compute-integration
          </td>
        </tr>
        <tr>
          <td style="width:67px">westeurope</td>
          <td style="width:155px">Succeeded</td>
          <td style="width:279px">NetworkWatcherRG</td>
          <td style="width:523px">
            /subscriptions/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/resourceGroups/NetworkWatcherRG
          </td>
        </tr>
        <tr>
          <td style="width:67px">eastus</td>
          <td style="width:155px">Succeeded</td>
          <td style="width:279px">us-east-rg</td>
          <td style="width:523px">
            /subscriptions/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/resourceGroups/us-east-rg
          </td>
        </tr>
        <tr>
          <td style="width:67px">westus</td>
          <td style="width:155px">Succeeded</td>
          <td style="width:279px">us-east-rg-backups</td>
          <td style="width:523px">
            /subscriptions/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/resourceGroups/us-east-rg-backups
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h3 id="delete-a-vm-instance">7. Delete a VM instance</h3>
</div>
<div class="cl-preview-section">
  <hr>
</div>
<div class="cl-preview-section">
  <p>Deletes a specified VM instance.</p>
</div>
<div class="cl-preview-section">
  <h5 id="base-command-6">Base Command</h5>
</div>
<div class="cl-preview-section">
  <p>
    <code>azure-vm-delete-instance</code>
  </p>
</div>
<div class="cl-preview-section">
  <h5 id="input-6">Input</h5>
</div>
<div class="cl-preview-section">
  <div class="table-wrapper">
    <table style="width:748px">
      <thead>
        <tr>
          <th style="width:162px">
            <strong>Argument Name</strong>
          </th>
          <th style="width:507px">
            <strong>Description</strong>
          </th>
          <th style="width:71px">
            <strong>Required</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:162px">resource_group</td>
          <td style="width:507px">
            Resource Group to which the virtual machine belongs.<br>
            To see all the resource groups associated with your subscription
            try executing the&nbsp;<code>azure-list-resource-groups</code>&nbsp;command.
            If none are present then please visit the Azure Web Portal
            to create resource groups.
          </td>
          <td style="width:71px">Required</td>
        </tr>
        <tr>
          <td style="width:162px">virtual_machine_name</td>
          <td style="width:507px">
            Name of the virtual machine to delete.<br>
            To see all VMs with their associated names for a specific
            resource group try executing the&nbsp;<code>azure-vm-list-instances</code>&nbsp;command.
          </td>
          <td style="width:71px">Optional</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>
<p>&nbsp;</p>
<div class="cl-preview-section">
  <h5 id="context-output-6">Context Output</h5>
</div>
<div class="cl-preview-section">
  <p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
  <h5 id="command-example-6">Command Example</h5>
</div>
<div class="cl-preview-section">
  <pre>!azure-vm-delete-instance resource_group=compute-integration virtual_machine_name=DemoVM</pre>
</div>
<div class="cl-preview-section">
  <h5 id="human-readable-output-6">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
  <p>“DemoVM” VM Deletion Successfully Initiated</p>
</div>
