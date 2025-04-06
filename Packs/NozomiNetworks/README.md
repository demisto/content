Nozomi Networks integration
==================================

The Nozomi Networks platform is used to monitor OT/IoT/IT networks. It combines asset discovery, network visualization, vulnerability assessment, risk monitoring and threat detection in a single solution.

This integration is used to gather alert and asset information from Nozomi.

---

##### What does this pack do?

With the **NozomiNetworks** pack you can:

* Manage incidents
  * Import and sync the Nozomi incidents
    * You have to look for _Nozomi Networks_ in the **Settings** > **Integrations** > **Servers & Services** section and add an instance.
  * Through the _**nozomi-close-incidents-as-change**_ and _**nozomi-close-incidents-as-security**_ commands close  the incidents inside the Nozomi platform
* Find assets
  * the command _**nozomi-find-assets**_ return the asset filtered with the attributes passed.
* Query Nozomi entities
  * the _**nozomi-query**_ is a generic command that can be used to query all the Nozomi entities.
* Find ip by mac
  * with the command _**nozomi-find-ip-by-mac**_

---

##### Some useful links to get more information and resources of Nozomi Networks products  

* [Nozomi Networks site.](https://www.nozominetworks.com)
* [Nozomi Networks community edition](https://community.nozominetworks.com/support.html)
