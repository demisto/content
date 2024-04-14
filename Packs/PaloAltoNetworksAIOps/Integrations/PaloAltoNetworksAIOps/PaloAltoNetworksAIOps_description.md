## AIOps integration 

- The Palo Alto Networks Best Practice Assessment (BPA) measures your usage of our Next-Generation Firewall (NGFW) and Panorama™ security management capabilities across your deployment, enabling you to make adjustments that maximize your return on investment and strengthen security.
- This integration enables you to programmatically generate BPA data for both the free and premium instances of AIOps for NGFW.

## AIOps Authentication:
- Follow the instructions in this [link](https://pan.dev/aiops-ngfw-bpa/api/) to create your own client_id, client_secret, tsg_id.
- Use these client_id, client_secret, tsg_id to authenticate to your AIOps instance.
### Panorama / Pan-OS Authentication:
- Use your server URL, username and password in order to get your API-key.
- To generate an API key, make a POST request to the firewall’s hostname or IP addresses using the administrative credentials and type=keygen:
```bash
curl -H "Content-Type: application/x-www-form-urlencoded" 
-X POST https://firewall/api/?type=keygen 
-d 'user=<user>&password=<password>'
```
- A successful API call returns status="success" along with the API key within the key element:
```xml
<response status="success">
    <result>
        <key>
            API-KEY
        </key>
    </result>
</response>
```
- Optional: To revoke all currently valid API keys, follow this [link](https://docs.paloaltonetworks.com/pan-os/9-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/get-your-api-key)