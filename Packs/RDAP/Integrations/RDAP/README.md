# RDAP Integration

## Overview

The RDAP (Registration Data Access Protocol) integration allows you to query domain and IP information using the RDAP protocol. This integration provides valuable data for threat intelligence and domain/IP enrichment purposes.

## Configuration

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for RDAP.
3. Click **Add instance** to create and configure a new integration instance.
4. Configure the instance name and reliability.
5. Click **Test** to validate the configuration.

## Commands

### ip

This command queries IP information using RDAP.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | An IPv4 address to query, e.g., 1.1.1.1. | Required | 

#### Example Command

`!ip ip=8.8.8.8`

#### Context Output
|Path|Type|Description|
|---|---|---|
|IP.Address|String|The IP address.|
|IP.Description|String|The IP address description.|
|IP.Geo.Country|String|The IP address geo country.|
|IP.Organization.Name|String|The IP address organization name.|
|IP.Registrar.Abuse.Address|String|The address of the abuse Team.|
|IP.Registrar.Abuse.Email|String|The email address of the abuse team.|
|IP.Registrar.Abuse.Name|String|The name of the abuse team.|
|RDAP.IP.Value|String|The queried IP address.|
|RDAP.IP.IndicatorType|String|The type of the indicator (IP).|
|RDAP.IP.RegistrarAbuseAddress|String|The registrar abuse address for the IP.|
|RDAP.IP.RegistrarAbuseName|String|The registrar abuse contact name for the IP.|
|RDAP.IP.RegistrarAbuseEmail|String|The registrar abuse email for the IP.|
|DBotScore.Indicator|String|The indicator that was tested.|
|DBotScore.Type|String|The indicator type.|
|DBotScore.Vendor|String|The vendor used to calculate the score.|
|DBotScore.Score|Number|The actual score.|

### domain

This command queries domain information using RDAP.

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A domain address to query, e.g., example.com. | Required | 

#### Example Command

`!domain domain=example.com`


#### Context Output

|Path|Type|Description|
|---|---|---|
|Domain.Name|String|The domain name.|
|Domain.CreationDate|Date|The domain registration date.|
|Domain.ExpirationDate|Date|The domain expiration date.|
|Domain.WHOIS.CreationDate|Date|The domain registration date.|
|Domain.WHOIS.ExpirationDate|Date|The domain expiration date.|
|RDAP.Domain.Value|String|The queried domain name.|
|RDAP.Domain.IndicatorType|String|The type of the indicator (Domain).|
|RDAP.Domain.RegistrationDate|Date|The domain registration date.|
|RDAP.Domain.ExpirationDate|Date|The domain expiration date.|
|RDAP.Domain.LastChangedDate|Date|The last changed date of the domain.|
|RDAP.Domain.SecureDNS|Boolean|Whether the domain uses secure DNS.|
|DBotScore.Indicator|String|The indicator that was tested.|
|DBotScore.Type|String|The indicator type.|
|DBotScore.Vendor|String|The vendor used to calculate the score.|
|DBotScore.Score|Number|The actual score.|

## Additional Information

For more information on RDAP, please visit [ICANN's RDAP page](https://www.icann.org/rdap).
