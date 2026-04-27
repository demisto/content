# VerifyValidIP

## Summary

Verifies if the given input contains valid IP addresses (IPv4 or IPv6).

## Script Data

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility, IP, Validation |
| Cortex XSOAR Version | 6.0.0+ |

## Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| input | IP address or list of IP addresses to validate | Required |

## Outputs

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| VerifyValidIP.Results | List of boolean values indicating if each input IP is valid | List |

## Script Example

```yaml
!VerifyValidIP input="192.168.1.1,2001:db8::1,invalid_ip,10.0.0.1"
```

## Script Results

The script returns a list of boolean values:

- `True` for valid IP addresses
- `False` for invalid IP addresses

### Example Output

```
[true, true, false, true]
```

## Notes

- Supports both IPv4 and IPv6 address validation
- Uses Python's built-in `ipaddress` module for accurate validation
- Input can be a single IP address or a comma-separated list
- Invalid entries will return `False` in the corresponding position
