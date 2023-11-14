function isIPv6(ip) {
  return ip.includes(':');
}

function ipToBinary(ip) {
  if (isIPv6(ip)) {
    // IPv6
    const binarySegments = ip.split(':').map(segment => {
      const hexValue = segment === '' ? 0 : parseInt(segment, 16);
      return ('0000' + hexValue.toString(2)).slice(-16);
    });
    return binarySegments.join('');
  } else {
    // IPv4
    return ip.split('.').map(octet => ('00000000' + parseInt(octet, 10).toString(2)).slice(-8)).join('');
  }
}

function validateCIDR(cidrRange) {
    const cidrRegex = /^([0-9a-f:.]+)\/([0-9]{1,3})$/i; // Regex for IPv4 and IPv6 CIDR notation

    const match = cidrRange.match(cidrRegex);

    if (!match) {
        return false; // CIDR range is not well-formed
    }

    const subnetMask = parseInt(match[2], 10);

    if (match[1].includes(':')) {
        // IPv6 CIDR
        if (subnetMask < 0 || subnetMask > 128) {
            return false; // Invalid subnet mask for IPv6
        }
    } else {
        // IPv4 CIDR
        if (subnetMask < 0 || subnetMask > 32) {
            return false; // Invalid subnet mask for IPv4
        }
    }

    return true; // CIDR range is well-formed
}

function isIPInCIDR(ipAddress, cidrRange) {
    if (!validateCIDR(cidrRange)) {
        logDebug(`Invalid CIDR range: ${cidrRange}`);
        return false;
    }

    const [networkAddress, subnetMask] = cidrRange.split('/');

    // Convert IP address and network address to binary
    const ipBinary = ipToBinary(ipAddress);
    const networkBinary = ipToBinary(networkAddress);

    // Get the network part of the IP address based on the subnet mask
    const networkPart = ipBinary.slice(0, parseInt(subnetMask, 10));

    // Check if the network parts match
    return networkPart === networkBinary.slice(0, parseInt(subnetMask, 10));
}


function isIPInAnyCIDR(ipAddresses, cidrRanges) {
  results = new Array(ipAddresses.length);

  for (let i = 0; i < ipAddresses.length; i++) {
    isInRange = false;
    
    for (let j = 0; j < cidrRanges.length; j++) {
      if (isIPInCIDR(ipAddresses[i], cidrRanges[j])) {
        logDebug(`${ipAddresses[i]} is in range ${cidrRanges[j]}`)

        isInRange = true;
        results[i] = 'True';
        break;
      }
    }

    if (!isInRange) {
      logDebug(`${ipAddresses[i]} is NOT in range.`)
      results[i] = 'False';
    }
  }

  return results;
}

ipAddresses = argToList(args.left)
cidrRanges = argToList(args.right)

return isIPInAnyCIDR(ipAddresses, cidrRanges);