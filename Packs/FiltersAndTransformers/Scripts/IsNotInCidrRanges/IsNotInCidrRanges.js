// NOTE: The code below is a copy of the code in IsInCidrRanges script, they should be kept identical

function isIPv6(ip) {
    return ip.indexOf(':') !== -1;
}

function ipv6ToBinary(ipv6) {
    // Split the IPv6 address into its components
    var components = ipv6.split(':');

    // Handle zero compression (::)
    var zeroCompressionIndex = components.indexOf('');
    if (zeroCompressionIndex !== -1) {
        var zeroCount = 8 - components.length + 1; // Calculate the number of missing components
        components.splice(zeroCompressionIndex, 1);
        for (var i = 0; i < zeroCount; i++) {
            components.splice(zeroCompressionIndex, 0, '0000'); // Replace :: with zero components
        }
    }

    // Convert each component to binary and pad to 16 bits
    var binaryComponents = components.map(function (component) {
        // Handle the case when the component is an empty string
        if (component === '') {
            return '0000000000000000'; // 16 zeros for an empty component
        }

        var binary = parseInt(component, 16).toString(2);
        return Array(17 - binary.length).join('0') + binary;
    });

    // Concatenate the binary components
    var binaryString = binaryComponents.join('');

    return binaryString;
}


function ipToBinary(ip) {
    if (isIPv6(ip)) {
        // IPv6
        return ipv6ToBinary(ip);
    } else {
        // IPv4
        return ip.split('.').map(octet => ('00000000' + parseInt(octet, 10).toString(2)).slice(-8)).join('');
    }
}

function validateCIDR(cidrRange) {
    var cidrRegex = /^([0-9a-f:.]+)\/([0-9]{1,3})$/i; // Regex for IPv4 and IPv6 CIDR notation

    var match = cidrRange.match(cidrRegex);

    if (!match) {
        return false; // CIDR range is not well-formed
    }

    var subnetMask = parseInt(match[2], 10);

    if (match[1].indexOf(':') !== -1) {
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

function getCIDRNetworkAddress(cidrRange) {
    return cidrRange.split('/')[0]
}

function getCIDRSubnetMask(cidrRange) {
    return cidrRange.split('/')[1]
}

function isIPInCIDR(ipAddress, cidrRange) {
    if (!validateCIDR(cidrRange)) {
        return false;
    }

    var networkAddress = getCIDRNetworkAddress(cidrRange);
    var cidrSubnetMask = getCIDRSubnetMask(cidrRange);

    // Convert IP address and network address to binary
    var ipBinary = ipToBinary(ipAddress);
    var networkBinary = ipToBinary(networkAddress);

    // Get the network part of the IP address based on the subnet mask
    var networkPart = ipBinary.slice(0, parseInt(cidrSubnetMask, 10));

    // Check if the network parts match
    return networkPart === networkBinary.slice(0, parseInt(cidrSubnetMask, 10));
}

function isIPInAnyCIDR(ipAddresses, cidrRanges) {
    results = new Array(ipAddresses.length);

    for (let i = 0; i < ipAddresses.length; i++) {
        isInRange = false;

        for (let j = 0; j < cidrRanges.length; j++) {

            // Mismatches are always false
            if ((!isIPv6(ipAddresses[i]) && isIPv6(getCIDRNetworkAddress(cidrRanges[j])))
                || (isIPv6(ipAddresses[i]) && !isIPv6(getCIDRNetworkAddress(cidrRanges[j])))) {
                results[i] = 'False';
            } else if (isIPInCIDR(ipAddresses[i], cidrRanges[j])) {
                isInRange = true;
                results[i] = 'True';
                break;
            }
        }

        if (!isInRange) {
            results[i] = 'False';
        }
    }

    return results;
}

ipAddresses = argToList(args.left)
cidrRanges = argToList(args.right)

res = isIPInAnyCIDR(ipAddresses, cidrRanges);
// NOTE: The code above is a copy of the code in IsInCidrRanges script, they should be kept identical

return res.map(val => val == "True" ? "False" : "True");