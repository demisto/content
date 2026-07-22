function format_ip(ip) {
    return ip.replace(/\[\.\]/g,'.');
}

function format_ip_list(ip_list) {
    var len = ip_list.length;
    var formatted_ips = new Array(len);
    ip_list.forEach(function(the_ip, index) {
        formatted_ips[index] = format_ip(the_ip.trim());
    });
    return formatted_ips;
}

var ips;
// It is assumed that args.input is a string
var unformatted_ips = argToList(args.input);
ips = format_ip_list(unformatted_ips);
return ips;
