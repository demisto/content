var private_subnets = [
  '172.16.0.0/12',
  '10.0.0.0/8',
  '198.18.0.0/15',
  '192.168.0.0/16',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '192.0.0.0/24',
  '0.0.0.0/8',
  '224.0.0.0/4',
  '240.0.0.0/4',
  '255.255.255.255/32'
];

var ip = args.ip;
var ipranges = argToList(args.ipRanges);

if (!ipranges || ipranges.length === 0) {
    ipranges = private_subnets;
}

var isInRange = ipranges.some(function(iprange) {
    return isIPInSubnet(ip, iprange.replace(/[\s]/g, ''));
});

var ipObj = {};
ipObj.Address = ip;
ipObj.InRange = isInRange ? 'yes' : 'no';

var ec = {'IP(val.Address == obj.Address)' : ipObj};

return {
  Type: entryTypes.note,
  Contents: isInRange ? 'yes' : 'no',
  ContentsFormat: formats.text,
  EntryContext: ec
};
