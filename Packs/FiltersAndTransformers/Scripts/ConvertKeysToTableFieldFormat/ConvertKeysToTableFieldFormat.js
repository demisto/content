// convert a specific key
function stripToCliName(str) {
  return str.substr(0, 255).replace(/[\W\s\\&$#@%?!_*;׳()^]/g, '').toLowerCase();
}

// convert object keys
function convertObject(obj) {
    var res = {};
    Object.keys(obj).forEach(function(key) {
        res[stripToCliName(key)] = obj[key];
    });
    return res;
}

var value = args.value;

if (typeof value !== "object") {
    return {
        ContentsFormat: formats.text,
        Type: entryTypes.error,
        Contents: 'Invalid input. Expected object/collection, got: ' + value
    };
}

if (Array.isArray(value)) {
    return value.map(convertObject);
}

return convertObject(value);



