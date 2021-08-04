var value = args.value;
var field = args.field;
var equalTo = args.equalTo;
var getField = args.getField;

if (!Array.isArray(value)) {
    value = [value];
}

var res = value.filter(function(item) {
   return item && item[field] == equalTo; // using '==' and not '===' to handle number equality better
});

if (getField) {
    if (typeof getField !== 'string') {
        logInfo('WhereFieldEquals - got invalid getField [' + getField + ']. Ignoring');
    } else {
         res = res.map(function(item) { return item[getField]});
    }
}

return res;

