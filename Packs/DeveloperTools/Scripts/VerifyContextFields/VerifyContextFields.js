var fields = [args.field1, args.field2, args.field3, args.field4];
var values = [args.value1, args.value2, args.value3, args.value4];

for (i = 0; i < fields.length; i++) {
    if (fields[i] !== undefined) {
        if (values[i] !== undefined) {
            verifyContextField(fields[i], values[i]);
            log('Verified: ' + fields[i] + ' == ' + values[i]);
        } else {
            verifyContextField(fields[i]);
            log('Verified field existence: ' + fields[i]);
        }
    }
}
