var path = args.path;
var fields = args.fields ? args.fields.split(",") : [];
var expectedValue = args.expectedValue;

var verifyFields = function(obj) {
    fields.forEach(function (field) {
        var value = dq(obj, field.trim());
        if (value === undefined || value === null) {
            throw 'Field ' + field + ' is missing from ' + JSON.stringify(obj) + '.';
        }
    });
}

var contextObject = dq(invContext, path);
if (contextObject === undefined || contextObject === null) {
      throw 'Path ' + path + ' is not in context.';
}

var isArray = contextObject instanceof Array;

if (isArray) {
    contextObject.forEach(verifyFields);
} else {
    verifyFields(contextObject);
}

if (expectedValue) {
    var value;
    try {
       value = JSON.parse(expectedValue);
    } catch (e) {
        value = expectedValue;
    }
    if (JSON.stringify(value) !== JSON.stringify(contextObject)) {
        throw ('Context path ' + path + ' is not equal to expected value. Found: ' + JSON.stringify(contextObject) + ', expected: ' + JSON.stringify(value));
    }
}
