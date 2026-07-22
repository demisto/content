let value = args.value;

if (Array.isArray(value) && value.length > 0) {
    value = value[0];
}
if (value === null) {
    value = [];
}

return value;
