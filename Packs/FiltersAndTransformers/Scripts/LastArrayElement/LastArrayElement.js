let value = args.value;

if (Array.isArray(value) && value.length > 0) {
    value = value[value.length - 1];
} else if (value === null) {
    value = [];
}

return value;
