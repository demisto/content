const arg_value = `${args.value}`;
const arg_equals = `${args.equals}`;
const arg_then = args.then;
const arg_else = args.else;

return arg_value == arg_equals ? arg_then : arg_else;
