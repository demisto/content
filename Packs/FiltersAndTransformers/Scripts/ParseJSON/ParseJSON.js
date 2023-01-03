var value = args.value;
try {
  return JSON.parse(value);
} catch(err) {
  return err;
}
return null;
