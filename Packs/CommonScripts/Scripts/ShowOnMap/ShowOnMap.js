var lat = parseFloat(args.lat); var lng = parseFloat(args.lng); var address = args.address;
if (isNaN(lat) || isNaN(lng)) {
  if (!address || address.trim().length === 0){
  return {
      ContentsFormat: formats.text,
      Type: entryTypes.error,
      Contents: "Enter either coordinates (lat,lng) or an address (which requires a GoogleMaps integration instance)."
  };

  }
  // An active instance of GoogleMaps exists, geocoding is possible.
    var commandResult = executeCommand("google-maps-geocode", {"search_address" : address});
    if (isError(commandResult) || !commandResult || !commandResult[1]) { // EC of an empty result is of length 1.
        return commandResult;
    }
    var ec = commandResult[0].EntryContext["GoogleMaps(val.lat && val.lat == obj.lat && val.lng && val.lng == obj.lng)"];
    lat = ec.lat;
    lng = ec.lng;
}
//  lat,lng are not null (whether they were valid arguments or geocoded)
var locationObj = {
  lat: lat,
  lng: lng
};
return {
  Type: entryTypes.map,
  ContentsFormat: formats.json,
  Contents: locationObj
};
