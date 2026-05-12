  function parseUrl(url) {
      match = url.match(urlRegex);

      return match ? {
          shcema: url.match(/^(https?):/)[1],
          hostname: match[2],
          port: match[3] || '',
      } : null;
  }

  urls = demistoUrls();
  server_url = urls['server'].toString();


  result = parseUrl(server_url);

  ec = {
      'ServerURL': {
          Scheme: result.shcema,
          Host: result.hostname,
          Port: Number(result.port),
          URL: server_url
      }
  }

  return {
      Type: entryTypes.note,
      Contents: server_url,
      ContentsFormat: formats.note,
      HumanReadable: server_url,
      ReadableContentsFormat: formats.markdown,
      EntryContext: ec
  };