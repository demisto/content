  function isValidTimestampFormat(timestamp) {
      const regex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/;
      return regex.test(timestamp);
  }


  try {

      var start_time = args.start_time.replace(/"/g, "");
      var end_time = args.end_time.replace(/"/g, "");

      // Validate params format
      if (!isValidTimestampFormat(start_time)) {
          return {
              ContentsFormat: formats.markdown,
              Type: entryTypes.error,
              Contents: "start_time argument does not match format '%Y-%m-%dT%H:%M:%S'"
          };
      }

      if (!isValidTimestampFormat(end_time)) {
          return {
              ContentsFormat: formats.markdown,
              Type: entryTypes.error,
              Contents: "end_time argument does not match format '%Y-%m-%dT%H:%M:%S'"
          };
      }

      // Strip microseconds and parse the datetime
      var startTimeObj = new Date(start_time.split(".")[0]);
      var endTimeObj = new Date(end_time.split(".")[0]);

      // Calculate the difference in minutes
      var timeDiff = (endTimeObj - startTimeObj) / 1000; // difference in seconds
      var mins = Math.round((timeDiff / 60) * 100) / 100; // round to 2 decimal places


      ec = {
          'Time': {
              Difference: Number(mins),
              Start: start_time,
              End: end_time
          }
      }

      return {
          Type: entryTypes.note,
          Contents: ec,
          ContentsFormat: formats.json,
          HumanReadable: `Calculated Time Difference: ${mins} minutes.`,
          ReadableContentsFormat: formats.markdown,
          EntryContext: ec
      };


  } catch (ex) {
      return {
          ContentsFormat: formats.markdown,
          Type: entryTypes.error,
          Contents: "Error occurred while parsing output from command. Exception info:\n" + ex.toString()
      };

  }