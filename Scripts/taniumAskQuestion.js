// An example script for asking Tanium a question

/* name - The name of the Saved-Question in Tanium server (mandatory if no 'id' was specified)
For example:
	Computer Name
	User Information
	Adobe Acrobat Versions
	BIOS Information
	CPU Utilization Over 75%
	Installed Applications
	...
*/
// id - The ID of the Saved-Question in Tanium server (mandatory if no 'name' was specified)
// timeout - seconds to wait on each iteration while waiting for the question's result
var taniumArgs = {
						'name': args.name,
						'id': args.id,
						'timeout': args.timeout
			    };

var table = {
    Type: 1,
    ContentsFormat: 'table',
    Contents: []
};

var res = executeCommand('tn-result-info', taniumArgs);
if (res[0].Type !== entryTypes.error) {
    if (!res[0].Contents.result_infos) {
        return res[0].Contents.Envelope.Body.return.command;
    }

    // Need to compare 'mr_passed' and 'estimated_total' values,
    // to confirm that all machines have answered
				var answers = res[0].Contents.result_infos.result_info.mr_passed;
				var expectedAnswers = res[0].Contents.result_infos.result_info.estimated_total;

    // Check the status 10 times, and wait 'timeout' seconds between each iteration
    var iterToWait = 10;
    var sec = 1;
    if (taniumArgs.timeout) {
    				sec = parseInt(taniumArgs.timeout) || 1;
    }
				while (answers !== expectedAnswers && iterToWait-- > 0) {
								wait(sec);
								res = executeCommand('tn-result-info', taniumArgs);
								if (res[0].Type === entryTypes.error) {
												return res[0];
								}
							 answers = res[0].Contents.result_infos.result_info.mr_passed;
        expectedAnswers = res[0].Contents.result_infos.result_info.estimated_total;
				}

    // Get question data (i.e. question result)
    var qDataRes = executeCommand('tn-result-data', taniumArgs);
    if (!qDataRes[0].Contents.result_sets) {
        return qDataRes[0].Contents.Envelope.Body.return.command;
    }

				// Extract the relevant fields from the data
				itemCount = parseInt(qDataRes[0].Contents.result_sets.result_set.item_count);
				if (itemCount === 0) {
								return 'No results';
				}

    var output = "";
    var cs = qDataRes[0].Contents.result_sets.result_set.cs;
    var rs = qDataRes[0].Contents.result_sets.result_set.rs;

				// When a single item is returned, rs.r is a single object. Otherwise, it is an array...
    if (itemCount === 1) {
        var row = {};
    				for (var i=0; i < cs.c.length; i++) {
        				//output += cs.c[i].dn + ': ' + rs.r.c[i].v + '\n';
        				row[cs.c[i].dn] = rs.r.c[i].v;
        }
        table.Contents.push(row);
    } else {
				    for (var item=0; item < itemCount; item++) {
								    var row = {};
								    for (var j=0; j < cs.c.length; j++) {
												    // output += cs.c[j].dn + ': ' + rs.r[item].c[j].v + '\n';
												    row[cs.c[j].dn] = rs.r[item].c[j].v;
								    }
								    table.Contents.push(row);
				    }
				}

    if (table.Contents.length === 0) {
    			return 'No Results';
    }
    return table;
}

return res;
