var res = executeCommand("IsInCidrRanges", args);
res = Array.isArray(res) ? res : [res];
return res.map(val => val.Contents == "True" ? "False" : "True");