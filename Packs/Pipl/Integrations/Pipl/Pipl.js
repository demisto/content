var url = params.url;
var columns;
if (params.columns) {
    columns = params.columns.split(',');
}

var sendRequest = function(args) {

    var requestUrl = url.replace(/[\/]+$/, '');

    var queryArgs = {};
    var argKeys = Object.keys(args);
    for (var i = 0; i < argKeys.length; i++) {
        queryArgs[argKeys[i].replace('-','_')] = args[argKeys[i]];
    }
    requestUrl += encodeToURLQuery(queryArgs);
    var res = http(
        requestUrl,
        {
            Method: 'POST',
            Headers: {
                'Content-Type': ['application/x-www-form-urlencoded']
            },
            Body: 'key=' + params.key
        },
        params.insecure,
        params.proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }
    return JSON.parse(res.Body);
};

var createEntry = function(response) {
    var data = [];
    ec = {};
    ec.Account =[];
    //Only one person
    if (response.person) {
        data[0] = addPerson(response.person);
        ec.Account[0] = buildEC(data, 0);
        data[0]['Emails'] = '';
        for (var j = 0; j < data[0].Email.length; j++) {
            data[0]['Emails'] += data[0].Email[j].Address + '\n';
        }
        delete data[0].Email;
    } else {
    //More than one person
        for (var i = 0; i < response.possible_persons.length; i++) {
            data[i] = addPerson(response.possible_persons[i]);
            ec.Account[i] = buildEC(data, i);
            data[i]['Emails'] = '';
            for (var j = 0; j < data[i].Email.length; j++) {
                data[i]['Emails'] += data[i].Email[j].Address + '\n';
            }
            delete data[i].Email;
        }
    }
    return {
        Type: entryTypes.note,
        ContentsFormat: formats.table,
        Contents: data,
        ReadableContentsFormat: formats.table,
        HumanReadable: data,
        EntryContext: ec
    };
};

var buildEC = function(data, i) {
    return {
        Addresses: data[i].Addresses,
        Email: data[i].Email,
        IDs: data[i].UserIDs,
        Names: data[i].Names,
        Phones: data[i].Phones,
        Usernames: data[i].Usernames
    };
};

var addPerson = function(person) {
    var response = {
        Names: '',
        Phones: '',
        Gender: '',
        DoB: '',
        Image: '',
        Usernames: '',
        Email: '',
        Educations: '',
        UserIDs: '',
        URLs: '',
        Jobs: '',
        Addresses: ''
    };
    if (person.names) {
        for (var i = 0; i < person.names.length; i++) {
            response.Names += person.names[i].middle ? person.names[i].first + ' ' + person.names[i].middle + ' ' + person.names[i].last + '\n' : person.names[i].first + ' ' + person.names[i].last + '\n';
        }
    }
    if (person.phones) {
        for (var i = 0; i < person.phones.length; i++) {
            response.Phones += person.phones[i].display + ' ' + person.phones[i].display_international + '\n';
        }
    }
    if (person.gender){
        response.Gender = person.gender.content;
    }
    if (person.dob) {
        response.DoB = person.dob.display;
    }
    if (person.images) {
        var url='https://thumb.pipl.com/image?height=100&width=100&favicon=false&zoom_face=false&token='+person.images[0].thumbnail_token;
        response.Image ='__img__:src,'+ url +';alt,'+''+';height,100;width,100';

    }
    if (person.usernames) {
        for (var i = 0; i < person.usernames.length; i++) {
            response.Usernames += person.usernames[i].content + '\n';
        }
    }
    if (person.emails) {
        response.Email = [];
        for (var i = 0; i < person.emails.length; i++) {
            response.Email[i] = {Address:person.emails[i].address};
        }
    }
    if (person.educations) {
        for (var i = 0; i < person.educations.length; i++) {
            response.Educations += person.educations[i].display + '\n';
        }
    }
    if (person.user_ids) {
        for (var i = 0; i < person.user_ids.length; i++) {
            response.UserIDs += person.user_ids[i].content + '\n';
        }
    }
    if (person.urls) {
        for (var i = 0; i < person.urls.length; i++) {
            response.URLs += person.urls[i].url + '\n';
        }
    }
    if (person.jobs) {
        for (var i = 0; i < person.jobs.length; i++) {
            response.Jobs += person.jobs[i].display + '\n';
        }
    }
    if (person.addresses) {
        for (var i = 0; i < person.addresses.length; i++) {
            response.Addresses += person.addresses[i].display + '\n';
        }
    }
    response.provider = 'pipl';
    return response;
};

switch (command) {
    case 'test-module':
        var response = sendRequest({'first-name': 'clark', 'last-name': 'kent'});
        return 'ok';
    case 'pipl-search':
        if (Object.keys(args).length === 0) {
            return 'No arguments given.'
        }
        var response = sendRequest(args);
        return createEntry(response);
    case 'email':
        var response = sendRequest(args);
        return createEntry(response);
    default:

}
