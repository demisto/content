var SERVER_URL = params.url;
if (SERVER_URL.slice(-1) === '/') {
    SERVER_URL = SERVER_URL.slice(0,-1);
}
SERVER_URL += ':15873/api/web/v1/';

var USER_NAME = params.credentials.identifier;

var PASSWORD = params.credentials.password;

function sendRequest(url, method, body, transactionID) {
    var req = {
            Method: method,
            Headers: {
                'Content-Type': ['application/json'],
                'Accept': ['application/json']
            },
            Username: USER_NAME,
            Password: PASSWORD
        };
    var reqBody = {};
    if (body) {
        reqBody = body;
    }
    if (transactionID) {
          reqBody['Transaction ID'] = transactionID;
    }
    req.Body = JSON.stringify(reqBody);
    var res = http(url, req, params.insecure, params.proxy);
    return res;
}

function transactionFlowRequest(url, method, body) {
    var transactionid = startTransaction();
    var res = {};
    try {
        res = sendRequest(url, method, body, transactionid);
    } catch (e) {
        throw e;
    } finally {
        //if request failes - commit the transaction anyway, to allow the creation a of new transaction for the next command.
        commitTransaction(transactionid);
    }
    var tries = 0;
    var status = {};
    //check the systen status, wait until transaction build status id 'Done'.
    //The database is only updated after the build is done.
    //Will prevent the need to add 'wait' between playbook tasks
    do {
        wait(1);
        status = getTransactionStatus();
        tries++;
    } while (status['Build Status'] !== 'Done' && tries < 10);
    if (tries > 10) {
        throw 'Possible transaction failure - transaction status: ' + status.Status.toString();
    }
    return res;
}
function startTransaction() {
    var url = SERVER_URL + 'categories/start';
    var tries = 0;
    var res = {};
    // Start a new transacrion - 3 tries for recurring 409 error.
    //Error 409 - another transaction is in progress (Only one Policy API Server in a global TRITON AP-WEB deployment can start a transaction at a time).
    do {
        wait(1);
        res = sendRequest(url, 'POST');
        tries++;
    } while(res.StatusCode === 409 && tries < 10);
    if (res.StatusCode !== 200) {
        if (res.StatusCode === 409) {
            throw 'Another transaction is in process. Please wait for a few seconds before sending another request.';
        }
        throw 'error - request failed. error number ' + res.StatusCode;
    }
    var resBody = JSON.parse(res.Body);
    var tid = resBody['Transaction ID'];
    return tid;
}

function commitTransaction(transactionID) {
    var url = SERVER_URL + 'categories/commit?transactionid=' + transactionID;
    var res = sendRequest(url, 'POST');
    if (res.StatusCode !== 200) {
        throw 'error - transaction commit failed. error  ' + res.Status;
    }
}

function getTransactionStatus() {
    var url = SERVER_URL + 'categories/status';
    var res = sendRequest(url, 'GET');
    if (res.StatusCode !== 200) {
        throw 'Error- failed to get transaction status. possible transaction failure';
    }
    try {
        var resBody = JSON.parse(res.Body);
        return resBody;
    } catch (err) {
        throw "error - unexpected response. Couldn't parse response body";
    }
}

function parseResponse(response) {
    var body = JSON.parse(response.Body);
    if (response.StatusCode === 200) {
        return body;
    } else {
        throwErrDetails(body, response.StatusCode);
    }
}

function throwErrDetails(errResponse, StatusCode) {
    var erMessage = '';
    var errArray = errResponse.Error ? errResponse.Error : [];
    for (var i = 0; i < errArray.length; i++) {
        erMessage = erMessage + errArray[i] + '\n';
    }
    throw 'Request failed with status ' + StatusCode + '. ' + erMessage;
}

function addCategory(){
    var res = addCategoryRequest(
        args.categoryName,
        args.categoryDescription,
        parseInt(args.parent));
    var title = 'Forcepoint Add Category';
    var content = res.Categories;
    var data = [
        {
            to: 'CategoryName',
            from: 'Category Name'
        }];
    var context = mapObjFunction(data) (content);
    var entry = {
          Type: entryTypes.note,
          Contents: content,
          ContentsFormat: formats.json,
          ReadableContentsFormat: formats.markdown,
          HumanReadable: tableToMarkdown(title, context),
          EntryContext: {}
      };
      entry.EntryContext['Forcepoint.AddCategory(val.CategoryName==obj.CategoryName)'] = context;
      return entry;
}

function addCategoryRequest(categoryName, categoryDescription, parent) {
    var url = SERVER_URL + 'categories';
    var body = {
        Categories: [
            {
                'Category Name': categoryName,
                'Category Description': categoryDescription,
                'Parent': parent
            }
        ]
    };
    var res = transactionFlowRequest(url, 'POST', body);
    return parseResponse(res);
}

function listCategories(){
    var listAll = (args.allCategories === 'true');
    var res = listCategoriesRequest(listAll);
    var title = 'Forcepoint List Categories';
    var categories = parseCategoryList(res.Categories);
    var data = [
                {to: 'CategoryName', from: 'Category Name'},
                {to: 'CategoryID', from: 'Category ID'},
                {to: 'CategoryDescription', from: 'Category Description'},
                {to: 'CategoryOwner', from: 'Category Owner'},
                {to: 'CategoryParent', from: 'CategoryParent'}
            ];
    var context = mapObjFunction(data)(categories);
    var entry = {
          Type: entryTypes.note,
          Contents: res,
          ContentsFormat: formats.json,
          ReadableContentsFormat: formats.markdown,
          HumanReadable: tableToMarkdown(title, context),
          EntryContext: {}
      };
      entry.EntryContext['Forcepoint.ListCategories(val.CategoryID==obj.CategoryID)'] = createContext(context);
      return entry;
}

function parseCategoryList(categories){
    var categoryArr = [];
    categories.forEach(function(cat) {
        var children = cat.Children;
        cat.CategoryParent = '';
        categoryArr.push(cat);
        if (children) {
            for (var i = 0; i < children.length; i++) {
                var child = children[i];
                child.CategoryParent = cat['Category Name'];
                categoryArr.push(child);
            }
        }
    });
    return categoryArr;
}

function listCategoriesRequest(listAll) {
    var url = listAll ? SERVER_URL + 'categories/all' : SERVER_URL + 'categories';
    var res =  sendRequest(url, 'GET');
    return parseResponse(res);
}

function categoryDetails(){
    if (!args.categoryName && !args.categoryId) {
        throw "Please provide either the category name or it\' ID."
    }
    var res = args.categoryId ? categoryDetailsByIDRequest(args.categoryId) : categoryDetailsByNameRequest(args.categoryName);
    var title = 'Forcepoint Category Details';
    var data = [
            {to: 'CategoryName', from: 'Category Name'},
            {to: 'CategoryID', from: 'Category ID'},
            {to: 'URLs', from: 'URLs'},
            {to: 'IPs', from: 'IPs'}
        ];
    var context = mapObjFunction(data) (res);
    var entry = {
          Type: entryTypes.note,
          Contents: res,
          ContentsFormat: formats.json,
          ReadableContentsFormat: formats.markdown,
          HumanReadable: tableToMarkdown(title, context),
          EntryContext: {}
      };
      entry.EntryContext['Forcepoint.CategoryDetails(val.CategoryID==obj.CategoryID)'] = createContext(context);
      return entry;

}

function categoryDetailsByNameRequest(name) {
    url = SERVER_URL + 'categories/urls?catname=' + name;
    var res =  sendRequest(url, 'GET');
    return parseResponse(res);
}

function categoryDetailsByIDRequest(id) {
    url = SERVER_URL + 'categories/urls?catid=' + id;
    var res =  sendRequest(url, 'GET');
    return parseResponse(res);
}

function addAddress() {
    if (!args.ips && !args.urls) {
        throw 'Please pass an ip list, url list, or both.'
    }
    if (!args.categoryID && !args.categoryName) {
        throw "Please provide either the category name or it's ID.";
    }
    var urls = args.urls ? args.urls.split(',') : undefined;
    var ips = args.ips ? args.ips.split(',') : undefined;
    var res = args.categoryID ? editAddressRequest(urls, ips, parseInt(args.categoryID)) : editAddressRequest(urls, ips, undefined, args.categoryName);
    var title = 'Forcepoint Category Details';
    var data = [
                {to: 'CategoryID', from: 'Category ID'},
                {to: 'Totals.AddedURLs', from: 'Totals.Added URLs'},
                {to: 'Totals.AddedIPs', from: 'Totals.Added IPs'}
            ];
    var context = mapObjFunction(data) (res);
    var entry = {
            Type: entryTypes.note,
            Contents: res,
            ContentsFormat: formats.json,
            ReadableContentsFormat: formats.markdown,
            HumanReadable: tableToMarkdown(title, context),
            EntryContext: {}
        };
    entry.EntryContext['Forcepoint.AddAddressToCategory(val.CategoryID==obj.CategoryID)'] = createContext(context);
    return entry;
}

function editAddressRequest(urls, ips, id, name, del){
    var url = SERVER_URL + 'categories/urls';
    var body = {};
    if (id) {
        body['Category ID'] = id;
    }
    else if(name){
        body['Category Name'] = name;
    }
    if (urls) {
        body.URLs = urls;
    }
    if (ips) {
        body.IPs = ips;
    }
    var method = del ? 'DELETE' : 'POST';
    var res =  transactionFlowRequest(url, method, body);
    return parseResponse(res);
}

function deleteAddress() {
    if (!args.ips && !args.urls) {
        throw 'Please pass an ip list, url list, or both.'
    }
    if (!args.categoryID && !args.categoryName) {
        throw "Please provide either the category name or it's ID.";
    }
    var urls = args.urls ? args.urls.split(',') : undefined;
    var ips = args.ips ? args.ips.split(',') : undefined;
    var res = args.categoryID ? editAddressRequest(urls, ips, parseInt(args.categoryID), undefined, true) : editAddressRequest(urls, ips, undefined, args.categoryName, true);
    var title = 'Forcepoint Delete Address From Category';
    var data = [
                    {to: 'CategoryID', from: 'Category ID'},
                    {to: 'Totals.DeletedURLs', from: 'Totals.Deleted URLs'},
                    {to: 'Totals.DeletedIPs', from: 'Totals.Deleted IPs'}
                ];
    var context = mapObjFunction(data)(res);
    var entry = {
          Type: entryTypes.note,
          Contents: res,
          ContentsFormat: formats.json,
          ReadableContentsFormat: formats.markdown,
          HumanReadable: tableToMarkdown(title, context),
          EntryContext: {}
      };
      entry.EntryContext['Forcepoint.DeleteAddressesFromCategory'] = createContext(context);
      return entry;
}

function deleteCategory() {
    if (!args.categoryIDs && !args.categoryNames) {
        throw 'Please provied IDs or/and Names of the categories you wish to delete.';
    }
    //save the categories details before deleting them
    var deleted = [];
    if (args.categoryIDs) {
        var ids = [];
        if (Array.isArray(args.categoryIDs)) {
            ids = args.categoryIDs;
        } else if (typeof args.categoryIDs === 'string') {
            ids = args.categoryIDs.split(',');
            ids.forEach(function(element, index, arr) {
                arr[index] = parseInt(element);
            });
        } else if (!isNaN(args.categoryIDs)) {
            ids.push(args.categoryIDs);
        }
        ids.forEach(function(element) {
            //Get details for each category. If the request fails, it means wrong category id/name was provided.
            //category DELETE request with wrong id/name will not cause an error. No need to end the procedure. Valid ids/names will still be deleted.
              try {
                var catDetails = categoryDetailsByIDRequest(element);
                deleted.push(catDetails);
            } catch(e) {}
        });
        deleteCategoryRequest(ids);
    }
    if(args.categoryNames) {
        var names = [];
        if (Array.isArray(args.categoryNames)){
            names = args.categoryNames;
        } else  {
            names = args.categoryNames.split(',');
        }
        //Get details for each category. If the request fails, it means wrong category id/name was provided.
        //category DELETE request with wrong id/name will not cause an error. No need to end the procedure. Valid ids/names will still be deleted.
        try {
            names.forEach(function(element) {
                var catDetails = categoryDetailsByNameRequest(element);
                deleted.push(catDetails);
            });
        } catch(e) {};
        deleteCategoryRequest(undefined, names);
    }
    var data = [
        {to: 'CategoryName', from: 'Category Name'},
        {to: 'CategoryID', from: 'Category ID'},
        {to: 'URLs', from: 'URLs'},
        {to: 'IPs', from: 'IPs'}
        ];
    var context = mapObjFunction(data) (deleted);
    var entry = {
      Type: entryTypes.note,
      ReadableContentsFormat: formats.text,
      HumanReadable: "Categories were deleted successfully",
      Contents: deleted,
      ContentsFormat: formats.json,
      EntryContext: {}
      };
      entry.EntryContext['Forcepoint.DeletedCategories'] = createContext(context);
      return entry;
}

function deleteCategoryRequest(ids, names) {
    var url = SERVER_URL + 'categories';
    var body = {};
    if (ids) {
        body['Category IDs'] = ids;
    }
    else if (names) {
        body['Category Names'] = names;
    }
    var res = transactionFlowRequest(url, 'DELETE', body);
    if (res.StatusCode !== 200) {
        var errResponse = JSON.stringify(res.Body);
        throwErrDetails(errResponse, res.StatusCode);
    }
}

function test() {
    var tid = startTransaction();
    commitTransaction(tid);
    return 'ok';
}


switch(command) {
    case 'test-module':
        return test();
    case 'fp-add-category':
        return addCategory();
    case 'fp-list-categories':
        return listCategories();
    case 'fp-get-category-detailes':
        return categoryDetails();
    case 'fp-add-address-to-category':
        return addAddress();
    case 'fp-delete-address-from-category':
        return deleteAddress();
    case 'fp-delete-categories':
        return deleteCategory();
}
