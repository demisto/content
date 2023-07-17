var res = executeCommand('Print', { value: 'id=${currentPlaybookID}' });
if (res && res[0].Contents && res[0].Contents.startsWith('id=')) {
   var idArr = res[0].Contents.split('=');
   if (idArr.length === 2 && idArr[1]) {
       return true;
   } else {
       return false;
   }
} else {
    return false;
}
