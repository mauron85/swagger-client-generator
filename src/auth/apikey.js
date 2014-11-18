'use strict';

var MissingAuthorizationError = require('../errorTypes').MissingAuthorizationError;

module.exports = function applyApiKey(auth, authName, apiKey, request){
  if(!apiKey) throw new MissingAuthorizationError(authName, auth);
  
  if(auth.passAs === 'header'){
    request.headers[auth.keyname] = apiKey;
  } else if(auth.passAs === 'query'){
    var url = request.url;
    var queryParam = auth.keyname + '=' + encodeURIComponent(apiKey);
    if(url.indexOf('?') === -1){
      url += '?' + queryParam;
    } else {
      url = url.replace('?', '?' + queryParam + '&');
    }

    request.url = url;
  }
};