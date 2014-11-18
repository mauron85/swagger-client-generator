'use strict';

var applyApiKey = require('./auth/apikey'),
    applyBasicAuth = require('./auth/basic'),
    MissingAuthorizationError = require('./errorTypes').MissingAuthorizationError;

module.exports = function applyAuthData(operation, authData, request){
  var authMap = operation.authorizations;
  if(!authMap) authMap = operation.apiObject.apiDeclaration.authorizations;
  if(!authMap) return;

  var authNames = Object.keys(authMap).filter(function(authName){
    // Currently unable to handle oauth2
    return authMap[authName].type !== 'oauth2';
  });

  if(authNames.length === 0) return;

  if(authNames.length === 1){
    var authName = authNames[0];
    var auth = authMap[authName];

    if(!authData) throw new MissingAuthorizationError(authName, auth);

    // Unpack nested authData for single auth ops: { apiKey: '123' } -> '123'
    if(authData[authName]) authData = authData[authName];

    if(auth.type === 'apiKey'){
      applyApiKey(auth, authName, authData, request);
    } else if(auth.type === 'basicAuth') {
      applyBasicAuth(auth, authName, authData.username, authData.password, request);
    }
  } else {
    var hasAuth = authNames.some(function(authName){
      var auth = authMap[authName];
      var data = authData[authName];

      if(!data) return false;

      if(auth.type === 'apiKey'){
        applyApiKey(auth, authName, data, request);
      } else if(auth.type === 'basicAuth'){
        applyBasicAuth(auth, authName, data.username, data.password, request);
      }

      return true;
    });

    if(!hasAuth){
      throw new MissingAuthorizationError(authNames.join(', '), authMap);
    }
  }
};