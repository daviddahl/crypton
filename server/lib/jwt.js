'use strict';

var jwt = require('green-jwt');

function createToken(aUserId) {
  var API_SECRET = "FIqDvLjGgkEEUlECFuMXcLb-9Wk57l7GcWtAHfKGqOw";
  var SERVICE_ID = "nulltxt"; // XXX: get one for SO

  var exp = new Date().getTime() + (48 * 60 * 60); // 2 days in seconds

  return createAuthToken(SERVICE_ID, aUserId, exp, API_SECRET);
}

function createAuthToken(serviceId, userId, expiry, apiSecret) {
  var subject = serviceId + ':' + userId;
  var payload = {'iss': serviceId, 'sub': subject, 'exp': expiry};
  var apiSecretKey = base64urlDecode(apiSecret);
  return jwt.encode(payload, apiSecretKey);
}

function base64urlDecode(str) {
  return new Buffer(base64urlUnescape(str), 'base64');
}

function base64urlUnescape(str) {
  str += Array(5 - str.length % 4).join('=');
  return str.replace(/\-/g, '+').replace(/_/g, '/');
}

module.exports = {
  createToken: createToken
};
