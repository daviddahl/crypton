/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
var app = {
  // Application Constructor
  initialize: function() {
    $('#account-login').show();
    $('#username-login').focus();
    crypton.host = 'encryptrservice.crypton.io';
    this.bindEvents();
  },
  // Bind Event Listeners
  //
  // Bind any events that are required on startup. Common events are:
  // 'load', 'deviceready', 'offline', and 'online'.
  bindEvents: function() {
    document.addEventListener('deviceready', this.onDeviceReady, false);

    $('#scan').click(function (){
      app.scanTest();
    });

    $('#get-image').click(function (){
      app.getImage();
    });

    $("register-btn").click(function (){
      app.createAccount();
    });

    $("login-btn").click(function (){
      app.login();
    });
  },
  // deviceready Event Handler
  //
  // The scope of 'this' is the event. In order to call the 'receivedEvent'
  // function, we must explicity call 'app.receivedEvent(...);'
  onDeviceReady: function() {
    app.receivedEvent('deviceready');
  },
  // Update DOM on a Received Event
  receivedEvent: function(id) {
    if (!id) {
      console.error("No id provided to receivedEvent");
      return;
    }
    var parentElement = document.getElementById(id);
    if (!parentElement) {
      console.error('Element with id: ' + id + ' does not exist.');
      return;
    }
    var listeningElement = parentElement.querySelector('.listening');
    var receivedElement = parentElement.querySelector('.received');

    listeningElement.setAttribute('style', 'display:none;');
    receivedElement.setAttribute('style', 'display:block;');

    console.log('Received Event: ' + id);
  },

  scanTest: function () {
    cordova.plugins.barcodeScanner.scan(
      function (result) {
        alert("We got a barcode\n" +
              "Result: " + result.text + "\n" +
              "Format: " + result.format + "\n" +
              "Cancelled: " + result.cancelled);
      },
      function (error) {
        alert("Scanning failed: " + error);
      }
    );
  },

  convertImageToCanvas: function () {
    var canvas = document.createElement('canvas');
    canvas.width = 420;
    canvas.height = 420;
    var ctx = canvas.getContext("2d");
    var img = $('#picture')[0];
    ctx.drawImage(img, 0, 0);
    $('#debug').append(canvas);
    return canvas;
  },

  getQrCodeCanvas: function (canvas) {
    var ctx = canvas.getContext('2d');
    var qrCode = ctx.getImageData(210, 205, 200, 200);
    console.log(qrCode);

    var qrCodeCanvas = document.createElement('canvas');
    qrCodeCanvas.height = 200;
    qrCodeCanvas.width = 200;
    $(qrCodeCanvas).attr({id: 'qr-canvas'}); // magick canvas ID
    console.log(qrCodeCanvas);
    var qrCtx = qrCodeCanvas.getContext('2d');
    qrCtx.putImageData(qrCode, 0, 0);

    return qrCodeCanvas;
  },

  getImage: function () {
    function onSuccess (imageURI) {
      console.log(imageURI);
      var largeImage = document.getElementById('picture');
      largeImage.style.display = 'block';
      largeImage.src = imageURI;

      qrcode.callback = function (data) {
        alert(data);
        // we have data, cache it locally

        // look up the peer from this data

        // compare the fingerprints

        // tell the user we have a match or not
        var userObj = JSON.parse(data);
        app.verifyUser(data.username, data.fingerprint);
      };
      try {
        qrcode.decode(imageURI);
      } catch (e) {
        console.error(e);
      }
    }

    function onFail (message) {
      alert('An error occured: ' + message);
    }

    //Specify the source to get the photos.
    navigator.camera.getPicture(onSuccess, onFail,
                                { quality: 100,
                                  destinationType:
                                  Camera.DestinationType.FILE_URI,
                                  sourceType:
                                  navigator.camera.PictureSourceType.SAVEDPHOTOALBUM
                                });
  },

  createAccount: function () {
    var user = $('#username-login').val();
    var pass = $('#password-login').val();
    function callback (err) {
      if (err) {
        app.setLoginStatus(err);
        return;
      }
      $('.view').hide();
      $('#scan-select').show();
      $('#account-name').text(user);
    }

    app.register(user, pass, callback);
  },

  register: function (user, pass, callback) {
    app.setLoginStatus('Generating account...');

    crypton.generateAccount(user, pass, function (err) {
      if (err) {
        callback(err);
      }
      app.setLoginStatus('Logging in...');
      app.login();
    });
  },

  login: function () {
    var user = $('#username-login').val();
    var pass = $('#password-login').val();
    function callback (err, session) {
      if (err) {
        app.setLoginStatus(err);
        return;
      }
      $('.view').hide();
      $('#scan-select').show();
      $('#account-name').text(user);
      app.session = session;
    }

    crypton.authorize(user, pass, function (err, session) {
      if (err) {
        callback(err);
      }
      callback(null, session);
    });
  },

  setLoginStatus: function (m) {
    $('#account-login .status').text(m);
  },

  verifyUser: function (username, fingerprint) {
    app.session.getPeer(username, function(err, peer) {
      if (err) {
        alert(err);
        return;
      }

      if (peer.fingerprint == fingerprint) {
        var conf = 'The server supplied fingerprint for '
                 + username
                 + ' is: \n'
                 + peer.fingerprint
                 + '\nThe fingerprint from the ID card is :\n'
                 + fingerprint
                 + '\nIt is a MATCH, click OK to verify '
                 + username
                 + 'as a trusted contact.'

        if (window.confirm(conf)) {
          peer.trust(function (err) {
            if (err) {
              console.log('peer trust failed: ' + err);
            } else {
              alert('Peer ' + username + ' is now a trusted contact!');
            }
          });
        }
      } else {
        alert('The server supplied fingerprint for '
             + username
             + 'is: \n'
             + peer.fingerprint
             + '\nThe fingerprint from the ID card is :\n'
             + fingerprint
             + '\nIt is NOT A MATCH\n'
             + username
             + ' Cannot be a trusted contact.');
      }
    });
  }
};
