/* Crypton Client, Copyright 2014 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
*/

describe('Card', function () {
  var account = setupAccount();
  var sessionIdentifier = 'dummySession';
  var session = new crypton.Session(sessionIdentifier);
  session.account = account;
  console.log('Session:');
  console.log(session);
  var card = new crypton.Card(session);
  var username = session.account.username;
  var appname = 'noneofyourfingbizness';
  session.account.fingerprint = 'fbc42d5f1dc4e42b3b02338eef5364670461f4bb02b80b66263407011619d092';
  var fingerprint = session.account.fingerprint;
  var url = 'https://crypton.io';

  // helper functions //////////////////////////////////////////////////////
  function getRGBFromHex (hex) {
    var bigint = parseInt(hex, 16);
    var r = (bigint >> 16) & 255;
    var g = (bigint >> 8) & 255;
    var b = bigint & 255;
    return [r, g, b];
  }

  function testCanvasColorAt(hexcolor, canvas, x, y) {
    var ctx = canvas.getContext('2d');
    var imageData = ctx.getImageData(x, y, 1, 1); // get one pixel
    var data = imageData.data;

    var hex = hexcolor.substring(1, 7);
    var expectedRGB = getRGBFromHex(hex);
    var red, green, blue;
    red = data[0];
    green = data[1];
    blue = data[2];
    assert.equal(red, expectedRGB[0]);
    assert.equal(green, expectedRGB[1]);
    assert.equal(blue, expectedRGB[2]);
  }
  // end helper functions /////////////////////////////////////////////////

  describe('createFingerprintArr()', function () {
    it('should create an array with 16 members', function (done) {
      var arr = card.createFingerprintArr(fingerprint);
      assert.equal(arr.length, 16);
      done();
    });
  });

  describe('createColorArr()', function () {
    it('should create an array of hex color values', function (done) {
      var fingerArr = card.createFingerprintArr(fingerprint);
      var arr = card.createColorArr(fingerArr);
      assert.equal(arr.length, 16);
      assert.equal(arr[0].length, 7);
      assert.equal(arr[0][0], '#');
      done();
    });
  });

  describe('generateQRCodeInput()', function () {
    it('should generate corerct input for the QR Code', function (done) {
      var fingerArr = card.createFingerprintArr(fingerprint);
      var qrCodeInput = card.generateQRCodeInput(fingerArr, username, appname, url);
      var inputObj = JSON.parse(qrCodeInput);
      assert.equal(inputObj.fingerhash, fingerprint);
      assert(!inputObj.signature.error);
      assert.equal(inputObj.fingerprint, fingerArr.join(' '));
      assert(inputObj.signature.signature);
      assert.equal(inputObj.application, appname);
      assert.equal(inputObj.url, url);

      done();
    });
  });

  describe('createSignature()', function () {
    it('should generate a signature', function (done) {
      var signature = card.createSignature(fingerprint);

      assert(!signature.error);
      assert(signature.signature);

      done();
    });
  });

  describe('createQRCode()', function () {
    it('should generate a QR code in a canvas element', function (done) {
      var fingerArr = card.createFingerprintArr(fingerprint);
      var canvas = card.createQRCode(fingerArr, username, appname, url);
      testCanvasColorAt('#000000', canvas, 100, 100);
      done();
    });
  });

  describe('createIdentigrid()', function () {
    it('should generate a grid of colors based on the fingerprint', function (done) {
      var fingerArr = card.createFingerprintArr(fingerprint);
      var colorArr = card.createColorArr(fingerArr);

      var canvas = card.createIdentigrid(colorArr);
      testCanvasColorAt(colorArr[0], canvas, 2, 2);
      testCanvasColorAt(colorArr[1], canvas, 52, 2);
      done();
    });
  });

  describe('createIDCard()', function () {
    it('should generate the full ID Card',  function (done) {
      var fingerArr = card.createFingerprintArr(fingerprint);
      var colorArr = card.createColorArr(fingerArr);

      var domId = 'my-dom-id-is-the-best';
      var idCard = card.createIdCard(fingerprint, username, appname, url, domId);
      testCanvasColorAt(colorArr[0], idCard, 12, 205);
      done();
    });
  });

  ////////////////////////////////////////////////////////////////////////
  // XXXddahl TODO: More tests on additional x,y canvas colors.
  //                Parse QR code canvas into data
  ////////////////////////////////////////////////////////////////////////
});
