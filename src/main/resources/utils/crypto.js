/**
 * Global Crypto object
 */
var Crypto = {};

(function () {
  var base64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  // Crypto utilities
  var util = Crypto.util = {

    // Convert n to unsigned 32-bit integer
    u32: function (n) {
      return n >>> 0;
    },

    // Unsigned 32-bit addition
    add: function () {
      var result = this.u32(arguments[0]);
      for (var i = 1; i < arguments.length; i++)
        result = this.u32(result + this.u32(arguments[i]));
      return result;
    },

    // Unsigned 32-bit multiplication
    mult: function (m, n) {
      return this.add((n & 0xFFFF0000) * m,
        (n & 0x0000FFFF) * m);
    },

    // Unsigned 32-bit greater than (>) comparison
    gt: function (m, n) {
      return this.u32(m) > this.u32(n);
    },

    // Unsigned 32-bit less than (<) comparison
    lt: function (m, n) {
      return this.u32(m) < this.u32(n);
    },

    // Bit-wise rotate left
    rotl: function (n, b) {
      return (n << b) | (n >>> (32 - b));
    },

    // Bit-wise rotate right
    rotr: function (n, b) {
      return (n << (32 - b)) | (n >>> b);
    },

    // Swap big-endian to little-endian and vice versa
    endian: function (n) {

      // If number given, swap endian
      if (n.constructor == Number) {
        return util.rotl(n, 8) & 0x00FF00FF |
          util.rotl(n, 24) & 0xFF00FF00;
      }

      // Else, assume array and swap all items
      for (var i = 0; i < n.length; i++)
        n[i] = util.endian(n[i]);
      return n;

    },

    // Generate an array of any length of random bytes
    randomBytes: function (n) {
      for (var bytes = []; n > 0; n--)
        bytes.push(Math.floor(Math.random() * 256));
      return bytes;
    },

    // Convert a byte array to big-endian 32-bit words
    bytesToWords: function (bytes) {
      for (var words = [], i = 0, b = 0; i < bytes.length; i++ , b += 8)
        words[b >>> 5] |= (bytes[i] & 0xFF) << (24 - b % 32);
      return words;
    },

    // Convert big-endian 32-bit words to a byte array
    wordsToBytes: function (words) {
      for (var bytes = [], b = 0; b < words.length * 32; b += 8)
        bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
      return bytes;
    },

    // Convert a byte array to a hex string
    bytesToHex: function (bytes) {
      for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
      }
      return hex.join("");
    },

    // Convert a hex string to a byte array
    hexToBytes: function (hex) {
      for (var bytes = [], c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
      return bytes;
    },

    // Convert a byte array to a base-64 string
    bytesToBase64: function (bytes) {

      // Use browser-native function if it exists
      if (typeof btoa == "function") return btoa(Binary.bytesToString(bytes));

      for (var base64 = [], i = 0; i < bytes.length; i += 3) {
        var triplet = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
        for (var j = 0; j < 4; j++) {
          if (i * 8 + j * 6 <= bytes.length * 8)
            base64.push(base64map.charAt((triplet >>> 6 * (3 - j)) & 0x3F));
          else base64.push("=");
        }
      }

      return base64.join("");

    },

    // Convert a base-64 string to a byte array
    base64ToBytes: function (base64) {

      // Use browser-native function if it exists
      if (typeof atob == "function") return Binary.stringToBytes(atob(base64));

      // Remove non-base-64 characters
      base64 = base64.replace(/[^A-Z0-9+\/]/ig, "");

      for (var bytes = [], i = 0, imod4 = 0; i < base64.length; imod4 = ++i % 4) {
        if (imod4 == 0) continue;
        bytes.push(((base64map.indexOf(base64.charAt(i - 1)) & (Math.pow(2, -2 * imod4 + 8) - 1)) << (imod4 * 2)) |
          (base64map.indexOf(base64.charAt(i)) >>> (6 - imod4 * 2)));
      }

      return bytes;

    }

  };

  // Crypto character encodings
  var charenc = Crypto.charenc = {};

  // UTF-8 encoding
  var UTF8 = charenc.UTF8 = {

    // Convert a string to a byte array
    stringToBytes: function (str) {
      return Binary.stringToBytes(unescape(encodeURIComponent(str)));
    },

    // Convert a byte array to a string
    bytesToString: function (bytes) {
      return decodeURIComponent(escape(Binary.bytesToString(bytes)));
    }

  };

  // Binary encoding
  var Binary = charenc.Binary = {

    // Convert a string to a byte array
    stringToBytes: function (str) {
      for (var bytes = [], i = 0; i < str.length; i++)
        bytes.push(str.charCodeAt(i) & 0xFF);
      return bytes;
    },

    // Convert a byte array to a string
    bytesToString: function (bytes) {
      for (var str = [], i = 0; i < bytes.length; i++)
        str.push(String.fromCharCode(bytes[i]));
      return str.join("");
    }

  };

})();

/*
 * BlockModes
 */
(function () {

  var C = Crypto;

  // Create pad namespace
  var C_pad = C.pad = {};

  // Calculate the number of padding bytes required.
  function _requiredPadding(cipher, message) {
    var blockSizeInBytes = cipher._blocksize * 4;
    var reqd = blockSizeInBytes - message.length % blockSizeInBytes;
    return reqd;
  };

  // Remove padding when the final byte gives the number of padding bytes.
  var _unpadLength = function (message) {
    var pad = message.pop();
    for (var i = 1; i < pad; i++) {
      message.pop();
    }
  };

  // No-operation padding, used for stream ciphers
  C_pad.NoPadding = {
    pad: function (cipher, message) { },
    unpad: function (message) { }
  };

  // Zero Padding.
  //
  // If the message is not an exact number of blocks, the final block is
  // completed with 0x00 bytes. There is no unpadding.
  C_pad.ZeroPadding = {
    pad: function (cipher, message) {
      var blockSizeInBytes = cipher._blocksize * 4;
      var reqd = message.length % blockSizeInBytes;
      if (reqd != 0) {
        for (reqd = blockSizeInBytes - reqd; reqd > 0; reqd--) {
          message.push(0x00);
        }
      }
    },

    unpad: function (message) { }
  };

  // ISO/IEC 7816-4 padding.
  //
  // Pads the plain text with an 0x80 byte followed by as many 0x00
  // bytes are required to complete the block.
  C_pad.iso7816 = {
    pad: function (cipher, message) {
      var reqd = _requiredPadding(cipher, message);
      message.push(0x80);
      for (; reqd > 1; reqd--) {
        message.push(0x00);
      }
    },

    unpad: function (message) {
      while (message.pop() != 0x80) { }
    }
  };

  // ANSI X.923 padding
  //
  // The final block is padded with zeros except for the last byte of the
  // last block which contains the number of padding bytes.
  C_pad.ansix923 = {
    pad: function (cipher, message) {
      var reqd = _requiredPadding(cipher, message);
      for (var i = 1; i < reqd; i++) {
        message.push(0x00);
      }
      message.push(reqd);
    },

    unpad: _unpadLength
  };

  // ISO 10126
  //
  // The final block is padded with random bytes except for the last
  // byte of the last block which contains the number of padding bytes.
  C_pad.iso10126 = {
    pad: function (cipher, message) {
      var reqd = _requiredPadding(cipher, message);
      for (var i = 1; i < reqd; i++) {
        message.push(Math.floor(Math.random() * 256));
      }
      message.push(reqd);
    },

    unpad: _unpadLength
  };

  // PKCS7 padding
  //
  // PKCS7 is described in RFC 5652. Padding is in whole bytes. The
  // value of each added byte is the number of bytes that are added,
  // i.e. N bytes, each of value N are added.
  C_pad.pkcs7 = {
    pad: function (cipher, message) {
      var reqd = _requiredPadding(cipher, message);
      for (var i = 0; i < reqd; i++) {
        message.push(reqd);
      }
    },

    unpad: _unpadLength
  };

  // Create mode namespace
  var C_mode = C.mode = {};

  /**
   * Mode base "class".
   */
  var Mode = C_mode.Mode = function (padding) {
    if (padding) {
      this._padding = padding;
    }
  };

  Mode.prototype = {
    encrypt: function (cipher, m, iv) {
      this._padding.pad(cipher, m);
      this._doEncrypt(cipher, m, iv);
    },

    decrypt: function (cipher, m, iv) {
      this._doDecrypt(cipher, m, iv);
      this._padding.unpad(m);
    },

    // Default padding
    _padding: C_pad.iso7816
  };


  /**
   * Electronic Code Book mode.
   * 
   * ECB applies the cipher directly against each block of the input.
   * 
   * ECB does not require an initialization vector.
   */
  var ECB = C_mode.ECB = function () {
    // Call parent constructor
    Mode.apply(this, arguments);
  };

  // Inherit from Mode
  var ECB_prototype = ECB.prototype = new Mode;

  // Concrete steps for Mode template
  ECB_prototype._doEncrypt = function (cipher, m, iv) {
    var blockSizeInBytes = cipher._blocksize * 4;
    // Encrypt each block
    for (var offset = 0; offset < m.length; offset += blockSizeInBytes) {
      cipher._encryptblock(m, offset);
    }
  };
  ECB_prototype._doDecrypt = function (cipher, c, iv) {
    var blockSizeInBytes = cipher._blocksize * 4;
    // Decrypt each block
    for (var offset = 0; offset < c.length; offset += blockSizeInBytes) {
      cipher._decryptblock(c, offset);
    }
  };

  // ECB never uses an IV
  ECB_prototype.fixOptions = function (options) {
    options.iv = [];
  };


  /**
   * Cipher block chaining
   * 
   * The first block is XORed with the IV. Subsequent blocks are XOR with the
   * previous cipher output.
   */
  var CBC = C_mode.CBC = function () {
    // Call parent constructor
    Mode.apply(this, arguments);
  };

  // Inherit from Mode
  var CBC_prototype = CBC.prototype = new Mode;

  // Concrete steps for Mode template
  CBC_prototype._doEncrypt = function (cipher, m, iv) {
    var blockSizeInBytes = cipher._blocksize * 4;

    // Encrypt each block
    for (var offset = 0; offset < m.length; offset += blockSizeInBytes) {
      if (offset == 0) {
        // XOR first block using IV
        for (var i = 0; i < blockSizeInBytes; i++)
          m[i] ^= iv[i];
      } else {
        // XOR this block using previous crypted block
        for (var i = 0; i < blockSizeInBytes; i++)
          m[offset + i] ^= m[offset + i - blockSizeInBytes];
      }
      // Encrypt block
      cipher._encryptblock(m, offset);
    }
  };
  CBC_prototype._doDecrypt = function (cipher, c, iv) {
    var blockSizeInBytes = cipher._blocksize * 4;

    // At the start, the previously crypted block is the IV
    var prevCryptedBlock = iv;

    // Decrypt each block
    for (var offset = 0; offset < c.length; offset += blockSizeInBytes) {
      // Save this crypted block
      var thisCryptedBlock = c.slice(offset, offset + blockSizeInBytes);
      // Decrypt block
      cipher._decryptblock(c, offset);
      // XOR decrypted block using previous crypted block
      for (var i = 0; i < blockSizeInBytes; i++) {
        c[offset + i] ^= prevCryptedBlock[i];
      }
      prevCryptedBlock = thisCryptedBlock;
    }
  };


  /**
   * Cipher feed back
   * 
   * The cipher output is XORed with the plain text to produce the cipher output,
   * which is then fed back into the cipher to produce a bit pattern to XOR the
   * next block with.
   * 
   * This is a stream cipher mode and does not require padding.
   */
  var CFB = C_mode.CFB = function () {
    // Call parent constructor
    Mode.apply(this, arguments);
  };

  // Inherit from Mode
  var CFB_prototype = CFB.prototype = new Mode;

  // Override padding
  CFB_prototype._padding = C_pad.NoPadding;

  // Concrete steps for Mode template
  CFB_prototype._doEncrypt = function (cipher, m, iv) {
    var blockSizeInBytes = cipher._blocksize * 4,
      keystream = iv.slice(0);

    // Encrypt each byte
    for (var i = 0; i < m.length; i++) {

      var j = i % blockSizeInBytes;
      if (j == 0) cipher._encryptblock(keystream, 0);

      m[i] ^= keystream[j];
      keystream[j] = m[i];
    }
  };
  CFB_prototype._doDecrypt = function (cipher, c, iv) {
    var blockSizeInBytes = cipher._blocksize * 4,
      keystream = iv.slice(0);

    // Encrypt each byte
    for (var i = 0; i < c.length; i++) {

      var j = i % blockSizeInBytes;
      if (j == 0) cipher._encryptblock(keystream, 0);

      var b = c[i];
      c[i] ^= keystream[j];
      keystream[j] = b;
    }
  };


  /**
   * Output feed back
   * 
   * The cipher repeatedly encrypts its own output. The output is XORed with the
   * plain text to produce the cipher text.
   * 
   * This is a stream cipher mode and does not require padding.
   */
  var OFB = C_mode.OFB = function () {
    // Call parent constructor
    Mode.apply(this, arguments);
  };

  // Inherit from Mode
  var OFB_prototype = OFB.prototype = new Mode;

  // Override padding
  OFB_prototype._padding = C_pad.NoPadding;

  // Concrete steps for Mode template
  OFB_prototype._doEncrypt = function (cipher, m, iv) {

    var blockSizeInBytes = cipher._blocksize * 4,
      keystream = iv.slice(0);

    // Encrypt each byte
    for (var i = 0; i < m.length; i++) {

      // Generate keystream
      if (i % blockSizeInBytes == 0)
        cipher._encryptblock(keystream, 0);

      // Encrypt byte
      m[i] ^= keystream[i % blockSizeInBytes];

    }
  };
  OFB_prototype._doDecrypt = OFB_prototype._doEncrypt;

  /**
   * Counter
   * @author Gergely Risko
   *
   * After every block the last 4 bytes of the IV is increased by one
   * with carry and that IV is used for the next block.
   *
   * This is a stream cipher mode and does not require padding.
   */
  var CTR = C_mode.CTR = function () {
    // Call parent constructor
    Mode.apply(this, arguments);
  };

  // Inherit from Mode
  var CTR_prototype = CTR.prototype = new Mode;

  // Override padding
  CTR_prototype._padding = C_pad.NoPadding;

  CTR_prototype._doEncrypt = function (cipher, m, iv) {
    var blockSizeInBytes = cipher._blocksize * 4;
    var counter = iv.slice(0);

    for (var i = 0; i < m.length;) {
      // do not lose iv
      var keystream = counter.slice(0);

      // Generate keystream for next block
      cipher._encryptblock(keystream, 0);

      // XOR keystream with block
      for (var j = 0; i < m.length && j < blockSizeInBytes; j++ , i++) {
        m[i] ^= keystream[j];
      }

      // Increase counter
      if (++(counter[blockSizeInBytes - 1]) == 256) {
        counter[blockSizeInBytes - 1] = 0;
        if (++(counter[blockSizeInBytes - 2]) == 256) {
          counter[blockSizeInBytes - 2] = 0;
          if (++(counter[blockSizeInBytes - 3]) == 256) {
            counter[blockSizeInBytes - 3] = 0;
            ++(counter[blockSizeInBytes - 4]);
          }
        }
      }
    }
  };
  CTR_prototype._doDecrypt = CTR_prototype._doEncrypt;

})();

/*
 * HMAC
 */
(function () {

  var C = Crypto;

  // Shortcuts
  var util = C.util,
    charenc = C.charenc,
    UTF8 = charenc.UTF8,
    Binary = charenc.Binary;

  C.HMAC = function (hasher, message, key, options) {

    // Convert to byte arrays
    if (message.constructor == String) message = UTF8.stringToBytes(message);
    if (key.constructor == String) key = UTF8.stringToBytes(key);
    /* else, assume byte arrays already */

    // Allow arbitrary length keys
    if (key.length > hasher._blocksize * 4)
      key = hasher(key, { asBytes: true });

    // XOR keys with pad constants
    var okey = key.slice(0),
      ikey = key.slice(0);
    for (var i = 0; i < hasher._blocksize * 4; i++) {
      okey[i] ^= 0x5C;
      ikey[i] ^= 0x36;
    }

    var hmacbytes = hasher(okey.concat(hasher(ikey.concat(message), { asBytes: true })), { asBytes: true });

    return options && options.asBytes ? hmacbytes :
      options && options.asString ? Binary.bytesToString(hmacbytes) :
        util.bytesToHex(hmacbytes);

  };

})();

/*
 * HMAC4
 */
(function () {

  var C = Crypto;

  // Shortcuts
  var util = C.util,
    charenc = C.charenc,
    UTF8 = charenc.UTF8,
    Binary = charenc.Binary;

  var MARC4 = C.MARC4 = {

    /**
     * Public API
     */

    encrypt: function (message, password) {

      var

        // Convert to bytes
        m = UTF8.stringToBytes(message),

        // Generate random IV
        iv = util.randomBytes(16),

        // Generate key
        k = password.constructor == String ?
          // Derive key from passphrase
          C.PBKDF2(password, iv, 32, { asBytes: true }) :
          // else, assume byte array representing cryptographic key
          password;

      // Encrypt
      MARC4._marc4(m, k, 1536);

      // Return ciphertext
      return util.bytesToBase64(iv.concat(m));

    },

    decrypt: function (ciphertext, password) {

      var

        // Convert to bytes
        c = util.base64ToBytes(ciphertext),

        // Separate IV and message
        iv = c.splice(0, 16),

        // Generate key
        k = password.constructor == String ?
          // Derive key from passphrase
          C.PBKDF2(password, iv, 32, { asBytes: true }) :
          // else, assume byte array representing cryptographic key
          password;

      // Decrypt
      MARC4._marc4(c, k, 1536);

      // Return plaintext
      return UTF8.bytesToString(c);

    },


    /**
     * Internal methods
     */

    // The core
    _marc4: function (m, k, drop) {

      // State variables
      var i, j, s, temp;

      // Key setup
      for (i = 0, s = []; i < 256; i++) s[i] = i;
      for (i = 0, j = 0; i < 256; i++) {

        j = (j + s[i] + k[i % k.length]) % 256;

        // Swap
        temp = s[i];
        s[i] = s[j];
        s[j] = temp;

      }

      // Clear counters
      i = j = 0;

      // Encryption
      for (var k = -drop; k < m.length; k++) {

        i = (i + 1) % 256;
        j = (j + s[i]) % 256;

        // Swap
        temp = s[i];
        s[i] = s[j];
        s[j] = temp;

        // Stop here if we're still dropping keystream
        if (k < 0) continue;

        // Encrypt
        m[k] ^= s[(s[i] + s[j]) % 256];

      }

    }

  };

})();


/*
 * SHA1
 */

/*
 * PBKDF2
 */
(function () {

  var C = Crypto;

  // Shortcuts
  var util = C.util,
    charenc = C.charenc,
    UTF8 = charenc.UTF8,
    Binary = charenc.Binary;

  C.PBKDF2 = function (password, salt, keylen, options) {

    // Convert to byte arrays
    if (password.constructor == String) password = UTF8.stringToBytes(password);
    if (salt.constructor == String) salt = UTF8.stringToBytes(salt);
    /* else, assume byte arrays already */

    // Defaults
    var hasher = options && options.hasher || C.SHA1,
      iterations = options && options.iterations || 1;

    // Pseudo-random function
    function PRF(password, salt) {
      return C.HMAC(hasher, salt, password, { asBytes: true });
    }

    // Generate key
    var derivedKeyBytes = [],
      blockindex = 1;
    while (derivedKeyBytes.length < keylen) {
      var block = PRF(password, salt.concat(util.wordsToBytes([blockindex])));
      for (var u = block, i = 1; i < iterations; i++) {
        u = PRF(password, u);
        for (var j = 0; j < block.length; j++) block[j] ^= u[j];
      }
      derivedKeyBytes = derivedKeyBytes.concat(block);
      blockindex++;
    }

    // Truncate excess bytes
    derivedKeyBytes.length = keylen;

    return options && options.asBytes ? derivedKeyBytes :
      options && options.asString ? Binary.bytesToString(derivedKeyBytes) :
        util.bytesToHex(derivedKeyBytes);

  };

})();

/*
 * MD5
 */
(function () {

  var C = Crypto;

  // Shortcuts
  var util = C.util,
    charenc = C.charenc,
    UTF8 = charenc.UTF8,
    Binary = charenc.Binary;

  // Public API
  var MD5 = C.MD5 = function (message, options) {
    var digestbytes = util.wordsToBytes(MD5._md5(message));
    return options && options.asBytes ? digestbytes :
      options && options.asString ? Binary.bytesToString(digestbytes) :
        util.bytesToHex(digestbytes);
  };

  // The core
  MD5._md5 = function (message) {

    // Convert to byte array
    if (message.constructor == String) message = UTF8.stringToBytes(message);
    /* else, assume byte array already */

    var m = util.bytesToWords(message),
      l = message.length * 8,
      a = 1732584193,
      b = -271733879,
      c = -1732584194,
      d = 271733878;

    // Swap endian
    for (var i = 0; i < m.length; i++) {
      m[i] = ((m[i] << 8) | (m[i] >>> 24)) & 0x00FF00FF |
        ((m[i] << 24) | (m[i] >>> 8)) & 0xFF00FF00;
    }

    // Padding
    m[l >>> 5] |= 0x80 << (l % 32);
    m[(((l + 64) >>> 9) << 4) + 14] = l;

    // Method shortcuts
    var FF = MD5._ff,
      GG = MD5._gg,
      HH = MD5._hh,
      II = MD5._ii;

    for (var i = 0; i < m.length; i += 16) {

      var aa = a,
        bb = b,
        cc = c,
        dd = d;

      a = FF(a, b, c, d, m[i + 0], 7, -680876936);
      d = FF(d, a, b, c, m[i + 1], 12, -389564586);
      c = FF(c, d, a, b, m[i + 2], 17, 606105819);
      b = FF(b, c, d, a, m[i + 3], 22, -1044525330);
      a = FF(a, b, c, d, m[i + 4], 7, -176418897);
      d = FF(d, a, b, c, m[i + 5], 12, 1200080426);
      c = FF(c, d, a, b, m[i + 6], 17, -1473231341);
      b = FF(b, c, d, a, m[i + 7], 22, -45705983);
      a = FF(a, b, c, d, m[i + 8], 7, 1770035416);
      d = FF(d, a, b, c, m[i + 9], 12, -1958414417);
      c = FF(c, d, a, b, m[i + 10], 17, -42063);
      b = FF(b, c, d, a, m[i + 11], 22, -1990404162);
      a = FF(a, b, c, d, m[i + 12], 7, 1804603682);
      d = FF(d, a, b, c, m[i + 13], 12, -40341101);
      c = FF(c, d, a, b, m[i + 14], 17, -1502002290);
      b = FF(b, c, d, a, m[i + 15], 22, 1236535329);

      a = GG(a, b, c, d, m[i + 1], 5, -165796510);
      d = GG(d, a, b, c, m[i + 6], 9, -1069501632);
      c = GG(c, d, a, b, m[i + 11], 14, 643717713);
      b = GG(b, c, d, a, m[i + 0], 20, -373897302);
      a = GG(a, b, c, d, m[i + 5], 5, -701558691);
      d = GG(d, a, b, c, m[i + 10], 9, 38016083);
      c = GG(c, d, a, b, m[i + 15], 14, -660478335);
      b = GG(b, c, d, a, m[i + 4], 20, -405537848);
      a = GG(a, b, c, d, m[i + 9], 5, 568446438);
      d = GG(d, a, b, c, m[i + 14], 9, -1019803690);
      c = GG(c, d, a, b, m[i + 3], 14, -187363961);
      b = GG(b, c, d, a, m[i + 8], 20, 1163531501);
      a = GG(a, b, c, d, m[i + 13], 5, -1444681467);
      d = GG(d, a, b, c, m[i + 2], 9, -51403784);
      c = GG(c, d, a, b, m[i + 7], 14, 1735328473);
      b = GG(b, c, d, a, m[i + 12], 20, -1926607734);

      a = HH(a, b, c, d, m[i + 5], 4, -378558);
      d = HH(d, a, b, c, m[i + 8], 11, -2022574463);
      c = HH(c, d, a, b, m[i + 11], 16, 1839030562);
      b = HH(b, c, d, a, m[i + 14], 23, -35309556);
      a = HH(a, b, c, d, m[i + 1], 4, -1530992060);
      d = HH(d, a, b, c, m[i + 4], 11, 1272893353);
      c = HH(c, d, a, b, m[i + 7], 16, -155497632);
      b = HH(b, c, d, a, m[i + 10], 23, -1094730640);
      a = HH(a, b, c, d, m[i + 13], 4, 681279174);
      d = HH(d, a, b, c, m[i + 0], 11, -358537222);
      c = HH(c, d, a, b, m[i + 3], 16, -722521979);
      b = HH(b, c, d, a, m[i + 6], 23, 76029189);
      a = HH(a, b, c, d, m[i + 9], 4, -640364487);
      d = HH(d, a, b, c, m[i + 12], 11, -421815835);
      c = HH(c, d, a, b, m[i + 15], 16, 530742520);
      b = HH(b, c, d, a, m[i + 2], 23, -995338651);

      a = II(a, b, c, d, m[i + 0], 6, -198630844);
      d = II(d, a, b, c, m[i + 7], 10, 1126891415);
      c = II(c, d, a, b, m[i + 14], 15, -1416354905);
      b = II(b, c, d, a, m[i + 5], 21, -57434055);
      a = II(a, b, c, d, m[i + 12], 6, 1700485571);
      d = II(d, a, b, c, m[i + 3], 10, -1894986606);
      c = II(c, d, a, b, m[i + 10], 15, -1051523);
      b = II(b, c, d, a, m[i + 1], 21, -2054922799);
      a = II(a, b, c, d, m[i + 8], 6, 1873313359);
      d = II(d, a, b, c, m[i + 15], 10, -30611744);
      c = II(c, d, a, b, m[i + 6], 15, -1560198380);
      b = II(b, c, d, a, m[i + 13], 21, 1309151649);
      a = II(a, b, c, d, m[i + 4], 6, -145523070);
      d = II(d, a, b, c, m[i + 11], 10, -1120210379);
      c = II(c, d, a, b, m[i + 2], 15, 718787259);
      b = II(b, c, d, a, m[i + 9], 21, -343485551);

      a = (a + aa) >>> 0;
      b = (b + bb) >>> 0;
      c = (c + cc) >>> 0;
      d = (d + dd) >>> 0;

    }

    return util.endian([a, b, c, d]);

  };

  // Auxiliary functions
  MD5._ff = function (a, b, c, d, x, s, t) {
    var n = a + (b & c | ~b & d) + (x >>> 0) + t;
    return ((n << s) | (n >>> (32 - s))) + b;
  };
  MD5._gg = function (a, b, c, d, x, s, t) {
    var n = a + (b & d | c & ~d) + (x >>> 0) + t;
    return ((n << s) | (n >>> (32 - s))) + b;
  };
  MD5._hh = function (a, b, c, d, x, s, t) {
    var n = a + (b ^ c ^ d) + (x >>> 0) + t;
    return ((n << s) | (n >>> (32 - s))) + b;
  };
  MD5._ii = function (a, b, c, d, x, s, t) {
    var n = a + (c ^ (b | ~d)) + (x >>> 0) + t;
    return ((n << s) | (n >>> (32 - s))) + b;
  };

  // Package private blocksize
  MD5._blocksize = 16;

  MD5._digestsize = 16;

})();

/*
 * AES
 */
(function () {

  var C = Crypto;

  // Shortcuts
  var util = C.util,
    charenc = C.charenc,
    UTF8 = charenc.UTF8;

  // Precomputed SBOX
  var SBOX = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16];

  // Compute inverse SBOX lookup table
  for (var INVSBOX = [], i = 0; i < 256; i++) INVSBOX[SBOX[i]] = i;

  // Compute mulitplication in GF(2^8) lookup tables
  var MULT2 = [],
    MULT3 = [],
    MULT9 = [],
    MULTB = [],
    MULTD = [],
    MULTE = [];

  function xtime(a, b) {
    for (var result = 0, i = 0; i < 8; i++) {
      if (b & 1) result ^= a;
      var hiBitSet = a & 0x80;
      a = (a << 1) & 0xFF;
      if (hiBitSet) a ^= 0x1b;
      b >>>= 1;
    }
    return result;
  }

  for (var i = 0; i < 256; i++) {
    MULT2[i] = xtime(i, 2);
    MULT3[i] = xtime(i, 3);
    MULT9[i] = xtime(i, 9);
    MULTB[i] = xtime(i, 0xB);
    MULTD[i] = xtime(i, 0xD);
    MULTE[i] = xtime(i, 0xE);
  }

  // Precomputed RCon lookup
  var RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

  // Inner state
  var state = [[], [], [], []],
    keylength,
    nrounds,
    keyschedule;

  var AES = C.AES = {

    /**
     * Public API
     */

    encrypt: function (message, password, options) {

      options = options || {};

      // Determine mode
      var mode = options.mode || new C.mode.OFB;

      // Allow mode to override options
      if (mode.fixOptions) mode.fixOptions(options);

      var

        // Convert to bytes if message is a string
        m = (
          message.constructor == String ?
            UTF8.stringToBytes(message) :
            message
        ),

        // Generate random IV
        iv = options.iv || util.randomBytes(AES._blocksize * 4),

        // Generate key
        k = (
          password.constructor == String ?
            // Derive key from passphrase
            C.PBKDF2(password, iv, 32, { asBytes: true }) :
            // else, assume byte array representing cryptographic key
            password
        );

      // Encrypt
      AES._init(k);
      mode.encrypt(AES, m, iv);

      // Return ciphertext
      m = options.iv ? m : iv.concat(m);
      return (options && options.asBytes) ? m : util.bytesToBase64(m);

    },

    decrypt: function (ciphertext, password, options) {

      options = options || {};

      // Determine mode
      var mode = options.mode || new C.mode.OFB;

      // Allow mode to override options
      if (mode.fixOptions) mode.fixOptions(options);

      var

        // Convert to bytes if ciphertext is a string
        c = (
          ciphertext.constructor == String ?
            util.base64ToBytes(ciphertext) :
            ciphertext
        ),

        // Separate IV and message
        iv = options.iv || c.splice(0, AES._blocksize * 4),

        // Generate key
        k = (
          password.constructor == String ?
            // Derive key from passphrase
            C.PBKDF2(password, iv, 32, { asBytes: true }) :
            // else, assume byte array representing cryptographic key
            password
        );

      // Decrypt
      AES._init(k);
      mode.decrypt(AES, c, iv);

      // Return plaintext
      return (options && options.asBytes) ? c : UTF8.bytesToString(c);

    },


    /**
     * Package private methods and properties
     */

    _blocksize: 4,

    _encryptblock: function (m, offset) {

      // Set input
      for (var row = 0; row < AES._blocksize; row++) {
        for (var col = 0; col < 4; col++)
          state[row][col] = m[offset + col * 4 + row];
      }

      // Add round key
      for (var row = 0; row < 4; row++) {
        for (var col = 0; col < 4; col++)
          state[row][col] ^= keyschedule[col][row];
      }

      for (var round = 1; round < nrounds; round++) {

        // Sub bytes
        for (var row = 0; row < 4; row++) {
          for (var col = 0; col < 4; col++)
            state[row][col] = SBOX[state[row][col]];
        }

        // Shift rows
        state[1].push(state[1].shift());
        state[2].push(state[2].shift());
        state[2].push(state[2].shift());
        state[3].unshift(state[3].pop());

        // Mix columns
        for (var col = 0; col < 4; col++) {

          var s0 = state[0][col],
            s1 = state[1][col],
            s2 = state[2][col],
            s3 = state[3][col];

          state[0][col] = MULT2[s0] ^ MULT3[s1] ^ s2 ^ s3;
          state[1][col] = s0 ^ MULT2[s1] ^ MULT3[s2] ^ s3;
          state[2][col] = s0 ^ s1 ^ MULT2[s2] ^ MULT3[s3];
          state[3][col] = MULT3[s0] ^ s1 ^ s2 ^ MULT2[s3];

        }

        // Add round key
        for (var row = 0; row < 4; row++) {
          for (var col = 0; col < 4; col++)
            state[row][col] ^= keyschedule[round * 4 + col][row];
        }

      }

      // Sub bytes
      for (var row = 0; row < 4; row++) {
        for (var col = 0; col < 4; col++)
          state[row][col] = SBOX[state[row][col]];
      }

      // Shift rows
      state[1].push(state[1].shift());
      state[2].push(state[2].shift());
      state[2].push(state[2].shift());
      state[3].unshift(state[3].pop());

      // Add round key
      for (var row = 0; row < 4; row++) {
        for (var col = 0; col < 4; col++)
          state[row][col] ^= keyschedule[nrounds * 4 + col][row];
      }

      // Set output
      for (var row = 0; row < AES._blocksize; row++) {
        for (var col = 0; col < 4; col++)
          m[offset + col * 4 + row] = state[row][col];
      }

    },

    _decryptblock: function (c, offset) {

      // Set input
      for (var row = 0; row < AES._blocksize; row++) {
        for (var col = 0; col < 4; col++)
          state[row][col] = c[offset + col * 4 + row];
      }

      // Add round key
      for (var row = 0; row < 4; row++) {
        for (var col = 0; col < 4; col++)
          state[row][col] ^= keyschedule[nrounds * 4 + col][row];
      }

      for (var round = 1; round < nrounds; round++) {

        // Inv shift rows
        state[1].unshift(state[1].pop());
        state[2].push(state[2].shift());
        state[2].push(state[2].shift());
        state[3].push(state[3].shift());

        // Inv sub bytes
        for (var row = 0; row < 4; row++) {
          for (var col = 0; col < 4; col++)
            state[row][col] = INVSBOX[state[row][col]];
        }

        // Add round key
        for (var row = 0; row < 4; row++) {
          for (var col = 0; col < 4; col++)
            state[row][col] ^= keyschedule[(nrounds - round) * 4 + col][row];
        }

        // Inv mix columns
        for (var col = 0; col < 4; col++) {

          var s0 = state[0][col],
            s1 = state[1][col],
            s2 = state[2][col],
            s3 = state[3][col];

          state[0][col] = MULTE[s0] ^ MULTB[s1] ^ MULTD[s2] ^ MULT9[s3];
          state[1][col] = MULT9[s0] ^ MULTE[s1] ^ MULTB[s2] ^ MULTD[s3];
          state[2][col] = MULTD[s0] ^ MULT9[s1] ^ MULTE[s2] ^ MULTB[s3];
          state[3][col] = MULTB[s0] ^ MULTD[s1] ^ MULT9[s2] ^ MULTE[s3];

        }

      }

      // Inv shift rows
      state[1].unshift(state[1].pop());
      state[2].push(state[2].shift());
      state[2].push(state[2].shift());
      state[3].push(state[3].shift());

      // Inv sub bytes
      for (var row = 0; row < 4; row++) {
        for (var col = 0; col < 4; col++)
          state[row][col] = INVSBOX[state[row][col]];
      }

      // Add round key
      for (var row = 0; row < 4; row++) {
        for (var col = 0; col < 4; col++)
          state[row][col] ^= keyschedule[col][row];
      }

      // Set output
      for (var row = 0; row < AES._blocksize; row++) {
        for (var col = 0; col < 4; col++)
          c[offset + col * 4 + row] = state[row][col];
      }

    },


    /**
     * Private methods
     */

    _init: function (k) {
      keylength = k.length / 4;
      nrounds = keylength + 6;
      AES._keyexpansion(k);
    },

    // Generate a key schedule
    _keyexpansion: function (k) {

      keyschedule = [];

      for (var row = 0; row < keylength; row++) {
        keyschedule[row] = [
          k[row * 4],
          k[row * 4 + 1],
          k[row * 4 + 2],
          k[row * 4 + 3]
        ];
      }

      for (var row = keylength; row < AES._blocksize * (nrounds + 1); row++) {

        var temp = [
          keyschedule[row - 1][0],
          keyschedule[row - 1][1],
          keyschedule[row - 1][2],
          keyschedule[row - 1][3]
        ];

        if (row % keylength == 0) {

          // Rot word
          temp.push(temp.shift());

          // Sub word
          temp[0] = SBOX[temp[0]];
          temp[1] = SBOX[temp[1]];
          temp[2] = SBOX[temp[2]];
          temp[3] = SBOX[temp[3]];

          temp[0] ^= RCON[row / keylength];

        } else if (keylength > 6 && row % keylength == 4) {

          // Sub word
          temp[0] = SBOX[temp[0]];
          temp[1] = SBOX[temp[1]];
          temp[2] = SBOX[temp[2]];
          temp[3] = SBOX[temp[3]];

        }

        keyschedule[row] = [
          keyschedule[row - keylength][0] ^ temp[0],
          keyschedule[row - keylength][1] ^ temp[1],
          keyschedule[row - keylength][2] ^ temp[2],
          keyschedule[row - keylength][3] ^ temp[3]
        ];

      }

    }

  };

})();

/*
 * DH
 */
(function () {

  var C = Crypto;
  var randomBytes = C.util.randomBytes;
  /*
  var TWENTYFOUR = new BN(24);
  var ELEVEN = new BN(11);
  var TEN = new BN(10);
  var THREE = new BN(3);
  var SEVEN = new BN(7);
  */

  var P = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x61])
  var G = new Uint8Array([5])


  function setPublicKey(pub) {
    if (typeof pub !== 'object') {
      return;
    }
    this._pub = new BN(pub);
    return this;
  }

  function setPrivateKey(priv) {
    if (typeof priv !== 'object') {
      return;
    }
    this._priv = new BN(priv);
    return this;
  }
  
  function DHKey(prime, generator, malleable) {
    this.setGenerator(generator);
    this.__prime = new BN(prime);
    this._prime = BN.mont(this.__prime);
    this._primeLen = prime.length;
    this._pub = undefined;
    this._priv = undefined;
    this._primeCode = undefined;
    if (malleable) {
      this.setPublicKey = setPublicKey;
      this.setPrivateKey = setPrivateKey;
    } else {
      this._primeCode = 8;
    }
  }
  Object.defineProperty(DHKey.prototype, 'verifyError', {
    enumerable: true,
    get: function () {
      if (typeof this._primeCode !== 'number') {
        //this._primeCode = checkPrime(this.__prime, this.__gen);
      }
      return this._primeCode;
    }
  });

  DHKey.prototype.generateKeys = function () {
    if (!this._priv) {
      this._priv = new BN(randomBytes(this._primeLen));
    }
    this._pub = this._gen.toRed(this._prime).redPow(this._priv).fromRed();
    return this.getPublicKey();
  };

  DHKey.prototype.computeSecret = function (other) {
    other = new BN(other);
    other = other.toRed(this._prime);
    var secret = other.redPow(this._priv).fromRed();
    var out = new Uint8Array(secret.toArray());
    var prime = this.getPrime();
    if (out.byteLength < prime.byteLength) {
      //var front = new Uint8Array(prime.byteLength - out.byteLength);
      var front = new Uint8Array(prime.byteLength);
      front.fill(0);
      front.set(out, prime.byteLength - out.byteLength);
      out = front;
      //out = Buffer.concat([front, out]);

    }
    return out;
  };

  DHKey.prototype.getPublicKey = function getPublicKey() {
    return formatReturnValue(this._pub);
  };

  DHKey.prototype.getPrivateKey = function getPrivateKey() {
    return formatReturnValue(this._priv);
  };

  DHKey.prototype.getPrime = function () {
    return formatReturnValue(this.__prime);
  };

  DHKey.prototype.getGenerator = function () {
    return formatReturnValue(this._gen);
  };

  DHKey.prototype.setGenerator = function (gen) {
    this.__gen = gen;
    this._gen = new BN(gen);
    return this;
  };

  function formatReturnValue(bn) {
    return new Uint8Array(bn.toArray());
  }
  var DH = C.DH = {
    createDiffieHellman: function () {
      return new DHKey(P, G, true)
    }
  };
})();