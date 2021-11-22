var Binary = Crypto.charenc.Binary;
var UTF8 = Crypto.charenc.UTF8;

function bytesToInt(bytes) {
  var value = 0;
  for (var i = 0, b = 0; i < bytes.length; i++ , b += 8)
    value |= (bytes[bytes.length - 1 - i] & 0xFF) << (b % 32);
  return value;
}

function intToBytes(value) {
  for (var bytes = [], b = 0; b < 32; b += 8)
    bytes.push((value >>> (24 - b % 32)) & 0xFF);
  return bytes;
}
function shortToBytes(value) {
  for (var bytes = [], b = 0; b < 16; b += 8)
    bytes.push((value >>> (8 - b)) & 0xFF);
  return bytes;
}


