// 获取手机端公钥
function getPubkey() {
  dh = Crypto.DH.createDiffieHellman()
  var pubkey = dh.generateKeys();
  return pubkey;
}

