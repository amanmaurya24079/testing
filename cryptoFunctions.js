const crypto = require('crypto');

const decryptData = (encryptedData, privateKeyPassword, privateKey) => {
  try {
    const decBuf = Buffer.from(encryptedData, "base64");
    const MOD_BYTES = 256;
    const chunks = [];
    for (let i = 0; i < decBuf.byteLength; i += MOD_BYTES) {
      chunks.push(
        crypto.privateDecrypt({
          key: privateKey,
          passphrase: privateKeyPassword,
        },
          decBuf.slice(i, Math.min(i + MOD_BYTES, decBuf.byteLength)))
      );
    }
    let result = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (typeof (result) === 'string') result = JSON.parse(result);
    return result;
  }
  catch (error) {
    console.error("Decrypt Error: ", error);
    return null;
  }
};

const encryptData = (dataObject, publicKey) => {
  try {
    if (!dataObject) return '';

    const data = JSON.stringify(dataObject);
    const CHUNK_SIZE = 210;
    const toEncrypt = Buffer.from(data, "utf8");
    const bufs = [];

    for (let i = 0; i < toEncrypt.byteLength; i += CHUNK_SIZE) {
      bufs.push(
        crypto.publicEncrypt(publicKey,
          toEncrypt.slice(i, Math.min(i + CHUNK_SIZE, toEncrypt.byteLength))
        )
      );
    }
    return Buffer.concat(bufs).toString("base64");
  }
  catch (error) {
    console.error("Encrypt Error: ", error);
    return null;
  }
};

module.exports = {
  decryptData,
  encryptData
};
