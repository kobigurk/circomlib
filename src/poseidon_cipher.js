const crypto = require("crypto");

const bn128 = require("snarkjs").bn128;
const bigInt = require("snarkjs").bigInt;
const blake2b = require('blake2b');
const assert = require("assert");
const F = bn128.Fr;
const babyJub = require("./babyjub");

const poseidon = require("./poseidon");

const SEED = "poseidon";
const NROUNDSF = 8;
const NROUNDSP = 57;
const T = 4;

exports.generateRandomBabyJubScalar = () => {
  while (true) {
    const randomBytes = crypto.randomBytes(32);
    randomBytes[randomBytes.length - 1] &= 0x7;
    const prv = bigInt.leBuff2int(randomBytes);
    if (prv.lt(babyJub.subOrder)) {
      return prv;
    }
  }
};

exports.generateKeyPair = () => {
  const prv = exports.generateRandomBabyJubScalar();
  const pub = babyJub.mulPointEscalar(babyJub.Base8, prv);
  return {
    privateKey: prv,
    publicKey: pub,
  };
};

exports.privateToPublic = (privateKey) => {
  const pub = babyJub.mulPointEscalar(babyJub.Base8, privateKey);
  return pub;
};

exports.generateSharedKey = (privateKey, publicKey) => {
  return babyJub.mulPointEscalar(publicKey, privateKey);
};

exports.generateNonce = () => {
  const randomBytes = crypto.randomBytes(16);
  const nonce = bigInt.leBuff2int(randomBytes);
  return nonce;
};

function nonceAndLength(nonce, length) {
  return F.add(
    nonce, 
    F.mul(
      bigInt(length), 
      bigInt(2).pow(bigInt(128)),
    ),
  );
}

exports.encrypt = (senderPrivateKey, receiverPublicKey, message) => {
  const permutation = poseidon.createPermutation(T, NROUNDSF, NROUNDSP, SEED);

  const nonce = exports.generateNonce();
  const l = message.length;
  const ks = exports.generateSharedKey(senderPrivateKey, receiverPublicKey);
  let S = [F.zero, ks[0], ks[1], nonceAndLength(nonce, l)];

  let ciphertext = [];
  const length_chunks_3 = Math.ceil(l/3);
  for (let i = 0; i < length_chunks_3; i++) {
    S = permutation(S);
    for (let j = 0; j < 3; j++) {
      let m;
      if (3*i + j < message.length) {
        m = message[3*i + j];
      } else {
        m = F.zero;
      }

      S[j + 1] = F.add(S[j + 1], m);
      ciphertext.push(S[j + 1]);
    }
  }

  S = permutation(S);
  ciphertext.push(S[1]);

  return {
    senderPublicKey: exports.privateToPublic(senderPrivateKey),
    nonce: nonce,
    length: l,
    ciphertext: ciphertext,
  };
};

exports.decrypt = (receiverPrivateKey, senderPublicKey, nonce, length, ciphertext) => {
  const permutation = poseidon.createPermutation(T, NROUNDSF, NROUNDSP, SEED);

  const ks = exports.generateSharedKey(receiverPrivateKey, senderPublicKey);
  let S = [F.zero, ks[0], ks[1], nonceAndLength(nonce, length)];

  let decrypted = [];
  const length_chunks_3 = Math.ceil(length/3);
  for (let i = 0; i < length_chunks_3; i++) {
    S = permutation(S);
    for (let j = 0; j < 3; j++) {
      const index = 3*i + j;
      const m = F.sub(ciphertext[index], S[j + 1]);
      decrypted.push(m);
      if (index >= length) {
        if (decrypted[decrypted.length - 1] !== F.zero) {
          throw new Error("Decrypted plaintext over length is not zero, rejecting ciphertext");
        }
      }
      S[j + 1] = ciphertext[index];
    }
  }

  S = permutation(S);
  if (S[1] !== ciphertext[ciphertext.length - 1]) {
    throw new Error("Last ciphertext element is different than expected state element, rejecting ciphertext");
  }

  return decrypted;
};


exports.getMatrix = poseidon.getMatrix;
exports.getConstants = poseidon.getConstants;
