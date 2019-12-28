const chai = require("chai");
const path = require("path");
const snarkjs = require("snarkjs");
const compiler = require("circom");

const poseidoncipher = require("../src/poseidon_cipher.js");

const assert = chai.assert;

describe("Poseidon test", function() {
    it("Should generate keypair", async () => {
      const keypair = poseidoncipher.generateKeyPair();
    });

    it("Should generate shared key", async () => {
      const keypair = poseidoncipher.generateKeyPair();
      const sharedKey = poseidoncipher.generateSharedKey(keypair.privateKey, keypair.publicKey);
    });

    it("Should encrypt", async () => {
      const senderKeypair = poseidoncipher.generateKeyPair();
      const receiverKeypair = poseidoncipher.generateKeyPair();
      
      const length = 10;
      let message = [];
      for (let i = 0; i < length; i++) {
        message.push(poseidoncipher.generateRandomBabyJubScalar());
      }
      const encrypted = poseidoncipher.encrypt(senderKeypair.privateKey, receiverKeypair.publicKey, message);
    });

    it("Should decrypt", async () => {
      const senderKeypair = poseidoncipher.generateKeyPair();
      const receiverKeypair = poseidoncipher.generateKeyPair();
      
      const length = 10;
      let message = [];
      for (let i = 0; i < length; i++) {
        message.push(poseidoncipher.generateRandomBabyJubScalar());
      }
      const encrypted = poseidoncipher.encrypt(senderKeypair.privateKey, receiverKeypair.publicKey, message);
      assert.equal(encrypted.length, length);

      const decrypted = poseidoncipher.decrypt(receiverKeypair.privateKey, senderKeypair.publicKey, encrypted.nonce, encrypted.length, encrypted.ciphertext);
      for (let i = 0; i < length; i++) {
        assert.equal(decrypted[i], message[i]);
      }
    });
});

describe("Poseidon circuit test", function () {
    let circuit;
    let circuitStrict;

    this.timeout(100000);

    let senderKeypair;
    let receiverKeypair;
    let length;
    let encrypted;
    let decrypted;

    before( async () => {
        const cirDef = await compiler(path.join(__dirname, "circuits", "poseidoncipher_test.circom"));

        circuit = new snarkjs.Circuit(cirDef);

        console.log("Poseidon cipher success flag constraints: " + circuit.nConstraints);

        const cirDefStrict = await compiler(path.join(__dirname, "circuits", "poseidoncipherstrict_test.circom"));

        circuitStrict = new snarkjs.Circuit(cirDefStrict);

        console.log("Poseidon cipher strict constraints: " + circuitStrict.nConstraints);

        senderKeypair = poseidoncipher.generateKeyPair();
        receiverKeypair = poseidoncipher.generateKeyPair();
        
        length = 10;
        let message = [];
        for (let i = 0; i < length; i++) {
          message.push(poseidoncipher.generateRandomBabyJubScalar());
        }
        encrypted = poseidoncipher.encrypt(senderKeypair.privateKey, receiverKeypair.publicKey, message);

        decrypted = poseidoncipher.decrypt(receiverKeypair.privateKey, senderKeypair.publicKey, encrypted.nonce, encrypted.length, encrypted.ciphertext);
    });

    it("Should decrypt with success flag and match native implementation", async () => {
        const w = circuit.calculateWitness({
          ciphertext: encrypted.ciphertext,
          sender_public_key: encrypted.senderPublicKey,
          nonce: encrypted.nonce,
          receiver_private_key: receiverKeypair.privateKey,
        });
        assert(circuit.checkWitness(w));

        for (let i = 0; i < length; i++) {
          const res = w[circuit.getSignalIdx(`main.decrypted_message[${i}]`)];
          assert.equal(res.toString(), decrypted[i].toString());
        }

        const res = w[circuit.getSignalIdx(`main.success`)];
        assert.equal(res.toString(), '1');
    });

    it("Should decrypt with strict and match native implementation", async () => {
        const w = circuitStrict.calculateWitness({
          ciphertext: encrypted.ciphertext,
          sender_public_key: encrypted.senderPublicKey,
          nonce: encrypted.nonce,
          receiver_private_key: receiverKeypair.privateKey,
        });
        assert(circuitStrict.checkWitness(w));

        for (let i = 0; i < length; i++) {
          const res = w[circuitStrict.getSignalIdx(`main.decrypted_message[${i}]`)];
          assert.equal(res.toString(), decrypted[i].toString());
        }
    });
});
