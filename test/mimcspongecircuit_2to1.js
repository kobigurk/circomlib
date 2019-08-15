const chai = require("chai");
const path = require("path");
const snarkjs = require("snarkjs");
const compiler = require("circom");
const bn128 = require("snarkjs").bn128;
const bigInt = require("snarkjs").bigInt;

const w3utils = require("web3-utils");
const F = bn128.Fr;

const mimcjs = require("../src/mimcsponge.js");

const assert = chai.assert;

describe("MiMC Sponge Circuit test", function () {
    let circuit;

    this.timeout(100000);

    it("Should check 2to1 hash", async () => {
        const cirDef = await compiler(path.join(__dirname, "circuits", "mimc_sponge_hash_2to1_test.circom"));

        circuit = new snarkjs.Circuit(cirDef);

        console.log("MiMC Sponge constraints: " + circuit.nConstraints);

        const w = circuit.calculateWitness({ins: [1, 2], k: 0});

        const o1 = w[circuit.getSignalIdx("main.outs[0]")];

        const out2 = mimcjs.multiHash([1,2]);

        assert.equal(o1.toString(), out2.toString());

        assert(circuit.checkWitness(w));

    });

});
