const chai = require("chai");
const path = require("path");
const snarkjs = require("snarkjs");
const compiler = require("circom");

const assert = chai.assert;

const bigInt = snarkjs.bigInt;

const babyJub = require("../src/babyjub.js");
const pedersen = require("../src/pedersenHash.js");

const num_hashes = 2;

describe("Pedersen test", function() {
    let circuit;
    this.timeout(100000);
    before( async() => {
        const cirDef = await compiler(path.join(__dirname, "circuits", "pedersen_efficient_test.circom"));

        circuit = new snarkjs.Circuit(cirDef);

        console.log("NConstrains Pedersen efficient: " + circuit.nConstraints);
    });
    it("Should pedersen at zero", async () => {

        let w, xout, yout;

        const inputs = {};
        for (var i = 0; i < num_hashes; i++) {
          inputs[`in[${i}]`] = bigInt(i);
        }
        w = circuit.calculateWitness(inputs);
        for (var i = 0; i < num_hashes; i++) {

          xout = w[circuit.getSignalIdx(`main.out[${i}][0]`)];
          yout = w[circuit.getSignalIdx(`main.out[${i}][1]`)];

          //const b = Buffer.alloc(32);
          const b = bigInt(inputs[`in[${i}]`]).leInt2Buff(32);
          console.log(b.toString('hex'));

          const h = pedersen.hash(b);
          const hP = babyJub.unpackPoint(h);
          console.log(hP);

          assert.equal(xout.toString(), hP[0].toString());
          assert.equal(yout.toString(), hP[1].toString());
        }
    });
    it.skip("Should pedersen with 253 ones", async () => {

        let w, xout, yout;

        const n = bigInt.one.shl(253).sub(bigInt.one);
        console.log(n.toString(16));

        w = circuit.calculateWitness({ in: n});

        xout = w[circuit.getSignalIdx("main.out[0]")];
        yout = w[circuit.getSignalIdx("main.out[1]")];

        const b = Buffer.alloc(32);
        for (let i=0; i<31; i++) b[i] = 0xFF;
        b[31] = 0x1F;


        const h = pedersen.hash(b);
        const hP = babyJub.unpackPoint(h);

        /*
        console.log(`[${xout.toString()}, ${yout.toString()}]`);
        console.log(`[${hP[0].toString()}, ${hP[1].toString()}]`);
        */

        assert(xout.equals(hP[0]));
        assert(yout.equals(hP[1]));
    });
});
