include "poseidon.circom";
include "escalarmulany.circom";
include "bitify.circom";
include "aliascheck.circom";

template PoseidonCipher(length, nRoundsF, nRoundsP) {
  /* transmitted data */
  signal input ciphertext[3*((length + 2) \ 3) + 1];
  signal input sender_public_key[2];
  signal input nonce;

  /* private receiver data */
  signal input receiver_private_key;

  /* decrypted message */
  signal output decrypted_message[3*((length + 2) \ 3)];

  var index;

  component ks_calc = PoseidonCipherSharedKey();
  ks_calc.receiver_private_key <== receiver_private_key;
  ks_calc.sender_public_key[0] <== sender_public_key[0];
  ks_calc.sender_public_key[1] <== sender_public_key[1];

  component S[(length+2) \ 3 + 1];
  for (var i = 0; i <= (length + 2) \ 3; i++) {
    S[i] = PoseidonPermutation(4, 4, nRoundsF, nRoundsP);

    if (i == 0) {
      S[i].inputs[0] <== 0;
      S[i].inputs[1] <== ks_calc.ks[0];
      S[i].inputs[2] <== ks_calc.ks[1];
      S[i].inputs[3] <== nonce + 2**128 * length;
    } else {
      S[i].inputs[0] <== S[i-1].out[0];
      for (var j = 0; j < 3; j++) {
        index = 3*(i-1) + j;
        S[i].inputs[j + 1] <== ciphertext[index];
      }
    }

    if (i < (length + 2) \ 3) {
      for (var j = 0; j < 3; j++) {
        index = 3*i + j;
        decrypted_message[index] <== ciphertext[index] - S[i].out[j + 1];
        if (index >= length) {
          decrypted_message[index] === 0;
        }
      }
    }
  }

  ciphertext[3*((length + 2) \ 3)] === S[(length+2) \ 3].out[1];
}

template PoseidonCipherSharedKey() {
  signal input receiver_private_key;
  signal input sender_public_key[2];

  signal output ks[2];

  var i;

  component mul = EscalarMulAny(251);
  mul.p[0] <== sender_public_key[0];
  mul.p[1] <== sender_public_key[1];

  component private_key_bits = Num2Bits(251);
  private_key_bits.in <== receiver_private_key;

  component check_in_group = AliasCheckBabyJub();
  check_in_group.enabled <== 1;
  for (i = 0; i < 251; i++) {
    check_in_group.in[i] <== private_key_bits.out[i];
  }

  for (i = 0; i < 251; i++) {
    mul.e[i] <== private_key_bits.out[i];
  }

  ks[0] <== mul.out[0];
  ks[1] <== mul.out[1];
}
