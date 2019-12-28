include "poseidon.circom";
include "escalarmulany.circom";
include "bitify.circom";
include "aliascheck.circom";
include "comparators.circom";

template PoseidonCipher(length, nRoundsF, nRoundsP) {
  var length_rounded_to_3 = 3*((length + 2) \ 3);
  /* transmitted data */
  signal input ciphertext[length_rounded_to_3];
  signal input sender_public_key[2];
  signal input nonce;

  /* private receiver data */
  signal input receiver_private_key;

  /* decrypted message */
  signal output decrypted_message[length_rounded_to_3];

  /* MAC */
  signal output mac;

  var index;

  component ks_calc = PoseidonCipherSharedKey();
  ks_calc.receiver_private_key <== receiver_private_key;
  ks_calc.sender_public_key[0] <== sender_public_key[0];
  ks_calc.sender_public_key[1] <== sender_public_key[1];

  var length_chunks_3 = length_rounded_to_3 / 3;
  component S[length_chunks_3 + 1];
  for (var i = 0; i <= length_chunks_3; i++) {
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

    if (i < length_chunks_3) {
      for (var j = 0; j < 3; j++) {
        index = 3*i + j;
        decrypted_message[index] <== ciphertext[index] - S[i].out[j + 1];
      }
    }
  }

  mac <== S[length_chunks_3].out[1];
}

template PoseidonCipher_strict(length, nRoundsF, nRoundsP) {
  var length_rounded_to_3 = 3*((length + 2) \ 3);

  /* transmitted data */
  signal input ciphertext[length_rounded_to_3 + 1];
  signal input sender_public_key[2];
  signal input nonce;

  /* private receiver data */
  signal input receiver_private_key;

  /* decrypted message */
  signal output decrypted_message[length_rounded_to_3];

  component cipher = PoseidonCipher(length, nRoundsF, nRoundsP);
  for (var i = 0; i < length_rounded_to_3; i++) {
    cipher.ciphertext[i] <== ciphertext[i];
  }

  cipher.sender_public_key[0] <== sender_public_key[0];
  cipher.sender_public_key[1] <== sender_public_key[1];
  cipher.nonce <== nonce;

  cipher.receiver_private_key <== receiver_private_key;
  for (var i = 0; i < length_rounded_to_3; i++) {
    decrypted_message[i] <== cipher.decrypted_message[i];
    if (i >= length) {
      decrypted_message[i] === 0;
    }
  }

  cipher.mac === ciphertext[length_rounded_to_3];
}

template PoseidonCipher_with_success_flag(length, nRoundsF, nRoundsP) {
  var length_rounded_to_3 = 3*((length + 2) \ 3);
  /* transmitted data */
  signal input ciphertext[length_rounded_to_3 + 1];
  signal input sender_public_key[2];
  signal input nonce;

  /* private receiver data */
  signal input receiver_private_key;

  /* decrypted message */
  signal output decrypted_message[length_rounded_to_3];

  /* success flag */
  component success_check = IsZero();
  signal output success;

  var success_length = length_rounded_to_3 - length + 1;
  component successes[success_length];
  var success_index = 0;

  component cipher = PoseidonCipher(length, nRoundsF, nRoundsP);
  for (var i = 0; i < length_rounded_to_3; i++) {
    cipher.ciphertext[i] <== ciphertext[i];
  }

  cipher.sender_public_key[0] <== sender_public_key[0];
  cipher.sender_public_key[1] <== sender_public_key[1];
  cipher.nonce <== nonce;

  cipher.receiver_private_key <== receiver_private_key;
  for (var i = 0; i < length_rounded_to_3; i++) {
    decrypted_message[i] <== cipher.decrypted_message[i];
    if (i >= length) {
      successes[success_index] = IsZero();
      successes[success_index].in <== decrypted_message[i];
      success_index += 1;
    }
  }

  successes[success_index] = IsZero();
  successes[success_index].in <== cipher.mac - ciphertext[length_rounded_to_3];
  success_index += 1;

  // can be at most 2 extra elements that cause a length not to be divided by zero
  // and minimum 1 because the mac didn't check, so between 1 and 3
  if (success_length == 1) {
    success_check.in <== successes[0].out - 1;
  } else if (success_length == 2) {
    success_check.in <== successes[0].out + successes[1].out - 2;
  } else if (success_length == 3) {
    success_check.in <== successes[0].out + successes[1].out + successes[2].out - 3;
  }

  success <== success_check.out;
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
