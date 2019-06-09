include "../../circuits/pedersen_efficient.circom";
include "../../circuits/bitify.circom";


template Main(N) {
    signal input in[N];
    signal output out[N][2];

    var n = 256;
    var i;
    var j;
    var k;
    var l;
    var nBits;
    var nWindows;
    var maxNWindows = ((200 - 1)\4)+1;

    var nSegments = ((n-1)\200)+1;
    component pedersenProvider = PedersenProvider(n);
    component pedersens[N];
    component n2b[N];
    for (l=0; l<N; l++) {
      pedersens[l] = Pedersen(n);
      for (i=0; i<nSegments; i++) {
          nBits = (i == (nSegments-1)) ? n - (nSegments-1)*200 : 200;
          nWindows = ((nBits - 1)\4)+1;
          for (j=0; j<maxNWindows; j++) {
            for (k=0; k<2; k++) {
              pedersens[l].base[i][j][k] <== pedersenProvider.baseout[i][j][k];
              pedersens[l].dbl2[i][j][k] <== pedersenProvider.dbl2out[i][j][k];
              pedersens[l].adr3[i][j][k] <== pedersenProvider.adr3out[i][j][k];
              pedersens[l].adr4[i][j][k] <== pedersenProvider.adr4out[i][j][k];
              pedersens[l].adr5[i][j][k] <== pedersenProvider.adr5out[i][j][k];
              pedersens[l].adr6[i][j][k] <== pedersenProvider.adr6out[i][j][k];
              pedersens[l].adr7[i][j][k] <== pedersenProvider.adr7out[i][j][k];
              pedersens[l].adr8[i][j][k] <== pedersenProvider.adr8out[i][j][k];
            }
          }
      }
      n2b[l] = Num2Bits(253);

      in[l] ==> n2b[l].in;

      for  (i=0; i<253; i++) {
          pedersens[l].in[i] <== n2b[l].out[i];
      }

      for (i=253; i<n; i++) {
          pedersens[l].in[i] <== 0;
      }

      pedersens[l].out[0] ==> out[l][0];
      pedersens[l].out[1] ==> out[l][1];
    }
}

component main = Main(2);


