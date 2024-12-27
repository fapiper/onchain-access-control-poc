// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x0d2d6c735e12617b0352d1dd8e451f301c9015d6a2341e4d1acedc240f05fca1), uint256(0x01b624af5a39fefaec80b93187ff6af06a0fd2a436177769b9930cb3ffd7f6d1));
        vk.beta = Pairing.G2Point([uint256(0x22459b162f9f7e80d8097ada65779fdc077d26fcd7ed917c778e55228609a398), uint256(0x221267942298164e62e2bb0506d2415207b0106ecf353d5c5ff0ee389943cd89)], [uint256(0x165cd314c3b7b3fc7a789e9a032133bc4358ff49c219a9547844868cdfd62842), uint256(0x108031203e6f3a58f4e506204c0760fec00d9bc9e7b76b0a3e78c16dec941b73)]);
        vk.gamma = Pairing.G2Point([uint256(0x206066b0e6353e6f867499d67b76bc06cdef84d7acb8321fc0b3436d7fbf8a9a), uint256(0x1a1e129299e5c4e063e3cc08916e8bb321a70663165dcc09f1423cb2a48312e3)], [uint256(0x03fd7389f714f25947a626d9a1c70ba8437dc2072983308f26f13d7fb30ed33b), uint256(0x0e4ace089b11dd1ffe563c125399e79bacb2a658126b93dae1f3ac2b1c2d8367)]);
        vk.delta = Pairing.G2Point([uint256(0x0d1ffc27abbbff0801b97294f50433e3837342bdaee9e83c0b1091f36836507b), uint256(0x0b1f7272e2607bb2c2370e3b427ea7cd85c47882e5332c1e8ab465770a362646)], [uint256(0x06ebe916e2c316087220f7879d551202e03b18b8f8c802b66b365bc8fe5fef85), uint256(0x1d7889a10a1300ff5587e81e84cbd2a27d6787828aae0e5fa6eb45f8c8f1c0a0)]);
        vk.gamma_abc = new Pairing.G1Point[](210);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1399b0603c98d7697d0db1d247453e7320eaa2f2572a0bb976a2de53cf4c91ba), uint256(0x148c70190ff4fdef5bf3fb6a3d05ad5ee4960131303e69238fdaa8bc644369fa));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2680d5e89755beafd09c261d22e45471a16fba116b28e9323bfb7e18519f2e7e), uint256(0x1cef0c94a98c0b956f853e948e2e8bd20db59a9739b80b648843cf0e681ad160));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x28da0d918fa0eda1b52f8fd360f7744d7a74cccef9e5551c4fa2a92fc760e466), uint256(0x1bd0551dc0c2a61e2b5b77fea2a86f65de5794ec82f8b060eaf119071eccc0ae));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x28bdeb9910e90d431a14dbaaefeb922410095ff72ee4e439e4be87c2a9dddd11), uint256(0x0acbfe28ecd34ce65f9f9282e5496235120196305ec90fbfeb5d050faffe3738));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1ed4f9851a1b2850e2e21f463a4d928822e31271fadcc420cd69b43e2a5f7efb), uint256(0x0b9080c59115f28855e81c7bcaf18d659bfbe71225f8d310b376d37c76e59425));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2d7bf85a0327c43101406d170b7818778989fdbc527991c4f40544ecbde7dfe4), uint256(0x147708635057c712fd9bbae4d05d4e20a500d453afdc5428fe81930fc165dace));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1e7ef503e39e5636f6d942a0d9dafe03caa1d3a074eb98fabd4763729accdc25), uint256(0x0d12ccda873891d3771f827d5fb4219a44ef7fa63b959d99a3219adf5f152b04));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x13679f774ae51299f7c10d491e5ffbd1f5cbeb495d4d290a61a4911f5f98e97b), uint256(0x00cd88533aace8c89265a91350486774e03074ef4cfdce83939993460aa21994));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0444dff300cd9c83a1322a6cd006b1dd6bd3d495129c3aa0fee3bc35fc33ed54), uint256(0x24a757eac9e9bab3b1104fbab4517e7b0c759d4416bf934a17f3fcbe551aa65d));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2b2c97eb7a2bc14b661a3302902ee7aec3e7598402cbf6638932fdec9b7cdeb9), uint256(0x06fa7937b9f292a8e56b43e60c28ed65e48f41a5e655c65cec6377a534916a06));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x16d3ab36ba24a87a35402bab753c535a378bb419d81b9f4bac48075171d69c27), uint256(0x1eeeb13f520037cf2c782902d00df34ecd2c1644fb9dfc814ca2d01f3ccaaeaa));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2f7e87b2ed922681b52141997ac9288a6b2b7fac1de972c7e69163e50b3b0f0f), uint256(0x07b58f519885f07bcf12641107a919e6f16cb3d0c7ddad0b49bfd61cf4c6722f));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x25d51c3dbf9f076c12e297010bf6ee182bce1898452752bb0d6eadcb6fa5c2d0), uint256(0x25a0e3debc90fadec83d1792553b36c4a7b73a2f734b4e8854707fff00bc3fb5));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x20d2f63d14f217c779be868534f6375e2eafe8a053424bef9690e599c455b9f2), uint256(0x23a3d177652946a2b9386fbe237c483da7a0b8303d30f7a664636921539a3262));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x300980075c72926f0d619b49d52c3ad7008bb390bc7956d5ba8f30584e3138d3), uint256(0x23ed5520e38acb57a077cfd68647e4c9fea219a59107d540b46f0b7ab4f5aafd));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0c40eed3d2e67e7b991758bf959747fef70ad0a72830b993c75436db1812414b), uint256(0x2eee637de0cabcad87f0937cb2f30f1a31bd0fd212b4f4769e78cd6d512d8e89));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x0c572c6f8f5bd05b8a18db0f9c25367ff1e6f956eadefae1d02daeafff567508), uint256(0x1dab89699951491d9f98f81aa37ee0f1ed0063044e679036f53459bda6f106f1));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1cfc19e3ff9726bd21bb6249d05eaf2486bd503fdb045b1549fe169ce2e0b614), uint256(0x1f3aa07b4dd9f7c661204704ece9632d00582817613b887a6786bef592c5fe2a));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1ad6e208a131c06ffbcb9b5bde0e95518e7216d8f353ff1c43f65d48e7987fb8), uint256(0x011cbc212fe499ffcbd7a05d129eb5b26ccc9f920dacd3585c149cf739359e68));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x183d9d27b74971a902fe5f5bd62ff5d588e8df4df09b4a0b511fe3a124ec09c2), uint256(0x2816c03ef5a946b79d7f5478a5297021c29a2960473192b595faf0d233b70bc5));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x115b433a0e517361dc94f171d1b10f73c252a6825b32eabea8a8ddcf1caa7c4c), uint256(0x255b25640e4d16a8db5194ec56a74a03002e0ae57b397b4c4959f4fe6878e447));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x0fa82dd07fbcffe3f3e0b783f94a1a8f8881e3b3cf59b28de9903a5424d7a1a2), uint256(0x21e958406cf0afdce8c9060ecebcf46ded987ad3560e9134f4b2a1a20121db48));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x149c3e27bb4ed351c555054f60c94b93452e6f8a54a961d44f413bd3edafa450), uint256(0x0716a81e1e81aa7a28a4c65f87f5e2a79d345d564a9bd595714a7e7808092abe));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x041b5e0657080f08771b33e2e86f38810dfd5b6697c374d9b3fa9566c0769554), uint256(0x272b9c1ca6961c277d2a1bcce696f9725dcd2dae75b0e8e14a785cde03a76234));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x227f7e1aa3f6d6f8fa61bf648a77f0f5b9a1cd37fbcfb8642a85e8ec42719b7d), uint256(0x2c1083d2bef1076b771a8501276f029579565049f8f84523c313178347888bf9));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x0d29f2a5f906b973e0cb0dae6e28768ae7b393a1110a4fd8f2d01f1f77d153d3), uint256(0x1a3d8f49bccb468effa52150a76855f04ecb4dfda75f11ebcaff7137f244efbe));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x2c54072abe41f14d678db6e83f0cc7296f2f11e299c2f1238948cae68e660390), uint256(0x1dd3ad81dd474d7b0b2b1103b3eb74e88006ce5a1d9e6cd45e2078c975824a7b));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x1d210afbd7360eb904c3196e6f1d5d0d4ffd426a105e346d7eb55670608f9a03), uint256(0x0537dc122e9810b8d756263fbd0d0d53fd6b232d7e337ab781251208ac573462));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x0d2f1cba51e21aafc4e0c41c5b2caf0d56044b495f2c28fce2b71eb917eedd3b), uint256(0x25b5e5fe97df64c965dbc909c5c5e6f8d7e5a736ac6382baf1854ad3baa1db08));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x14b5af0777ec74b6d8067bca5934902d7f481002e13e39a06f91a78e08a7f7ba), uint256(0x2e1b92efe883d203c288a9fec8c94cd9c68025ad2e0cd49c6bfdd05f4da87b30));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x296138111a579433bc0aee4c7615a9eac541e082e34056eaabc820ab1cf8daff), uint256(0x1a90f25111795021b124f4bf64d7c777d35760f0b29601303c2de3216e6cb3a1));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x1aef6a673f21e3d5dc150b1b9ff9ed891e831e0f2205a274f0959af24ad94c43), uint256(0x0f7b1010a5b718273a313cd6036f06cecc53958909c43ca74f6072bbfe15cc15));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x2ff1a50aa67a56fd7d67dfd84b6d24df53b92d89453e78ae887bdba6fccdeb46), uint256(0x08d28598b6e0e9e25de635f2dc0516ef5c23352fc1873edfd90da783b85c593c));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x155a233b56d7929cf65fdd5595e0f605ee1429b6f2493ff06e5d7d31f7930b4b), uint256(0x20c60467440531b94be73c71b94acc9d45e515f7aa3aa693fa4639429577810f));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x04f677f3736b8f81c467451e664d94e4e6c2a30b18886187c2451fd44e0be239), uint256(0x0a4b3ba3b9b56ca49f3646d9118dd875a4d08c3ea9f92b21a8f4d82c92f9c447));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x2a07b43d4e93e9e75475fcfae6f19b91abdeffd2523fed02a75cb7bfe6b17811), uint256(0x17a13a282253e5d1eedbb00a7c01c6ee02e949807d3c45f80992d782c1684817));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x15022037e63fdcef15e97a6c0dfc60a59515e2ae858977c71e48461de4906a2c), uint256(0x2eebe934199018038fecc003c675a438c5acd28d900035531ae2a374d14273e9));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x140081b15867988422eb161a6e54383000d7c23e91681f107e1ec14a6485e97d), uint256(0x259770824fae80818d9e268129c70df890d05bcaf7d987b7ef8aadf9a06adb65));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x288a4273cb4732f71bca19edb730694abc57d63df0c51c096e55e13bc6b5be8c), uint256(0x24208304ffa9bc7a47708268ddc744f0802971182b2f75949294a4970c8e1f6d));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x0375110c9e9643a603bba894bba0c1a85ffce1652549ad073440c7d46ff97752), uint256(0x1482a997d05eef50e21831dd095ca9187d26a93b5ed6f2879eed6ee165485a86));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x139fd521e3e5be91d1575aea80c1809dca785ab1b0dd3b403b6f221b18f002a3), uint256(0x1daf74d2f451d2b4e9626fb9385882d80a193d4ab2027a4c578963e6a1255b20));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x1038059d8d8dcf9358d2763886e6ffdc1cf2b5b1d72758591a446d14bc1fbd20), uint256(0x0ea07d514d408650bfa7c204a8a36e8567522b9285aebfcf37d6cd19c125afdd));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x2f2716c68d89f4be424907e4887e51c0797c2d3dc7ff3da4431730240b6bf48a), uint256(0x249d6e28269eb6ca330b55a1cab21328f7be0ce334a9b0f02e6b7f221e622f87));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x2bed37cb57cedd85406a3685e38ff0b115cc8c4f573d19f7629cb35da100ea90), uint256(0x006699611605d0d0b1e4e1c952a28d66a8123623e70c9f5e9992d03d1db93915));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x2c01ad8f9aed510f653348d1e7e632389daf4ffa9cbb223a24b24964b8c528fa), uint256(0x2adfeac64f1d0c6763646a080defb427c22caaf869e6f62d4afc286c1a216927));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x1ee0523260602c75247abf0bcadfeb322387622c076ae2f9974fdae9cb18bafa), uint256(0x17fd6274bf51e0b909ae04cd1098a74311e068a771acb86e6d8007a379b226c0));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x25a403951acca86058cc6fd3f9c797e6210f99a667ab74247a0d893f003320ce), uint256(0x26fc1edcb3e2717844a9f007f791fb9ac574a72e521106ec12ed6e143b528b1f));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x287b6bb79b13cc27df33dbe1e79f7beb23bfdde020d0fecb75a8cf041ab3ddd2), uint256(0x024cf91ceb0249e9aa9257ce0230dabc0c1f2fc8e3fbe959ce62020812f98009));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x26c1bef041a1c9f6128284d7fb02226053fc16250719425f02487f47584933d0), uint256(0x2e59eb51c2ea13f625f81310c8b11980ca641297ee1696327e9958445891dd0b));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x10a8f63d354568974ecb171313ce2f43c69631f1a3e8b87f7c1a88326dedd09a), uint256(0x14e47458d374a6340143f646a02287ec11c1e96227a0d3d83420ee439ce1e653));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x182a70f4327e6268f661bd6419e1ed057fe62a1f6f7e7bc4e66bf2ed2de273bb), uint256(0x007903953a19081dec592b7e1defbe0058b9ea058f78b5bb89afa39642af8695));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x1d574acbfd2d075a23e508ce217734f4d9acd98267a0ed14cb18f98947c58d14), uint256(0x2643abd44a0437e919de2ef4e8efb5e672b8a05f42d8c10055415bb623ff4529));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x06fa0184009c38d416417089d862bb315507882c5fb35da69760f4faebfd50f1), uint256(0x277403aba4dc923c53c7659def233a262e0ff14faa31e9e075a3a197a167b57b));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x093bead3db0d31bef1c261636406f2192e8f1d2e7039812745764e106921aae1), uint256(0x2110b8ab3ca977189a1e9caaae3ece9d40fdd640d94213257922184c40b9404e));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x19b50e5757c629f2c0fa3530e47bd3b45f5891c44d9e98bfc1473a1698590bfc), uint256(0x0db6e089345d55f37ba8c4e28c7af00c5513d18c91206572bfefea95530682e0));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x14c2423ecca22639f3f53862d012963750aa215aed283bdf91c663a9c853ba05), uint256(0x0d1f384af847c943fc76947db179cff9b0c3a1695fd8c2b72329617e47764eca));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x277e0cd628f9967c09e68c72aa86ccb0d61210da8dfd6d212c3317f93789389e), uint256(0x14e94a49850a541ea173ec354255866ec1dd9e004edc02b5633b699ac10e8fba));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x1bafda4059c36f7cf75e206d9dbee25655f320c0c59b7dbf561236ebc7c2151f), uint256(0x23a7cb7fba7969acb4eff29378fcbeac731bbaf6b3de9ee5fb3df41bc6163bbe));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x13b1d7507b83de7e73fa33ff71a45fbd49d7a048c280a3ed81a7bfbcf4db26c4), uint256(0x1399e1296028d8a219ec5b2ee6ddaf1cb9fe953c763553ba324979c0e43b3ff7));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x2020d6e7f3ac4f44ec78d17156bc5332d66bb8b043fb5a7fa157cb331e9d31f6), uint256(0x02c84b073347926364124038036d00d5f216cb269188e93f636e77cdb502f537));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x0a08207555ad4bf8a240bf892611f04762a8610f1685ee2c330f59db739e1c35), uint256(0x260bb9f06b18a66c136b7a5850fa9c04ec4769716210252b0d26f6cc49b2d0f1));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x0a00d706862aa39cdec94c895aeb0f061a7e876de45ecc296c52285270d6108a), uint256(0x026d2e0a206966b035947b50c76b501de58ad54b6330f417ecadc4348def3c03));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x2517589fe5a1d236b2f3ff6ca8706d02a68921588756ed667bb5712a8a1d8679), uint256(0x11bec9c23f36d91f393da257553e1cca498144b1d244c1eaf8fd5e74ca424acf));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x099fb9d72fa92108efe898c814b8001a0810a719b536bee7a6c943e6f964f884), uint256(0x0a7a621e10d30796128ce4f2e41ab159415279069620345138aadf43add09593));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x12089cf17e126a276ac4d8a87f1234aabe52e788e1df249ccfefb2918e4db4d1), uint256(0x2b869771e5ae073bd20f41d0d999da783a7145508fe8488d23aa3b4d72b8774a));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x2aca6c37cf5065b55b564ea99914cea7e2f618136aefec14ffa73a187a91a784), uint256(0x24c9922fd84679dd3efd0217462a42e091e2fbd5d19a264f898a0dc2a4d110e5));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x0b9ec03018af58c665b6655fac4b74c78d1d3ca2519cef10e4a9adf86b81a3a2), uint256(0x1603ffa006dcca5e1415c67643db5aed980a92cc70183a9184a028b5141fee8e));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x0bbde2f5c6d269a039d901db9cd9566d41f9d1f889cc7e9ea33cf3a98737d66d), uint256(0x17cf3c690c509acea372ec70e421f516cc3ef87f301a4674e30a885c534429ce));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x0a58a8f4beae22320019c4dfb4a88e9a7388e8bdee682ca04a843cd5ad655c31), uint256(0x2e30f9e4578b42e8642aeba5f59b158f972e08155a80e9effb06fda29dcd3c5a));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x0673636ac904e9b28a6c1dfa7ac6dde3cdfb73dd7f4fb13215bb0eab1ec5496e), uint256(0x28b6a5de21873c0aa54aa455741c5a09af5151130fe244cd5b807d78c2dd740c));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x109a8f4b676fe8190bc0e203c1d44cfc09d391764f053642b2afb63483fa56f9), uint256(0x053b2eda7c8a670e3affb27e5fcfbb1cc874357ec43a426b353ebc586a853f6b));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x10248bee111161bb9f68dfe60592212babcec57970d6c3b71de73be1670b346b), uint256(0x21c9afbad03ce28d94b5cc6894675616450bb503093aca52dab6f35ec7dc29aa));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x0644c6815c74bd75ee58a76024dead0a462237341e0b8071bdbe8fd530b1610c), uint256(0x2ade3dc46df1c1a80b13979f75e3b3944551eb3d579fab58aea98b9a2b8efcca));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x2e63f58c38139a14a0cbcbf2f29edbd8f682a713c1cfeafa998f4e4e3134867c), uint256(0x068ee292d4f8130490ec2973b1ada919d5ff930c930acaa2a8d474ba4ab13658));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x1058b88cd468512f2d41dfb35a49b12d61775343e3d3b3a1a40c8da45d956bc7), uint256(0x188df12221ec2f72285a53b32dc6fe115bb712b17f26a789314c34ad20771529));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x13463031019270316898ccd55b8eb3a86ac96ee48ee2961a61c882bed5c567a2), uint256(0x0e3fd07871025e25ebdcddb4b427b7d038e338fe8e17372ab8832bdd4a4671f0));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x22cd24c92c4542a1a4f65e682c1e199f731bfc9c394073292223aa03ab0ac4cd), uint256(0x25601287e1439cba6c94ea216baf545c00fdefe99078494f65efbfcace38a552));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x211b5ff495cd99190143ea003db62474741d9ec771b655bc20a19e013e9047c1), uint256(0x0e070e2901eac7c5f25fd6b52dd388a863d39be30afed53c634e519378735a00));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x101c4583cfa2716ddb450ca1286584a3391efb47dbe5f9dbf3d9bf31a11fe343), uint256(0x252253f1181ac7858bc8b684088179734612e4a98a8ff925d29dd7616c21bbda));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x27fe17cea130f1a0d0ce8bfc8ae93b2d16f243febac9522f7f04efdf6a4d7069), uint256(0x1f5b34fa478f4bd680813a361d5e62c00da48c808a059967fecfda6529c78ad4));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x2fecd9652bd2477da31cd25fe1958f553dc405d0a641c5c28e06d3a5b4f79d6b), uint256(0x247098405f844cfed5d83cb0791638d5eda794f443be4ed2a6320c072501cbe9));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x0f42af8dfcd7a0d530eebbff7e26faea33628b1910e0a5a9e9ddf16ca852b3a0), uint256(0x1cb5ae0771a9588e0ea9111b0b781efa0df81e8aec60c2c75a7f72286f6810da));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x08a8ffa97787f1e103402131fee500685204bb13d38ba60417959dba6fe73bf7), uint256(0x1934d6248df8ad224e45a3e6afb3caa0f4229271c255db182c4e2a8516f1bcdc));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x2f62eb2fcbb0d996c8567292104468784d9b1d4718765bfd81d6b534d351308f), uint256(0x17f3c78bb3a036971be280d984460dc1ba5eeb52b38c7d7c90e83cd900ba0594));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x26a054a8a786220aeae06c40aa217956d4539a8781dcca9d1ee5763852f3d45c), uint256(0x2605e080adaa2a6835e3886bfc50ab27c0a27854d262f924687a04b59c5e7d05));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x1829e1a102a44cb948c514351542da159b1d1e405d839d7ae3e47dae586b206d), uint256(0x01fb50f5d42d6c7d7fdba92cc7406fb4aad160f1bc30a932ca99a5bee0370808));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x067df4437ae33ab8da31e4f540c94fcabd186454dfa5ed23093e42db0abf97e2), uint256(0x14aca23370cd0878a4827333374e99add281ba80a6bf89239436fdaa9c19a478));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x231cf0beba00a90e462f25934f9aa70cb2127127d6aaa4063a58a4e7d3b769fb), uint256(0x206aaa49285c6f08a98bc59fc2814ec65e8ec001ddb8e616f51b33efd0569757));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x127b07e82ad748a0e95af9ce54d3492b6b514e10776a1ffc69427a4aa51ac020), uint256(0x14b0bb5f6ff54703e31fd9f04ca80432a8284e1eaa097669bb8e6e24bd5524b3));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x1799275cbde900f7f40fc514791de0c859f9731f92924c1eee6d38d77a449d3a), uint256(0x272979d2d690e3e63580471361a2013ed8fd26efbeb59a50fb8e9a9b344d2a63));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x0cee7d1473531508b8d56a6fbe6013366589987a6c8155263bf1c8a168b8ea24), uint256(0x276ca8ca6a5bd9c93a39766feb5a44d7ecf1de88e479ad95157c8202f1a0ca51));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x19a53055c1fbf03e17b662b42a08123110411f0e0924631507e866a92277eb53), uint256(0x1b176fa7f3ced18fb34f2578eef3386ef2b95b836ab715371df0fe3c36634fbc));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x02fb7b438cc757aff4f38ee2c162d5a549d7b3c67e1968d4865313d919ee989d), uint256(0x0209ad4f914a2dead193ac94e26a52e96a637473e10fdb53be7728d7f63b38ff));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x2c908599efdaaaf84c984fb1d06741bf6fabde4c5130f239d06f3ed5ab8caa48), uint256(0x125f2db88307a31d0b6b759ee8552d4fdb5baaf95d0ec437d92cbad25ec40c15));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x13a64a62b9eeeaad7092e5a0db4fc7b2d5a6771da82a9340e0410d585df6cc57), uint256(0x16e789f75ed9c2db018c726408865e99bda0aa7d0160c2a0e9e33127035278c6));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x210a77084c23342d38827bccbffa3ff1acb5080798233d40ec1f6889f9e4679b), uint256(0x1c67b4887e9d1d56bfb5f73db50417444d6d98693507493cdcae43653bc42fa2));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x14517c19a35260981029e47de27dc7764e0f0d00bfc8801d78b2db2b36d73f2e), uint256(0x1f343d14a1e468da88cc35067f787235270a2f0a0a8a78a2bc041bec8894f8da));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x06ab1fb4eb215b2f4f090887a7597f132e4bf41f5410fb20cdba9aa32bc7f87a), uint256(0x0f4965e9a8b6d87b6280a66655e77b8a96a58ac48f6ed9cd37a60b0e9034be92));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x12141e8e570b852962a43eb0b2ccbe1a9cd3e02a4642d2531c65adc9ad6bce32), uint256(0x0e7f52f911f55ce4b611d664acf669565da46084cccf2d6aceb77549d47b64ab));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x29bd592c2a6ce4258f9100b933d0be6b2e199956aa8e5dda94e3c2e8330089fa), uint256(0x2e8d47fba2e946ac3e9a1c75fd040aade8b6760302e5d15f394e930575c7933d));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x00baade8b6fff7b4a1ab369f5f94bdd95211bdc74a0ff644ec4a9aff88a4b626), uint256(0x08708130fc598e074491d697d55be85ea9616540e6885ce2150eaf681000d47a));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x087e0d2d98c80bd9e99204af0134bce45d4d8bd3ec81e11ce51778230c812374), uint256(0x2fb9fb6fea3b938c299767fee620a11b05c29906936ec0e90058125e956fd8aa));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x1cf4d5354b35a9952aaaea78afb5e5ea4eb27afb290e9eb2c753e84c784579f9), uint256(0x188b9e44f83317b69f1be9cad809f0e902855db45430f484230ccfecdd98e9f4));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x02856de871f72a49ae857e5352d7f731d1fb7558a9aa9a743fbd6cd4b96de1bd), uint256(0x165d05b004b7bafd3718b312950a39c1583d2e62cd0e6642269d824fae274917));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x0c3a6709952e069f01d91b3e57775099fa15ab90bdfddb8f00938a1c61c9bc33), uint256(0x1c75aecf4aba34c7ce9aeb773fb48c8dee6d83db96bc6097786d589175889875));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x00a5f5bef55a27ca7ec3c4578a785b4a279cc06d434937d75e8e963dc92fa826), uint256(0x1882f280e6aabf19d4d96a79d4caf6b62b89fed7a77e776631fe44afeeeebcf7));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x27d9b60aea0ab50b9c5b017b372f1740aa25890bb64c0d326d8eaf2523277fd6), uint256(0x2a0371835c1f2460ab18e48e89a3ff986032988469b41993260ff315a815e28e));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x268e3e185df719cf65ef0d2f5e0d0b57efb911b45b5688c6ab5d1b4be07fb7e9), uint256(0x071a5ca53fdacaa0bbc47b61600fb0a129e418673aef162288ef0bce1f0ed1df));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x2653c516aac15c059d3b8fa60b4c5130f61ca874f48feb2ab706176e64a6a18e), uint256(0x24d267ac1b46bd8fc8dac6b4387f6ca91e146eb52254694fa6559881838a8da9));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x0ef01c660ea1a940a9f7b127ec4d09073fb2421386004515a22b4b8d7bcd510f), uint256(0x03ac2d6725a615110d39717fa2ca89e2a0d4398d00d9109a3b9c4d2cb8efb901));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x2f9ebd53ec08cf5d6b4f8f9ad581efa211012277321a8c72b96db6c6b29efdad), uint256(0x248c911c868a23405f76a773a921cb90fa22e66e61630e5d7e98b512628d6118));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x0983904641d4190839ecf26fff1f9a490c508cd9d61804dc85d90e3abfa993ce), uint256(0x006b7a775d52d6d4bb3191701251d72b2400d6376f738a3dfc381b4b84c7a7c6));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x0c55e7a29502887e900257567845f2e3379f3eb3994f4b5d9f3c967367a55c38), uint256(0x1e769134a2369d907e876bb84f23c9dcc71a096549414362890fd85d6db829c9));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x04d368109e49e56993df3b5bd04d93017d772ec87e87bd436c625eb67bbab410), uint256(0x17e9e335ff04513b8280f7769e349a6581ea873ee9c83a2b5055bf844f64c688));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x09deb061512337412b55bf6f7368dbcadbd0677a4ae41ae946a9f98682d02e98), uint256(0x1d1f5356d1457fc090b243b2b31688a2b33eddda3d467f8585cb3adab6118453));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x2e68f17b5a039aaebff5db5d6eb4e660a54bf1554af9fa07deb1bc160c7cdb03), uint256(0x2c296bc823dd7d73e4f687ee080c9bce232f522f40fb21ebd14ea9abb82ca82d));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x2283bb4eca745f38f3ae85ccf139a22ae73c24ad3a5d9445e5f8d357d5e08796), uint256(0x2e30c06ccd587e304a4f07c99469742e6faea6c8a007eff978289def2c8e3dae));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x0ffefd5cdb14363aff931efaec30e8e8a0ebe7e1fc07a71b156efa58587f19c2), uint256(0x17bd0969b192c5188ab2cf9c8df90f65b13c04832d7b2d433c5823dbc627ebef));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x0b2977f594d063bc2398370aa6056243a9c80837d65fd379461d61d6d1949205), uint256(0x2afe1b180555d8b61c31dff2e4ec3cec574cc28cf7c0ad44e64d3e876203a496));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x1192ac0d5eb0a9aeb912fc9f8bba333fea94aef4723efb1cf996d46d4e2d52f7), uint256(0x0998a3cb71c4608bce806d1dba693721982d5844bfa5bb81928f730eff7cc27b));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x004505194d1baaac5ea011e9dfc7023c48845d7cc16be93cc507094e12b75664), uint256(0x2db700028d5b2b7e937bd48a9de69e1753a2b36f2a6a267985659590384629ae));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x187e50e27bafc99c7888d183f0ffa7445e9247eb7353a02d416856c2ba080361), uint256(0x2a5faa781e40631d8f6f1c985f19d8d0a56ca8352d9aa93712dfe91ba870bd6c));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x2d4d53dee138e200db6a6bba80e37429684d85a04e8d9b73198e4939825427fe), uint256(0x11bd1527e88c84ace121e3ca3ee582af547b5ac4a6350adb12342cb7f84a7217));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x2e2db88c3fad9aa04765d1d3f15e7aede8c72a7d77f1dd5bcb7b400ab1c568ec), uint256(0x184dbea1dbdcc8a4e15ef917965696db225e7d722e5956c418693eef9b7c363a));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x247d490f2512027a0c2f975dd0c317703412779f2e9edc6ffa6b8202fc659cb2), uint256(0x0f1f32fde47d35c3e36375319b9e6817e00ceb425f61355b8c94d8f33f0dd0ef));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x0ec7f0c2945aaec0036ea232c9a33402e803fc93fbe27a07ac316a49d8840258), uint256(0x0c579fbaa179d9bc1cab1428c4ad92e99ee39bc2559ac45e8d944ae8bc2ed78e));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x21be79717916a4d50133bf950bdaf9cf2cd8235869e270ab14a39c4075de000b), uint256(0x10a4d97d7ea85550fbc815bb6d021a4f03b78aac7e2f9c90be2924d3cce27b57));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x27ff2582149a5cdb74e4e726d73c5cc25ad590d8dd15963faff6b54351b49c57), uint256(0x1934857a3e9be2829d244bf8c3974eba8b52fc5c1ece13093ac9c92ffa205bb4));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x2f9f335eea905a705e19ea23c93a628c5ce8efd7be1ade09abdaf3da72181495), uint256(0x029f78fbf4d622f350f632065066f5d080232eb2718fc05cf884669834c49067));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x0f018663635f9a0aaecef6f39bf0e21a138839c2dcd00d0c8ff34a57a790b51f), uint256(0x062372c163e2c4ca90b7e8f45c4c020d1cb26a50f619cf0a6d0ffb73763ce0c0));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x0d2b818dd0d42a7836d58d5bc11de35e0d0d3222028be5c9ab38c56b108ad091), uint256(0x19cbb15fb601802ce1fce36a62e5bab3eca244cd17b3ce3e978c13a097a7b15e));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x16ec3f475a66730d107f95a53d30685c6c6ad6ffaf891aa2231057ce36fef009), uint256(0x2e74311ae882e380a88d2de488881ee3d346830f1759c4f3616d8aa3379a32c6));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x29d715d91b1751430effc90dfc2ece72ffce799d4d1017e55819edca2b0b310a), uint256(0x1489a693c9d38c16d9326168489cb3a8fddbdc0dfa05b474ed2749ae512723b8));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x2d04a0fcd6b25659abc8c1e156bfdad471c5abec6500a48c9e84ddc9287260d7), uint256(0x0ddc3372d51b7b5845e705048294e46b93b952101aa638c0a03ddf32a313a26a));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x0672dd8e0230b74e7ab9a81e00aef4f9469839d3ad9c53362d4ce22a23b416ec), uint256(0x0fb14f69fb8fba452f8830c456c8a0b6623d07b27e1d069416d9635f2e8f3645));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x2069177fd920e88cbdc10d00deef65824c36d664ecf4002c45dce6c979428757), uint256(0x14e98e40859eeb4463128225c6de8d38d552a9b05ea887f83f2a618c057cb58e));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x124460647fa5ce4d5113521ce9a9bd43f49e3a405581344aff37461a975d0f22), uint256(0x0a08e7e8fc998df2558825cbe0e585f63969b38ef18af13f74d636d2f96f5989));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x016037d8797fe209be57782fe0b68e428b5da3c0cead0d5428f3fbab5603438a), uint256(0x01e5f43f3eee0610c07f1349bbebb0829e0619d27ce86633a454633f5baaeb68));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x0d9064523ac8eb2175e4ebffd1b0997de417edb8a571d9a965402ec879fdea3d), uint256(0x2bc641cc0c16cc60a7926709f2fc5b382914c1875b5e547874da913c8b5afb50));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x11fb9d03d58034684ffe13dffcdb274f19d29079f6ce29d6acb07e7084b12239), uint256(0x1e595c334921725bfda4ffb8a76bd7664eaa7fea5f063a8a976f55235800d1f1));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x2b77641bf8b01dc8ff77d3bec2edacecb3d882eb838f8a7d59d54eca8ce20228), uint256(0x2df32b3f0e0fa0f9654af85540329a9eb17a7d2abe653ece618cc826d5de9cfa));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x2edd6ef616e23f6075e62ad1862b7b265ccc892a77d25b09be95e6d0f9ffdace), uint256(0x21c3c0e20b156e25558b0a79b4db9ee6180472baf348f7fa8e756a61e11c1462));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x087f73be9cbbb65944a78f2e537e690db518b175b0c9152b7bf337a9c88bd2dd), uint256(0x116fc00fd25ad3619d8cb3a5c5be9417b2376e9729e58cc635bcd7146bf0cee0));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x01ab2ad41493d21e75e0d4d105625ac11fc0b665642eceddf15cd78f089729f9), uint256(0x13f3aa98fb25209cd7664be0ee7f520b16846c0375bae5f7539f136df7d685ef));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x262cd3f5e6f670a618ba01231c18da92fd159e96d69823fc6ec12e8610f1b19e), uint256(0x01c211e2edb0728e1469bb970ce7e6c5ec12962eeab3803ee763fbdb938e09fd));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x0d695a35b6811ca89e9de19953c1c92e6d8f0a8a6f1ce16c243cee0c0d7d1cc5), uint256(0x0b77b7285efc4d5abab281c6e6e89033939f9648124fb3349dae705e995a1e1b));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x2ff98a599c128aafb9c66468f33ebe218103159fea8ced2c0590cdbd05c8be19), uint256(0x170bde8673e95ad6429165e4b94a714c372928d19558ba9a95ff2c020438154e));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x2d76a54399987c0df2ad24f9ed07b7789ba9f47513ed558c1f69b8a1ab7e7067), uint256(0x0e5b4577fe382c3eaa59d8b2941e9d895ee8fe7c608c1c05b8246d16caed59ea));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x1432717019a78e80b66232fde1ebaf66823c1bc6e01575dd9d0370363030fb44), uint256(0x08f2b8bbab2589573f0b0c1b944feb30d00a097f98fd2e6375c378b57cebe197));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x127a4c2c607604850674a1cc7cd1fae84d24502061f88160a347c7424001aa80), uint256(0x17a14967ed29252237ec26ea65c6834ac09b6c57c1a48eccd2cc1e3cc916d10a));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x1b8cac6cbd326bfa3b43cb4f4b101569ad79a43820fe0e8f7f87b62d57775b00), uint256(0x1275e50c37031eafcc05e5889a2eb37cf796a0e9f82c91802045ccd8d6c6d174));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x2cf3cabd971080e556f2c2b07a26e61491b70c2005c1e700c43f41e5df13e54c), uint256(0x17139dac950952f73f2733392ac1c2f4530033c7b2ceb313f8a0a2c188262a85));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x0ddb0cb0de79d718003477f4a6804d50493d54ae007f59346b825c03baaec852), uint256(0x14b26b2de790c2403ecc465173a6e6069e7fad335f688d190812798b4f252958));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x178b320e93f97d6225236ec06846d195a2084124c950c3f7f14cf35bacb96453), uint256(0x0337bbc393ce6975149f00b4c6c4ad96eb306687cacf04fbc541e2fc2113c550));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x256bea5f61bab1645fd0573dd234d35ddf177da9883dc04c1e070fa5e145464c), uint256(0x11e65c3a576324ce04a37f25899d22b94d166fb66b5893ae2f4d4ebf8a09cf23));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x0e0c1aabdc09cf3d61feeb7e553b079c16a6f1aea7b8a0f0aa0effb89db8fcf1), uint256(0x0998ed5184de5859e7c26fb579851df66ceb5398e08831ec5edad97140f087b5));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x003d6b36747562769da37ee1dbd38e4acd1088c18886c31f942e305d64576d1a), uint256(0x0b21d760d8d0cfa732fcd4013212464017738e5617e06e9308b89c6eadc68deb));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x01e984aba849621f3262ab7ba52fc179a0b7ffc95acbc09938cafeeaae5cab55), uint256(0x16c85b07c5dea00ab294c5a8d4ff3f9a2ca452e6c6b170ab8667de3ced5f47d9));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x0a7a3b378bb7c19e58f90766a221606a2c111e9a5dad812e62170a8f4843d45e), uint256(0x22d2f3915d1ab19e169d5df9372dd5b2a610e63915407c77b179c3415d947595));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x27e8d1d38978d3a8a2f515ac777cdc142a7be6afbe2c4e252e20c5369faf8785), uint256(0x0efaf14fa98203c89cb293d563c8a1fb0e76afd5efe32d17efd360adaff611f1));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x210957e8cba7545966cfff23988bbcdd9a6ec88c3b9a4c11b2b33aa0b9dee86c), uint256(0x28a5bf1266cf5cc0d16de4ebfee20d3504d25cacea6c2b43d4a9020c7624ef71));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x2921c99e2f6ff9f3e3e085e889499861c1947eb307b6fad8f2ff3c643ae2eacf), uint256(0x05c71fe07cd18c2afffa53fd6ea77b50c3a297bb703b38a6a93832c1676fbf25));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x28745271c937c6c837f4205193545fc63fd519da375801c50a8a0423bbc165fb), uint256(0x184f4e8af5dfe875c40bb1916ebc6fc9b989ca6303e11290aaf79c4006be2bf6));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x0dbdc1b9838db5c2443081ccb0151814ab336bbf0a82abb23f88babf88c628d3), uint256(0x0219e8b2284edffdd55bed65f7f5a2eef91a37cb745115e771f550bdc33af8f6));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x2fcddf124e49f56de523f95d8cb168ae6168fbcc3fd7ae27d1c6424c488fadc0), uint256(0x0986b7b48ca191587cf718706ddeca4288d921c37a54c63a0dbe10213c053301));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x132b8f3ee15f87ec60f65455d6740cb663e14310e1d9ad81146717558f2d16fc), uint256(0x2dd1d4a6be7545ce8af8b513f237272a2dec204ef5471101a050df2649c3b4f3));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x09f1d3983f2aa7f63bf1dea70a4048ce9b3c7cf45ef61f6352431f5e8bbc5e76), uint256(0x2000b195c9a54114d24411d14217b6c736bbff77711ac3f7505d887f7b912ac6));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x2bf29a9ee9796272ded1bacda84c3fc5edde2ef51e25e8bdc3ae8d10f483e44a), uint256(0x24157adbdae9b3f500e4bea4a869adb6ca5aa820649e27f269b77a7bdcb46185));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x16b35a4ee4ab6ee77f159f4991fcff9324531f6b3daa63deca69a5ff76fc3ef6), uint256(0x126b4fbd97c75544d8793d7728b5e44dfd8725e18b9cf32e78e3ded16296a54a));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x22ebb4e86ddef4f4249d86787fe5da1f7c025bba9a48c1d5cedaef951b176882), uint256(0x066937cf65c8013ced69f6609bc28c55f9fdf136ffe985a9ca37cc70ab35baa9));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x1fc34fd33aa1d02397f12f3d888fadd6dd8fc606021afa1237838a527a6b8689), uint256(0x0efefac8494793aa693fc13525ea1b302da352cc5f5baed515e1d2bc7495b1fb));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x0d6d5d5f60a357643e8fb72ac96b4f057aba39615f1b66c530e875cb6d775aaf), uint256(0x2a03bc9e441b206f8540a1f9974b637b55cb932c7487fcd9431e78bd45756810));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x18ef90b216bd8517dc6056631a3bbcbb47c8950fd622cee7eaf0810a603f2cbe), uint256(0x21ef8a0f7c4fb1cb8fcb8d0603d6c1ea30adb3c7469925f264f70a065c0951f6));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x10de98cf0a80a0fa7820397ccc411732f09242fa54ca479bc507c890d124b5b6), uint256(0x0e7834425d90bb2880996ae07d54ef75e0a5125692361f7226070fc34d423530));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x0bcec6e994b0535d4c29a701f353cf0207b30faec763d3a8510cade19370129d), uint256(0x2759d9f11380955524225308db13abea46904556bd5bd681b76c8aa377758bac));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x110600145fc9799772923281f57591ade92c7d734410279fc9828eb1d1f8310c), uint256(0x2becc6ab31f87d3fc0fa2dd8efecda77809b1ec2a8e11db5f254cf7ce710696e));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x0d1ce5c4523c4e3db5c8c1ef7c8178da6f80589c42fbb2701ef6a8e75878ffcd), uint256(0x2c6df79f73c0c9a0dd54d153145f655b1971aadcd419eb314a519a04d262ff33));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x1e9c6a08a16e70686eebb8a6e623bb2b74f4b167ec98ff730608ccf62545e97d), uint256(0x265566d8677d57282fee9d1d6d56b9b75a46b9a3fa0503f83579b8efa655c152));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x0e258c190004275004e74da7fdd369111883ae4a06949d9552cf4454bf9125fc), uint256(0x1b63ea4c2667446eb9fa13aa033f9d7291584aca69f53fc5366a836a5630d5ad));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x27e916ed0668856c9fa32bc204563338c8a905ab9f9766ee9f5d8fe79adcc85f), uint256(0x2aaa2f23eb6cae465dd09a61786ba3d971c9b02883861f141e06f9a1839664c1));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x04ba50f961e350666bc928fbbc489581fc37e01cedd43d51d8b888ca694f99c0), uint256(0x0bd41b258513a6762a18fa03d873311f2cbc64305ed4272a14d975af9e767431));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x0620832a894127c0f558f21cbe07e988dd798f39a9293bda91335a3591c52219), uint256(0x072e8aef0a504a0274e24a03ed5a2538941f65c14f90242a645c14a4fb53d9ba));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x2db156a4014adda3396119673effa63c8456156e955cd4f289fad9330c46b60a), uint256(0x187b1e3d0800b98746650f787ee2a2b5ad450367924c53818c43950f1b7200fb));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x16b27217f49016be6f9a789b568f75fc9711607bc20c25c9798ace9f48688367), uint256(0x13375bcf53932cce74af3dd579bcb27d2a2e7a90e762f9fbc707022e89cd9d93));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x29723303388c2048f06dc17301dbc9816f55f8f2122e1c41cb0853e77a4c1906), uint256(0x08c91b9e7d9e7999ab7a9ff0420c2087e67c0abef9fcbbec5500f2a7adcd2243));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x06f7d1cb8650e741ba615a18628a65f42c6e3c981ad137034464b21c85d1297b), uint256(0x2a399535ef6f56fe683ec890d9c10e331e50142317b80071846a3a0e5d919187));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x1789da144c9d78e3391ed18a2566c79b9f2ff28120197de27825f986a7392020), uint256(0x1cbca5bdeb48d82c4b8ea47712fccbb74b8ed6a31db6f119649bd3da3293d596));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x106ed1f9dbf8d7ebbfd5e8d8ef74448a76408612121ee87b0d5218bce5c79102), uint256(0x080d00145103843bbc9347051f30c67576f5c5ced69a2bdf4d8028523a755971));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x25e48bf5116c47dcdacba30318db8924f610bf48dc7c0ca0956e82954e0664ef), uint256(0x22d9bf853321bc5dd5ddc77dfb7b82fd9d9fdb40c94f67f6c1e4c32eba0fbd56));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x2913622227a33daa212178bbe10a591fc4b3f9d8852429bf4db205a0827dd5a8), uint256(0x0eb19a589f4ba6569f3014fa74b7be17405024e16562cc8714f05d677237f7de));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x1759942bd0a16e5246297046a834c443b325047338d10f5ab84f7568dd316e88), uint256(0x0d61aafc8698b85ce39ef38b74f8c8f77fbe53fa5a61d1b2db7c23f37cfab948));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x2f9c17d2eba3d3349acfca19a9c1dc02fcda9151c051e5b304406290fd828300), uint256(0x1df2a80594626668141acde1d1d2b60b870a179a8246d1e80545bc2365fc4255));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x26c1c37504ede543a4bef72894c65c367ddde959a09f1c16e017d3816fff6d83), uint256(0x26014db48d21ac0c52a2bcbd376fe5264a21fe6b069924516de0962050b42e14));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x27ecb0a61334672d3fa9c5ad1ec0dab8835083907a04cefe372cd176c6fd306e), uint256(0x240e430776c0054261cd075af812be3ab58aef39702af2e5d27db71a2ff36123));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x1144f14a40a0847b95a91ce348a29368dd8a693dd509bb5765d4b34739dc9f67), uint256(0x233065ff61a589cbdd0d69166c689e0dd117420795c326fd8eedae5e1ee159df));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x01e9866a909c1e857e4a56d2aa6f9a0f93fcfa05f52af52d1c2e127b24d7b141), uint256(0x1c8b25d5f73f80a8761e9c3b50782d35132ed4d9740b0a3385cb2b18e4037dfa));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x126fa9412fde45e4d5727cddad9e7211e05d4d1d37081c1cf4864b592e8abade), uint256(0x103c7c4625305ecdefcef9574ca64a0c2b2c5a327af4652ecc1ae17e3f3be57e));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x0193d00c2522fdca0eb61661d7b7028d1d9c22ce43875a5ddd3f25288956e387), uint256(0x2b751aadbdfb573e4e64dbe2efa4b4311c6aa7b6997e33fbc136ae3feac786fe));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x2ee7c4c3dccc9ab3ef19164274907f2cf007e49f310317f49a24227974c95d0d), uint256(0x028809ea810ea2c26ae41b415ab50539c12d104ac612b84e2441ed283bc26198));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x2fa88b8c837f28ed28dc33bec8b90db771dd3ca0e82d675cfa3d1f862b1bae59), uint256(0x09d504a055c32c9611bb30f128061e8bf489457f8ac811e5054046050fa4b99b));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x13532c9a5ba7d0a776d76a0edba03297adf2507c0a1f9c9c939126540605e264), uint256(0x1e5d33e66f19edf1f7d618c12fb2aca2b2070963013564b903213a1b3364773b));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x0a01d26b2b090a87ca0d3404116ad53dd26d92b08cdfb2b20125f17106837da1), uint256(0x2ab25939da543e72d796040bb23449061a3a77a10d69e98662c60dd9a669d580));
        vk.gamma_abc[202] = Pairing.G1Point(uint256(0x22de2d976f6757b02f7e41038f456ef2cdd71cb5ea2edd6548ae22f7c466f9ae), uint256(0x24933f8f2c6e93c33d75694e0f9f44ce1aa4ed7bb808e699f42a8acaabc4f8dc));
        vk.gamma_abc[203] = Pairing.G1Point(uint256(0x2bbf9ddea0f9fd29c003e53a974b66235b44c037e9e1a0310d9eb652643eb161), uint256(0x00945266e76c6fd0d3a2a06124e02065a13c814988808904d78a680e830f198a));
        vk.gamma_abc[204] = Pairing.G1Point(uint256(0x03cbaa01f58d1a304cd82a2a725a25e11b2323f8f8cbcfbee29fa57cd8ef2f94), uint256(0x27a79f2146f8638abd7c86dcabd245861820a77ecdfde5d6d5e2fc877afe7ac3));
        vk.gamma_abc[205] = Pairing.G1Point(uint256(0x0babee66d178f297995fcd4cf654e856fca1548876a38eb0ba69d9841e3e7c24), uint256(0x09f3f450a1dafb298de6d91de939deffa867d4e09cc3339c651064e0616b15f0));
        vk.gamma_abc[206] = Pairing.G1Point(uint256(0x24f8a3bd7127ed6123b1b8b68f0e57c35f33ff34778c2989e6d4111c4892d0b2), uint256(0x10841a411b740dcd444c44005e19d1e0e73ae44bbb5f15536fe61b575f73f4c6));
        vk.gamma_abc[207] = Pairing.G1Point(uint256(0x0e6bd21889e5ecb5fe76577487891eb83a2e34fb04a65caff4bb798504661d93), uint256(0x2d8354655167daa1a8694f0a486117d25b7886e963d53d8af6f8e481f40614bb));
        vk.gamma_abc[208] = Pairing.G1Point(uint256(0x1f37009d075fef33bc02121a479503afe9d75b4fa301ac157675bf639f0380f9), uint256(0x0ef98e8bc17f448118e711ddb774b7e991f7114f84b6eb6a91a6c055d17aadd4));
        vk.gamma_abc[209] = Pairing.G1Point(uint256(0x09fa00bf25087219bb08c105aef4a220100d98d75d63fbb95c731d6e4874dc46), uint256(0x10c9f87be3f6e21df817b052d906914f4c019104c86262fbbb8e85af92062ebe));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[209] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](209);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
