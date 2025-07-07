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
        vk.alpha = Pairing.G1Point(uint256(0x232e410867dcfd2306951389e712d898c5770fc5e5bb66aaa494bb14278d6897), uint256(0x0ff8b5db388f8111297c32e00ccccef2717bdd818ee5e91c6b1f5817d869abea));
        vk.beta = Pairing.G2Point([uint256(0x1a6a967b9c8a8897ff58ed9a900d403bf425d30e47e938dd9e798d428871ee19), uint256(0x2454dedff8ba53c176569ff61a2945bfbe8c20444778ca9e2d2992c47503f959)], [uint256(0x2022699a893282bcec6e9d73c552e8bdec2cc2e0186eb885d4809af058536702), uint256(0x1afebde31df6754a0ffa4e9ada48cf3669988f0bfc91d201b864bdff67caf596)]);
        vk.gamma = Pairing.G2Point([uint256(0x2e7c0a061cef07d94eaa2a4f75337964fd5e79871debb8fdea155f768feb72d1), uint256(0x2ffff4ba0863acc27cae0e4b6a362c50e8f91c75a2857c0603dd591062c8f425)], [uint256(0x0a30f34b1be7663f8d9428c30aa8211e2a6c1b02b7048915219c355ca7bf4465), uint256(0x2113341dcc942cdfeac46616658dbd7b0f51069fe8f86ce664592a3fd5960894)]);
        vk.delta = Pairing.G2Point([uint256(0x0e2092e8160dc68fe790c8e69670a600483a43a207d3eacbeb962b779389df9a), uint256(0x1ed075b2dd3cecdc78958434b7defc581b02ddbc6d358f7ff3c7590d21a3d4f5)], [uint256(0x025a01e6d89747b759ff24731b4b30069604a9f41d6d7b7d8647c5ad8992c179), uint256(0x0882bd08cb779610784ecf98913927f983b1283376b3bda5a77d6dcc6fa8fe97)]);
        vk.gamma_abc = new Pairing.G1Point[](89);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x27113cbc44c51647953e88a87f13208779d3a7cfa028fb4e407f424c331e54ff), uint256(0x0de78cd65191525e7f3933a110a0d447689c72e0c1109d56506a13372ae0b629));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x29e3149687f4fbaee3a76b81e2158e2cece5e7f1aface9bb61031bb0b4259115), uint256(0x259ec77ff167a2156cd8c175376ffa8141e511dffab3f1fb87836debfc407c0d));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1f96d4851922cc4f1897c5eda72f50564c6d2a176b836d7910b331f4db9f8a4b), uint256(0x0a51cfc2d64aed5400d9720b638d647c2d0881800a42982e6fb242d96cf794f8));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0430665e114dfc93947c4a34878060c2c1b150e030b4eb87b1f46f501342b831), uint256(0x048bf33218f546253f0f52fddc977b2bc3ebe3f85bf949bd4a93699404222634));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x05a502200d15350c5dde50c5dbbdce7adabba50fcf64564c0d1c32f5d01972b8), uint256(0x10f7640006239f2b6eb8d5dd708e4a4d5162713623715ee6857a9665fbf522dd));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1459a1aa0a124c7bb82809286291e1abc41b6d53c4905d083bb619cae091ec3a), uint256(0x23e2793396c9efc17b65c0f7f41b93bba172c8035c6fed88c93164aa45e88976));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x248b31a36161bf41b807d10d6d8f286becb4197884e3b32aec92cec64b10ac97), uint256(0x2abf145ee8afcfd6482afd3aa9b4411a636b48164f85494b8d4cabad99bfbee4));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x124447cd76d0923d5b6179ccf7754c5ec04bc727e5a62674e64f96476f450252), uint256(0x29ba4c00fc8354eb14d7c6397affb6a43f54f77bdacbd35888ea1a977976646f));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0ed7ab18c74db9c035215954a42a2b2518cd9b5fb3d1bedd8869b1c62eeb71d2), uint256(0x17a407e28d27227bdc8e7c6fe5dd8704c7437abf31304cccf71e08791cddb203));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x077e81c64462f5537a91701eae4583ec17a89b58375c30f3228e615e2a09e0fd), uint256(0x301f3429cbd378c5b908de9573f64af97b22867f0870dccc2a4858273590e81e));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x120744496864ac3af65518798ad949f749c184ec3a456296d25e5c7931eb2d31), uint256(0x1a75104d8ccbd5b409ab279f30799adb03b3143fe5114b3612656c96b57a32c1));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x282e0ceee30ab3613341902374ea953a5677f7735f23f5fcb6390f81d7a9cfd1), uint256(0x30539e0989d4266d3e52d309ac1f236bafedfe5e6c75ab168a61d220d7dfc6fe));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x28531e18fd1599484476013ca3b82fdd677728b1e1fd26b83cb9af6f786be62b), uint256(0x195e509ca397f8bd40f7840439e19c9863781174dab273b8cc26f1b10689f698));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0195f500543983d248c131afd958b9057817d7b7404eb9a3474ceb1081a63825), uint256(0x1873f178bb2457a8a4ef0eb258e345812f3c5d3a757a7048ac464b38a92e1b6e));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1416a44eefee6b0ef1066d4dd55811aa389e126b28fbd34126791d6ce17068f2), uint256(0x27cf0b3ecb29b2a669ef183191a30c93e3dc86e7276b7daa62180a5e4dedeb3b));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x06bd28edfbbc1213bd1b6afcc89c7ff76728ec4a7607b2b0b2243390a08a69d6), uint256(0x2fd7d546a940f232c64e76ef1533dd9e771c123002f0561aa4c5fa68515f5f4a));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x0f343e35e6e6022f07248a595aa814a58a130c89617146c8560f14f5882d3d38), uint256(0x16ac431e08b62c7043aa1c2e975cd82ac25807a8b785282f01533a016e12d467));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x22ef04c0e0e0a832ea13c747851593fc33a98c2ac57a6e154d4dd097b93df38a), uint256(0x072b78e51b214f0d750f52e54a3e0dfb81dcc5b1ff5c05504c7fec7701d7ee8b));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x0cae172cc40dd63ef7e951b0dd68a0bb47d865a72adfa97c76f5994bf8a656d2), uint256(0x3009b55d9b9fa2b363c6f649b26f5fbfdc429e39bd66634a0994ac139c00eb8f));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1096726c38abdbb0d6c59cd267473cfdd7a6a24ec385f5d4fe80b1f4d88d4222), uint256(0x177ee6fdb87cae289ee58218b2ecf911a2939b9772042d97636184b0d18467f1));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x0ef960f75d96193120d5e80d2487632d13602734275ad7eedc719c6a06f66227), uint256(0x13a43b38968ea564063ff96c178a7e4244d82c11628ac71eb7994398b4ea5ad3));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x10e42cca86cbb7c7e203aeb9edaa65dde32e7f02540c9aa576ee6a07ff007702), uint256(0x0ddf8038c5a3c87590d711265c746a193dc06b45beb21cef3889d920478b25af));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x1a51b5130427744e1778e8dc2be681f56684dc0865b00faae2e0308d11fc067d), uint256(0x099994e1ab7510185db709493893c2280b3ff408728efa2ab4946a9ec69da7c7));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2b04a75e93378109898a1046d5f85c86cd77be69babf01a925a0bd1ad11d45dc), uint256(0x0383349adc5d6986dd9ab05e50e5aa0615cfac5a5682160f2c2e4483c497c2e0));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x1592ecf3015bc48fa1119e3bb298b8b3b42bc833917a619b8657c2b1ae09ddd4), uint256(0x136bc88a77e6f7f55aea4f11828be7a74999632ca6edc254d7942d02315e1ed1));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x097ea9d3217cf2ff2ea67d52a99770b886bf3b5755b7d65cb3b7f10db9140bd0), uint256(0x2c1be61ead694503307b9ef0fce90211a5968d3683f5eed5963165955a80c920));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x268f4402524d2002a0a925054bd9b9f935665466617281a7120c00b873f2b298), uint256(0x18f174b86319d95ef40950cf41390c3da9633f5500ecf18c53e4e88a2cc98e38));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x05a484c93f8bedee5a283b61005f70d124ec44f2238cd97f22f4f01d00069cfd), uint256(0x26ceb7f0a1c5a35d21c55fa5b00ba6e9f05d369e8ae33b9cd032a2c3f9be5fa5));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x13aa712145199a73193c82da41c9f247060f36553dd8336f2e19278e9c57fb12), uint256(0x2aaa14730d547e232f1e2ffa49ed22ab4993ddffd0449913cd21a1e47a3084e8));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x1360c0b62e4056edca509182114d2c40074e0fb5eddec46cdf98eae6baf47a1a), uint256(0x23aa4119e1a37ca3a830773845a473acb1f3b8aa46d7166c755d2a15700a14af));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x0f7b8266a5fa40ab7dfe422169aea4381352b3c534fe9fb963ba416e6a0b33ec), uint256(0x2422e8e626c68576434fee8d429e0c57e695366085cf68e16e04fb52667e18c6));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x073fab6d8c3fe0d57d6d0790402cb024686f00eb72e0d6d77286800430552542), uint256(0x2006e7f87c3c669b9780aad2f09f4d66392520b777ee094ef132eb2ba6a89fc4));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x1d7cb81fe3fda287696676740e21ac9398616e8bdd75a0d896bb52c99c044053), uint256(0x0b396d391229ecba076c1495d62368ee2daf91d6ecadc90f5e0a849ad24c8ac0));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x17a3da0bd5ee313c66a774be77474df89b91354f577a2e81f822876abe18c2c5), uint256(0x1abca0b7131ef4aede62bb8da3b6771978be85912787297b5578ddb6f94fdd34));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x05e00a86027bb88ae76fe0ad599bd3c375c443e336129c4a79022ebeffb79716), uint256(0x004caa5e9a406355afd22feceedc07bb1676e50bfa7178e27f89756bd6154997));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x2e97314a2dca27aa0ebbb90aa0201b7c79e1213e5f4524aca34d1e96cffc4142), uint256(0x247bfa2d93523d3bd161f20bd32ad45a9b8b3df0c656c813f5d80c61f3c6bec8));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x1875d2e164c930f6195a12b2a37a004824a05043e0de78fd99fcc55d9c12e0a5), uint256(0x01ddf7870084146a6dd90ed9d2bc72d3e90a5c6bb4c284a7e8b5c441b7271b56));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x1079ff458bc0ce02bf89149551db73e78d2247ab8e96b9a5f77a5b40a7965008), uint256(0x0dd3042026243514220e2a10e6255089a5f15a7a2d29a3e7d8b7e17f700a8a70));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x2294fa7607f8f88052ca51e23fc91da60a6450282202f6944740f76f580b1022), uint256(0x19cec3cf95e8c69acf2b46d62fbb4e480d35f63ab32c71ce5ca00b95d235da0d));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x0a0898ff56a156c4cf24454a22b13ad707243fcce2fc84007926c19b37717d75), uint256(0x078137b4bae993e74ec58c932c2207df93ce5c0143e72ae169330546a4f3c2f0));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x034345d978460a082748fef33339d455ed4ee248be5b0489f53d32c3199b1b07), uint256(0x0491a867a4d417f903a2c6989b5b9fc7f05f3a4627c13cead21a8c03baa890f2));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x2cf2781746ed8ace843500b9bfedf7ae8e366fd4ee0ac35cae82a12541439b06), uint256(0x099687724c24f730769c826ab760179d32f09714adf938dbff71195199a80acb));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x2f399c4d137c36c737f874817f8ebaa5dac59b8d216c5157afe3f2a0e0ba7409), uint256(0x1d2f0677ee5bd46f3b41b1d514a784dcea363ef0dcf4f2dd3b0bf4f9b92f8fe4));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x1343ad3a816a4916df0d32b4f01606be917f4b2853a261a2aad8fdcfb4139e29), uint256(0x071fea3daf2c2a149df4e87378c7430cadd724f5a00cd497396d98eaf34db1e5));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x17b9ea6f17aa5dd1c67d88caac41b6cffe31d87e1439b3db65e18a9ebe3eb363), uint256(0x1568cec3fad5e694d88af61dd97c199e2c43da7b55ec5ec7a3368a4fa9ab35cc));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x29e14e66134ea24c91296cb9df9be537015b17217ce6380215aa0bcb7b009e36), uint256(0x2e5a937fbb08de6e41919d848837a1b8d197805fff91efbe366bd761e97aa284));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x2e4d3036934b6db5fd191b7f175ea20fec3f18ff4a401f949bacdc63bfd47e79), uint256(0x08c968a7510af5558706d827528c63a3fa8081b5a3e33bcbf5ca979a6f4c7ae9));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x0aec35897c81ecbb0937df297147a0ecc81c2a98769e86537450bb2aacde6e7f), uint256(0x0ece73dcbef8b506c871234ef0ba51613c65c06e0b9efcf3d7d8a7a9217a7c6e));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x1d36a2d4083fa3355b976c3f3bcb98a8a6dfa33e95cb39a74175846aadbddd49), uint256(0x27b63ae433e07f4b6bcb5b5d48f86b50903cf76d74c6056ed642b6d119c3152e));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x0fa1beaa90f435e017fe31da24686523cbd190b628c12e77ffa374d1309dd528), uint256(0x0dcb5defbcd28c967b4ea117259d5a1f17292851caee3a4e2029c6ce33ff66ce));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x1360a185b1ebeb13f122919d1e66d9d98a06793bc114f6d7c529722e1343d87c), uint256(0x1fbb119fffebec32853e3a1d775de3a807956c4da1df452efc858f2aabc0231a));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x01aff1851cff38ae215bda5bb47aa831575759b59d7149f233e558d731516338), uint256(0x22ad09734655eea8beb0696d50a8608de8d4070b20619cc7e97e917490908a2a));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x2464cb6e5b754d754416458babc40dc352909c5f2ed43c2505266b3fd7930cbf), uint256(0x0552933b3a5ee15e597a5d111d353bfdfe1b980612d0a53bce8c4c0fc7e3d109));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x26188bb6566bfbb5b35c4cfbf1920f5aed968128273f7a47700ad1008271e4c3), uint256(0x095c0a49909cc1b1f81ac011c070880baa6ee291be8fab2f18b7026fd8ad008a));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x0eedd5939fb15f8c7fc1826c88fe5e594afd17b346874e97c7d0fa3fd00f3e9c), uint256(0x051952f274c04658c1c3b5af4ffa85f53ecbd78ea59a6dea02c4d76a7e24250e));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x19e630cc50a65c6c51800825bbeff7aa1efd60d8f9335906696446e22c07c35d), uint256(0x1ea00a583a9c35a3716b7a406a5270a3c109520b2be884fc58fb1def81f06340));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x2e678145d1365940fc707e13a8d05aafaaafe11c158d2a607bb3ba9d63ad18a8), uint256(0x2f8be303f67d261cfe4c8ca1b8d062c91719db640016ca20c0edacdb92ee2ee8));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x21cd2ee7fe5479ca84b52996edfd994bdec0b5971b098332bf635e4bff5341f1), uint256(0x05f9a346e98aefd26719f0f611695cd6873bf15ce571d3633adb0e141ac6deca));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x06c8909713d34afd0e5edc58311b04646ac999e122f689376dc338363095b17b), uint256(0x289e4990a4f626c2b39b3c53131252781461384f0ea3fb523c350fa6cc18fac8));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x10ce8933e8cc08ce8487a7870f0639873df8d4aaf871eb6b77f013284a80e9e3), uint256(0x1923c8551edff43d84cfed6f130c8d4cc78835742c807ff90001534cf62aeb9c));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x1393a69051dbbcd12c4f3fc1257f1c21f8fda20668e36e3a503f30636649a042), uint256(0x09ba02617f3327a89381b1a28576c12da08d83bfbd5fa8383f65503093846099));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x067b2198f6d55143f4a43af3aa886245a4ce41dd2508916b2ad67780e6dd4708), uint256(0x0c21cdb0ffa4bfd551faf26b65403f08776b4364ca97a545a4b33d2c9ea84217));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x0804399cac7a31eb0933aef58a84bac56e5e7a51b8840886a0029da2209919f0), uint256(0x236e6db22f289a8976f03855ee81906b774267f36d09b52d08e1920df2817963));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x254a47642515b8f2825a13a4624904afb729302b54b5c58494912249a130722d), uint256(0x04132b1f0ebe52669baecc1ff1f34bce0bdebef7aae51ac9f7060f3e58a0ebe7));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x0837b48e763ce0470e7aa1a8d25e52c3c5d57f8dde54710c921a2335b8ada752), uint256(0x1ef472f74f6b14c4567bde679bd03ac1cadcac466a44f915e52119433e9e58c1));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x0722ed98acb28e26292b9c41c55fd4e03db346b5d717cf955619dbbaad3d1f91), uint256(0x3051a1b236c6777e1a1d7e4cd12f3d66f894f4f5ed3683cb9857e0e4dad99a76));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x29d2f4dcf53a44f6c145528ca3570a43093dded5e5991c65fafdc012e02d1c93), uint256(0x2f3554ed1c748abea601720ef49c3ea66161d8c89aea6cc20ba2ca813d939dd9));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x0c5112932d74f5621801a3394de911e4be0ce194dccc60ba63fbff8e0ffdbb8b), uint256(0x24a3832b343a69b1bd5fc2a19347cf73d19d9c18d3217e2ee580c517f811dbb0));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x305f29d5787f83ff6fc0b7afc764fb442e877e921a2fd16e40d4e8ff53d22c67), uint256(0x28ae0d18e088b0fd2fa50656ae0f70be4dfd5a6fcc95ccfc09681cf576100a34));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x1db25b359f04b3f301e0bf7b416faab6d960bc4685061cb5924623b124c6c094), uint256(0x22537baf69b5e8db33bf5117dc58d228756e632057d991e57b98d54241cd873a));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x209f36ff4bebb07611b65184b2e2d0b6e28062262863a3bbb26c5d4a04873bc9), uint256(0x2f86f466bcfd2bc6007faac30715404d9f49bf805b18050efd10dafc14ddad6b));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x248d8442da9074ca323c05cf3c38b51142775471b6dd64db11389c330b24aafc), uint256(0x25b9518110d5ce44f226cde7a7743184a70b0d3c43e4b001cc5f9c86780023b3));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x13ba3b0c637c5708a58381f189aee20d31b0703b44169ad147c15cfe742bf3b1), uint256(0x30305f529f97b88afe021cba912d824c8cfadf9ddc3f8e7a747112f08c3e965e));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x11668fb65426e2c4d1fddf4ff72c211001849426820b9d435caec11f5906977f), uint256(0x2d096461296b8956d915f19b54884ac53e085d90fdcb4e7ebfcd6a786ff2affd));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x22edab1956cb1525b03304033b3328a2f0834e64e3865462b4185d69ee9da38d), uint256(0x0ae4e9f6d0b586afa5d6b013d54b5f225af57eb3d22a9af897938a292d5930b1));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x013ba4c08c7b07bbca3ddb44a50e0128f7185095084c0dfcab9a65e6249a681d), uint256(0x0f3e23258825798d400b7974c3ac170f5f479f34cab3c1d4c94758420de9133c));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x0dd5d400b738256897f73a69fa518ca21a56c06d468b3ee326d7c761440ee51a), uint256(0x113a82b96061159294229908da34fd6bd83a7771b6d1dca20f2cf7b5deb28251));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x25e209aa2161057e28bb545b5ab2703363f67815606ad602aa0affbe3d96692b), uint256(0x03e3869e65c9eb3ec5966bfda1fc205425f35562c0f6b1d1cc5147e333a985f2));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x1ed3e91025c869c37631b40f80a578f6a228268651a35db3d13b4145f6779137), uint256(0x1dee5585564ab6f2ba42b8821578c0eadb8b440107ffacfb95510419d2a4896f));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x0c5f529f0b71bbae2be24dfb31119f5650bf67c0d502bd3a75757a2a5c75abcc), uint256(0x287856371aeb1b4ce2954e0b6e20e1a4bbe906a34f3f4e28707fe2e62cb92249));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x0d572ec115fe7a69058353705b9d083b3c21983486a7814703225a1ee4656c70), uint256(0x18d3f9fb8b5cd33d5f870fcd63a47811b813f95e63050d9033ecd731c1f2de50));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x215610a28d5fb82cf0828e625975caa874d462b80b77d660b87601b2c964e691), uint256(0x21b120b2ed7849057e1d109f4e9b0d92d719258eb0ed7178298cdfb94f55164a));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x243459538262c083d1ae177243e92bc47238f03b77c25752e4d338550d9800c4), uint256(0x13fbb060926e315b232d4fd597f6dfdd7936ccd9ca031b606f1d589091e74871));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x18a697661d5825fe803f6d879d06d03eafc4b00ea4a36075b6ec91e21603fe3f), uint256(0x148341539ee93637360e9a82931e1fe21c41fb85b78c2470951a52db80507800));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x1680fbd53910e8938677ccc746232e12cdfd18c97588fea86136bcd22b3f1e30), uint256(0x2120783bbff23aeb99d8656742aecee90f7636e54eeada0b9d9f1d161d34e33a));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x25cc6ff50b6e1d0328cf406124e52663b98ed486aac2e6809555966af658fffc), uint256(0x2a0993d8cf3fe59cdeae46aab3b8ddba0dfaf1312813c82ba6bab52c65fce3e2));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x0ddcd0a4ceacb00eede94f21475aac24f3f67dbf2ae72b1b9d689ec206a56316), uint256(0x1001177ebdaf64744231d20be11a984267372518ea56c4b0dd9265bcbfcb5989));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x11d0ffd001a2a4c5fabcf6810ba51827d99ab9fecc980422d4bf3dd0bd4291a7), uint256(0x2e9448f11242ea02b00e71563b423804e56078d666641fe3cac49a355723f230));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x06c954d1ca903b3447774b90950399f411b0561d0553749013a6be555250b407), uint256(0x05fcbf7b050c97221b2207f245ce7760399a2a7a386ab1a91a56fc42d6e43f2a));
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
            Proof memory proof, uint[88] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](88);
        
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
