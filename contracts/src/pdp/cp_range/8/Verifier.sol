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
        vk.alpha = Pairing.G1Point(uint256(0x0fe793e4408561ee3551707c3d19ef1f4f0d7f0a61b6fd428a2189bf5e1c41ed), uint256(0x1d5b9a0430e00fe57436f136fe4cc43b2f7a6e62cc0013e8ca6e0a1f04e52f65));
        vk.beta = Pairing.G2Point([uint256(0x0a5b71c65407e99c5efeb03cd3cbb8e55c7ef256a193f044cfb897fd667547ba), uint256(0x2355028ac3aaeb2b174eb07314ff2947ea174912c933fd20994fbf553210270c)], [uint256(0x280dc22156ec69e73b4956759acdeab9b9260b9fc0ed23748975ec4e54119ba5), uint256(0x017499f2e00ba47e32f748aa655f02161d17bbef1efa0762e5c8d49ebea5e4db)]);
        vk.gamma = Pairing.G2Point([uint256(0x04b33ab2ed59df73c515aac9c403ea5f839a5f4d2c4eeb4c18cfd7d7fef30462), uint256(0x25dbd829b88c7035607b5f46ade0c6d49460e5a9fa9b007a6bd89e63cade162c)], [uint256(0x15da020c6e34ae490baa3ebced59a7365780eadce1688e15fac15576e8a5405e), uint256(0x1c18e0d89d1de784e524a698c0e1b2b7882aeafb347ade8d43ab60db4c7940ba)]);
        vk.delta = Pairing.G2Point([uint256(0x248d335b2fa340d6ea5699a1c1c33bcb3c3698d89f64821639db34691c52b951), uint256(0x031ef98f1f7972567ca470d77ca6f91fa4f3831139a071b1fee7d25d25079f60)], [uint256(0x0806271bba729c28f095a1bfe4073cb74882bef99c843b8439017ace585ab7b1), uint256(0x1390df0151f65b8efd69a715e0ad3b4563ffd2973bf74d05c7c4cfb9b7342919)]);
        vk.gamma_abc = new Pairing.G1Point[](161);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x25e648f503d067804e74cbb0140d900391154352754db5a12ee21a0f05afe4d3), uint256(0x1a44c630875d0292e6fc096d87f67c444e8c16d804e990a7eb413939ade1fba3));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0875d2382948456e1e12826e30d2bffed83953b5f25006296c1ad279dddc986c), uint256(0x2073c3f1f9b1024a099590876fc0a69a384a89255a1462d6a75c5b8f479915b0));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2c70e2b1ee1d2b9f5a48d47ae17a120240c1dfa74633be288f9f4325cecfe269), uint256(0x0b80297bee3c11b141ba56ba8fdf239d87fa9ea76698a71d71f005e55638c57f));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0c5ec1415b8eb876bed29f8c16ea3e14dde74759846ebcfb0646f963cd88feef), uint256(0x0d3d59d7eab72d4a4f2d2f15fdedc00b68163d69b7f3bcf749f1debab72b9ce1));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2a49d6973a7e2fe6ae7b49b721ef92dea32ca638688b382cf07a1ed3142cdba9), uint256(0x14ea72a8c7c51a7b798127dd1aceaee4191c0bf44c7945e9b97e3ac298345872));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1dfc56b4c74183a6acdd6621f2f147eb62c48e31c1ab188d468ea103c582bd09), uint256(0x29c5548c7b7714061b83817ef2ad6e47e8948b5ec4592fff61c095dfec1c53ed));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x216eb8e2566b7f3c86530efb7f99a530b3746b889f3c5532dc55756a5bf2b705), uint256(0x025a2ff75986e061fcccc4ed6e590e59a304efe3dc4d15f91254f7200e28ac94));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x28be7bcd03d12afcf79e95fda58f3f241fb241f398e91b98899ad0f8c868a3a6), uint256(0x0f2005d8cbea7e020312ba4139abc8477cf538beafaf19769fa5277c8fb9c3ef));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1bfef0fd1df1a72e9c41403c94119011ea19a306a17bc4f82d7ba77d7ce8b124), uint256(0x1571c81b901a4d3c5aeae838b67681c280bfe6d3b67c66985208686a5a4f6b44));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1d5312ff8a602fa73061269882cb4821f63bd6ceaa26edc9bf3bcfd4ad93620b), uint256(0x0e64967e9d9167c1fa353d3d31789d252be77cc4ff70ab71533cdd737df54d16));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2dce4d0ac23132f99d03c2e3ee29e54eee69e80e53d147bcbe4dbd6c1b7a9236), uint256(0x045f639f5a6aff13111e9ac4ae395bfe5f3f847a452bfc151e06d3579cc54fa6));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0fd9a6cb901f5ab29ea295a4777d39d539f02f2ce6ded99c1c71b13d93a32536), uint256(0x271f9c14fb2d2469e4b7d77531f8ed963aea0e16aa747f0cf2209c88f2d19078));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x09a9663fdcfb3031090179ce7765ce183483da2b190a473436a9f02488877521), uint256(0x2897348667653fb4c71f73520292eaed58b30f3746d670ceb6791ed01c316962));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2f4a9ccecbcf0ac16e86099ba2915d711f6096096a8ad8bf38a09223f87441c2), uint256(0x126407fdf5f95476b69d8a6374e27db2840558b4e09007d46523689ebd8be66b));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1f8481cd92d9c5fd2225ccaf0af2fecd818e7f237e377707f85e5b25bf48694d), uint256(0x0205f5d26ebe1eda264971d6d0d2fabf4acc5f7699e93dd2d391aecf2518e881));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0023ba7537b40baadd048e2581c5d74cd700b9cc5314f2fd163a3ee516bfee15), uint256(0x0be370eacd1243fbcc20ebcddb09bd4e14000a80aa182cff22a2a4160d04f56d));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x0e6eb36a3f048d90a15dfa9a292cba7a719a7850ac3315fdc300e0a1922e448c), uint256(0x0089aa961b05767accb00fb2a35fb3c7153d4d64b5a32b5fede896f1f2130cad));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2233e32dc6db80dd170dfa7335375b871e7b4f5fcb700f000c4acb7b8a6c053f), uint256(0x279a644ca6d4462ceca32c82acef0ba47dad383f2204f7e9c115684a32507965));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x03d17d87a7ff85f9770c75c6d79b5f3f09bafd19c20be38a1ee4c3c715388baf), uint256(0x010b6ec363345619b6f8c4506795b9fa0b4804c2e1483c3a02be5cbe31b72a2c));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1ec5114f848d86d8f6180c84c6f1268e2157f05eb53c00c8411ab94f00125ddc), uint256(0x277bf583539a31687a166338ca03dd32826ce0148b54a22ad245556d1a1294dd));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x139721b95fc2889823857f2eed3fafefad4d801aadd99f8fe58d303a91fbc907), uint256(0x08fdf04432243aa5b1c24dabd319460f93e246b9a474834e060d135c37b43b15));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x05c0f85970216e137586bc2f1ddadef5dcb9e6a5f743f98da70fbdf4f57fbcb5), uint256(0x2e4f6a9c9c955671d657ca2039c8eda8efe4f23069fb37d451dfe162043d9057));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x22f6c6028e1fd8f221bc6c1fe46afd4c233b90edcc77651788b464c718c7f39b), uint256(0x243a0f754a00ffaab157fd48b7a994bad7dbc81377873143b75a24f924332e53));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x03fb35ea5ea0f22f00e14e68cfd89253847c2f17f037d653577c4fbba34fbac7), uint256(0x145cfdb1c73604ad891bf7e38de139299428edbc0fc547e6160bd04a9217cdf0));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x05b3396b26d76409f091c3ac17c945c17ed82b8b5ec54ec57c8133c12072459a), uint256(0x1843709b915e997e602408c71bd11df872545b07addc8e015a8d384d538d2fdd));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x16211fddb408f7b88714a05109e0b459b3ded5266c7e8672ae283f356e5bd2b9), uint256(0x1febb3a6754fc0adc76f441e013d1e278ab10c639018aa25e62a3e8a2ae78b59));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x160c77a25d75edfa09aaa9446f3af3feb69a6d0583d82adccce8e8619d5e2968), uint256(0x0359ba17e7bef2491f9a736587668f2e2c323e53d63b07e7ce78005e75fa7c89));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2261d605cdd33bea3a1c2613ebc7340f91dd032dac9593788be30dc9e238ff69), uint256(0x2b6e986f1b7f87d72c5a8c260ca1eb1cbf5f5e113d170fdf2a86b1370cd218f8));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x15be7efc9ac6ebef2b6144e061ebcf90ee17e3383adb8d651e2ed5e1b7339917), uint256(0x1e305422f7e489326052f996f485c3aecf3f6cfb00db696c8fcafe008c1bda56));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x16af1009568549da8bb7cd8d1832ecd570cdc050a9a7550263f28c03375432bf), uint256(0x067a5348313e42167dd8e004f342d37bc64bd4f7e07547d048f91f426ec6daff));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x2271f14cc0b7c11d81fea0c6a890d9834e1a8cf95781de963f6986abcd49cc7f), uint256(0x2fa265872fb0929a9224d9b1ee18b8ecfbdd43cd0ba4d846c56004aeb292c854));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x155d74ccf1af7320f7af48a9ba546843d3401cdc2fb7d1d96d6f612e0bda8bb0), uint256(0x0928ccbb3ab429b36e57882899bca881cb66a8a3f82f418bbbcd2b147c61c5c2));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x1d2e49d34590dcf80f72e72e298140036be2b0a8639de0a33aa13ee78584ed6e), uint256(0x0b33b7c196cb1da5a3cf0770947e405f483f8385520f3b3fd8ed430eb4c36064));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x0a4c80f853e70be63b36cb26a40a90d1a1e20621fd08841538f7bbf3f52b2b69), uint256(0x12ceb5156925df4466df97875c4d8ffcddd2fec2e99286360cd3188498878a77));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x25c9c6f12577e55542fca9b9001d002a0e6f7737407c7ddb0409e2107619075f), uint256(0x24ef5204985f3d656e01fe853ddd6e070a4c2f944a1b994f416bac334ec237af));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x144775df31b2fda7ad58cfe6b99a048dc99edf05523dc8107562bd0fea24ae8c), uint256(0x263573f4f51225d62670f23391eecccd6a04c8e33fb4a1d312a93ec1f557f801));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x1b96821f5b6db7d47b05edcebdbd19513234a6b34c1e6b60589580f0de2b681c), uint256(0x2b9f7a3d587b2a9c65c0cf71733369b26f820bebc739d0ce3d911f6b438bb0a1));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x23cb3fdc004f904ded26d60849dce27ededf1fcaa37d373fcebac6d1a32bfc3e), uint256(0x1bd25e96449c2789bf50388c3ced139f8ae516701c7dd1ab5b7c3dbf0929bebe));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x25b3c9e5b172d67b0cc6452ae5ab9a254c79f4ca4d2c6b5fa4723eecf02bcf58), uint256(0x04c01ff26907eee7aac1255aa6b994337cb9ab41a4719db562cc24ee20319a18));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x14196d1e425a2c0b06094ee893596e1118cab04d51c2902539ace0f340f7be97), uint256(0x1220b89a38f2e3000f674f4e07c8478a1b5391eb725c91367fdf24006d9601ac));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x012fde600d0a5eb4630470f9c19cca2e2c95444888a82710f72f65bf90c96e82), uint256(0x2dfb3f1966797b4812f043f36cb6b466524559fcb39593ec36fb91a90cd1259b));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x1956db63012e75f41da3b068593e3baffbe6bf58a3df60f757bf29d02bb0dd30), uint256(0x2ec5c4dcb54cd82ab67eea7c95402f1a0bbd40ed817d768531ed09f87a9574ba));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x0ad275047320c2cdcaa90c42fcc884efaa02a681b4eea0af25a3b159868134b8), uint256(0x07bf6d561acfc0abec758b5e66a031f0c25d6885480919ec6dca389906729a1d));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x251159704a712df013fff89190f750f5aa354143982d90a452092406a1ef968f), uint256(0x0817f9cf51c8de3ed07d7f6f87700e66ab9d944fdd74b1d437100d26a3e2c61e));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x10c873a387d8777e54691bc2a94f9b2c9403b79b9dfae94c3102ae65a78dc458), uint256(0x2fb19d0c84720953ae0eec882ee25ad5af6ac1b8b21130243dc645c5efeaf1f9));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x16e5c753078211e201eacfc8760fc1a7e92776feda0b9e457047f56f7c1da4a9), uint256(0x094d377724bba9e6c7122915fbdf5cbf23559f95efb33222b8c611a5b67e7076));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x0b6b728537e306eeb81a700c9b9403089b13b46fd0ce604fb0aaa4442705df67), uint256(0x20cded7b1b9bd143285926e6e186091c941a9c24ebaadf9e123fcc8a203e9486));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x0e8063ca60b213a2b2c41885b299fe7b9b1a82145906f4a0cc65763fa31a38c4), uint256(0x085e48e04b90f3ac686d7592c7e63bc515ec41925bd5e5d00d12d758238f09e3));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x1d0997e26043684b620df9961c94b869a3678526a39c93f50c35d8d50a427cbf), uint256(0x21d4e5c5134c5e222f7d2744fe80837cd80e0d80a885076304ef207b240c1b77));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x0af4682e0d5270977e0d212793d1a74ad030efae7b644e0b9e75f6d1d097d91e), uint256(0x0468bb15fd4a058f6e2e88a03aeb9e37809cefb3132495cba5e7651ec9925ed5));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x121c369b077424406436c2b0e04ec07d804c9652b87bc84d6f9c3be85ac730d3), uint256(0x2413e1d06eacfe6d9b95cf4d080756fa4d4add5c3e2fe3a8a175ad1300614a6a));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x00b0f038b3f46692fa8b4d1010f588b3ef855771f2f08afa4ea8fcb63ef7fb47), uint256(0x234aed4d1369f33f15e8fcf368a95aded8470c2b8554fe378e3119cb63fd306a));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x0e8b66b16a43586a401e8bd4860d691c68db07053d61eee883c83a5116f50c48), uint256(0x109ae69f58d2f7639d9b2317e3fd0ac600b2972298a6beb4404ac51a57b61c81));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x2703d4d20bbaaedce189a532d359591c38f64f55e4e40420a57f3b07939dcac3), uint256(0x2a2fd16120046985723a9e81b96cb40e0c9ad2ddd2c6202ef235e6d2b745bbe4));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x11a215c45ba9d63683116ba3aacc5aa1b0222b20d0c70bf5c76202acedb4dfd9), uint256(0x1ef38ab0943a2b30c9314182c90dd071d79b3bcbe0eefad5a82fa1f2c118c52a));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x09f287676483f4a7456e0ee8c65c08f5f3e2212a9c7350c2381eb235f6d5381d), uint256(0x094cc0b9fc3b5dc3af0b4f3b3d87a6f956d4e191e7391fe57682249fe12e4a5a));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x20eded948b2c819f02aef8666c2a4684831c5fa58bba4bb1aa1627901360299e), uint256(0x1b312c25a79e8c113a5d64f68f2cfa74f77566a2685cc9d28c35f9e8e21cc834));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x27eba734c02b2d52a6e569e042d8baf823a08c7ed09950b22ad26b9e610f4e4f), uint256(0x1acc09bab657d1d6dabe57aad63750c1b7c7795173cf4889ffeaaffdd8fbc6c7));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x2a73c61618139d28f926f3016587dfcfd68d3b5c7a38079420e42e3638a9b463), uint256(0x2082c5233263c81e2fd3728b1b1458567e8a68aa4423421493f743fff1707abb));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x0e355d82b3e392c30e398f2defcbb6396bd247152967c50033d64c20452d03fa), uint256(0x032fc4a069d11aa67350ffffbce1703ce583e384ae8afae467c939f2680f9c11));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x304b38f31ba44c6933dea3d941bffc9099949725b7f8c74cce59f2d76e624e45), uint256(0x18b1ad543d14f33cc1bcce3e09e875850239b6fc659f485efc60cda5a86958b4));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x19ea29538d8b8d6a75bf52815ab7338ac83e91cc3ef4a7fc31d6e62eba285c71), uint256(0x2cbeca6a8282a15f98f8871f3fce20b4ee30503f066cea682aeb3268f7e23982));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x2b51e643083afcf360c01cbc425ba621bbfcc3f0a8c775408e5d9b8a2fd15590), uint256(0x09f9a3fdae68445ad7e08535b5476675b9698c30998b23d3b21692fb2feb3b16));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x193edd752332b6a8a6fad6b041e90bec7c767ea9e903209dddcc4525c0f6cc11), uint256(0x142a777773becad2492e49699b135a9c96dbce0005f219e4172e700cb32b3f58));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x016dac7d7ebd200807d332f9793112d5d5ec32e86f39173b3fb121388373a091), uint256(0x16ad2d4de9fa2a13fc8a7d416dc8301a0f114376d6765db8c4068d4e2ef74811));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x0d4626449bdc5fb649991cd8b656fe6d5b6d844e06aa92f946e86f08b306663d), uint256(0x208c25a7fa04a5516b4f349c6fce9aa5426cca4d5db6e65b246e07c6dfce9a38));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x18920e9332e5f8963da11e70ffda964f942c8003e99010f9b17a7dc3c6f03afa), uint256(0x136ce4327eefa99c09a24c6af2f1c4dcbbd13f22e856d4857a581d4f211cce57));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x13bafaec9add1c9d18d27270c0044368989c21e8329d80c8a50c07370c79bdc5), uint256(0x16a745bc499e85888828a8a12d49ac14134cb956abdbdcff7ac17276d718f4f8));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x06adc881c0da03bf08ff6fd29dec31452ccfdabe4dcf3d9d5bba09a35cc9e5fe), uint256(0x284ec7278ff1de7a311437c7aa559f49d2bfe7dc51108033042a41fe841b9557));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x0baca4a5711c6160b2e508c950367775e1e78eb6738048e8eb490da9b37c1e78), uint256(0x1a8adc5062721e4e1f203a0ed25751e2ec0cc7d052168ea08a249261569c323c));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x221db0b7188490a8fa5a84cee74c01a1347007d843cc07ce7bbb2ff4393fbeb4), uint256(0x0d51795287076e257285b226ebf3ff299ea1c0957a2d5acab1c9773eaafcac45));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x1d570c7817bf6d4b7db4d44731893aab52eb38e6df890623a94f874c29589ba1), uint256(0x0935b803074f2d2f7853bd56aa57c99fde0970e14430cbb896d949063eaa9585));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x1f347cba77c79fe978c8eb00b19e3f10831aba0f9864a22592ee8cd05d19e120), uint256(0x2780a959f445359b873d3f2a8672735f7d0cd84d9426fc7655d7b698db3725de));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x072cf4c18926332757e4703a481a632442c42bdce0d726599801d7f8569e4d4e), uint256(0x14dd6d3af67f76abf746be4906fa3e4152ba5a735699d18810d53e3ad9987418));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x2b19f3a6df5652e089035a8e19eaa31ff19b4ed913e857b649508ab689457c66), uint256(0x14718ee351fd7596ae5fdc3db662bd6f5a10b0a1d73876ad77caeb1feef10120));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x10d51347e21af41873d4ebdd07685100289d2605c6337d8fa2a7c610ca3e8e3c), uint256(0x1e73a4d0be244b5254435cd42bba6ac4abffa2f3f6f5980d65105c5e3d4e640b));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x11ec11100c20c280a2f15c885ddea7cecc3534d7029f1255d31a328f47d08cf2), uint256(0x2b147a7c1bfc6c0c8775969a7ec273314ecf702d044f3d73ceaa227fc4ad6ed6));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x26314c064e1585ddaa7159f5c7d26d1792e3220c672aa5e7ca342958c2360ef8), uint256(0x20b93e9b425e67a4be359ce5f9471ec7f1ad611caf0441940e31887d0cd48b4d));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x2583082efa77a26e8e92ad96dc345963646c08c55901379a4ae8ecdd75ed0169), uint256(0x1810998060b2dbf7f548352b157d52b76bbcb551f19ad53998a2a9837fc21308));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x027fdc9b635272628fd839e473540d30ec66d16d6b647b4f8e96a1bbd7d857e0), uint256(0x1689a977fb97c4a130935e0705ea37c01e807113cced52ded979a7e1b676212c));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x1a030c03e15da814a418aa4628481a92753e01a7a853f67512e7330f0ec120c0), uint256(0x1f4c21eb7a5312fd787a98bbe791b7703d73b3b2f214ee39288cce97f5ba9412));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x218303dbbb4a9baf4801180c4c1d6ea3f23f7abaa7907aae003184262c9d8fd0), uint256(0x16b3e84fac34eb6da042d8677deb9b778d2a47ff6d5c440a16e1e393294e4d66));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x23416236611cf84f3aabd42a1c2960de300b9aa0f483197969b0606f8bb783f3), uint256(0x03d88e8ba06ed09913aa1f8cdda44cb9599591e3c9999a4e64207e4f4645ea0b));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x2b5140a0fca2d4fcce235c354bb302ea387e8bde5ed6e86ec6a21849a6952a2c), uint256(0x2e332a6c07098adc1265ca1a5f097380a9b0097422cc69ba0c6d5956714c7e74));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x29d1184dbe165f0bf4be8c4ad80f289f0b260cc2de07f73067ea0135c731e2b2), uint256(0x21d884b5bdf4754396d2b4997cd90d06f17993cdf79ba436b3b9ee4576a57ee2));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x140084a870a6fece5a4fbe42254c0356bea3d4634b271345e6f35dacddfadbf8), uint256(0x1a8ecd922a26a6aec045858e5264f5b3887e05bf0d453eaa88d410d7dafc2dc1));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x25043e32c166c9c5e8742d56719527730c1b79d28e5481241468860222ec7425), uint256(0x215378772330d44706c1f7960586d026d13f9f405eb72eb3d6ff8d16934271fd));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x0e49fdba03c54d1cc26d084c9d80baad9840db2ffed5868a3e62340b432f0ada), uint256(0x0c882a459d87bfcfaa5f8a0354401c8ade8bed3020a5b37bbe88d048c5fdb74b));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x06eb17f220e91b78d9ef3b9f0af46e7687303ab5438f30ac938702610e7d1727), uint256(0x19b1827e8c1aa584286379c080fa11531b543cbf0e72115bbff363b5c8a7da9a));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x08a1a4fe4b8954495f27b414221338259b553c4cd6923930dc574a6be0f100e0), uint256(0x2cc584842b0e149404ce99f15aba42171820d9d9f14f0680d2216b73e8e78b17));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x2aa5587e5ad0f9b7357c09a8789d814ed6824de77f86b11dca2c5ed63d24cbb8), uint256(0x1a22ddd87f13821fb097dc1cd8a5a44668c4f9987a01d5d043dbe493c6a2e9de));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x26f78a73842b8eb485bfa4edeee8b38e54923d33274ed3b8419c7fb999b73d7d), uint256(0x0335d6cf25122cc0c20831373c7595929d6f527b3213122dbd6f41847494cd0c));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x24f82d1ed0c4e78de0037cabf4732c547809e6b955f591ef32da0ebd5393252e), uint256(0x282652e736cf25e75ab75252b54eb8abf3872f3a5fe42f0418050074639f7bfa));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x106dfa99715d65d5bf3ab8d5937e1b658b8efc8dc1c128825c3d02e9f5bf5b8a), uint256(0x240b7cbae8cea614e75612a277c5e0f6e5811c6088f37fc61c51c8b8e777e9d1));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x250163cca48a44d463235569e04e3ee1ba865928ec4c130e306a667be37df69c), uint256(0x1f93d87e4c3d101da95dceeb26ccbbd4d7be1b4e7795616b449d33b5371d4339));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x228f76850f8b432115c990382bcddfd118ab5a11aa5cad7a0c6cb1f894027775), uint256(0x16b1b8778a5fa905541167134869d2709c7f08678ef778454bd8daad82753d51));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x02cea43a0abe6c93301c2788a9cd47457d1c3cdbbbff214b0cabe5a2bd7ff314), uint256(0x2541f5f88523ade464ad63550bd8cdee3cb4d154c9ed4a05a6de72e506954f21));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x09636fb161f8077ec69de253ffea14a5597f6c19bb7e0f67ffa369893fced187), uint256(0x2d7f2b2e69c220b361eee25f51872c50499452c39d621b74c7857649830392da));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x165a0ba8b5a85cfca48b12c0b4d83678000157ad19e9ebe866e989f2274efc50), uint256(0x248576fbea34fc3e26e4b882a1f01b6b8a529585b00e7e3edbd3533a36d2d975));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x01645410dcb924e058ee194eb7ffd3f150c78e90c1fcfe55a8127af7e83aa839), uint256(0x1d99818048d9ce79442a9466769ca76a0d4a038371f90fff9af1eb57cac644db));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x2b23d333ab553af5b32ea5b7d02981d9a5bd02dbba383a0f0825cd7ea5a0aecf), uint256(0x235bef2565889b15816a814b5508d1cf0ce49de4d157f418910956c9b8ac9e40));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x27a8fdd19a6a2623442d5001d3d99e73fe0d5f8a74d18d513389ff0e2a8ffdd1), uint256(0x14607d5306f8fbfb6f59eaa25b7b797303c9bba2746a553f7c366375fa59b2d4));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x1cd2f52e998d1078524fad955fbaf3e1b434a67f8a3e52b73c92a99d853ca0e9), uint256(0x089503dc48f671f3ab7f4337e7f7ad750d4b99c62cd658785a59b38824b495e8));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x17b7c32a85f0fa93d9e3ea616b7c3860b78b811be623bfe6beabc5b153cb66db), uint256(0x119fcb690b2bffd08979bc707bea889ebba08c03bf219970ec22de88b3af398c));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x083693a3f83fe02ac0d9b6c4a6d0be1cb5bfd14da6bb859d93156b63d554adb8), uint256(0x13fdb5a8eb5c3532545254602a4797a2c4c2bb1b5daf47d9bf21cc2864642b17));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x1cbcac759d8564dd9d1a6cb5d473e545f0cc39742068116f6778bde0fa9c0fef), uint256(0x18b44c37c29ba484300f1bf02d8c598410a70b81b7bb3cfaaeb79b5e73d5f4f3));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x0ecb278fd63dddaa71ae2e12240f06c3630612244af7f0ff3201730d151f7464), uint256(0x0c326c008c482410c3d5351997d8659809bd66bf7c0a99bb9f453a646d895058));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x1026b001daa0fc889579bd8789c31e7f43059c29fec7b9315efba48238984d3e), uint256(0x08d740470407d5516c68db8d9e291a3a7082ad39b13c736a17568b21558c06a4));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x0ac0ebe3270530349566876e4014c41b71c4bbaa814855eb1ff505694a50b8a0), uint256(0x18f13136ccdf82f89e3664e31111f02a5434c4091d40661b5ad961f493f30d78));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x1ddd9fa2496cbd1f32f4531783bb2590c8dbf167aa021282d426b736283477bc), uint256(0x16c349f4e8418d9014e7bafb33a4a91e9713745f65abb0acefa25312a2012565));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x191e4ff730d881e07b9d308518eebd745dec0f2ff60286362715901e0ea995db), uint256(0x0cc377931639dfe93957326f6f3373f43341acc9985703bd44d555cbdb805cc6));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x0febc1f5c6c67c4ee7662933fd606c8f0f56ad822a5e47173736fc2620158e58), uint256(0x1c5929d63814b383694dc9a26e7dab250ff078057fc58fdbf57e2a73a28c1254));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x24fe305f67bb26af5b3a7c8f64067dafbe4f29287e6416c070d706db4ad8ebc8), uint256(0x1bf068adcf4b577d2d6bd9eef2cae7a78e59c168c96c63c801efdb3da42d5d5a));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x23d0fc14151167643ea2025ad46e60a6fdfcbfa8b3c36effc67e6b678970220e), uint256(0x28e9799d3d06143b624170e264912389e4c0f04281c9330fa921c1e4a4e6b8a8));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x0f176f8e427561a0733d6e7a360231109bb361062819034bba17d778eb864a28), uint256(0x10595c8ef450d230ece481472a4656774b552fac79f95a5aedb29ff965590fff));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x1880eed9f0432df9d179b70e94a35863cbbd9140ba15341f0108ea2b03367c9b), uint256(0x1b4abdbf3f004ce01ea47c391eced1609dd7456c31944b83b2321b4e5fa2c425));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x083b3e5ecc439b817b1ca2cb288d24cfc1a061b595d6dcbc7be1bc1415f695d5), uint256(0x111348da9a7d843bd22ef1ab63bfd75b1fef1939f1f63f6c83b2831c9fdad686));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x2447407c485a2b59678327d7ff44ebcbe4b4e08b42f02cd13e8848f1b3cb302a), uint256(0x0c038df7dba0eab70db07feb4f0b8ae19b970537d700664d6c704367ff650c90));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x244d0c05158d5c7863859635bff555a0e90a8ca1bfbfcbabf965a05d1bd51ad8), uint256(0x1004fd74c203919a8b6f0a9996bfe1cb2aa0e477e2b569f8fc362d31645ffd20));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x15c70725675ee85cf500eb8d7219be1fd77ccc36e11975eacc8b5333317c1893), uint256(0x0f68e0bfd23af39f9164e6ada9aaa40eabbe34f1b0589bc4c04c5ea5684897ca));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x118da2bb474d1b3ee1942d2af57bc53cd41ce586c1fab4e7cb9a638ec705724d), uint256(0x27eb98462ef678e75e2f27aece074f046f2daa3148a76692e926b98cc53f31e9));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x01a9f75d500b3fe6b4cafb964e889fbafcc3d9b664792a68fdff2495fe66c1a9), uint256(0x1d31bb591e3db0e32b99999cf228a1ce15e6f0ec40df2be6bc2669c7fa57410c));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x13fc7cc6b4a3dcf733daae84fc1be01e6f88869eb4613866d1d5e70777903ce0), uint256(0x12a83b02c2fa95e0212a2ed4db5d7bec85819843dd995ff22e66597a2c9fb375));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x1873c9dac0ab5852c9ae74dd5872aef91339e3ac1d87674ab44f0ce260cbcefc), uint256(0x234bfa21402d7fd3f01d8b7f244d0278da67ce71409df7b216e59102ba3bcdd0));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x1fb68ff1e905de94293f4a6afd1499a237ce5951be220d8afacc106fd4ff2fd3), uint256(0x2bcd21a3a2e540c9eacc3999e42eb72489a409e0db78350407feed3ead7cdafb));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x27b0d40894b7ccf34245e8437f6aab3447bc8cdaefbba03905e8096b43313071), uint256(0x1bd2b6f350016ac0bbfd15a263d79a303c7347ec424dcbae1705ff52359be47f));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x12c948cc5f3dd0b2078af41c7fc391b51ac7cdffd564f44671ec8a5c3a71f719), uint256(0x0d337dc922e2e3a3082eac813399fdd063a6f98680d85fea8f5f52ae81a3ec50));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x18c5d9c144d7876b568847951a3404a5bb797fadb8b2b41d466a1f14bba8a312), uint256(0x2691a68758a54db439c90ef3daed5d816dad205fc9484efaa701ff6f68ec64ce));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x0d1119481f33a7dec0c67b8496af47d4f7910898f306f646eabbf29b49aa2043), uint256(0x0313dfb9a9e85bcae4a1060318989f3aa633924ec7deefc3ba38f7c0d664ecf4));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x2965464867dcaf4c57ab48b87d03a4fee3745fd3919e766eb525272f666f4484), uint256(0x101589f5fa923b0fe6a2458f60075eb0d7d63ccf9dec419f77e18ef4377222c2));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x1b68a9b940fed0edc4762d05e7f3984bd8d5506590fc541efe547275b5741cff), uint256(0x03b08b97c65a0c9e67d97c2330c6bd0607a99f47cdda8b9846155e948705dde2));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x2a3698d11ddd6d05651599f84d703ed0aa7343c8624e9ef903a21f9b145ac634), uint256(0x2db1eea3afee5cb6ed02fd994ce90250aa381627f48b0b71ee8644b84d53e9e7));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x1942db58b9d112684d48af2caedf1ac9725652062e9835d463daac39462ef253), uint256(0x259cd3a89d1c48f5704fbe5448730f14d52032cb2ca082e17670939a1f7a7a48));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x271fba8c3a90fc940661be32077b742b2856580447a191342da7d07f7518e212), uint256(0x2c8de8f247b9f3ea28124c1f72b289b364801dbf689ec0692b57bd92532505ec));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x22a83962f44d37a0a6ea9f7bec0c0e00ffac5adc73268019ccec4fa15099c0af), uint256(0x24e0bf8d5b957790827650aa8b8097eda4de5210043812da4899e7c9e8b56d13));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x08dd519b1b4992133476a34ce070a099504605b24bcfbff3879b9461f2559178), uint256(0x2faafeb5f7cfab3526510f450a2b1378e8c97347a0558b210d24b15142dd8758));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x1a0c788fdf17398f9da9db7662f66b9a40192d0941f53707c972c01774e546b5), uint256(0x15fa407c03169b805717b7e2c99b7e5ca0eb4f894f9f493f1679690ecb5b8250));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x02d844624c77c351755c9fce3b1f92bcbd95280f78887a37eebde8bbf5583e63), uint256(0x0615d9f67ad2d1e2715f1c0ae5d327aef2380309dddc9b2eb127ef28c73bb5d1));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x2f2c19570220e7304638007b98a30651cb28a9409bb9eb79e0803ac98d650bdd), uint256(0x0e59385297a8c39eafeb44f25b89445f45a35b5e6eba943431bd7ca46faadf63));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x2b3a9824dc8704afff7fa725cab6c1032cf1f7a679f03d105e4784d104110d1e), uint256(0x2f17addad01b4daa075e8ac9d79967bac3a6f000d90972c0e4c97aa4cf60573f));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x1c5ad129d99e1f678cd492cae8a54293987523a651ac7e96c42df9a9eee2323b), uint256(0x1863fb3de1adeb174b11f5d67cfa9e56bae6274a174a84af3fe41da5f1c804e3));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x268bdb39ab9fed94b22f7c854d25497aab1c88dc3243cbce71683e79fab1a838), uint256(0x197896f186c66958eb1fa7f4a0819ced5a3df6576540944d3077e25b1be4fdf1));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x284a16948e181804f4d55ae614ee7f7641621bc5ca2c8cc14f67ea629b894889), uint256(0x14fcb419b8c496495a6679ea7c6f18112ae336dbd8c655d320039b412aa25c82));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x1b2f17a1e7003447928333723372654aefc6254af565a9bce75005234e50617e), uint256(0x1baf36d4b04fad8df9c8f372698a1233c6ce26dd7a7579b9f3c2633e61bade08));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x0bdb790497d6fc78d563514fc9f3995f2392b913ceeb6bf1f697b962e3bd3397), uint256(0x17c81c6e9fcff3aca5779e1954466bc7d4ae889fdcabab23c2c87c6d64951601));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x2476f8f910b7af57d5694130d92ffefe6d42abcc9f5e155eb075b9d58c7e9d75), uint256(0x109b8a3895d713cb2f16c6012b2c204d2c2c943cb4bf0715ea3b3d61aca2c5de));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x2dad8c0e7ad82ae140c2afb5b2502be90994b02b30f0eeb9dd982337277481c6), uint256(0x2cd31fe00aa8f9c4558456e2def3a80f9201bc7be4e3de0a9b5b751f7f05703b));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x1f7333a0dc04a21cd25086fe392658ddcf38225481d1ff357fd0790b37271586), uint256(0x0cae792f3a42d49eed51d804c8b8306770c9bbcfdf512ed197948dac4de25754));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x0763d1a464874b4d1f74bb68b7da3ea6403ed16c3dad5742f5af4071f41005c4), uint256(0x0277f337c3f6446076e4187cb331dd2711059999168da0a6aad14a4af2a5c45e));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x28d8f2e76e7c93ea976fed7f9bc30be029b8d8dfcccaed4287b51cb7ab666849), uint256(0x0e0dc06532df0787e88beedd3a66ccf527fdef9134ce05d863f5c488e4add0df));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x13be303b615a798ff687e7af924c642840bab52cdf60ba228319fbd4f4e18154), uint256(0x19dc72e34dce159420e2d40c3f145bfd7a9042a704661797e75d7f211c63db73));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x00c60a6b40f20751186f9c61f4dbff8096900b5a07f4a0a492f095e1529d2916), uint256(0x2ef14ad6e3623b9954948ff5e83f2a4093afcbae23c9b79f2d686ed3fa6f2511));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x0489c7af302f5bb330286198d256b5650c1081bee0663856fdbacf8efca4dba2), uint256(0x2b18f6d3e95fcbbb3915d2342226edbcef583a2c734ae357edd16bc696f2090e));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x0657325b56550d31502d9b8775402d8bf222661469f2664b8648ec2540d098b1), uint256(0x284f6d97e2f501112b5996cbee6122fc91488b09200c6ec6dc9bbdc836ef8282));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x0f7042ced5ff4b91f533acfdf8468ca6a17a3b3f89729cb825ed2bef56685424), uint256(0x26b90e6624aa67c8cba20c28fd9337cc870453371ecb50698e902e1163c01b0e));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x21634cace166ba3a07baaf08f7b6772d59e026a71be9d675cefe845bdd26eafb), uint256(0x2c6cbc2bfd76246e49189cba1373cf8255f4085b872d97c1ac081510448c1a21));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x230cb114d5fe79654c425238311f790e44365c213e4a039fafb9c0e620b62b96), uint256(0x152d5f5da82e69802ff82489d2c6c4c64677d4aff0925c5902b8aa27da0ddc9d));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x03cff1a9fc3421013cd48ab24b9675aff42680c4132bd031b896b1d986010e10), uint256(0x19c9f08e2262e78b760698dfd39d3d79f7c30bb45d9ba9b0a47d083bb6749ec5));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x22957627f8d371ee82c4f24c432859d3799788d4138aa9aeaa26e70153e39586), uint256(0x2dd5ee9990b67f8b9ead01fbf6ab35affeef812b6e590df95742a613a22bbb33));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x06b7cc8dab2718ceb43ee65e0befc7ba61629e96b5a33b1c17d970bdfb6b555f), uint256(0x18da82356136f507321d2a1a0b5421974fc21b20b4f4a5e7059dd3ded826c4bc));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x099ecd106be7005cdaea94aa40133e9e70834eacf0f7b43752f6d2c84cc1b67c), uint256(0x1a6744698c1c4d032809b088bf28e7f3eaabec5ed935f9125d172a02604c8799));
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
            Proof memory proof, uint[160] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](160);
        
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
