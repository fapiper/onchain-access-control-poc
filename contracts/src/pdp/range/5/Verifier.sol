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
        vk.alpha = Pairing.G1Point(uint256(0x281b437365e904fe698cf7601e61e6f7405efd9678794f61e0e832a20183241f), uint256(0x13dd687ba4be744dcaada9591cb673ad6a7e12213df5c4248d3ddbf943b1169a));
        vk.beta = Pairing.G2Point([uint256(0x19f5cb37e9da1e33ca76a8abb2b790280d92faf5b82d42e3ee46a82b1cc1ea94), uint256(0x1986602c7389ee12906df4a40cb52619172215a6097f7fd5195a900645318c18)], [uint256(0x025e41bdf801fe599220f807eccbfbac7c6f1174741defa65b2e8b4268982945), uint256(0x027926e6784bcbd5c3c1e1fa8c9c7e5a55fc3c707435f9b7e290dc4cc0415177)]);
        vk.gamma = Pairing.G2Point([uint256(0x24f9d0e1388aa48884e3a4929ef86d4578e6a4d01066a8161c42106d547171ab), uint256(0x14a482aea118fa08a01fa6c8ee978de1e0dd3771e58ccd8a2a44b05513b4ccaa)], [uint256(0x2a02bf1024fd826738ab0c029a33c6ac30a44a1849354b8e9b403f42c123bba5), uint256(0x0bf38147c3495b9b1694632d9189a01ed5b2d5d70835e7ea2b9cb7b679ab58ee)]);
        vk.delta = Pairing.G2Point([uint256(0x09686fefb1f1af74b74b9d43e1ef57bcab683a83a5a246f77ea34f62c86208e6), uint256(0x2d7f8bb96cbe6266e4dbc1d8e704a3266bcab850444fac49975f038f0d2e68ef)], [uint256(0x238076554e12fa43908abd84be23cd4c806e9fbb4b36270adcf74802f3d048f0), uint256(0x0fa9939ea985b61b395d0fd5984106e6432461720abccfa1ee3ea06d396a6024)]);
        vk.gamma_abc = new Pairing.G1Point[](102);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2f345420b4670621b43eec7aa016bee0fc4f5e4683c785060ea68e6d0340cfec), uint256(0x230085222802b6a187423ec17ade8133d2b0ddde43789dbdde0e15b07dc6c443));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x207b1bbadcdc0ee8ef1b12d65bf20b3dc9cbe688876601b35fcba21033f8db51), uint256(0x2fb7b4fea4f41ec1c3ba70a183cd38cf5c6396c46b17076d27abb00286d9e6d3));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0b9477dec78a84dac0b28c6a9cb5d5b8c7a179b3707349a7d3843f93af468c2c), uint256(0x1c5ca2a8df28b447bc5039e3cfff969ed8437c42a30d6ef1e0b406bd4be9addd));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x12bc02d03e7d6eb0da1a75f03d1fc60da6e1fff6816b63281ed93ce90b998e8f), uint256(0x2edc53bd31822d0872d44a2abfb12a3d9a82cc4730d97cad4ac8d96595ab0d93));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0ca449f3de723543bc888eb80b675c4c1b07f47322d7dc6356e2d3d3ef898ebe), uint256(0x0371add62b861167e8a825bddbb3b7ef7e7049d28d919dc8fa419f568b3c0111));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x01289d3e3a8078478ddd142a96e3ff10c65b16eaa4cb6ef0b4d22af08418e2a5), uint256(0x23068a4da2dfd5bc19d387499a7b9defbf6bdb7a37f8ce204aa93f7925d7973e));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x106c1587ed34ccc9a58ad40a723dab9742c06c2cc3b7ccef2700714bdddcb35a), uint256(0x168f1e3bde8689203c30b060762ba43c1d7e103ad2d56710a9def090817dcba3));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2a0ddf0580719bae42ed55a29b7323f4712f6dbe0a48c221b4e1d96b44081937), uint256(0x279a2cc03fe87a6d1737cdc85032d030f666576b8dcd667517cb33db89c5bef0));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1589ac9f1d0716b87c05a3957ea818950a2ad94d035d13fc29d4e8afb74c9c20), uint256(0x2383f8e976691e68e31388465fa6b0c108c9b6564aaafef5ab2ce51969e06069));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x25731955b7bfe646f3c9a5b2659f097ac2a8be39489f8df5172a9eaab260dc33), uint256(0x20ed0f2320c952db47b669e00bd836bc5610ec86a4b67f07c532c6cdd99e2d01));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2b1fc54d97a013b4032b0b13c6959a2857c7b0f0b43f78bdeec0deeae3a83fbe), uint256(0x0780d7e070ad10fa32ffc4635ac1c5d3ab6921bff19ad301519d2205ee8efd26));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x285b997820be5b3430cf758336ce5ee46df90e2c68bbbbcd5389f31a67f71bbc), uint256(0x07973c9fadbb79713f1701bac66d3f766adb95eb8efea4ce11930119ddfa86ab));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x074d85552ff95e45a8c5db7053626bfee367b937dd6e9b26edf0546ccd6fd7a6), uint256(0x0312a2a162900b381f2396c2ff27837d93bb6430392c1ecc0e70ae6d64fc8301));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x090be9995b32085992767c7c64b98e3875d5c6bad8aa3a19d62bd7eea3062044), uint256(0x1cbabaca8ff9d310809631485efa7152585496c4720d55b326f57c6f2f1813ba));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x02ca42163925303c569066fdd43c1c16c5e3cb8a550c9246a6f54b0849a6d13d), uint256(0x08b569daa6013009c2d5bac72ea4097bdb996ac6db67ca37baaa2f8a52078260));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x290b691a270c10258d30dc8511a2c1c57199581a49009c9c8177218d32f14ce7), uint256(0x0c2b4616cc0e837979f0081287810794472a0cb79be932002af43c792274198e));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1ea8429ba25876945a0a893b7b2cb8d2effacbedfa42cf63f26016a96ca9be94), uint256(0x11c734b8379a3502bc62670ef504ff305349cd3766f51a7ae644da96b42113a2));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2e1f25124d1bf8927a300bcebcabae98134799477790f00cfd074be5f85de53e), uint256(0x17616b231c1d23910154b50c66642132ec79ab566392cced3d7903b6a8098711));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1dd929d7c55e913c7e2a94d1ed0cfc6149814431324dd353c62f158331b7fc00), uint256(0x0daf63603fc91e160e5583d7b73e6c5c4148b0757875b80dbc9ddf251276c01c));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x10fb71510f7ee718bc1dde9d39fc257ae2cdab88bda3aeb81fa36b43804c8cf2), uint256(0x1b2573b8b81a2cdfd1da0aa4d532eaebc6d99f032528046a88b1f53da966955f));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2a33e846ea6f853ca6209c15c606be761f1bdbcee50c589a8c99e78dd0806732), uint256(0x07186cd99e49a8e81c197779edc6890a7f0977da8096f4ef81636cea196981b7));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x244b17f373e67c4dfd4b6eb871a387ba2b2686fb637f182fbb73d4fdb3850174), uint256(0x3029412fdfbc5193daee78b40f8014a3a811a0e90b1b0678799bbaea196473b8));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2f8c3b5a86d18dc61e279ce5b6fb500cd8d7210e4b9daf3d5f8158f876b18aef), uint256(0x0a5d318c0a561aff66bd79c90dda6224290ed3527b173c3abb05327e22a05829));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2eb15107c750969e9798b93d4675fa327fb8a41b08b52e9f785163c76562439e), uint256(0x11ae8fa5179a2b5020e82a1353bd3279860ee565f025f7d900f0bf4ca498d665));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x212af66cc25aaa92a9da5638b3caec828ebe6891d13ee7cc496681df4eaf5806), uint256(0x2907cd69fbcf93dc01ae38c92d1e3c1e0d06034ee77902067b5262334431346a));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x09abe692d1abfc694c1dc8f24e8df4923fe09b28192911baaf8c888c96ced87a), uint256(0x17d589bbb58cad4589b0aebdff8c32042d2e4554bd23fc10304a467aa329f614));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x22d973c468267772da9cfff6cb44689652cc553dc491ea9d4837861e7eebce7c), uint256(0x15f25154fd671de49c528f51bfb079eb458d4d004a15dd4c0a48edf393f920df));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x1c2596b1c5b1127ca4f4ad0580b9fb98104b4dceac4008c42185fdd583cdd5f4), uint256(0x097b7c490c3b290b48418194937a45db77248974169abcf07b4dbf9bc228580f));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x233818166080320d8c5084e1d715f43d48d18187fd348319e91363a3ec75187a), uint256(0x27a3e27b38f9a8ad5f20f44daa77f57ff11252f198b800594241329841d5fae5));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x065e4f622e6123df0850d80f826e4d6e6d9d95dfe905a1bbcdbdad99ebf5eaad), uint256(0x1caa20787355091ac1f6fcc74045b1242497bf5fea78615023263b039789a3e6));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x0d3505cc036a8e75e8a63f5dbb81a3d2ddc7374e5784b198233706f5631cb653), uint256(0x2631e8a0dfc81dbbbe591e5c4cddbd66fb578d9d15d1c43f25aa3b54f88bcd6c));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x2dd3f1605fb947132960e01e547de26f3eacff1ee8e68a3e52c056069d4b185e), uint256(0x1fb7cf5ee23b18b825b81196fedf4aac7d809a576044951127394adfbcfd1837));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x0af62b3e9561fff954e1b48023edf0eba369898f47b1dc2d6ba4bbaca60b20c5), uint256(0x26d44f9163b5a57b2dbf89ba71117cbe675ad8adf050a7925cbb1b7cd2f2218e));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x008e2a9e9b2a2f22792a02abcd64824a26c1e1a0666720cc37501e03daca9f43), uint256(0x153f437f86ea8ac0fcb74ceb35578bbc5a27eeca77c11d87483f35fc085f5c8c));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x176f6f83faf8d302b63aa4e9126db74366dcc4c220224e41cb2b1b5991a5236b), uint256(0x1ef2cfd7ea519098a9cdf1a0316e667ad25a1020671388080d9ee2998b93c2a1));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x250dbe60a41cc5d4add473aedb1820c19f8b31b54e77fb920ebd5234f10fa09e), uint256(0x1f508f1d07286bc1e85911ae87ab5230ea9f95693eff4daa4713c7a79cf83ffe));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x081d690dae0bbe1ae48fcecffc007a69355e9765c617325cd5ceab9a7c331662), uint256(0x1aad0d83e03cc18f89395ba100cea35e5881aeab64ad4de6305bc8ca62f5e662));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x05430a2a874e62255036df6c00551d7604df8b228f2e409a4c5e3c4950daeb34), uint256(0x26ad4fd22885fa5f319af17605e285739ee5dc135e25cf32418f88ce63bb072e));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x1d8ead7a06fa32e5663ff1e224ddff4a9c950b3d9e14b9f4a4797f7f9c28591f), uint256(0x18164fb30c2b3c68844a0d546883bb701e149c4c29da5ae9af66abbdbcd178c0));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x1909d3bd38801f1522955e96fa3e8cb2f3ea977c64165fb230db750fe46eb4ae), uint256(0x153ad1b8e94916c1ce43c5e27b2d29987bbcfe470825bdbde13b3dc13e5d617e));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x01b1a9b5bd9d33c805d2f9056b45bc715884baf895674349ee71ac0f7cf18a5f), uint256(0x0decd12165630edb286ee9f52ee980fb6ba764903cf4cef8a9d1ac39c40667a2));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x0505a2308e498ddf8959b7458f2d22d183084a758c0e0a844e3a44235565a01b), uint256(0x2eda7cec87b5824e825bdf71e2d2b9163c59a511961aaaf6f57c7b758f05478b));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x23009afdee9799ad4328409b0b5e77a263060fe7d8ab6c228241b0782e915406), uint256(0x0654363f77d7bd19a20a563502c306e9fc24ac427ba448970593a09431775108));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x05b41d7ec42668bacc095676cb07b3d1df6cad04166fcca1a95d27ed94b0dc80), uint256(0x0770314d0e81ffb03c3611a9c093e6a12552859190b847a832ff436a6668416b));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x0592b7e9fa2e63b5273aaeadba55c38e4c015995895fe749bd9eb2372832b738), uint256(0x2dbc1874547f12a021bf5f6b5340cda8ed0b74945c98202b988a82d9e9043501));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x16d73780f86a4b0284d5339cf40d88a868720e05c95b1bd04e57ef7900958ac6), uint256(0x1a81d85a137502ed8e0fa8bd8164d4cd834a0843a5b7e77a0c7eec342d948347));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x1a4fa4e154f27f75da8d40d928f3afae68022f0ee93c6d9700bbd58292a4cb7e), uint256(0x2d109764195d6bb5ccdbcdf24cd4cd5a9e6f38c9749360c1e24ac6fe9cdd883c));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x227953c49b86b98283b7ad1b0aa3e02cdd7ee8d2372a34d5f263d2caabc8f13f), uint256(0x29c3d7149f070d15847dabe88d25ab9f21df61f4eb40ce281c1916bba4ab72c3));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x14696ebe6a361a42f62128b3f9e81dbd8fd7d35b0fdf1f21fb6a18271fbe46fb), uint256(0x0f337330d467653b10ab49ae1e47a1a16ff515cdf261d049b1b1aba40a0305c7));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x2d7abc24164b42dcbdb7b572c4dcf4d089e8811bf46e4f02d4378390853fd869), uint256(0x2557b5ee5c6d46f36558dc99ce6bc8837e3a817ee5e14d2e906b2c77c7fdca62));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x2d3b24440ea25504970609a880ba9a48b154d6096e99f6d3a4408e8cf917ff18), uint256(0x2cd829a4b4af9a7792cf7f1d0c9aa5e7e204d94b9498f0b58b59fa49ebb8f75e));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x216e83c044022a6d1f3bd3ef8a2da2d88c95d94536327567080cbb0f2089daca), uint256(0x2671379acf33cacca605ec06649d3f47f31f866c88b9b4d6936bccc1a277fe06));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x28a7cff16c20a977cdb0b48b80939dd85d76ed3b6c7427b9203adaedbc5ac695), uint256(0x12bcf974a54531425dbca909fc0e95aeb98c7ddffdb00edd73afc0af3c4b7a0e));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x0256a9758760d0ad8f2fc12a2b9c06030380c028b9291f2a4d622e5d8ae63ac9), uint256(0x110da179d7d03a9d38daa0b1c3a647218fcf0142d4a195fdb481d2a665d234dd));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x1c148499135b344908a210c736dcc6d70a63bc958d528156ceb9ca9b31f65bdf), uint256(0x14dce341cd6924d0e601e87ef1a6b175d9958a12521018e0370a4e5a2d45ad2f));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x2d5e5508758c2b7aabe9b218605d5259a288df1562764cf9dc3f262bf400a512), uint256(0x2177a76172d6a4a294812e8cd89f7301fd5539df804314e848cd0d6446190d0d));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x1fb51ff63dcece3def02c679e01837208300b6f16c6463493cee3351ea6edf23), uint256(0x15815e2c37fa851589fc1ab147da990802b10bfa2924e5977f3f9ac08f8386c1));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x050c4b65f0be265d08d9d08c486c58cf52caa40501ccf6f4239b0c2d82ee2c90), uint256(0x26f91ba38f31284df9c00c1d0a7c1cfe732c3d4dd3d3f4d015419bfeff5b8911));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x1acc092c462946d7a46f4a7c312abf748e8b794f519004c403b7261f209c077b), uint256(0x1e8f59a60987849e9a3baa689976c44be8075f06199922223137a20024a87232));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x059f88a0b5feb5d05fe50750721c710be1682e7dda97d7cfd5a280755370fce8), uint256(0x192482bd6003cd8181aa2f193d05d8a6aff02a2ec8ab89d9f623ba3454b9e8b8));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x303459b3bbcc5bc918935ec135401dd63f512d7fc4286801a9c0d67530e2e69e), uint256(0x1a5abdbd5bdc79917f4d8234ba1724655bea07232abf8e115113a129e63273e8));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x0483b6e9aac5765dc31b0f92e2f269b059df6be47bc532f789d0b58ba6037ba7), uint256(0x2f3f40a6cebf8cb7dbe16081a9fe1a92c215e95a9fe5f1f63ff81915c7607f4c));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x0023676a1243bacd5d8c4e5c7f89180d78528cbf86d4efa7b86ed86789ca853e), uint256(0x2398e17d494e8eca212129cb5a7c11e2f1272dfc1f3a90c2f20d1e9ab89fa945));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x031a1af74e7b578402f7006dfaa5e63320e2a724b597433c4a77bc14b9eaf2e3), uint256(0x12628c8822a6abb9250f109c27a70a8d6baadbce84484345ca85baf5550ec97c));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x125fb4683bfb1c684d8d0887471678f531eefaa6090dc48ce576c06cbe976168), uint256(0x01784d8005c4fd88bdda2582aea6f237d5b0ec0c7145e67636c04c26ad0b674c));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x19c03d9b7e7c9e96deff6fe225f5fb48ab93e084b3ca2827d976bbdf8213b18f), uint256(0x2e0494294ce5d84258995555a928bfbe0bd71d60284191571d114e0d4203e2d7));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x1c6d3bf95214b0eda545a3354c781b3e53e1afafaeda5324b31f2e34c67e2823), uint256(0x1f7d49c103b65dc30f3336fff7a7bea57f4a462014bf1536e57c99ff8198065d));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x0447ed5ee648c113ac5db0e55df0806141f8314cf2655837b4dda0789f2b5bf7), uint256(0x283874745936efc1c7643d2ecc674e10117630455c186763a2a0a2d142acd26d));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x2b6eb47565825c19c63a5f0b8036f5dbb5115b89d7006aa88b3f4c539d3cb678), uint256(0x026629a81ee9bb502a981686c26a9276ae18bd7ded7ea62f84bf9a7f201b4be2));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x1d964cf6d23a28a36f5781d0aaf34545662e90691c560d3544246b69d6cad2a5), uint256(0x1dc207e99c024f3fb98b5ec004cbe0b2343a601edc8e492d8f75bdd3ba76c2e7));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x24cfa7c7a31be9aefd202ac7bdfa3394d8cef1a5bd4c092f2ecb9b14495a4642), uint256(0x16a7ac01a11b1d1b7a61f4e1f686c5a81e0d02cd321e081694edaabcfd6f06ad));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x030a2aa794b494f336a453f7982bf249a5eeb0c067e53f04feae0cdf69ea0d10), uint256(0x0eccc60c8bc8e9088dc007ac825ba5879f20d35362656c78ec7084bb8f1812fa));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x14ec6e19dc83d801560a4723deefba1ce50fff0637f70e7b5ca0daf8b56a3057), uint256(0x183fb4397c51c412f4e8eff012e4213978a066ddd605a0dc4586f7f55b967a03));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x0d16769ec86d6ac06fad683f853768edf874153e72dc2d3044d7482922aa9d06), uint256(0x1adb799277cec6133dfdd1a5ebc20219d98871ef8d0f40a1a5e2ecc763c46d30));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x1aed4cae2dfa36309bb1e68324b8ee4731fde0cffe31a1d71bb61a78bd292a7d), uint256(0x0d5ae566f72fcf6f5a10aa9ca71e22159489a31c3780ceb3fdf3a80c1936f6bf));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x0dec398b9fe644fe04478e5a36102c5442e13f363917b9872f2a6f783440e45e), uint256(0x1ba1843080b4d6a5c17ddef5544cd6fb8072774d1ad4ec656272c3282f4f916f));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x06b76644faca89e83565c1187209a1e437b0a780ce8c7881107d0581d197cdc7), uint256(0x29edc889b7ec2a9de0127711c1add29f444bd9b11300fdac1f461f43b269ed6a));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x0ed222497b35048302b2014532305d54eb702ada5ca71ca9cd42dc23aa6d2311), uint256(0x12337bb6ba77895873f8c378f5868033313f62b1622addc9ba89e1deeb468271));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x27731af1f78caecb0760a2ba27660a8a97712941b6bae3c16fb6a08c70f6a750), uint256(0x15c4db894c03c86ca25c1da45009eb772c7fe79cb31d6f0155ca4577fa8fafd4));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x0e97da3d82e7e39b0d64c06b3f23d133d17045e6e69f8c19cffa76ddbffe1a36), uint256(0x05788fe20f49d0ceac9ff1f976121fef775d4e9e6fe18a3858032d53f3359613));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x0dfb6f5ecf6bc8650668a52f10f2065748923558881be174c735cfd35680135e), uint256(0x03d8422a0200291031d99382d58d68904f4335a1b5e08b8f86d9737e70563806));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x164be3845f8e55ec4024b9b3d2824448b08f5638243117382600d6f715ff6bb5), uint256(0x01b3b568b26628fdc28f4527f6680e0e14deab7e3258eefe3b0a0234cb9ac189));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x276dbc055db6851f7af00c44e3a22e374167cf3484a6ad20287e57e05e0a6be3), uint256(0x07112403914b7cdd94da4e5e6c573dd10973c0557d832017eab62735865bbe10));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x204b6b23dd9ee1fad3faed021eb5e748c33da2ac2895bdc7acb1b17500381737), uint256(0x108cf94bdf74c52fe94103e7220e5584a6e6d887e3c534ba172f234c7cf38787));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x128178e69340ad9f4f0cb19ce879ccef243fdf960d2ad4ed81c764bcd9449713), uint256(0x219b317e37418f004015d8961b8d4cc4c40c54a57485b4b6b029dfbc9f032691));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x266d7f8f90912c39f0d35476604f3fe59a149c3c47bf41cc1267d404a4bc8c16), uint256(0x0792b78554f1e12840d587f71bab5d3f478795d286574c2c9b010fbe39a669ff));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x00975723ee017195211c1259fae0726a68d9d68cbccc702865a514e52b817bb3), uint256(0x0603f2bb86e7804811237778a9afe10f781a4abf8154dfd446d1f61cf53e082b));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x1a9d6f2d9818d24921c344aec2c94c03b5cd5609fab5be403e28319f28dc18c3), uint256(0x22a4bfd7c0e276f13cb84699bd13a7f3b802c9b0657bc5209271d41bfb3b7b33));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x18921a0d12615c6a8b96d55d77658cf050622c2acebc79371ee806a3f8820794), uint256(0x03c766b69a85cee9e17bae4aa301fc11c9b5d5b8e6c5871a27dea0ff2dd169b7));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x00a060dfa09c2b4d5644e2c07e5bdd6c942bd53a19a912a6a8e5cbd13e46bf8e), uint256(0x08ce48746dee44ca9b72330557aed664aa62c368d4f932987deaf09fddc7608f));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x187080f99117e77cf4244f1b017ac53bb82b3e07084bd96e8314df3604fd3570), uint256(0x016eaf95e97e1d88dda0a39723d611f3ef19e9ba871c4f171a6fdef5d277a9da));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x1035258a842ab1a1cbd76c668c5d5b274716d4b52b342c3a6ee6ee9a8b9626ad), uint256(0x1515f4216fe2c4fb4ad516f998d53e251cdfdb856ca9150bcbe6621b09a722ff));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x105f4299516ce0df9771707d7b9fde1e56ae53897f84943b8aca830867491828), uint256(0x1ab20f26293ade1ad11713b32e0c63a43ba96bbf69f51658454b1804f2908eb4));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x28ef253bd8d2cf6fe1dbb55ab26b4cbacd5f28d7f9c1a686963efc03e73aef40), uint256(0x2d84cf7baf6f92848e5b9f4ab02a3f0d59a57185fcfa2a6228939254f0c1ac68));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x2e9f6fcc184e8a026e5e738de4c00c093a45003577fd7de92be74920dd6f82be), uint256(0x2673075dc758262a626288a4c8f9f1512b3a5ee72b235227bcd74899b4f125b2));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x0625b9ebb3faa22a0db35c533e88ee16013472422c16e90f1f539904a02c9f7a), uint256(0x140565dfc2afbd32a7bb9e55fe00e8faaddc0a2df03a2312abcc67daa81ca2ac));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x196bc4e3f8e4e6f883e08634f76d78537d2df709121b605708c80321d2087d18), uint256(0x10182602876996f97ae792f6c605f3b22e96a65179b719671d3ff71af8ce8b56));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x1253a8e313d9c12af502074597270f066a9b5492ef395c69c41dbc1ce10c9e70), uint256(0x113361f56599fdbafeae6c801c556af570e589856b064fd423a59073f5023341));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x0abed78fa9d09746151873a98aef3701623fc38d21bae8c33d1c87b5f8684388), uint256(0x276d6587593106f10a593931cc927033608596a44d3c0294f85dfc915546bb14));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x109667599d4e2d9ad2782a0c30c5f11275d2a41a8a6807958dec567bc82a8c10), uint256(0x2d3fd9c745dd116e41486c94d8a1707bbe7a0a69df4aea54a7678a632d5a4e6d));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x2c899c19687191cc3b879d5636a6a751bb7fcb3719407d47b9420e1d9681f68b), uint256(0x11489196f7a02bf8cb046778442ed6631e368758c12535a8edbe7b38578a9deb));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x041cdffc106918132539f8123423fe4527a7c863218cc20b2c6d17a96e431d68), uint256(0x1063c1a4ebf4a4ff83e312e6c3e0b4f1be3e4760e74a4e9bfd4c107208a028ea));
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
            Proof memory proof, uint[101] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](101);
        
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
