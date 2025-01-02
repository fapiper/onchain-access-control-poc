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
        vk.alpha = Pairing.G1Point(uint256(0x1a0662be13ca5291338731715d47e0b21ad694cb44761dd02c14d5224dd30785), uint256(0x1fa326d9d9685ba9236cf830e54278762339f1e01f692a1ff47de853d69cf180));
        vk.beta = Pairing.G2Point([uint256(0x1d9c222959fcfa6b31978b123d7af8d6bddb6b2d29a6b64715375eb5ce8ff74a), uint256(0x2718a176122bf7b2e81de4f559cacd69f241b94604b322eed3eff35775b79c9f)], [uint256(0x116b2b541415f9a413d0796954116bb5197f5113648eb4d512cb9d92eeadb6e8), uint256(0x23ba94f34268237099fd0f32f3b098f5d54428f9f1d72826d0a877e27ad746ae)]);
        vk.gamma = Pairing.G2Point([uint256(0x1190f81545e2f0a96a0787b768e791e6ad8d8a0fcd8091deab46e664c9bc3fc1), uint256(0x1f09f33bedaa4876ae2f74ea45207de311bf92d4bf3656a68aa3f8fde264de63)], [uint256(0x0928b09ece80c7d97d8fd05475f50833cc9b22ecb052154cae28904e71b517d9), uint256(0x2f751b258d9d82c3bfae0e330115653e1a5c933795d14c7fca6271367ad864eb)]);
        vk.delta = Pairing.G2Point([uint256(0x22606fc1f859ead4178316066a23a2e6e7ce31f2bb3133779735d7f4bee8eaab), uint256(0x2ff8f67e873810ef92102fbb80150013fa87170053c1739e50e7ca69b0bca5c2)], [uint256(0x21a09a5045fd13b0488c754e6f774304b3c5a1c069985d13d93086b405f7bb33), uint256(0x2de3d39970ff834dc1d15ad97e0ec6f2cf8035c1d2f18c84692c42e67be411e1)]);
        vk.gamma_abc = new Pairing.G1Point[](54);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0b07e4085baf39cb88bccea7837ec4aecf21256f6bb583bad6586ce75ab0809d), uint256(0x2dfae6b83aeed115c086792b7a5c36af355801899af2892775b0e9fc209db54e));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x209ff1b81cfdeca9e908edb393f58b2cb45b43336a576ca2a20db2cdfb8a03f5), uint256(0x1df8763e2910a9be8020b75014343a9ca5b77c7991e4c01346fd36b2319f4376));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x05f17ed10a1e5bc46b5865ab8a768b9e8c4d2db99d7b70376a802d4cf33ab2a1), uint256(0x0d18ce6fec2ccabe268f0d66361dbe833fbe8f9622bca052619a035c5c4aef5f));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x10a370deb761acdaae5440ceb9ab76004a9a6a0270b5c97f00689b273de31029), uint256(0x0fe229d3f5dad4cdecf0ead5efdfef868798e9b2a8c5a676ce907d2125d72d97));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0d033bc817b7281fd3aaa1079a23f29ec4232fe5d128337f4ef5b5c2f8425520), uint256(0x1c4e32a4c3b70e8ebc31d7285960a54354ff508b72f0267ee540ce16ce52f50a));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x21811c416eb5d303e16b148947b62b1830b07d289a83c8bbe2abe395ab03358c), uint256(0x0e19cc433f17950c4a5d351c6cffc15cac5a9cccd81fe014f01a1ca6beccd3cf));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x20545f5bcc4bbe613cb86a1965cbd5545a59a66967ef1517c2b45adc5073e9f5), uint256(0x03144f896e0e649e949ef29a0c4587142412aec4bbbde048bfb1a1d1d0ed34b1));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0c1570be3f748cf95fa0c8afedcc5e2a55b200a40ad02071a5b276bba588d677), uint256(0x1d234bef22cc06c0a2ba8d72d0056a1d8a7d0c3e88986ea15b2161d7879ccd75));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x246f261dcc87ffe0c3e6ea6819cb247e6748a4a191841ccd1e1f74f44796d2fa), uint256(0x0f9881ec8e6627cec009378827fd1532c1d07eee7d0e7bf90ae34f463822f743));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x26c1fbd8a0e244729d1b399fcedd8460dc9334dffdcb9d1198c503c2ca4bd26a), uint256(0x22b4456aaad031b054aa7f0b7fdb7d0e02b370dae36ba92195c9a241dfbe1973));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2f38c313fed1b4517c84a2e9db112672a0e6d1f660938393b0e0a66cb30c2ce5), uint256(0x17c51846695368831392a6beb110ed5f2dedbd929f4095970ad23834bcd12cab));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2fb819d94e06cad36d98d0be0278f78f2694c17dcebfa8c481f661c01f25ba3a), uint256(0x11633aae97205d4f1532bbd5883a6af40df55cbe4cc9f819b9600fef36b7592d));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2683e7f13f39afdc1fe05039dc9d8b539854f441ae78364bc78603d802ca4726), uint256(0x040b9bf4425b220a80848e47f2a84246b5ba14ceea587ef395fa40f7abf5bc33));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x303439539c3911e520a122ee6e267eb2fa9815805c0f655826fea2747ef51dab), uint256(0x17a2a8e8da2c1727e45a5bd41dacdc55de4078f83934b0ceac6400c1ab4b533a));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0f93ef6e7ba5084e9a79b26c22539b1cfc3ffaa022ebe92e57d8a0e771e7c22d), uint256(0x0f27485b10a8cf330a936eda5f7d3ee09e7bc16e44dce3d47a95940347bea9c9));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x20d396df8ac8757a2630cfde7df6335ada22e1514f4875ba0d2b05f0baed2891), uint256(0x1cf7f16b5db743b18bd949a4dd1d2f9b571f9f1f0ee395fa018a4764ab49ddc6));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x24545c326b12d78c4e31bf691300561f2fb27b366b988a7580fd50aa5d532ef3), uint256(0x0544b897740aae11d41f414f7bdcf9487b5855ada86ca4c483785095dcfd84e0));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1fd264c0df6984ca29ba1545591d913fac0e4ae89d926d8059110a6a80fb0597), uint256(0x1bc0ed45d12828ad49ac6bff488297ae528ebaa5a03dc36dea67ab5e274c6281));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2bc0098c9b36855ed3294d324927c2f570ad85a3443d394d55deb23ccc522c9c), uint256(0x04ebedbb4c3483a2798bcb428b141d7e4e0747c0d153758d0bb8f897ba980a4d));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x08a9084b92fc08d0e4c27b19ec9cad871c5b6ecaed6bcc41542cfa0724729c9b), uint256(0x16ed683498cccef5eab22b31a2390a015ba9ca4f13ba9f8bc7d41705df035f17));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x0323462f6d0cfb03b0bddb868b4b01ef7f4c45ae7d38ac1c716b11d1468e8f05), uint256(0x2c5fd9526eef00422c2cf2bf89f69523cf1377e19a69b080ff47f9d170bee5f0));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x074474de39170ede887e7da131553f53ff9f79078326633ccb394647ff3ac753), uint256(0x17fac1274f6ef5c225736cadc68d4b888c7af674465dbbf8af546e9731a00345));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x0054955bb0af8debb56d5cbd1e6c2ea1de857593ca3e91c0022994aff017eb2c), uint256(0x0c2c67bdab9dea1e404ac489dfe766e1ce7e9f338cf7f46db55234eb526ccffc));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x189c28c76273bae1a4f53245722e90e9260777f12d6e61073423e71b10d92d54), uint256(0x0f46c126a8d2c40fc8fbab44ef9b646f625e42ebd34aa20a6ce98503b0a1edb3));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x1d3d20b304655a8627ac6d5348cd8fbe074fe015ac6cbd9f9760f22fc8b5f658), uint256(0x0bfd3b66f39e9408202722ef3be535ff46c2810f91be39693785db2b6eeea647));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x1213c401748d50b10d59baf8927ed91299bed332432c614bc05ca77a1255823e), uint256(0x1308973fb9ad8dfc746dddd32dbcc9e18d939e2e275f45429809c2d1a7e5ea46));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x2485085abbb1dcb8552ef0314e946c84ff403f2a68454d31c2e3e5b52a699f83), uint256(0x2ffd315c793a629bf5539425f5032231fae220404f6ef923124996bc2e526205));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x20097aee53f511de81495bb19d4b0f810c8f06a526e00c8dc62e83192a965899), uint256(0x109699cfb502018140dc27fe9b82c007bf0e204d6ae3b65bde09d6c543cac730));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x17e61cf6a3032e01f1413afd787f9ff87c21510685c3bd156ef9527342a6ed8c), uint256(0x230dd998d6ff40e08ef94f992ccce3924524f5c42436c61a7b985854ba4e0f9d));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x18efab873bf851fbf139356641e21100a725ca40112cacead2b6db0807c92e84), uint256(0x06cb2744c772937ca4fa09db87871eaee68334ef23f2dae664db15af21543efa));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x06b5d91c3bc2b446342a103c08cce26af9b41b365954022fc69b0711881b51e1), uint256(0x0a61687c2d7f81e198530f372f99a0cb4ae973676762b173c3219fb1164844b4));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x058adce289cf73f6d5e35481202ea40676abd6bcd80d75f5583b8cca1487c959), uint256(0x19b33450e35b726f7c5a1b3900f8aaabfde261b2a106971a095a82ba99e9a4ba));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x28859028f90b6052483a9e1e5a11e2927981e5baa9ee1c0c148571bd5686a01a), uint256(0x2eb03345ac91f35bc5dd244ff0bb896b5580c0bbc9613cb05eeae5a4f4e53045));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x15e6c8ab7fdcf56fa2320199d70e0fbb38edd274bc1e8aab0ed11ad39c47ba0c), uint256(0x25d19fb31f43e7c33a38cbf7d713142a47085c4a7a2b0bedf8301181a88fb6f6));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x243dbd62679dd3f8b96a18fa1962bd6a0616330ff5d5be6455bb30ecacbdd35d), uint256(0x057c3d6731c6a68f68b5c884a272241464b88895e737ed82b3a5f661ef5feae6));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x17bc5916a1e91e2a0f7915a8797ba7c38d06d41ae28dcbd5e3a5cdba2a5640af), uint256(0x1492baadd50ef614448b9c450ecb11d4dd59be84d36c2f4b617e466f2554a15b));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x15c5f07f254ecf19176b37f8e4aa97efca0ce212dcfd7aaa090459efd78fb6b0), uint256(0x073c4a382460fd07b6e4b926e5588dbdc68118d3ad5517e9174b3c3f63097eed));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x06c5dccc16d89666e40f1d4831241704c9285a975dcbdeaf93aa33bafa621d3e), uint256(0x04942a1a4f5ff709f5e92ebc9d3196a056e789d54e52ae13bd3670d7ab094d8b));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x207653d1d8a0e74e251cd07f00fa7d0e59fed5c3b1bf0d358d4fa4ee89dc0331), uint256(0x2a751c30f5fc4df0941d98c2a0867c84bacaa263092dfc09ca06ab1a3334a50e));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x09cb08e5f28806e4e4a4cdc80f4c9f3eaec05e3083137fcf16f40ce7dd70e3a0), uint256(0x225b049cca44ac758d541bed91b3132edb5210f04aac3750259e4f3f5ba603df));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x1014664b1fac510cab9d3c77be5d5ba4a5e4212d0d422c152126ac0cd396626c), uint256(0x18b0498525d2174d95acfc3b6488a14a685303b86486df27a3a4fde7f16ad8e7));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x29d048529414cae7e968b568802a141cb85b5837e8ba9277fa2d8b950038ee39), uint256(0x12f4d0e3e3c12a7093c9f3b6c631c73827a02fe3de1e4fb4dbcc8d4bd1bed85c));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x2eb142db1d821ab37d6a25a91af6b27ffe29a934b7deedb0e5cae12452b9fc4e), uint256(0x251a727f2bf288e4d97367f7c8479913b3823cab742b74d8fae27673d7ff658b));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x2787874c487531f659623315e7ecf781f025caa97d628f2088cbb0509dccd0c8), uint256(0x086c792b071ebf4e0fbf8e75da49b83be3eb6a16df92cab58a8622848cd8ab2c));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x2348bab3c2af26b50cfed572dcb93281ad4b2668eec4e0480783f52b4778445a), uint256(0x10c1600c8ec3a8689b5325abf02648e33041df9e911acf7dc6503df98ab12863));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x04008071af70a7a8b581591d0d4738e785c88eee535a20b5e802d2816cf5c226), uint256(0x17a13dbcc9b22f0f9e7cd1127b9e7bd269c095358e2d24a289de427eaae7fc57));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x0e33f329404afa914180d09f4152def6c474e8d60181d86e1988c2f2e9d50d50), uint256(0x2be9ad8a55093970532003d0d4a2be301b90e6faa14e0fd7e4a6cf9df671d515));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x20883d5e7ab7f1cf53f0898b896eea3fd549a81d15905054be8f87785fa20f86), uint256(0x139db3a3d8529b4cb8d8d59f7bfc633b26b4c0367ca468c4a7d9a5b2ff556b67));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x19469a283ce7776e10c9ee0f6a8080c4a507587f721897a68618defee5facb0b), uint256(0x1f8afaf167eb632a59cf855a7b7987dfd801a6f89a01d557304a20f3e633f889));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x0bf5256c193eb25c2784702a3acab0c961b2057a2e998ef3b27495062c529064), uint256(0x04ecaf7a71dad02d75929f6ea0e8e514bb0103cd33fbc78f430e8297111acd8d));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x24ea044e43696109eda2953baffa2757b2197a5e705b1cea289e03cfc57f1fdf), uint256(0x1dcd82aeb60ef04e8e74f120df6b13e68a8ef9b6577c323d474dd8910cfdd1d8));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x225a6300b7d005707a66474cbb7a25d1249282c45e1907898284f2c30999b913), uint256(0x0f94138209405080f93fcbe4cce9c906e7a9d36a6b15eb2f17d43448b5cbc7a3));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x07210585521687d7f45b4c3b414db19b8f717f07360e69a3cdf2f3a6481d31e7), uint256(0x035439800d7f9b84619c7abc19ea39ccd27ca343ac0a2ee61007f4429e73a618));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x0da873ef429977755202e624f9639c636e3db2a7aefac6aa8272e787cce4a6f5), uint256(0x00a4e0c2c6333207003eb0617f64981a788ed802cdc1a714201f41fbe35d466b));
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
            Proof memory proof, uint[53] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](53);
        
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
