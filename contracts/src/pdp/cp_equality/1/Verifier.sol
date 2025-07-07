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
        vk.alpha = Pairing.G1Point(uint256(0x0dfbfd840061489fef9e9d954845a3a41cbf93f59def10c5ef337e5428ac4b43), uint256(0x10c4a9af9c5c1a392add8be4193de6ac14b9932cb1a8d8942cd1202eb13b6033));
        vk.beta = Pairing.G2Point([uint256(0x14b0127f15918f74d316ae808ef57a2442af50a6a139b8afe8c5f2b8e8e9f3bb), uint256(0x2ca48735df0f65b4cd88bad82aefb8212f0b544ecf3008cabd85fdbe6f28a6cb)], [uint256(0x00de017ddb34f3936e2c12ac86172a895c89be6748bb3a3e3ed913fcc0827fa6), uint256(0x1ad1521338d190025d39044e79a7b90ec6cee215708a63189fc5753d3552b53f)]);
        vk.gamma = Pairing.G2Point([uint256(0x0da6e354120aa25b9665dd826bad6621e94faf2b117b68138f9fd0feffde700d), uint256(0x0eef0fd03ae5ab5856d68507888d83d299c82d9c80f1a880ffa5992405605959)], [uint256(0x0e63b9056ed3b49ee765db3e19d8f83c87a3f972ccb23521b1da925203f44aa9), uint256(0x2a24757a501eaa9ff8643e781d3652ea7349832ae6583d24ca5ac60e21eae8b9)]);
        vk.delta = Pairing.G2Point([uint256(0x2d309a3325915cf6f9869b80fca246d0bf86c99879834634005893b2bf7c0cea), uint256(0x23422eabb7ce53bab4a5995a030f1baad931c9b91560782fa9c9102e362a6743)], [uint256(0x160d807de38e937914aeae41075c013f7ca911f89c49a2b42417b2b1a89b3df8), uint256(0x25bf7f0e2f0bcc194381d8d552d8363a707b7b7a1d5d0445f5e339870245284d)]);
        vk.gamma_abc = new Pairing.G1Point[](33);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x19241947d669b2ed55ca0fc8f545000273d915d45df99c3ab20e087333dc7425), uint256(0x071a6fa85a42a30864c1b4429770fe5900a6b33b8d6a7bd43f4f650c412d5c7a));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x064a83b5f8433c3f4db6e553cf0c08109f5fe7d2d133d166b36d5a47bef5302c), uint256(0x26e77e87c773856d929a6e768cfb7f79cb79873d25aac2b9e58261b59aee5b3d));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x304ec7a2bd43a2e57de1667003482e33871700f9b066eec10791e908d621dc03), uint256(0x1aab030ed3c28d2aab1ed281bd7c946848c8a62b3b57604daaa6a1948ee19bb8));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x04f210886a4c42b22e41cae485576bb4a2c9ba594b678034635c068322c1fe3b), uint256(0x1bf296a3cdd40fb1a7eb11c1b99b7fafa98fbdac774fb541d936a3168c062036));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1f9cb82376a8f042aaa16a5e240aac2810ebab7ca5129d7d0ebca9ac39147e4c), uint256(0x0bb94aaed34436d378f0a10110f1ad8dccddca1cb828916892e8e13cfeeb8a49));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x14a15ef03f68dbe3fdce0c990beb9f76772ad5d9e3ade8c1f8d3bb5feeeace75), uint256(0x09450acdab6d4690bcfbbcbf3a7af002be36d3c993c3e5f3df11421e41ceaaa7));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0bd880bdde977ed702184660c8f7fb3ea27220c23a30a15461f0efa45393abef), uint256(0x028b78fa94a76b4032943beab758e08e9a30ab1b3055a55476f24e45716d9e62));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2f5fe0a34afbf230f3c14f079ff738f73d74c6c87d58a587e51c2adc9eb5945c), uint256(0x1881d6b8a56337e8fe837c28c3bb18de2ba815e42394b25837c68dbc27bedd54));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x24051f0b4d460fabcfecf28506e8d6e416085d7565b1ad676f18b06ae019b53e), uint256(0x1f8f835799dd638403558b9ab0b04cf9416b6e99f22d4dc54341c1dcefc38d45));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0e5a94055f131bc758838d89dae4169ee2c08336c59bff853e08e8e3cbfe883e), uint256(0x105a9b04176850525c586a485a16da84576e9d9d33bb4974908d18c73afc786c));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x08b4295bdaa79bd93017f430d18ffed032233520f943c49b8963f1361d61c96a), uint256(0x1b010b0db61bafad5b80997fc59b4ddae9aa76db6045f8ac1bbfb0bcd88bd708));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1e2e20d0987c9c991ba9376c21748353a522b1e37f040c7ecbf7058235f03645), uint256(0x1487f8288cd3fb24b43b9bdf6d6ffde1333739ca062beea5947ead480c72bd31));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x283a5bc2b4b13462b031f0e2efb77f2742b8ef21a7e6c870769e387a1cec3345), uint256(0x22f22f97b067cdebf98223a4806b3e3fc6e55d0039e58b4f593bad2cf975259d));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x141526b5467061a97c370a40c334204dea3cc36f9a9fdeb4d4a4c83f255895f2), uint256(0x2c222ebb6a74ad6034c307335364bcfab8ea28c12678cb010180e939ab445042));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x02c1d890ef539336bd9ccf496614112ceed67343a7e7829f49effb30969a083e), uint256(0x1f4fe312fa80532c380ba1949e7a53627096f66776e8182b9be25b8b0b5d3fca));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0492389b49dc3de0ec6ae7c073bdd3eb651886b6edb0ac0ce64bf9a89ceb02b7), uint256(0x2c5a2080ef00e8441ce34405f73e5a3e786bcdcf82a783b76ea153a0542f7725));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x00277c3822da3fa9454e68c7cba919389f23d6e43dea90a1e55d8a2ff4ae6962), uint256(0x1a6c8fdab7b59daffbd1feaa543e393ece5f2ba8560e42aa3109d8c2b24f7d8b));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x06a8bb60fb3c0234481e8371ac8b0c5b6a7b5c8377cb433ec7052529e3015bb1), uint256(0x24d213f1de75477415b66b5a0cee860be556c4969de540a04d31afb0d28a5da2));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1fe35d182c43efa30361d4b950efd6b852480c9cf2f1b6b12eee38e5baed9595), uint256(0x02b5961b802ffc2bcd560f5f3108e6b42de445c23053b6703afce3db27789051));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x22fef26cc2117ab4758c850942ec014c359e04a74f9920f3630ef22854477223), uint256(0x0d7628f5592f95dd18cac824d67158539085147b006598058ae51be5e0acb5d6));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x0752bcd550c9e648e04035a2a3b9deb2ee101b1ea9e489b66681b940e430840b), uint256(0x0a681fe57de15b8fa113feab658cbd0ab26617f27c9342eeef6a52de5616945a));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1c4779f9717bbba4aebf9741102e9f809c8b4a2f5edb983cf11a30d1c2edeb18), uint256(0x266c1e1e513bb54eba79a6afb04a7fa8a1cdff6db16b2658ad69f9db76ccba15));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2e97bce5686ccfbd2c973f631e257b6c19eff386638b139755d3b93ddaadc6cb), uint256(0x1e413d4e518a9b0d81e4954b73858ed62de5711b2cc5417c544cce8b7bc02704));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2cf33d1a16bdd8f356e5a60308796f0d7448104435717ba7bf69d91180996186), uint256(0x0c6118562a4b7eb181721fedba15110aa6125c4bf9490b9e513a153c822ed449));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x23a1c10f105d2280d9066d586f7ea340eded8bb6f9db4c5e4e96e85dc94b0153), uint256(0x221dcf07c61e634de0d8c0f3c547929d6b5e8e61ae80fd38210527903904a3ea));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x2d0dc1c3b1630c60b6372aad58aa06737d175d83e9f9c73dfd3cccf1df7ffcd3), uint256(0x25cf0918fd26d2e63a4da40bcbe9e18d8297aafb4f8633702b11e3614d9bf871));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x28b1d29cc00f65d94f9c5d94ac8dff8312fcac04fb6ebde2ef545a140cc5a0bf), uint256(0x06eb09700ee3b724ff83795c5ce9067d534b15072da6b3eaa02f22f4e2ea7c16));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x170d90327219aebfc70177122c3d63f8d7a43f8be9829e44bdb567e5dad52472), uint256(0x1b184c095e43b58b5a41555a0d787835fce5e341fe63f279d597d5e64bd8498e));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x239b2c68cdce7f5f0766d0606fe5c0615f028384d60a7a06f8dff6de691ae3b9), uint256(0x2efd99c12c42ba5c936b519380349ec1e894fbc7870ebe7f12ef590deafaf240));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x2dca7de11a5431557a633ac19ebe523de656370c7591f383af97fd1ef1c2c75f), uint256(0x285bcdf83d46a0a471cbcc72ecd9515b1f8a146da057e6e92204f978c6678423));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x090aec1932724a9ed3d035a27fc5bb9f6e362525232f69675b0e4c8bb8433658), uint256(0x25fec7741e8b82c1f137fe49c1ccfaaf75f18d3492d5294f465626b60c15caa2));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x1a5c52a62c2dbf183b77351ef91d6f75546820993368fa92297461782bb0c1b7), uint256(0x212a65afd1c262e09adc10c65239dadff001092aa9447849baa61238fbbdfeac));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x2e56d8629af2e5ad5421b20fd18c44846a1f0237decaaf594053b3b3e6b19880), uint256(0x0baa3a95d32c7a86c451eef311a35a9172fc5aaef970a7515b4121c0e2b47bd1));
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
            Proof memory proof, uint[32] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](32);
        
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
