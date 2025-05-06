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
        vk.alpha = Pairing.G1Point(uint256(0x2990cad1539e0da9aa27355bad089ec9244e5634f2d623998a3607384c75a77b), uint256(0x11aa9e410a25cf52c1ead5d79ea62859f6c2564d681244c1c4be54d426792f2b));
        vk.beta = Pairing.G2Point([uint256(0x07a9306c3495b5bcd58c1bc59db4455fb6748388afb2dcfe100b831641c76d1d), uint256(0x071b5f0b68ab5a0125186e74872a5802fe0de4e34412a51203671f74d597bd85)], [uint256(0x13b578640b8a69d6ce8aa2053b29a6fdc9702d805db9d4eea95871f96ea9bdb7), uint256(0x0de7bf54ebdc287cef892d54d8ccdfe788fcd3fae943158efb31f5ee5c3ac5f4)]);
        vk.gamma = Pairing.G2Point([uint256(0x03f52c711477380601627b14d6415bb16a004c3b0d977d8072c907cb715a5aad), uint256(0x2559ff3d52a238cf68b0f147ed00f9c2b85f95ac073ca49ea50e7942c2b48e2a)], [uint256(0x2729d72ba681d21f3dd5305edb6d0e3dff4fbe2135c2ce20c38abcf646c1b0bf), uint256(0x0abee4d5858e4f5aa751e6dbd2c625ddaf75632bb6d6b5274d2e15c5e624f335)]);
        vk.delta = Pairing.G2Point([uint256(0x28f59b4d8e07bd3530f834686113d24d7e071853550c76036e32d00d78e0dff9), uint256(0x257c0f4fb4d89ab4e7edb13ace0436ee6627723b47ebe98d7280ff9e7ca8b795)], [uint256(0x2251cc7f360f5edbf2d23f1c845ee93e6c212bbf2fcfa32bd18ad7971d961f44), uint256(0x123e25ad566baf3c7b781ad57728719391f9702abbf17aca0a6501f625b5d076)]);
        vk.gamma_abc = new Pairing.G1Point[](32);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x149ee0b8e191ea3ec87ff3114cf18cb6a6ddb1b7c6fd9d08f8b78decc2f9aae5), uint256(0x18888bdd61ee01f06db5912dc50a005112932e3c3524afb3b285fce0f356558c));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0b17b5e33b7d34d005b8a9d667ff65528e00dcf4571175a87f32db082ca4eaaa), uint256(0x252a7bee4fbb603eaec4af5915511829d0a346a692834fa97cc5dc727d07e16a));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0118576a13286d7eb684e77e1c729875c35fab24bdeb7e97e85709cb6422d649), uint256(0x0803ad3ec6216c33e933ec4b257d9da0313053e1187e7db99cdf0420d8aa649e));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x20207b752dae8108047835c9fef4915707016bbbaf8fafa5f5fbcdaddddb7293), uint256(0x03d372b20f1a2e513792e08b677d1c314aaf3ba584fb491b9bc574bb97a984b5));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x120c6738d99649bfe91ef44a921c9afdaecc719e7ff046bccfafb06be631fc4c), uint256(0x25750b4b301100b0b616d538d46e28dfde1a1bc6697dd86e84f821c581deb569));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1de08f5b6f7219dd5e01640103c0ddc6b26779ca73cd8d1cca2515a6545fcc49), uint256(0x207d1e5e6ea320cbc6f8bf7e62fa452cffae8b7578e20d398b617b602ef05a43));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x28e83209e8ce05f1b3b5344a18d31f665dba006434b63981386c69f6c9c799f8), uint256(0x11025c09f8e62d14303c3b33532f5cfb909ec8fef0e58901946403055d3bf503));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x228ca5616b249344f04492d2d055d596ea2d196020cc32acddbc71ae1d5f1eef), uint256(0x05bd1f6b60ff224ea413daa8e0a2fbc4c16d5e74045da8ab703a2859952bbad1));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1e4ee908042f5eb8567fa26cc4d03ce0e54aef487db3675655b7340ef21806ff), uint256(0x2f93ea71eed5c7456a9e451b33ceada0d32c114b2e0501c103060cacf66ac40f));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x192caf3383b6d81ea61dd5189095d31e79b5133e549ea90c44b957a76e2b7c44), uint256(0x23e3f8fb583b8b14b88894adff2418379399141c4f12be8bf7905a2856d63df4));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1e7db2210545d6d890269248a95c17b5f1f2d7efa2702429ebf7eb6bc8f92fce), uint256(0x1540b2112b974b58d1e050f793f6b83fdca1e401fed454f578cffabfc91d77c7));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0f1ac4c3b03fcda7c7d6886b2e41e851fb36db407c567dc7c23a67e181efa918), uint256(0x249fb1cff19f448d9c71747826f170a598f9b913b26e557480689ff418e878d0));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0a4335f32fe75ba1fffd967e02b4725593e9ff6b7b9c5dca9c5b1a8372dc75c9), uint256(0x1612ba6b3bc870a82b848e93bb5faa6f20a909c2e03b3d786e223019a6de735b));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x05ce1173e68a18cea7a95b6ea1c3f9f718428c3e4d4bf8ecc607e9a372ca1c17), uint256(0x0aa24999550954e9b0a21cd3e7270bf0dc9eadb6a622220777d7811495c8817f));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2d0a7564f325e022d5ec2d14bdffe3cc3d7a0cd0b137a7fa8f701d6224ca7569), uint256(0x186112fec003c003d952d1cb6d97b627a7fe8e8baab8e874b333214905403cc7));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x165d7446333e28c0c34aac53536ddf1f13284f2800f0e72a67d692d28ed6389a), uint256(0x0ce23a5beeda0db46186528eb9368779e17bede834c3ebaaecf4e3febe3ed44b));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2706f1123a6f5cde5a704aae998506a6c22d1a501ad95813526658cbc7072666), uint256(0x21a26a0c2dc55dedbb4b4828e44737f8ed612e68799982f240e11b034cdf6c90));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x084433ce1cb88e1d6e34956aed5e7b7e603b8922fc93c6971401561a4b4c2f06), uint256(0x1ef3eff6edbaea90224af07356ab7441277f4b1f5fe6028f20beaacb479fde9e));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x00f856cd984cee54d3f391ad9fb80d00f72a6f71be7d032445a65d679ee75ba9), uint256(0x0f850dc5ed00fac459bf955782d96418c9ee75c3c7c39a0ae994558cee8266c5));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1f73edea408440b64697f51828faffbb3999c947560a5e56cb1e3a0d0c107d06), uint256(0x111ddaa04b4a8ce728afc4abe1396a855841c6162679ff531fb72c83107788b0));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x1a5eeb07b8077ead2fb3416e9b0eba61847adc11fbc2920cb2c99e09c77b6ce7), uint256(0x20079dabd1ee09429f13d3123db26509d8eec9ea442ef72f8392ed30e08f8925));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x03913fabbdc5ccd0825212790ac5dc96a9baac34bcc06c2ad579ec2dfb40190b), uint256(0x2a1233ded7f5bfcfcfe2e80a9c88d76cb4d65e657449de3035f8e29d9c417230));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x0d8b2943613b51394ab48f5b005fcf5553f453bade7f8fbc8fd3512423ec1f72), uint256(0x0de32870cda941de3f6edf8f119e4163e7c31ef4e395ea60d864fe27ac573154));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x0f54f90f9665ef749d91304cd7e020ba9c81436a5e30e0b4b04905efaf1f0537), uint256(0x06b30f9362789b74c52bca766499e696d89410d615881c77516f3e554dc3d130));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x3031ef6dd91bbea90774f41f353be279740ddd6714510ede0849f0b46a5a054a), uint256(0x29a2d0e3e710a74f4d6814338c56f8faeea1fa15db64a40689ee50598b3fb54f));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x20e4734ad8f99aa9f57c2e4c842959f49e6d5f19dabcc84d1c9ebfc2837cbb40), uint256(0x2d76c32886188231ea4d8f427961dcf615303a09de20eec2b15057f1b4ca2e63));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x247fe964d4bbd547de3560da644a1b2a0b1e6e7fac6fd0aed79df74fe1547822), uint256(0x02b47344e4b1ef411d28bdefea9cd645d3482fd90ca01860f1b85735de99d461));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x252f817ec2089a6cf0500472f77f7aaa79c4dcaa8d4b099080260ac9857b5966), uint256(0x14132940ab77fc158b95b7b814db63ffe0e7c8157e72f603c85ec154ce0af46a));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x25d54398425796e3501cabc27dc5dc3983df3f4d6d1a3171f0a2495b31f465d9), uint256(0x13f6cba003e90377fd11a1cec49c4aedf2e72a3a32225076d2d4af2fed97fe82));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x03daaca86cf62a84a9e9f278805cb581d47d490ac02d2d4844682ac69ba3aa56), uint256(0x2b1d94d724f1a022a6bc382bd5c261962895cfbe6ab305865a5eeb3ff7e1a3d0));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x2ca8a44826d29adad76813b3894698a8d438cc41fb7af018cde88d647bf3a93b), uint256(0x150510b749bc6187f5cdf60fa9f6fb4116278606d1808b7191e09399915c4cb7));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x294487441318209d2b8715260f46ef75ffb874ebee0d162ce65632ec2958faf8), uint256(0x1c6aee2e1b124b12b4c28b25e80f33f9e0a46432d46feff7463cdfbf0336534d));
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
            Proof memory proof, uint[31] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](31);
        
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
