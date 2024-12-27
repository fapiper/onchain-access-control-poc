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
        vk.alpha = Pairing.G1Point(uint256(0x2e9d6775acec131ee26a57443bdfeebcf079cf7f61c7d2608fb474ac2fa02891), uint256(0x0e9009f5ec6e2ccee76b8ffd2285488c93afd3fb0e62f063fcfdbf66c9b3213a));
        vk.beta = Pairing.G2Point([uint256(0x2e608985b6345d4ea6bdfa5720592ae81fbabe5170c8a0fa179d0e523a1a58a1), uint256(0x039b735e61ed599446997daecea8eb3e5039b4d4163104704e32ebf1a2ebe02b)], [uint256(0x259ac4deff61d1483836ea12f926e600d28e07c8dca94e76cf86d033b0895c9d), uint256(0x2b6822026ebd45d3a5a7dd4a22e98c6f3f4a6dbfc38c40f11fcaa4384990a99d)]);
        vk.gamma = Pairing.G2Point([uint256(0x0a80fd490ac4cb189da17cb0aa14c351f688d95b29d4206763f6f8f4db37b84a), uint256(0x023817ec6fb2f594fb6319954fd959818cfed10c11395ee8c6adbc3a88e8daf8)], [uint256(0x16a7f17b8c55f8cd73e43bd29ad229a457df52e95fe649145d4ea9346def82cc), uint256(0x2310d05292943fac37c64f41dd9d4a2603afca9cd88f0b12c84196da5af14fe8)]);
        vk.delta = Pairing.G2Point([uint256(0x2c7c62f6910524837fefb9438fe6d76f3a88d6b51093be85d6d571d1a4a8cd38), uint256(0x0acb5f239b27af4a51b3be4bd164284d57f1174be261f520d2f9dd0b34936bf1)], [uint256(0x2ab71ced60b4ba53dcdfad679a99368e5d3586362a7d74b63674a18bcab72683), uint256(0x00bde5c7afc24316e524758773ebb0ebd764bb7c884e00ebbfddf05ae2f09edf)]);
        vk.gamma_abc = new Pairing.G1Point[](80);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2c9ccf3dc47edda63b68c04e159034cc2925ccebe1b99f92a2fcf18bd0bfed6a), uint256(0x110956c46f2a3830fc73d04e3e629b358d4de34b64e4675e83e35b3bc2da6531));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x03ee4d437ea419a9bc5efb83f30f40bd134a955f6172dd61ecf6b279ed038fc5), uint256(0x2238b0c22b82d60d8f68174238ceab02065cfa49658e868ea7beb0d65173533a));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x26848ed87d4cde3a993ecbdb4de2cfe9c4b54e492c1ba92a499277cc6f0de37a), uint256(0x25696cf1ff527abacfc4b141c773e79da6ac8242940b0fc4196752e654d4955c));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0648260e9db2037a69edc50c443e189637aee85d56f50a8f6ce12878f612e145), uint256(0x0d5954353299212780392bf9bde0a2826ca833029f8f2f6111a5345b092d2c0b));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x14d591a1b824a58f79fac91fc08cf77473ebac8b0d0aa18148253d2694306204), uint256(0x22c51127fd8e5a5be4ca43784e8ed698ba7a785fec1ae83dcb00515487f8bd9f));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1dd7fbb9175114422eff236fc6ebdf780c9464b37be197d7c0eba108c6fec767), uint256(0x22c5aaa90df39b2f78164232c5037807d0f8da7fe4835e225c264a3d417e9f1b));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0bf13bb80ed8c5f3413f10a1f27e43b4388eb1bf849575e8cb20a7fbb115a6da), uint256(0x305918207c8a7e1b646a2b1a439e1070dcec87f9efa71c5f6a423abfd39f539a));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2c8ee2bc04ede7fb7739be3c3ef71bd11acdbfca0013f9f54d7e3b673febc8fb), uint256(0x1610cddddc0cd75588b5bbdce9f15f825bde5dcb3c76dd5a0e70729b68ba1a91));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1a4ef5c62dc16cd7a1e6f2c38ae63bf151a4e5fc0e934b26c239aba619b85a54), uint256(0x0de6b35b2dbd20e1504e2a7aacbbace5dfaacd94c020bdb4d85aac63d7b8a4cd));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x20367595fe02b84b25679e242e1f03d61543d4be4767d8e75e07c71232235257), uint256(0x1899c9475b6537bf5ec2bd54435d7487b92d2c3fee6bfbecb95c649d15d04801));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x245b725ee827fb5532aac12e69be346c89d149ee4e91b10676a18ba65a9ba5d8), uint256(0x10b371711f308273851395d5a5c4518af5e43750f6192baacd3d68400f227d30));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0be51cd61bb4f5dee62d64663039e4fc329aa64f21534ac50995e31bc08c324a), uint256(0x2f1371b84d31e1079d06739c57c611bf5d27f2b8303e76f619851e27a7c94707));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x16de0473c64b9e648d666ced12d8f048dcc598ca59d2411334859ae49abf3bc7), uint256(0x27f1d66aac11171880634b75f43f9b1ae71d67747a842b2f9535741e9449ac53));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0c3a804d08ee4017a275b054ed281bcec9ac1b22d3ea33d5e7127d43b13d6f36), uint256(0x10fba29565e167f7bea9b20aead833e453b0954ed277ac155b851fc10de265a1));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2bf7345dad6bc216f6aee52095613dc05c1b8c194702f025b8771ece7d50b6c2), uint256(0x26877b041774e05e330df4f2eeaa41407440194e89fa043aef033e2f1f091e7a));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1bebfdeb2a689f744432cbfa4ca2cf8d66bd389b13ff7434bfb12f928fcf0184), uint256(0x01a1934e2f57c9727c911c5db8c79b43db75c6cf76dd8a92be38640446cf9a40));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x01c5bd2cba8e17bd8403d2513371e71f73b98e408061e6aa28eeecdcd581708c), uint256(0x07fc79526357980ab8065185a1061665c89d9e2f6e08efdc1ca673445c5a2bbd));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1488dc3b66803f0c714de76781488764079ca2da519558029f12fbc50f9fa4a0), uint256(0x03a16f4409ac5a20fbb5c90c2de2bcb443b103c367d343c77077acf1bddef41d));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x12db1e17d70a87ed231db754a66c526d097b7a00a7d97a1bf58d287ee96100c6), uint256(0x0ea32d034bd8f286c45f115d9ce086649a6a4b8e5b45325472f27b02dd71d329));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x13bfbdcebe12a9bb884d9ab742fc33da5bc0c794c25bade2a97daa08abcf3e62), uint256(0x0372aa85b90557938c55f2e36b641156ce0bd88115ec06b2ff5bb7c447578267));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x1c534c3436432bc2a3878eaeacdd3f4ec79b703b7df66ed7a0d5453c906951d0), uint256(0x006b9c3cbb55c6abaa1f12b8c707f4cf345e580c8347b4ccd87d0e580a6b064e));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x09ca1c652e4e6dde833b795874d46c9910a8a7886255573d49f0d971c7d3ff01), uint256(0x205c1948f75a7bcfc90465c9d44ee63ce5e5be51b296d68d4b0b157ba196d91a));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2d0ad03021b68bcc995eef740614a22cf96d4f60bcb0a1e42c5ba1b877befcc8), uint256(0x0b3a727145f0bceae07a150a64c7d4972a97034efd56f830dd664ec368417609));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x24663980d7170624a51920e8e1ab711c571391ffb8e2146bfeafb27436076136), uint256(0x0ee74e4255de3abe71e5ddd052599bee9d2277e5db0affd249d3b6ba74db887d));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x299ecd9d95009d4d24cca935ef6662365d2cb253df7d9b993374c286a279ea03), uint256(0x268679a082cdb2ab7b655a23dbea0a802ca341360152c89527ec83053443a057));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x143376e4b1c1e1e143cd99c24171ad1948b99624f144e90edb0a30fa6fd193e5), uint256(0x0fa52896e08853a2091a498f4f456b26dbddfda6e4ca2f321f044c5cca416448));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x154cca408766830c9816e53a7a7b9cb008f28ad8aba1a5d4d36d5493f34dbedd), uint256(0x28caa484ba3f8233225df9d4cd415812882ba2018ce632cfc2fe748adcee7a3a));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x1cfdcae44732515ba2217b838d24ead8a2194101612fe16ed82291ae05766f4c), uint256(0x2255cc246b63cca4414eb55bb132e9b9bb3974594df5ae5583c507c1f6d751e2));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x0820ff283e526371bbdfeb516d7b1789e23d133a3bfe80316f478e026d18f855), uint256(0x18f7517c444d28e87bde22cf6136b3e09e39f58e6c9239b71bbd08b92b6462ad));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x11413f5a6775e54edfcc47e83775b405bad7b8a4f8a8ef3e761f8fdaf7fa03d3), uint256(0x15d7627737839a27f03114a79f955afc2faf943f8a07154babf6714cdf751c76));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x14ecf0717c5c8647ed0726071da8df987bbb3ff3622829eed636dd8ec9c7c746), uint256(0x2bfa277541ffe923c8cf0609b7edb836651105889526d115d3e43c39760a9214));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x06989ac3805bc36014182c0ef6c1e495ccf5371f1d920d3af2b58ca41051ad33), uint256(0x10c4fe760c15bf385f319a93a573524effe028fa7c355139ed935fc5805ef21f));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x2314207cdfb4f07f7270d1afa4c9280f2d9516d4774345af26f337fee47a3613), uint256(0x039e142625ed6181876678dbde31d9728a395b9bbe20f039c597bd00e84ee1e9));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x1a391c224b8303ff0d76ffd25c15eaca74d7e8d5f92bd6e088595a10470bc60f), uint256(0x18ef36232659b712c01bacb2de8cda3091abbbd73e720dff98ad9cd87ca78b2d));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x03aee72687a0ed9c304b345d42611b233cbce4c774407b4674601254eb3dc6c8), uint256(0x1af2d50fdc1ee56fefe4678f82732d2b68e29d92410db98862f52b3ea6e30e19));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x2b48021c62825177b7900bb9591a2d78d7561ebde717d89ea85258bade5fa4b4), uint256(0x190243ebf9671a592217258b338877c8f6fa1508582aaf4812c85f9e508aec2f));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x28696ca8ad41dd9469fb1ba57e4c396c21b186e43c3dfb40a5e56487761442ff), uint256(0x0fbc304c1fa64bf945224978ec643aca3c31cebf9a4a3a270bcd923090e2a22e));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x1db7aae459445ba7b1279e6af5e91c1fe8b4f54ebc71e67d4941aa589cdcc617), uint256(0x1f6b0dca495ae623cade8cdc414da9ee859875aba70fb9502d4bbdb57de63eba));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x22f4619452b26b4d8d7c43ab71fd84d72a2810e8403e1a516a5382cef3c58006), uint256(0x236b8f624e944eb3fc62d67272296bbf26b6167afd9538582ac296aebe1a1493));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x081ed657979e62f5420c85c92e6740632abf093300ae3816dde7c3e4352b3703), uint256(0x1f502332032103f4fc053106cd8ee11e9321eb114ab5a2b1e405b1589d32ff6f));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x1ce5a98019c3f9ab75630b76dffd946163ada387080b6c8d2351ba5c409ab2ca), uint256(0x25330fa432e9f9716e4d13f9fd91cbb568908a9973899d918330292d62e26116));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x0e8ad2e9f63a6bea0b638a9c0ca2a20d9c0307a8deb2881eb65614e0c819a8cc), uint256(0x05fce9ad1f2b42df13419650cbc80d0d56c12025296570bf5aa40b5d5308cdbb));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x1f40120d75fd546c9e5a929dd0be054a8c6c9fcd2e3bafe4691f80a90621cb8d), uint256(0x1622ac6ca3302f818682faa4eb95ab722243a84e32422846317a048d536f1897));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x2b52b04ee35bb5e712ef3b72fe5d21334d1a44444cd194092b3b423e357f7f18), uint256(0x0be5059e3a58fbabb6fe396207c0e51b2d6ca1fa7e12c340742744004d84c950));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x2605eb4a75289cfe9cc8954029dc80bc44f90547818d0494cfcf08ee2696f855), uint256(0x1184aad25c5f49fac53df56ce9f12afb8b41e9903a2e9cd209711fa6a6579172));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x03d9d514d9ec5c7c49dbf607d3f2d3102eb872180f7736b9f0b635f887b81f0a), uint256(0x0b28f179ce2090870e7e7b7c4b06b7cfaf4db7260396534d8cb6c724e9ed31b5));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x1fbd459934e3c6f7a7523e389972fc41cbd377b9ce8fcc2c66f4d193e118eaa5), uint256(0x092e3457a4da056a5dd546955dca0044bc3bd9caeb6eb9e2fddd0248eae98d61));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x0510c3e3b1735698717879885cf4d4383a524eb6a6b551b9fd07c1be95bf894a), uint256(0x2ed5959fd342107c3001298bcb810548faf23ae446ae7a60e8b2f67291d8264f));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x245088576457343aab56d8a4d26beafd3709be24c6fdfe319a67419c9cc71440), uint256(0x1660e490ba247c1def430b7b94fe361d4e75389924c22cfef63527484a6e0074));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x0f69024be595530f0e3c433b371650723215a2bf7df17057ea960c00dee587ee), uint256(0x004780d5e6a33853457f34ecc16a5a718a2c1acac7a0d70277baad6d1010db12));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x2c52285ea4b962fd37197726f38dcdcbd065a9c44b0124c52281e3e07231626c), uint256(0x109f109c4735fce3f0966d22edf764c800ae7043c456dd94f95b0c74faea7a0d));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x08c99fe55234de88c2abdfb88a545e183f155f3e6d7816188a1f83e78fb4a1af), uint256(0x174c43f15e1a0206a50789b8651279dc7f9441fc7c611ceca44cf8ca57c4b875));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x2f35749c5041ec9cbd3ff082f90641903f906c0a9bd860d93a08b3a5c40af0de), uint256(0x0d4fb45f1fbb7a93cdec57309e54137fc7d8e765d1fbbf5869ab68e0406833b5));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x1a35b83b3e5b20b083ec56f53a5999f80b0e600ff12ce5a1921b6c5a4f4fc778), uint256(0x0a59a2ecb4c8b79c34ee4a8d036efc87c41987b8cf63f6ef3f48a23562622278));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x2488dd9bc502527e764e005d708c84560af6175a1a61e65ee0f9562332bbcb7c), uint256(0x1fb166249f3c7204158e8ce05e17e23d12c9a98fbcaae19575a535bcc1ce21d5));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x1c9a9a0f3af0b8c75011c4228db92e262c7776e8c85945b259bdd5a9b994d8cd), uint256(0x270585310a5ad4ce61343a8b9b188e142be93f20225db2ecdd8a073126b6c2ab));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x2eb98a206ef59933a73c73986bf7534c881a93332d1ccf46901492178946ea17), uint256(0x277c3a3cbedf25b183f7d597481944b306f09c550502466c9c97ee94bf5d1a58));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x0496d45c7c2bfddd6078756eed204df21c7798e3b380bf6ee5e8c7370e84bb0f), uint256(0x14de6bd50ff95ec0dc2401e164b9aa9dcf64818230b3c81958ef1f2be187caa4));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x1c388abb8f9d367093407fad39edd79941c5ffee6d097607650ddf84e6c94310), uint256(0x0aacfb565e632e0f120b79528d0dfefd2bfdd97dcf5938aed2da6acad2b04c76));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x0dd23a9f9ba65c503ca83039cde20b36bdb515eb7a46460bbb8e0978f7d50b28), uint256(0x101155fc64fd75745253902140894413d5bda92aa73776c454217f50ab82a9cd));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x206bd258cd9d96633a9224962d71b4e0a7e57ae0f333cc616cefde91fe0708d8), uint256(0x1d95a2ddfe5f67cf1280f51d86701c9d1a380cf3ba8bd3d8e11d84dc4b619e58));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x2a28f39b1e651ecea95beb05ebf49fa44e742c8b2e85ff98fb272f47cbf8b4ba), uint256(0x137a02afbb03b282bcd53363652c25094de0f5333395df6eb2c28d1c7e789fc2));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x14283c937e162088d080e113063edf043af331886f80f65ad2de7eb960382125), uint256(0x04e415b2608640c5d8fbd9c2b7302d1800bf91fb04edb50a601c9fbba70e703a));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x2036b6c68f410044e8919eb2912c80a9833ece6efc3fc548036029314357e1ea), uint256(0x14b36436d8d5ac3b52e664e237730b5e3a42b7ebec10b7d13ee182edb04887c3));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x11999f1dd1e97e2661dc0d925384fde1072b3da7d0aefe2b16ff3700ab7931f4), uint256(0x06cff826ae794a3d7921f04e18603ccfbcd8518ca6764f644c41045b10ade426));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x05faf26ab437163c1e5a2b1c9334f7462c5a8e8897e0bcae01ac3ea522df1401), uint256(0x1e34d2c58cf6c73ddef7d0edd21b836681c9705b9001e4249a0fd6be3fadbd7d));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x01f3889c5c827256c1c5e8e73b7a66de9065b81709436792f980af89b57cad44), uint256(0x1c9f8d7981087573795601d4825c1284d18269c6a27d9e8a8a980a666e391802));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x167e2b28144f97478207db170f5aa1044a5e72ff59011540983337ffca8e2bf4), uint256(0x0a64fb6f1f31d78aff5ed7d8a43cc9b3a147b53e149c876c30ea5512d64969ef));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x1da1bb6f3827b5309dd7d91b7fb2d03f5c29260ffc3052553f38991963fef806), uint256(0x094675833a7abc55fb5f1eed3e4c91721174ebf69ea4f0d890ae1ab99b94b614));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x2c5d30754c292f7a1a6229fa38117d946c1af794f976a444b84360454147d7d9), uint256(0x0054091379f01bdd87ef6bb098fa23063c1b9fda0ec619c6adb8ee49c5900cd9));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x2b6f9cc8b7239d53f7e8101148cedc993a0dfefec5e496900b95b7fda9b9f41d), uint256(0x0e2dde35eb9e605e79f7a3139dffcd6b0ac7a3c79f90fa62bbd419924cea5770));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x1544cedd9b3da618abebd66e9ef82afe2536e72ee064354f7f073a883fe68ad6), uint256(0x1ab67c4260a8a595a5ec047c7a47106f5ce7b72e249f1166260cb85d1061c405));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x166017ce009b67ce9571f22eb442949e31cda3cdddcd0a27f33647771cb602bf), uint256(0x075250977463c40ec5b19413aaefd2d5b184794bc8ac21c57564e64ff4ceacaa));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x27f8d23d0dbf7259a7a19300ae35669d0ba2cd8f4a92e8860a03ce3ad86069ba), uint256(0x0d08a96a83ed9b639a75731cbbe8191e2d8993b3268679067600839b3e87065b));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x221a06b40dcffca3630437346f2091bebd86f3b136d016d452b1c57a08bc4c6c), uint256(0x0474bca3f99d9e63ce4cc0f1c1f6decc5ef7709b7661bfafd7ac2430cc8b0c21));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x2ad4f405eb6161e83cd736535940faaece271624ed15de21f104097be84d13c3), uint256(0x0259dea85de7517e9ba62b71ff7344c1d641493fcaf80ed3c5e6f12f382ba947));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x16a9bee8ad42c7dbbc71aec1ccedd9c3cb3fb66edf4397a93264bf916c8764b1), uint256(0x0664219792f4196fa26565f6661086784866a8df52a960ef4b8b50a940f6b3eb));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x15d28a65f593f6aa24af91c841add90e3a7b1f554d9247839c4ad1c38ee96d41), uint256(0x0893f9183d3309f7b3a3473e3a781b7a3e3696920a80c19a58f7af87b6571473));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x2a3b214511fc7b67d91e612d4610ab3e62332efa1975cbdb082bc871790a2366), uint256(0x265d2a0255dfd4d24c6961da54d1b6680458ea55c3979443db835a1982fe5ccb));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x18a4c3886449577ffc5793f569672a63e302a3a1b25ab5e20d5fbed2a51c8a02), uint256(0x2165c987fdc52af3d6be5209fbf07c1e913e190b8af44683660c5b9ffbf59baf));
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
            Proof memory proof, uint[79] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](79);
        
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
