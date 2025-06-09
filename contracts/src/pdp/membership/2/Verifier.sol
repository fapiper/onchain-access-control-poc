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
        vk.alpha = Pairing.G1Point(uint256(0x04287ff8d489fe4b212f505af0593e498cda27df9098bfbae7f6b0ded9cedd4c), uint256(0x2278d09c03c7286b72a396a5c8ea202cdb3249c742d790f696bc8a8da625a100));
        vk.beta = Pairing.G2Point([uint256(0x0ed423a637d18b7fd07e0ccbc7f51ca709e478bca3b148cde5bc9285faba4845), uint256(0x0ef9a6451f4247b3b9da25a05564a04d8ad51ddccd5dc14366833c8fc42de2d2)], [uint256(0x0c7b0508feec3f35ddb5189049510b277d6cdc8c3161ad1faf44bb82fc6fd6dd), uint256(0x2fb7cb35891b062bf47ec36b3752aacb8e227e95452b3187317026fc57f64212)]);
        vk.gamma = Pairing.G2Point([uint256(0x1af1fb8f17739e55707ef144c32202bf9e7a99d3f2721f37040267c54a280ee5), uint256(0x117d0dba1555ec3e4db7dcd7b0abe721dd878bff10cf06e511cdeaa1ee21e796)], [uint256(0x2f4309b966f054e91741976d36c7fbb778b578f608dfec21b52bac58390e8f5c), uint256(0x05ea067b1defb168193101630bb730ac16717117e0dc33d6700c1b4ad1a678dd)]);
        vk.delta = Pairing.G2Point([uint256(0x03df0f9b93829082b067469916eb67c4641453e1cfda4c24be3174ba0f2d2313), uint256(0x0f8a2fefffb76842e8907bffb84c64b8e17b503243e27973805d0f8777869430)], [uint256(0x22a51728c9e804c08b4a85fa44c45fc2b4496198b5b65445d2ed46f63e1cbaa8), uint256(0x015843560dceac911e8994ef63923a1656bf2012b51f2d45bc14dd166fa460f2)]);
        vk.gamma_abc = new Pairing.G1Point[](119);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2b660d26301295f07ea0df13e30b6fd4641f16707a005fb15cead30be55bc0d0), uint256(0x0b82b8000401d8421c7927dfe0ef8e929d49cef4611b60d7ee110f488ba95e8f));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x245b02717ab19b33956900f45e1a70cbe852c550dca17e391b4f41da8bb4e3f4), uint256(0x0ca915a189b8b009b3969ef3eaf108d822d98831e05c4305e63a13e676c36add));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0f41a6d64f1d99b29610e8be8ec9a9d81615380ce2ad4809a36a2168c05c355b), uint256(0x02853e8cbff43dcdbce942b5bf165f46a36e009539422eb0781c7924f85f38db));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x129aebc886bac50a0ac0040d983746820e298eb64551edd69604a07b975554de), uint256(0x00346f3206b2874d410b188a42794a68319ee7afe687080a07ddb2ce3045a527));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2b41f91310388887ed5faf29f8d96e9f05edfebfaf9ac8858c3cf4597415392b), uint256(0x0e76876a69bc022f9a7a19b5710a06200e80b0f1feb403f2087a5b60e0a85a9b));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0e0d53f60d2a5875131342607fac86b3381c3d7cfdf38e583d2d21d0d7858d07), uint256(0x19375a916323d47c7a11ad799295fd92a6b6935ec5f6da5b6141e1bdc2f90c16));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x27895fdb3bbdf8eee0566b9e3fadfa97d4ec8887d41559d42479cbc3fb61f03d), uint256(0x126b98d627c8544f138435c45c588aa45aa3b750f4a717b43b9938d4e75febe6));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x26a078db7f5505569b565ed4b2bdc74b4012fe4207fba409601f1571dd114633), uint256(0x0cf60195ff98abbf9ea8ebd2582cb2585c3471b1eeb04daf370a045be495fd9b));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x252ebffbd021b7c97706f15e89df8231e64bc92152fc47e9bc3f93a3bd4f23b2), uint256(0x1871e723c314c543ed38bd2d5631134ee716e8b3c3998ce55a6722a8f7433ea3));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x00cf39684a81e2ded1c1ce03eec8b0ef9caa042a4043af2de3003918b1a38f85), uint256(0x0da721fa191830325a95259804f87e1390d40eb78a853e53e53b339fe5e0618d));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x241a3b27fe4edf6882989c9055e79e79eba21399d9825542c7bbaa7a5c880b9c), uint256(0x12b34e783c909ac9263a142c2f095a5252aca617ff953f16b7efc914926f61cb));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0157581841909e95146e71d82d370beaf95b99534207723527a1d0e41f9c86ec), uint256(0x2c725e2e997a49275a69671e29f6ae74367b85f4c35c815a3ae6efbf1546ea67));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x10cbdec519e6dc0dc5036993e6c0a9b5b7d1010c848c708216b1f146514c4c00), uint256(0x0884cd3f6a4fb84940c0dc7c088fe99c62e2f382157e9ceed6843db1a8a08ec4));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x10a3d484db5ad8a8ba70ada1e95441cd7a00c9176ae9fcc5b206343b0beea9de), uint256(0x05a32221ad2c97fda648f64a126346b8263290a6a71a1b2d45b95c908b750ae3));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2cf8459587055064d689d21056c5a5946287f12b065a237ad190e38f7240bdfa), uint256(0x1d2001a6d2bd32f863e0093b94d70694b59ffb7fd264586e8beab05dde889a55));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x027989d1280f7c297c8145bcbda4a52445261140d119836c923006ef901a0c5f), uint256(0x14938f94b098b09b7b493150fdb2a2b505e08b561b2418f532f5e74b691d7c6e));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x0f44c8dcfca81fbf5905b4b5ee22ac9f193f385089920f8984cfcd91db12e17f), uint256(0x0a51dd9aad583b2b3497e0153e8fe72b685be3b975d2f987ce7e4242f323e157));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x141c4d01fad2528566d4be727587a13a824b45e2c238622f28292aeccece4b3f), uint256(0x21928106ebe886d7f7a8421f119bf7a2d113dca04e01c94bd764c8cfa5b72328));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1c1a9623bafed4b8d99ec9e3acbcdab55a25d38a7d50fc99bab8c784e72a7de2), uint256(0x24ce89b5d5391777f803a11fadd6dd380a7ed589a32d9968c1c29addbfbafcc4));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x0dd90be45dd9382e8b8b2621d7e40744aee79debe1c84de2b880f92f96090464), uint256(0x05ba184a5aaed13b320e3a763eb4a52a4e09e34369519d8f7dc31b8d023a3ab2));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2b6c1b5f0465f9f0f87a540e654f0957220a1dec097854eaefc23407bf604ba7), uint256(0x1954f4ec8a57569bd37db9747a26d3b651072f443b0ff563cc41edbb236c21b3));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1d54b80a4cc11076d59df4aacd9a9b8732975e4054e2c6ca059f030a5227392f), uint256(0x0a416ad58591753dbf01ecb541df40528cf1966e5796d1efaa64648e1d44af43));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x077dd8b1ef576d642f86d028eaf90d7c4b03802fbeb789acaacfad4842149daf), uint256(0x1d6c3c98a2476071c1ed5f874a9afbf13b44dc47b8d946be86e0c557ad9102bc));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1cd922a4764f9df07248d9ee6df1a832330f6c60787da448541c4d6a95bbf055), uint256(0x0fa4df1e9aa3c6a98c4c620309593479088bfdd9d16f7ac41d1f06542ea116a1));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x0fe15b62319b4dd95b26a1632e51fb57a07abc7a1b087bbd59b2ab2372809384), uint256(0x2c5c3b1dbf61803df0be93502efc0bb3a08c1b9284f47ad336ba3d9dd20700a7));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x2c89f1e12399a88e885764fffb1a0425329a58cbd241b147a5621f5b35ec2689), uint256(0x0b67ca65a4e9d10c38ae7a9f0c88fc3853fd44437b424b88925122c638686eae));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x03d0ca77f2899153914fbb8b1674fd18db604b0e841026c1ec720e17b1a20880), uint256(0x067d20eee390dbfb6ed58523270e14a884f2918af39f7239e568e399f6bf00be));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x073278471d252793c19cd9e797dd86dac65c1d8543e780700b2992187960cf93), uint256(0x12ecc3c90e38b707c7639175feacb788b7081c5626558d0db2418a20409971f3));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x268d7ed1b407019b7e21bd8484ac28a26ef09724db726bd2d50de1ff43096ade), uint256(0x305499470a5cfc1eecfa206e4cf0d25fef3639d4d726c858954f23c6ce4da6b5));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x128412f45c3eae18bdc7f66e45f5dc44989a6c3e75aa0c3356c050b41b5347e1), uint256(0x0f509f206380134e649676e9e3855aecfef2ba1285a8c51f626b3211bf0dcdec));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x0193091c1368561093df7ac91681ffcc4af11f0d96abd97a1696ee6faf75455e), uint256(0x02e5064a74b04573124fbc05b731300bcb0f36a1648b1be3047960756c742a3f));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x156252c4370fed238313d027616c6b89d1cdcd6b6542d6f1857d3e420d0a0fe1), uint256(0x02e280f7d5f1c355496d1e17450c727c64c7bb3f5a16dffc02f0530383d552ae));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x281943ae6e46c4ecd0a074f0836d9ce7b11ef9f792890f7d1843805fb3404d1c), uint256(0x06fbaa055711c4075b92be912a9177babda6c5d30dbb9e2966af78d6b3db3566));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x01c41e57523033d02ce0482c1ccd8d5c1b903b4707c91c23aa73c3e242bf217e), uint256(0x05d673d6d3911273081421a220ceeba98a7871466c4e186262a3d08588fca7a4));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0791c5465875e184c6238788514faf4987f48ad61dc8f3f23bbf30347da4fcbd), uint256(0x1ae03fdeb05b3610be218a0732202561ba7b23f7ee202dbb61efb60aa84fe705));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x05c68608792af0b3286538b596b3ec14a28ace03cfa38e985580427400440be0), uint256(0x05e97776c6795a3f28d8cb49584e39876bb4538fc3377b2e559b18085cf780e0));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x2af69cb97d3a06fd9ec4d881d186a902c6dc6a1993f0258258c1411f027baaca), uint256(0x2b07e881c7ce4d7b411be3f457e6eda12a99164cb53357a1a844d1a74a90bd1f));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x0cdedba0af0f62d99df3eb26e27f9811aef01e1f2fc73298d65aa4e8f5373afe), uint256(0x2b270eea76dc00cd9e84b92361ee5df1f51f82c7c5cc4afdde74db9f45e50b88));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x09e025a7546e6c53e9d551216ca8840ec5ad0510b4c21e827533fc4a9d2b0462), uint256(0x1ab34ef1a5d11db1ae3280f75f02382d107e2b2097ad204e80fc12f46bcfdfdc));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x247aa848c99ae94225ec6f31447fa25ab48516998795e9d65690a45bd2859e04), uint256(0x012fd18b2b20a905271fc86a7332c35f01cadf0cc9e7e182d5b6edf13e3fbd51));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x18063b8440d6a41665b41ebdc2009020cd20f9e0d886ed2a672d480f5d58e4b0), uint256(0x113177b35df765a50818d7f82618c6b5fc63b38278b4fcd7b5b5f281d514f632));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x173f3c7ba35df58d7f1444afaa82524a31e84a7d8ed1f7a389fded4186db1400), uint256(0x03401fc30dd30e13f6b84a072fa0dfd29558ed294f769147a009fb5c1b811e15));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x122bda9ff80280b3ee389d032fe47ec228bfe41059503adbefe8fcf83c0c4f9e), uint256(0x0732c55a444575ab3186a26cd6062e0960fa199ba93b969fdcdc9ab32326537e));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x06cc1cd170e7d1bf833972c75c805c535b5ca9455ed01548a74d9c6cb3bb0a18), uint256(0x11997a5c4c7ab7197b8965ec93c1baa646b528a496987f940320e2cd3e786b5d));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x18f1993aeb30a2e8dc9a1f787acca66c3964c29fc1431dae77dbe5efcb470749), uint256(0x1da8d39baa578a5b335d45c7e4a6b2c804952154e1c156b7fd67c509f43fa10f));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x0721fa17b3b1caeee899618ffbb264ca0b5927b24b719a6fa36e9add17704c83), uint256(0x2b77e4b651d5ad9535387c1bc8e3005dd3eafd55d7afe8aa151bb21527595062));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x0bf620d767141dd2f054df809d315a13260faae7b90f795df807a40100f5e696), uint256(0x285644d687bcabe733887b2a1f0d782ad00e4717b904411f8c139a3f92fa2aa2));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x2d5016cac5ea837c30915f2e1c4cf9d96141345a0001cb6d3146063f455a8117), uint256(0x18553abced3299b0be5253e5f4ace22a0c45b53f50016f7c93249b5a7d38163c));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x1e6ea023d0cf2f30185d9d8ef8dd48901c9961e70b80144f7e3383b3ab040c48), uint256(0x2cc946479be0f2b762b59ee63edc7b41d728995020e7f0e1803dfa76fc4947f3));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x2d1991b50e551dab443dc92b3a947e7063534a0da430ab8c102c780e712c419d), uint256(0x2949cd6ac54fe9fe582e170d0cc258b2ced3628a98280ae497b4fd271c9d9b34));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x1267f626de52c73c9f657fad661613da227d9f93e39b784a0281bcf1ee89a68b), uint256(0x1c9914419d6e17acf552f3c74574803971977049ea9455a97c2f58b142499238));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x1921c6908b7633f3eef83bf83f03ef7bf0bcc39fe59e2aa5c390ad652ad7f6b2), uint256(0x00be654598f8654b42f90d2ad99c9e8b32ceb5550327c6354e4f1746eaab6f94));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x073ddf32869d1e7869d387e85e8611cf156f673ce8eae2bd7cf2fbdec870296c), uint256(0x165d8d7ddb26e3dc5f226efee41c2e2025e3a685d2e7fab8d77349a3b24495c9));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x1038d3e980648024a9960277a0757c38360acf4a7da30525a7194da7f19465e7), uint256(0x1b5d6900e1ae7216a8dffd50bbc8f4cb8f48a2ba786ebe37eb08202fc92eac8f));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x168d8d43c4d7a384b629141f9e0618b43e8d729daf12842653ef855eaa1b1d9c), uint256(0x0e5803c7509401c380a5538d511e8d2c3306aa500ecd271627de5bcb23d06536));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x2d0898279e35b381a48cab9efc6eeb97fdb50479523f009dc579e450cd2170d2), uint256(0x051b28388d2ee94f44878efc75f9ea2673132e0f0a44b6390580c75f80ede9b1));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x18c57108f069f4a8294ea7138cd129bf153c49a363804e3b6ecdf60319df1b27), uint256(0x249dfe53cab3bf9e2eefea4ef080b51203b6e0901237a7ca0e79c043a237ff5a));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x10306aee01a0cc7e7bef32f51b92e5b7d59f89eb3123e934d949261890de55ec), uint256(0x1df990dfe198fdc0bdc118a88e14f09bc97b8da80dd7f2d5491b0cfe5362933c));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x24c64492df8fcda3948ddffb826c1593e84c37d782864527498ab5cd19a797d6), uint256(0x29eec876d3c3f935e35eccef0e96eeb0a0c35765df531f4b8e0d08bad407ec3f));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x22937d71854015622fccb0a3585a3ab76d68626dc2f73a713ea8f8871cbea3d4), uint256(0x013e45e6f874a4e5724e45dc63d87f2f05c4ed4de7f4104e9f706b53d3c2f448));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x2d5a21458866ef9c211b95d4fa978d761f6211cb109089a88811dfbcfc2e9a76), uint256(0x1a71589022fcf7cdf7dee680d09539134a1f31c350725089441588124b9ca9cb));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x113c99757852707eaa3843eab361b195663305a662cb5f1b7d1edfda299ee411), uint256(0x25f7a3fb23b78086e421463fd50a669b7980dcbaac3fddef84101735a84b1088));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x2e48e51d94a56cdb8ed7070568149e4a3f45d70b2fc51e567d6274f8087018a2), uint256(0x2b90b5d0054ab8474fddb8f822383b0d6acff2f1579cd353cbf9bdf3ab2b478b));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x262c1a2566b972231ed3eb4d745e129bb1bd2aad961b7e84e84acc6c0464e0ff), uint256(0x11e334a0e969496b9e99abb0770f9f99376162d281329dc4f439616046659007));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x15c1774186151f18f5d2dd07139d80cabbb543e95b3bbe260cbe1cefaf8c490f), uint256(0x1823fd9ae4bb8c9cc8c1b0199bad4c93a95dbfe8c8be33303f0bc530ef54d796));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x229e83ef772782d54b704e810c2000fd8ba92701a07da347e6d7e73c593870a9), uint256(0x0676ac031c514d416b71812c999428c69de14ac961f2287e42768b9524a6cf38));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x070b81ddefd9725223b26052d6a55ae10dc03c5df719ffd69b21938cad79929c), uint256(0x20823806e716535d105bef912cf7ac586bbf07217f83b2ca6f46567a9c374ddb));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x21c13a6e291f45a8b09aa9d4080e30367bac423f7dee11cfc7bbbb991fff45dd), uint256(0x0fa1cd640781181add0ea77480993662bbd781602317ac0bd68d6b4543f5c419));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x244b771a6e900c12ecd3f84d0471295db0ac160ca25fc1844ad7bd555f1c0a34), uint256(0x04febf31596e4e18c7c13701d5ae2eecb2c6e56621231ce54a1fbf30f6b51ef9));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x1230a88339ee7b37e077d51f817af4ed44ba0c1dca33f6cb7f0ddeda2556b2d0), uint256(0x257b7e2dfe536fb017f59b6834ffaf738e7dab1e41f8277983933fafa520a9c0));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x2fbcd7adaae566fbccacc3f10cd7e81c3198e063b1b8bb9e2e057bb5de82200b), uint256(0x221d961246499a8acc974c8fd00a2474e60f36d50b775433a27889beaa979eab));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x1797eef4257c05dedac8de96b0f4a962dad4b43dd447757d826abd07c0f826f7), uint256(0x2fb171dae3d47f760bd1e08c95fea24fdb3b65df0c92785c451c08fa7fce895e));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x0973c9f85f32f016f85c46a80c8d3d3e1ce144290d426d493c48ce6761b94997), uint256(0x1511a15720759e1d9f5af1dd3764fd558a1feae4fb996401fac40c65b76221f8));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x2c2dbd746f77b829ca463f928ffc349cb3f7cbc8fe1d78a6ad25cadec684f659), uint256(0x1d153106c3f8fe997da6ec155a928ff9e6cfa89f6f4bcddb027df9c9e82d8c3c));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x057161ebc5a215badf5275c0afedad9d7bccc2db5410ad0ea5a564efb7871076), uint256(0x2c9cbbca99814666a208352ff2a147d6a6d2348e7cb9a09789b0079d2c1d08f6));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x2d5078804954944ee0cbc7d9968af4e04847537f03f68e51a87b4082b0f534ba), uint256(0x100b2c2048236ec097218bc4836a7aa4f0d496d15f28154257af99d5e916fd17));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x002596f62c5bef7e0c21a07f70f7544bb4e09bb59c7bbbdeb7a28e9e0ba64947), uint256(0x0248210ab1838f8921085afe02adc7a0cae2c89619acb9211d12733409b42cde));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x1d8e60c6137cfd86fbc878ec11ca18d31d1858dad10cc1981325f96e74adc0b9), uint256(0x0365544533ceed244b175ab006ac715642b391c56f017806467b8a584e577b14));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x2f587c8bc40a69e8d903c56f391afc2cbe74f5f4b6f143ed8e95d62bfd8853a3), uint256(0x2c9a306788f5991a087f1cf024bb19d0472ee064a78a31f84741c50bb13c63dd));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x17057120b51da394bf6c9e4296e992a89c36dfdcb4816502bda7ca0fd3455580), uint256(0x0962ef05434c8a1a700557b9a9aafe271f8acd5237d8e2fe83d692a59f7e60c1));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x06fca2f22484f95aeb649c3d462e2dc8608a7633baaffe08d8c3f9bb6f6c8e33), uint256(0x0c6d3c86975671f65df7badecffddb7e16976f3ebcd42b4f5aaf45047b75c3b7));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x2544d14e78d4f11f22d9af50a911b2511b18a27bb41bb288c9466b3f8bcaf420), uint256(0x0ae26c394b94a7e0b9350b954a573743483251e0811afacb6062c02873ef5a21));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x003d859c2cdfac2c27734fe5c3f22d2ddda84a322a778fe10b1906097e7a91c4), uint256(0x19496d4e1cdf19ec996ab94d7318c2026b3eb7c91b26b9a05d2beeb265345201));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x215e51c32e6c698915bdee07d0edfc78c0a70a146bd93ca841078354fc68f225), uint256(0x07e1f2c9ef06628141ef34f37e317685e24fa2c7a8394d1cbe4eead270deb593));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x03d598649b58a89c3d06eab02649eb651e6727f8e55da2778ea341f5582e3ee1), uint256(0x0bd67792d08bfef78dce00a08ece2ee120883d5db8bf259c636023c7c453fd15));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x304f13bb8261dfa0d2f5f6fb9cf0381575610ed379eadbb2a904ccca29bc2ae6), uint256(0x28b10b00b30137b7af7de24151cd672054113dc695edb63b06100d6f043204af));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x22befc523dc54575cd5060c8f583a5eb34fbd7737f64fa4159d8ea6a3dc8d508), uint256(0x0da2dc3e82dc8669168482d2dd40f8de97f28c19ae90f10404b13c70b456c8f7));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x19b2b4e76069ef7a188505815008b57b12205407b71868858191aa30064cf843), uint256(0x086cea62f85be23381968782aaf09ddb631fbb93bf4434e57832dbcfb41f4379));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x19c878725099edf55ddae39390aa4a91148a78fd11e62792559fe9ccc877a8ee), uint256(0x03735e9b99059b331d65fca9378eb3dfffac2b630047ca285eaeaebce6f3ac6e));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x2c2162b20aa3fec78c125e13d25563e912eca535d8ca7f369abba491e7cda1a3), uint256(0x2e48cf434f6674cdc12ce4f8253e070f88f83c8bf8a8ec71feac487028bd5bd1));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x2d7293adfb3f37a46e0c5f9482cd06ab3a63e8d180e706035d8d7a9f1ef3c699), uint256(0x00a8ed5160c51fb2bf35cb89ded2ac34659dc1fe8d6e1421cc82f11f020529c1));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x1df9034fdfc7e5252defd0f2a591420fd87c5e45c5da6aec94d394a90b292f83), uint256(0x138ffe7cd8c5b3991159320b95ca0e4f70724bb75057f3899a0c1dd1da3698d5));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x041fefc84973f4f1823d6248bcbcfb1eccf9e6f1d4e7b67765da7d665161eb45), uint256(0x27b3e172f8572a04d8e08b4c161b5f44262e4ed2b12256ebfffc9f709f2aa66f));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x2c9e202ebb614d48cde0886091e3facfa6223b5dbc7fda021726f4bd79c5fbc5), uint256(0x2ead50db00ae12e12d9f47d736d37dadfadbed9b2081f4d4605ca7bf0c96cf53));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x266fc2c046304878bc36cf775ad806f7228f8ad8c6900fb5d051934b0673ed03), uint256(0x207ef29d522281e3ec8b85493de1864c3b4e7edb2eac48b33b042db99c9a61fa));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x15ccdeb3421c105b7f9bfb038703a1468634f94ebd01b5c02fb593ebe2698e04), uint256(0x2f5838bc905285d8a31e1b9174a299a9b41f9c4b4de7b59977db76e8ebaddbc4));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x1a10f65adf533045c5ff32ca8b3f8439d91a9fbcfb040186bcbcfdbffa054a01), uint256(0x21f1ddf2945d729e06dbf9e9874bb140a7c0c1feada541d308722eceebee9908));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x18b6f451daf898be9ec2b63bf4a46484b5f9433f7f8c23abd525a1f8f1bb54d0), uint256(0x0897c2021eb42b2738fe8c7792d2c4d12219be5cb5c4692b98f6790ad2d0071b));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x1bd0adefac598acb94effd336003c1421403a80fe4014057c045f30a7f67b690), uint256(0x1411de0f99715d025e5752848a2ac49217a38ad5fff3b0e96d7d37634e927124));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x0b2aa5fa5f9ce4882e3a5803f106b7e23b5f4e14f98bf69e8beec8ebe3858dd6), uint256(0x00434fe7c224dec3533d343266c1cac95b4e91c3bcf9bfb0b4e69da097360bf6));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x1c56c84ca7ed4af2dfdd7c928ac56e81497d851ba58e87421fa39fab5ffd5a3d), uint256(0x083fa6a2786bb345d1298632837803ca3b7478a547ead4696e3ca8ce381524ba));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x203f2a5d2323e6d0e3df41f33e9bc36e8dc76e029dad8f2fe9ae014a358fac65), uint256(0x2aee1caf890c7d43dbcc5166f2f928c48c702a4b2bde7069940fdc19dae2b24a));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x2a601e2815bdf419cf8057ca1d05fca2174039d3f38d1d18a4189f87c2625b51), uint256(0x04a04b834fd6395eb82c57e8a087eee4a941623e9e1bf7f05d580b494a4cafe4));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x073618f60e1ef0b60085beee60b122b9ccd2bafc7730284a0c4ab4f3e66c1e6f), uint256(0x051a4a238bec431cd8d6cb614e57fed7b2089881810fd4b5478cc8c57514b1b1));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x093ef8f6322925ddf73c796d11ddac869abef4e5ce60ba65b4b10c2c9ae70f31), uint256(0x1136f71400f0d1e371767c6a65a58afbc4b948eacbdfc917e9145b10d2acc3cd));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x0724922319c3d7d1ef407d0035a7610a5503c69ef2d24c5fff406c3f30a10f55), uint256(0x1ee313424fa6e68153c34d9b6032170f2b0024c3c82f471e9bfc5dde20bd75da));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x2f43cd179a23c8c0113cb6e6f758e10f1555d330dc124c29f5fedbfcd4a3d036), uint256(0x03aae3446185bac3492b44cf8ab9540d27813155ff9ee9a8fdcd77f597bcaff7));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x149576e8dde6ebbe56e144cdd11ba3d6a04c75e6ca870a32b1c472eb13798d97), uint256(0x0020e419d91693d9f53fa77f4597c09bd7e7eeea75b748acad4482a7ca39205c));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x17a0476be4f12b862fbd54166d996398fc636dccc73b29b5efc97b4ddb57c22f), uint256(0x18ea5f975f57573639dbfa8399c255fc2c13929fb68662c068050777c998b402));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x120c95c238db3e3998a7764843028738d4f953f683e0d67c0d5c0aa84ba67c08), uint256(0x1c48c1d95a948102420722dfd7237dc4e1a8a3d5b1cbed3dd9d8e3e3332c37ce));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x264fbf480e57865129006c3222251e9bfd0bf251cde3709542ee6eceacb04b5a), uint256(0x027b5e0744010a5d398babd408d2ed262cac5fc0505361c5bba251198e593d9e));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x209f01837349f09542946758859fc6958b14f78489d6ae6a2d2ef1e379d1aa55), uint256(0x06acc571ce68dafcaae80bf53fcdcf70a8fdab1510d0dee06ed58217560332ce));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x10aa38b12b3bcad6600a55ab4ed84a265423e2f8b0cd67439be57c1e7cc13f88), uint256(0x2e3abae03984eb5c4e873391ae98d839a3a4e59cc709d60b5f01609ff5d89e61));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x245641e246508cf9db31c9c890ee1295d1fdfd35b987be266f968bc6b6139dc2), uint256(0x28e736727fd2100d6ecb2a8fdb69114e70c3040e3427b5318fc1e1fc9febcaec));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x0719520ae795511f37093f1e72c7b5f096969d6b365fe0f5d613aff932837c5a), uint256(0x2d9eb67077535b22daa080cb0f5f9d4189da681866d17e6b2a69df9212f711a4));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x214efb1e4d787fa89065bc0df70842916cb63213ca190b0fccf07b7b9fdeb6b2), uint256(0x299b14988cfab07c1e5901706da8b38e1e6c4911b4d2ae22e8e80034dd065159));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x1ffb7d20b5e833e11c50d3daf4ada400e59161236f7e47437d43236f259e652e), uint256(0x0ef439061df07902ddc1239659647f75c580af59af25972702255d4771ea5040));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x0e0bef4a26fa67a97a1aab1580cb7ce600e241b70ab5ee77abe350b4950339bc), uint256(0x22dcddfdadde3b5a57eda45668f907d7c45f4bc377a1123b55fa350c50456ae8));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x19d034ec61506e2107652db9df3ef28440348b7b10e7f32772519202d499e23d), uint256(0x2fbebb3f4d3860c23a0ff1774fe419a5c3124d8e2828ccc776e03998ae95f0b0));
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
            Proof memory proof, uint[118] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](118);
        
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
