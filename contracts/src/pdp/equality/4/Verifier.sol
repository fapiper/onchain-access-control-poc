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
        vk.alpha = Pairing.G1Point(uint256(0x23676074d582c1c25d9ad0c5633a2453f6bf1610b406d07e2af246475b3f83cc), uint256(0x08ad8228e8b23d4439e94f5fff5140fac37b0ec88a86273747570f3ff56caa83));
        vk.beta = Pairing.G2Point([uint256(0x10341e7d30ca390dd1ae2d4bf19ebf287a50e28cdea6a0368a49e809cf5c8930), uint256(0x2354d7b74872fd954c01dc3e77c875491b42a05805cdd9257efea3374bf92cfd)], [uint256(0x0e44d0ddd1df0dd7988702f8725eb3c5f1c59c6a4f935d1e18a47dd5a7c6c695), uint256(0x26b9a32c7a13110a232c72dc8c96e7343b56c17b2102e3f88088fd6016af4c73)]);
        vk.gamma = Pairing.G2Point([uint256(0x2c165bd03772ebf1fb402c493863f8611092afd95d8db45ce116dc40e81cd06b), uint256(0x2dc60f54f658a374c64446bb576e19792ca6f80b9bfa54c11bc221abb55f9602)], [uint256(0x1d5674847623db03ef02af3b7533e0355bc447d42ec3229ddf04680d3124da77), uint256(0x2b8858e9a3ce859c76cf0c7f07a50ad984543894f179a235264d3ad56305cca8)]);
        vk.delta = Pairing.G2Point([uint256(0x22466686be3baa62582a594b1fe01d1b70135caab30a62f04c3df51f5f0392ce), uint256(0x0976bbdc512d4dfd4c3529beda8482c9a7c2758c1eda6f0d8f9ffa8b5dccaf36)], [uint256(0x07aed4b1e987946dc8331a05565c631059c759c217ac283ca8f27ce5b5a3cbe2), uint256(0x20b77e5714532b748e9fb515f1959f1d3d8be3762eeb26dc506e0e4579c5088e)]);
        vk.gamma_abc = new Pairing.G1Point[](81);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0b20bf0252ca524c5921d3886bba6734a5c3c4ad5cdb5e4d88f74d705cb6bc3f), uint256(0x2b9012abd35d88da2ca398e259ab9edc3ed2ce451b8f347b59d9fff3a3285130));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0a06baa6d390a79b77d8a83bcfbda83464e60edb4cc4f090d925f6b92ebd6ee2), uint256(0x1456bab78017c9e07cf36b688ed40444559bc43369dc155c9fd9c8276a7daceb));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x267de84131aed7698c2ed2e3996292fa7269d2bc44890bef38f2f4c6a67d02ab), uint256(0x2d7b5dae6b142dac7a936d106b9ece9c5d065f1918104667d8813b5d2cf55c88));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x25bde4a5667d978629e3093ce7b9a07d70d3b59eeb49be9d9775bc77d10dcb7a), uint256(0x29adabbfa8fe4e76bec3f0a7b0e03cdf1d5393105c913a1b14e4093ab20e40e7));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2501ede9d830249881ccdb2ec12aa5741a69c8d69963b652d42bfde8013c4790), uint256(0x0c9ffaaad35eb6ce52275899f5569ba0edc9bcf6eaa42c5a912726d38f1365b2));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0aa8a094aba516b67d063eb2f98b831ed07432bafcf8e4fe9ba357856e5e76e3), uint256(0x1920163eadf1e1db9b0dac09e75c02ada18df32178757e1025a6340d869452f1));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x199202c91b8a40a59f914d0af0237e3b6dd3b6bedf0cefe2fd1ab27308a19ef0), uint256(0x15233eeebf9df69a0854ecfd76952135512356386a86e9961b85297421ac1cf5));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1fa34d1eba9e42686c563753d3caac2bdb1ce5af0cc29d8067638460b2ff70bd), uint256(0x25a71961c74dec09c62ed8a3e78d794287b8667ae86d834f350932a6bfcf54df));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x14471d8fb0470b6e23a7abeb77e7bb9402626c4326b34faf53b2c78131b9cf60), uint256(0x0519ff75b6f6f1e74d94509d8573f409447cb1ed1666a3955ffd6dbb91aef021));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1bf53e1c0b021bf643cfa19adffb1e4a1369bbab325b3897e671da83a7f420c8), uint256(0x246d4a2f061b1ab24322e2ccdc949fe1c4ea9694455d6b642b2e8aa617d99dda));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1ca20e037a5b5778b148176c251303c88866199b955507e8b21ff86ba3ab6d10), uint256(0x22bc95e053a4d725e7e62356943cb1f1c4de2fada0bff7c427d34e8c387065c1));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x03ebb81c1d5c411ae61239695591bbb8324c1da34a555e73dc10473091e80bde), uint256(0x3021a600401f275b52917c400af64e4a3b28a5a40ea9947f332809b2c9a042a4));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2b3aedd11fa69b71e255eb018b723ea0d3f545e58908d45897bbba9366595b0f), uint256(0x0be10ec17ea9389368df67b5dbaafa77505a7b0353d6c9eee58452b9d6e0ea29));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x12c763c78403ee20afd3daa808af767ae8933b0915f5ced0cd3525036809241f), uint256(0x26896c1b023d7fcb7866b815ec0c17b50cd330b924eea4e08cd5001b4474c34e));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x05170bcc644952a29359c1c2a267ca914cf22bee6beaef33a6cb00ae09a8fadc), uint256(0x0538604a6289a86fb3b928a6fcae083d4f0a6e049dfd5ebc76bd11d2cd969d24));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x09b2d981c55c9c0a4f8eb20bc7e800c483fb4d250c8c935eff08e00f973b6057), uint256(0x1e46a3bf2e9309447039595e848f19eb6fe71e5a527108c2763e339e32601577));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1c21d0c05e3a9ac9bc0680e57065f0861bca541944da4009cfe4eb22a640047c), uint256(0x09e972521d062528d736b11f4df1b15096869fa5eb59140d89cdf4bcc539a7a3));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2bd042387ebc8b1d19ac4fb9c9c280cab61bc051c44c6219461d4cbb59fba0f1), uint256(0x2a5691229c75b10830ffaf47392d8e02c9ba1fd42f8ed919b217d4df5335344b));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x12b9c4f1c5540b281e4a1487d54d4641f45eb2bde2e439115030e07e786bb3a6), uint256(0x22247292d0c49300d698151d2e62537ed411b37e877ec67f6bb2406034345eff));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1777b053b3a83fc4502e1af603310e66da067dd04b6751f88153fa1143b67208), uint256(0x1eb97d363aecdefe4f4b4a02cd46d032adccdb52adaf5b5ab7a11b2a6bc42b3f));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2533b56df7fe04624422447bfc4e27a1df9fd9d560ae71ed810b08e88de210cb), uint256(0x179223bf55f9e4b306f0e806c6c78185234827cde425448f3f974d9e33d42c99));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x247e39465fc3d31e1ed6a45daad2f20226873d3f78b9786247191c9c52112fe9), uint256(0x1d972ccece9b605818a1a8a721bd04b8635e112714d0526ceaa8b04e9cd3d2f0));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x193c16e9d81350adebb3237cc5cf055b3d955e85a5935ee6cee8c76b60cd9106), uint256(0x12f8d02c09acc2e964189b120d0fa3536a4d78ef34bcb77c0a1f0f9861f5f8ea));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2f7bf538b7fc4f0ce69e94a36fbf5d6607f0d9d98bd16204f9c5e63f5f5ca0dd), uint256(0x017e2852f32da47a564e791fae0df4597669866bfd538248e63244a53c6de5c6));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x28f8b9ef2bcbd36ae6c942cd2e154631ae7be579b13f63d66c736aa9cd13676e), uint256(0x29990c7953a30b8243c39f96f0c8580171fc75c0a877d0cfd02e8c9c18be751c));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x152133decfeff30470ebe1b0b24c73c52c2be0735cf4bfbb9e581b51a7f19dfb), uint256(0x2d79821f836bbbe511c44f318714b890e4474db907491b772211cb4750879067));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1b235ac4896e0b144bfe9864adc3505212b553990a9bccce1bafcc0d0a9deb91), uint256(0x1cef43b0d704c745cf8cac859e90249e321bedf693cdc9be9429019366e3ab74));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x1b078df049944454e844077f234ac60be47806f73a4b0a75f79762c02c6bfb53), uint256(0x2cb7b42d6fe458ddf0ac23a7eb2a191df01c487da140510114b8165a93f200b0));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x1ab4de1f54ffb717bd716b7e0384b04e4d9fde1caadbb5b59f5fdd1cb96e7927), uint256(0x14a0496df6a8bf5b32a6d7a218acf07845878e09e8cb2d9bc7a0f37da1f1a6ef));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x24ee833ba0c5007f1d91f9af64818c1c6b5b6a6d268a1a750a5745c55082b704), uint256(0x15911cbb3ea450e052de27802788200d442aea7b487014f9d97d28dd09cdd8b0));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1c223f46119c33ef66b0d75be278b69409357908d060b3cd6c2b630c15680b44), uint256(0x11f99ffdd035bc38a2c37326047b9b9fa3e96fdf72844c8c687eea797b6358b2));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x1ed141c22442fd78f27593ec6e2a447e4784974f7583f32caeddbf9c9e5511c3), uint256(0x2c5977ac3f99e8362ad8e1914020822b8f02655f574bcd5bd306bf44b04a7e56));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x1b10c0bcb1b86dcb76f200f6ac703f1ed74c3f527fed4085ae37ab7f3c037242), uint256(0x0fab9053660677525b8759501dfb10b0a5c19483241d5adb6ee237dc5956a644));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x03cf8de19f2bd0879efa25924d5487444ef44f5fae289e593580b8a271436be6), uint256(0x2baff836797469755b3866d6dc0111e58ceac1a0dbcf0b191af738a825fc5649));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x24d6e40500e4e0bff06ab6f8af983ca81411b5c3349830b272f14512725438c0), uint256(0x01a0efe0467b5b138aae18b555fac3ee1e0c3ee656a777e13e381b8a535e431a));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x094e0b85f50c3f4ef74530f7cf81c373526a4b77d0d047576f947609c63f4646), uint256(0x10de53fa228634fbbdc881320c99407a1294841fe699a4301845891531493b04));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x10e85ba0a2594d8bab41e72a7fcfab102579481f270711adfb509dc3252dbde9), uint256(0x1efede9085a4d3643e2c6e835983acbada5ff5ff59286fec8a660f878637a39b));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x2bc9ad8ccc71f04e91124318ddf20921e3df8d00867ae3f589d5b59b4054955e), uint256(0x15c18f0a14a3936c4a65238b7de125a197202a0b59ba6810fb9e3c9bb598b3aa));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x1f62259ebf718ddf27f47673fcd42bda9c11b02f821b587be822b8d23fa36b6f), uint256(0x2b69c371f3ec80707e6d277e935931a5e787bac0c717cafbfb8be1538898aad9));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x0b1087d8d731b063baf5fb9cde0b5710088300dfb2a422cc3a95facc84ba251b), uint256(0x1e8cf09766d30690250f98e6673327e88a05550b4eaf2b12e1ec1082fbdbbcea));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x1600fd06cad9b1e2c9f0c24de2024033dbcf3b2047261b2bd8fc650047f8d862), uint256(0x23a8ed0ced1e946c51476b8639882d15b0a5ea0f2d1ed65ba66d3b3629fe4226));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x2eddcfdcd43a9243dfc7f5ecd7bfaa64885478b1c0b05c947491eeb93f4a2bfe), uint256(0x0255de046ccdf37b8979743e079510d274fb0e32b6edd336827fcba1b5cfe367));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x242ccf2946c779db271b9862d7ac8c92101572bfeee84e39f130065d031c67af), uint256(0x12bb71e54ce37bdaaf17003832d83e776a1ef08537ef6a3a1bc94ddf6f365db4));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x0720916bd8d76a2c4fe8b924f419743a3cc3a024d3d1104210f5c1248d71c718), uint256(0x2bc971cec7c598d7d0a4310130f651e9c5e754323e5908b3c62e6375d4fd5f93));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x22a52f13bc97d8902dc84ad04a4a99ca8697574e45950bfca0a939f2d37c157e), uint256(0x292cab866e3251b833b195ae475641954025bc7c3b02cf58f5fc598cb7005b89));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x12ac031d646107121ddbe846e02b1599ad6007f8f9c63ed760d45e933e7cbe87), uint256(0x05866dd6a6f731b6335c93da832e96709fb76d778446ad3fbdb0ee9e7ef6255d));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x2f1def9972c6b2052ae1d3ec79fdedf6c9d0cc6ce74d4e125628392f49a44ccc), uint256(0x2db835f43d294de1a8d44ecf5644ea7c123bdc9ebfda72e01b0f67145617c545));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x2b2ae96950951d56b59fb2ad6184ee8808a432e4bd36c4ebbeb9452af0439435), uint256(0x1b94c738452feb4265ef6561f458ea60200c665525d9e35ada680b5a60905406));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x1f73c189798fe1a432806f6cc1731fc65c16b067965f5f22077790ffd8ff2810), uint256(0x141a89669ae4f6b20227136b2186fffa991549d67e1c599c3bf000dd60b3a682));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x16c78a11d11e33e9be8dc7ed48c8d615327fac1fa9c5f4c7e13412ecffa03ec2), uint256(0x112701d866fc4a03e2ac83ac1577683f65996441727d405d882a2a9949fffc33));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x0765e42d6f7d490284bb9b5bc8f3fbec6b91fa7614ebcde1c50fd657b04b9cdd), uint256(0x25b0f6c7ab6723ae31ee8cf329a98286ab77520f6e55bc893c7a3accb91125d8));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x1144ce81255efcc15305b54908200f2b1005514f004bb9f667eff3d025fa7913), uint256(0x0bc40e3cfaeb0b03647227c30e38f403c9641fc5598b7e411087f361b904fae3));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x0ce916a01cc0e7ad93772887a7952f3b2d851c238ee819891f32547b6a2b7bac), uint256(0x217c8ccd35d29a30848eb701d2734cb595df11894cce5f83c37b6b07fba8e37d));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x11b3664e9897f37b3c129710dcb35ce27187834b94fb54f836c31da5c839f5bb), uint256(0x083be840bff1da2d7d523fd253cc69ff2155efe0f7b3eecd1d0cb6c824708558));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x0487f8531b36e7a0e086c2ef5676906eb1d08d5f0e272a3aaf93a11f2d0b309f), uint256(0x2022f28ccd76fee0e41fe420016625b990e625a6a19bd7dc0c355bb57fabf72e));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x2086a68cea493fd83a235ea8828fdf8d6c97121ee71df36efca293707bbee55d), uint256(0x003d10e7a0ec3253b1da2ead7c43924e1a53e39f8ac92b25d86ae145545a88b3));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x26f5665c88abf6013bc05525c36f61edad7f36ec58b0031b4ec58a82d9243911), uint256(0x00c9aa1d69dbd618ca5f64114ae1fb9aa7a020e26bf06be58b1824a237fb7642));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x2ccb0c21fece6f0e8caaaf57f8f4617fd7e3aa70b764fb59cc6bacd64907dbd2), uint256(0x121f5f0d941c8f86a2fd8fd2a049e3fee33f2ddd0e6e96a7fc90cf90728c9eaa));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x07e415fb7071664fd1e2d8d9fb2222415bd912f46f16347e6ba08beff5fcee93), uint256(0x124ec180225130bbb9b3b064be7e7d8e9095113d60b1abda99e3d8053c13bdf2));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x2b91c1d3a5afecf9b01ba986b6465ef1208f446843d6459c1c8064d6f9ae9757), uint256(0x13eefbd52a830466991bc3a1958198e2de1415f407e716686757aaab27dd1e9a));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x1cb64d3d7c871f55b02842fde118c71bed6ff1aa3e3fc47b7642ed05e9078ba3), uint256(0x2bc620fdc7356e4dc20cd4580e30312a349af028c2b275969d4963e0166ba62e));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x2604acbb0b47769edda671cb9c40c0013d8d2ed19199132fc52f4c4b35ec10ac), uint256(0x2d94ab9aac64b47ec695854f4a01864d8eb3ef0177b98f674e6139554414bfee));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x2932435925d990537e23699fad6ed0e41b208caa442e6da795cc9d9dfb56f9d8), uint256(0x20cab576b883fa7b892c17841b47034547ec8b6fcba650e1a119ec7b48b361c6));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x1ef702fd13fbf1518df0e7fbd319248a33954279ca7eec8e410866b4885840da), uint256(0x0cf56dc1baaf95d4a183540622a082c5a974c5672f259e26df5c779e8068dcd0));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x033802326a6e82631c222b30bb6e003a976308ba8f50637871a09950e9f8e2f6), uint256(0x1a6c7ea4819f6c50b7dc6fe5a036c1dc1d13c3db31e6a5d04a3ae1bbd60df93c));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x247621aed28d7513aec9cd665cacc0030801a12568f7f4632ae7eca292f802f0), uint256(0x0049436769f6e64477a410b8b335fad15e9791d76c272cb836330c6e3b9d2cbe));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x20ffbb104cb9efc9fe97637fead267350bd2105f6e821460380875581218fe36), uint256(0x18f8e986595bd975444cbb0d72cc9b8eee0252dc588c795e8b3086c3402304f2));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x2ff02e6b4b5d454c0dabb73e399e03c8c7b06f41d4d6363a9542d98a3cc8e90b), uint256(0x04e4e617caedd9d8152d554a115256917721c9b742242d84524ceea64ae1f5d6));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x2c7df6a5216807e88a5b7aa7930f9c9cdd660627397a97ac8b1e8fd57acd1709), uint256(0x0350a779786506fd6110a7a83b0102d40283bbb9b44921335407b156c6da335c));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x2b5f3716f9911aa457009a38389fd6bbe5a52d99c49eb4226f37eb3cc33e71e6), uint256(0x04ebf0ec1e72252eafac5830352c0f053bedc0f17618fddf2e4ab6cff91a14a5));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x0cc08db1d481090bfeefb3a287dc2e700666a3e59f0e46397691558f69fcbba7), uint256(0x11c3fe80354e631aaf95fdd0e5e69953adba53dfe1a39ef1ea064e7e0198b0e6));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x267faa79173baa2bd5eff4c533769400c728ea5abf80600d04fbcd5eb397eadb), uint256(0x241b0b48e4fe8ef4ec684f171f5e3118833ef25adc1f17c0b9bf314d6f099a3d));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x1e6eea4c301d6fe3cc1835e5acf6e9aa56b7fe3285a38636f6c4e0916b246ede), uint256(0x2f912ea70433ca1b88d614f98e7595357a73a9a2e3c5f3d650eaf0f24c7e1709));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x0f6141887e4e51fd9781cacc6d4f4cb85127e034a0e209399b937e67d85db918), uint256(0x2f5f8ba85c0991765211d11b4465a3bf124b8c4961865c9e1bf7c831a764c796));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x01720b7024258df06edc719ff4921c0efc7b648ef15bf91694e25a3ca2518806), uint256(0x073637ff7c251dba39f1126989e8212c23aac320cccc61648d52ed49b065dc73));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x210c6cd1c412ff5f6fe0a93f9c5cbff790f51561d461971d0d48fe6f372a10c9), uint256(0x16b2474210e5b8a853fe45c1860e2a00a35cace9a152e3201eb2bf6fe01033a2));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x1c28a2c3ab98317db8cc7c6020a2902492d75f1ee1a67249c0e3858ec1f9aea1), uint256(0x287f9df201f9e5ae85aa23a2cbb832263c2d9856611f5b3434b3b99b88c43ba0));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x0518145dabe7019c5a04856ef2d7d95822f8d2b6645d236ccc78ffa6195df8b9), uint256(0x29581dea6da98f37d45dc2bfc785a32d6975caeda6e4b4d3ca2bd47e4c7a2e72));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x28fc3b1129db1427bdaf38cb9df6018c72ff394a7095e0a2cf4f305912339e41), uint256(0x0bc44c0449711975e017f07be5ce99b6681544f67882fe4a4f931f3b35787191));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x1985e0bc4e05d8a87d140ed9d4612598d75421ec1ef9c1795eb4350c0a09c80d), uint256(0x030a0b30bfa70327bba00efe65ac7297021641e9af3c83a9184a9a1b2e9ed513));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x0e7470adeda1c368dcb90c4d6111013ab784f1fe2cc88eefa2e46c1225a468ab), uint256(0x1b20fe9c47aec9bf98156b1a5a732c4f2a84fcb5d1a334863722ca3041eb8055));
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
            Proof memory proof, uint[80] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](80);
        
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
