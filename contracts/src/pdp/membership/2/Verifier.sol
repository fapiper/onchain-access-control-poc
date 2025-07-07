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
        vk.alpha = Pairing.G1Point(uint256(0x29477a7e6bb4418b16c417da295b90ccfdcb223ec183151fc2f349b26d1d3ee8), uint256(0x1ec314cdbba481c20fa3657aaf784a88d3098990667cbf7d3acb5f839380131a));
        vk.beta = Pairing.G2Point([uint256(0x16ce5fd17c41bd79f6d06c507f14c3d94301d6c50e383cccb1044a34450be355), uint256(0x2537b5ceaa4083894181aee9defa832c55c8bf58eace54b909e5de77f6881220)], [uint256(0x2f7aabc349fb4f6f0521a592427001c53c8aeac07f907d0993055dafcff67347), uint256(0x20af17c1232b65bd9bd1a8321927ed08c40d4e0d102d1b088b9168de6fd44fa8)]);
        vk.gamma = Pairing.G2Point([uint256(0x035cfcd70a8e516258f067f689588ad3cc5a03cc34346752d59987f3a018f125), uint256(0x2073d0ed99cac9d3ef399e687aa826a88d7fdb556ea7eb9ffb950f5365218efb)], [uint256(0x023a420c10f1c2646c153385db8fb1e5bdf6ceadac551b0d133f7f68fed03b7e), uint256(0x1f53fa5daf733a90257196e0e0e88bcdee56d006843d747b5f7b1b43cde3ed84)]);
        vk.delta = Pairing.G2Point([uint256(0x230de76e1587cc2c3e1737f30c53359f2e571157b17c843857b164991d2fc6cd), uint256(0x16eb6be6e092b5293249a9a19f24de4158cdb163dac1d11c185895f3f9f8c062)], [uint256(0x12eb7bdf6171192fd1af128b78e1da163263fe0876bdd6d3941e9048dcb661e6), uint256(0x29bc5714ec5512f3adcddf2f6b20a2ccc6d31a2b53509da1f7638216c8c9246a)]);
        vk.gamma_abc = new Pairing.G1Point[](119);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x28e87ca649f7e11cf347fae062072a9cfdd0124d59ad88066c5b1dfecf1e6019), uint256(0x2bd2d3e174a2bbb492204ae6d7d875a188d832c846a3dd18a07103183bdbaf7b));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0b57e5dcdab44f81ebcad10a696443e9e8e52ce540d967f05696a13918903c43), uint256(0x1ee27b58e8f83c92c597c7016ea4e48fb18cbf3b8f2e539f458f312ea9b00f10));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2f299a9e5fa461f4fe9a6214ce5dbb207c0fefe3436d5f07bd24e2d403a6e2bc), uint256(0x1726f3ae83680e3fec196aa0ef3bda7f17b93b603e9a5e47b59b7da4fa297500));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x289f434ec9dd77eb4a10ed965c87dcbc55f9265f99e5be118b56df190596f2e8), uint256(0x2a29e84fdd35b54e47956d90911cbda93a92ee629221fde47221701ea8fef621));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x20455a42383bc103ed643abbb9753ce31d0b56536d788514e4e87005aa54b803), uint256(0x2db67b7eccbb0773f49c1ab630f8a21a18e57706ba7000f793d993ec5804efb8));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2c51a1e376b1ebefa6a43620254ea51ff50aa64202b6aadcfc655a022caa9ee8), uint256(0x24970f232c1cf16ece1c6703ce0dff17d295e49ec45af86293afd8c14e982a02));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x138e7bb46341340b0319502692162fd4de87995fb81b9efdf9bfd7b53e5f5a7b), uint256(0x0f1743f75efa3650c42bebbc29cb1abeef4a2b85aa28abaec9b50cdaf634cc47));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x108d355739303d5cb90921a7bf6d7a9e6889930a97c3bbae8f1590b858d83930), uint256(0x161e083d57e386d238297c6842ce3145de153affb2888df1207f3dd2821bd446));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x21a10d3974ac52d2110df799f8ae51ff06de7d6d8e03672756fbc165fe53abe7), uint256(0x03de42e7d8f3e98c1ff38a9e723718e72671fd21c7c42a49a33784507cb7324b));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0709526c09e9833a3c322bc90b7cf73c61de39d19f4386e535c0083de67656ee), uint256(0x2bd2d3d364e9df5e884e67098a8c5a2b535924ba0cc7b6258437ff34d6e103b1));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x19d1ed4bc52588454cd79853f2e23feb466ff25b2654b33ad86fe6c5a8db4505), uint256(0x134ad0f55c2ace4b764a6276b000b61be27ef94e12751b58e31134d2ac6d51cd));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x00868c0caad283d233c573801bdf5c706c93e96e440edc6670e67337d380dda0), uint256(0x0b2c183bd664d7503b20d0e08a26dc147e91ce2be1772c9c5a7e0e61571a1227));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x281c829c13c57484314ac208a4625f0fe97a7369269d60db54e547467b5aa769), uint256(0x127d8724b3dae25eafb8c11e2de38308bccbf6503f4c439b9a87ef2f1328ce37));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0ccf2b233dd47c2a2cc85193cd9e37dc2982fa1de5639b801024538db4fa171b), uint256(0x1c55240d980a87b090a66980c1caca70c6133e6cf8e54a2a4fbdeb3700c0fc2e));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x01fbcdbe57711426f71e1e846947cc9a4f0e08bf9758bd1c36fb3108b142bd58), uint256(0x18b82bc8c800351921b47b745dffb521e585e52dd3c712cd51c8a21f908444e5));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x2cafc27d82625dbc1a679e13ba6a9b69e61313b16fbf22c3c85a6a5a0a037d7c), uint256(0x1051d4be67aee14d21803480c0f9e5ab4d8b34f485e5300526575558c87039c4));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1119e579732f1a160afef9eda73663a171007bdb778619081cc6183a43f32342), uint256(0x10c026ac1b9d37a8a15d078bdac841e8fbfc71c216303db195f001c8908b71b7));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x28f8ffbb9676123f6f4f1dac4aa14fdd6771160795bbf2dc91a2af9c8dee4028), uint256(0x1e60620d45a5dc99e2036cda77aa4cc294d654fa5a8ae52082060390edb80935));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2cde40c2b07a321bc63f96223965e022d3fe762902c7cda45ccef3a3a71399af), uint256(0x1783e1d2ab154a0d1c34fdc29a86a96fa0fb7cabea40df260c3b2c46d67d7631));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x053c4714a25e8dbfc109edd54d5685ee27c3e92cedee3de776671065e2c19b6f), uint256(0x0dcb9fb0a0ccfacfafb730626fcba899539933cdff735bb568e23b07239bdb96));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x0e509d889c08f7f07c38e25b88d35cff824d93c2fd55e76d429a1d7ece8fde88), uint256(0x0aed25a04bee83d592c01208fff1b02e12bbffc2223518f3fe13e256d8466a7b));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x0f95b26f4b9fea11f2f87c431f36b931cb7a77040338c7530762f6a436305d26), uint256(0x20ce53e0d2067adfc530dc6d6aa6f22430eded409a629107e23aa18b7732d070));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x140491254395bb7a3e568eed149ae04ada6de065365e8a100b9d2a289a841aab), uint256(0x204d9e19a625d840ea619069dadc71e3792a007a06801feedb842660bc727350));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x0f262dceb550def54eef9e77400c5dcf51eb628d83367425cb20a5ef35600370), uint256(0x15ae7f68c47ee7b89965b198cd362fc5ff25632732ed4345aec76d2ce5c7ffc2));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x1722c5b891fe66541f36fb7db61b99990f2a86cf26d2fd9eac19da1b5fbfdf4a), uint256(0x2821367870d7ae53bfefad30d7542ca5830a74a9b0d0ba2da0fa28bf9a47e209));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x0cfe75a11ba0cb0bb2593dd8565c9ca7d9a8cf32f04315769b55afb5c00fec28), uint256(0x1050ffd35c89f919720c3a7a70e72db5ee3e4ff0967a7f802de70b1ea66ee4df));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1490148445cb5e6e3e2aa6a4ae9dbf9fdae8fd3c3c21f79e393ed84665ca6c79), uint256(0x2bbcb11a0413b9d179b7aa4aed5d0bcf5f0345f40f3eea6c98dcedc3d578d5a2));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2f558dd6fd902d725f18247eb4f96f3ad96c5ff0c246cb09b65ede901b31932d), uint256(0x00a44891be665044d3cc987c313911df9f362ab8cf1f65ea43b49f39b192de8f));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x1b65496d8e9965692682ac7c23034de6f8d112cd8aa508f8e8fbfbf41f721e57), uint256(0x1b47a32f379e54bdc54bbff7f1ff34fc764d61e39a7c4e03d431d808849d3d4b));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x081b529c7f042ece933fe257ffaa0b719a161e2e04cb5fca863d88ae4cc24b07), uint256(0x2190f8fe75582b0644d81341d2ab44ed88fc70a0f7b94b2dd7119d26ce2e8c03));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x28c23123dab8aa2bc474d2ee2f7af6b0c19278c6092e4dac1518a107d3a65129), uint256(0x2914accbf55fe8b45985204d4ee711d24984306d132d5ebd8a5c0be0e60426f3));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x02ebda4a0df2258c6f944bd3f51008bd6a9b5ad4cca4966811c0a60f73b5bc10), uint256(0x209a15806cc40ddb648f8e0f55bf7fb9bc9caab1015ac9fdb41327521f57a1f9));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x1e979eb89f74b6d2abf030c27562cd80394ac9d714042c83d6a69e50533d3cf8), uint256(0x241d39c412bf10c085ec903e5c075205584644b5c3c8e4469242cfa9b9404ca5));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x08b3107459e70f7d9ef6dff268b94fc5305cd7d0c9833f08ebb18d434998d8d8), uint256(0x2d9e6f2e3b4564f6ef635a2cf615e32b4c78d34281bbc468085b5eb7e9112c68));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x1235fe11f39e5612d49f9aa651568b40fbff85b572e8c070ae2f8fb3aa04560f), uint256(0x0c2f3a5b3ef02c7cae53d002ded9dc92f4469157a4287ff0ba34aec06c9f44f4));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x20f952f95a00c3b32efa4b45b328a5d3c78e4a86032c023ba2d10b9407185dcf), uint256(0x1eaf95f08229fdcf3eb580cd7927a92e6e5f577158e51d8f59da194d066646a5));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x23ed7a5d0b65e6ac7496a9d24e5231574086de9e4bdf0f70832185db177c865d), uint256(0x2dbf54e28e8851d05df50e586223eb27d713f1fdda84a7ea05c43761f52accfc));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x252a1976f5d209dbcf2cc4de2f714ce467fbc75779bc29a97b6396889d84de7d), uint256(0x135760eae97116f5b1d220c8b2714993254722986611335b6dc096b921839653));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x1fee33c7c4261d62020524c7f9541135b9ec8d544ec3585a0ffdc037142f46a9), uint256(0x10df1cca9f8d4cb844f34e3eac9979f2fed4527412ee1b39aef8390dc73a15bf));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x24f1608a5b1854c62621e60d7a5fac47390edea6519b23c9437078eb5be692e7), uint256(0x061e902c1028cbbd6309d15ce2e1b4dc1cc9b5d9c89a987626ce46a39f3f7d46));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x2d705abe4a022ea0bc6fe5cfd0c1c9691128b45e73a23a3d34f72c2195d4c332), uint256(0x21485acd42dc75c1f8977fb1929861c9d9596d55dbfb0383f46b0a6d4e9a42f2));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x02e0f46bffbd38a61e832ace44b812b6e8b93b71da95fcccb4c39a19a149886d), uint256(0x055e27e86fb66eb306866929fc821814c794a635e9586d653815952b6a71b3d3));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x049ac139cb9a6ca0205a119a69f46da6b99da875faf049dd06b20e680bdf31fb), uint256(0x0599ed89bb895e75cfcd4e85ac96f9f016a84d9b5ffaff814c132343fd370d86));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x27cf30a1c07a169bb95757ce81517ef24cbb555c790a6df23eefedb9d43c2aec), uint256(0x108323ac4df71205ac837b1420b0ebf0f99eeb2ef51fc59b25a525d5a7999ddd));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x22312d29b650252c8ca0042796406fab91b9b349974c1eecaddf7be2383f7a7d), uint256(0x079a88e0cd760b8dea7b421798144847cd1b7ccb16ffaa3cd1a8f55c32851624));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x1f041328fd7cb97b576b8fbde58b6049bdbac8df8622d4401ad0d5fcd43a8d2f), uint256(0x1b9e12de4de9cb4fed528ec23141c9733ec2026b8a1ad475fd1bf4587110af1e));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x0b93ea6d5b7f0124bc25b77fdba53d334d13dbbd0770d154a6882c8434fa71b5), uint256(0x1658597a6c84ae3a9a9980c34dbbf37bc12bc5becea03ff4f85cc9503a9424bd));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x0ed1cf269fbe3408a286be8f6a3b09bd6e8fd3b6f2a9db19545248b179bfa2aa), uint256(0x0ba8155d91bdc50d3e174b80ae93d3dec4dac5ccac9f61e02793c6794d8f69f1));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x06d1e46c348b101d6a18a40e8cb70306fd67aaeee5b1a9ce9be4af5a2e8fe4ec), uint256(0x16df6af0d1ef7faae36083948724593773c7f6ffaf2d3496494d2075bf8233fc));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x27a34bf169890877aef7ff206c6300491c13ca9d3aa8529d919374f9c8b57024), uint256(0x15eec7bcfb6e87ea59f37fb0637d9075250131540e1e60482c87b46d549691d5));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x26b68fbd564776aeed20211c4ec6ffd02ce76038c96576d0708bee397135ea63), uint256(0x099829ff240032e54098b18cf9dcfe057431acc1a5ce8fc76d999f0a6dbaf3d2));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x1875375d97c619d15d3848d7aac6592a2e9a916bf68aa0783f364ad0f58e786f), uint256(0x1232be1954ed350b93124aa2848db3c98c8dcd86342f57775540dc81adebbaae));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x0ba32509b80a6bab8ff08a78fe50b5c741663b9f7464efa28a02c443ba059654), uint256(0x260e3cc08ec1604623cd9816ac3f7f735890bea3efedc7b789e96bf304b97b04));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x2c027cf9c6d8905157792e7cb371c8ce736ae71731ab70d9cddfff52dc5fad30), uint256(0x10f0cce314534c715f91a40e46d21d483f9ab7f684ffac17407995294b3c7833));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x12f0635823e985b4d812fa17a8b4e81ee558ef263f04a4e6365533b482904e1e), uint256(0x22d04e7c61dfc24e9068b1d0254c0182469caad8123b23241650122cca153ea4));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x1a9c9715053e83d100eb967b4f6143d7c69d5ae124c1fa8dff986046e9dfbbe4), uint256(0x066ba61ad3897abf4e808ea52927dba5701c08f4c33408c42ce78e47929a3e97));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x0af843d67120c0292f0ebf3721e6729fa3863f0d1b46bee8855075dc949484c9), uint256(0x2613c69d8b436e85fd4f316c0252afdf96ef3ff5d73ccec2e8acea9bfded9de9));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x2e8fa976de578dc348aa6dfc3d27238d22c28ebeeec599e799a013eb18438044), uint256(0x1a240bc3a012faf0314b7bf2dbc70da1c0698a78591f2fe34ebce6d74aafaa0b));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x083cf660c6460b28866fe99f1dfdb21f34b81508e032fa0cbd7e979c5784c4d9), uint256(0x03b1a121a26f1d2d47761c30ed2fb7a12fe9b78f2afccc98d04993fb5905f988));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x0a877fa5316b7e849fd5e1e6cf2272bd49aa42e676689c791a14fb1e2aac8a48), uint256(0x2785b8eb8b3f16bee51775653973bc026efcae04865cd61f20309d78ebabaf42));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x27c97d48c96c315b41627593f9ad6c68a495cd7986b14f16ab588c686a5e0e8d), uint256(0x2e393112d5a248e60907cc229e9b0e0d0b6c3755f2883f9c60e84be3dce04dc1));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x052b54d8bcd456f9e350b57d8a6d1047f98c383ecef4bbb35f59ee8af5e9af09), uint256(0x0e1372c8383c5cec721d008dc4a3e3eeac1f37c2813dbefff0dec3bb1855bba6));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x0a7c1fd31571762f78c3651920daa8c9c24555442f5fc9e5877aee7bc4e6229d), uint256(0x0460e06fa98021e1537de4f5b890e336be3fd07665e3545be79c66421b9308eb));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x167e1998ad596f9218acc8a0adb4029d384a84f04ed2e3854de901be112704fe), uint256(0x015ae0abd81c2d08768e8b4b47e965e0b7c784881dc9fea313c5e16da3b3965e));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x1ff0fbd306adefdd12395db2e48e6df313d7b2d6619c58d2e20360bfcc3d33ef), uint256(0x2ea3ad900c71ce7a073106699f0842beacf48c2f112edb4b80abf685b4fe1be7));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x1d7b2739738236c9e1c2eda644882ed41a68bd59e0fc1479113da18a4289f05a), uint256(0x11c9a6d2ed4dff103336473fe01e03cac1c05a3255edf0f891cb9d7b3bd0484b));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x1b3160114612de4e6a5d1991825af97b9bc6833d2b0e0c2070eec1d54edd0a07), uint256(0x00b350daff11138213ed4d8597ec7b8ba73b8606dbe0d7b00a3e58cb4c11cccd));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x1faf23d6e29c12fdb77919cae4386c638853d961ebf705d8452866724f8276e8), uint256(0x0536d454f27df3f8c8067bc09a4d3edc4ea4348e6a49893ec562af68561761e6));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x1e8be1f2a0f9fb4f063d3146c680832598b31c4c86905b08bffa42316a5f11f0), uint256(0x2944d770df27f5bfc846e1269c186d3e170bd5a344e256e8655972e506842ebc));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x01e08331d9beca3352ad31ebae7c5bc877e52241924763fea55d8e7f7d3fe24d), uint256(0x16e3be2c6b23a9de3baec434acee44a2430baeac20d27f31bcac9b02881f24b6));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x145de41eee21fd8ba8ac4fc41b7ee683664cdfb3b504d6ef166d74fef07861f4), uint256(0x0d2a30f940ce2428672314b7da8f899a462acd43dcc61e3e3f6082b43e318591));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x2634c4257cc3c2c2470598941daa23df77e28c4b9b7e173df1a0257ff5ecefde), uint256(0x1bc6480864e266994a240111633398aeeda9613748eaaf4c9ac572defe54d8c3));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x2ebc3279655b35fc160c7ce3a266cc1009375d9a0c5f2f22c14852a6c5421a9a), uint256(0x0d4d857200b7372186fb8663b5161daa0e84d9118aff9e5556b358b7b9631ddb));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x2e11aaec59b5da6c6a8c247981beee79578833b0fa14eb9f7969eea9601a8398), uint256(0x1c19d60420df0cb84ad21d007355e57a6d6d4cee0ea1b58392be2a39e21f1838));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x2712912d6ddc56911a6c1bfa917cfdb46398d91a0eb215b61c501ba1cd0b1c0e), uint256(0x1f41999972f045234aef593ac107deec2c523cd5734d695cb24479d8bdf5201c));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x086097a85db5a6dda5e7be6100f14906a8e9cddf972996ab7dcdb345af0619db), uint256(0x25b4a810f3578aaafcfb75d6df1a9feea1066679cdd42a88ec4e2c83bd528a0b));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x2d547a1d13138a7302ebd367be8841ea42f1cef1af045518c4bf81f8d2261641), uint256(0x02de011b6220371a49d31a3e20e973fa1ee20edf4a5647a1715890568d07e6ed));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x2917b9ef7b2ecda03bc5533f9a92958930645e6d19f4f2d2e9d8d48d31b23061), uint256(0x166389db232bb52c06a4e98e2d212edcc66c50165e7885eb4383ff89f3ac03bc));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x07eccccff24743ec77a22103565882336aaf612b4af8789b16d064409ea754b2), uint256(0x0c5ca239536e873bfed2a24b743f0bd3a60a3157d6a0e38b1fe831cffe85a6f1));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x223f8684aa6500343a5fbcdcd9850c251853234003500a1d964c82978ee8e823), uint256(0x0654af9cbc0a7b5ac57136d48003ec4b814823f70cba94e51c2117949c258dcf));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x170aa0ee2ebe075d77815ebbe9dd791d71963461c021d4d424f81e58ecb6a366), uint256(0x2d2735aa368e4eafe34d0d9ba0577d34156b64d9a0a3e0bca5588fffc070ef1d));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x07845ba005ccd6610af2011e88f13adb9d3002edfd6a53e4f9f653df6a07f332), uint256(0x10d747492d7022efc0486f339318e36f9fc53dbc8279ac3c9824d4d432a695a9));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x2aaad7ac457af443bea81660547c475c5a56c0f01fad2435ea21a4ac4b9cee1a), uint256(0x19132498a8af1dcbcb1f996c3679484eeea742ec2d03258af19f1b9cab9466df));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x01eacf2a4a209fa66b63ba2ac4d78d5ec5fa4153d93cfe9a91440e8e496ee341), uint256(0x03bcc1de7e6d2ed5357df60b0ac6e639d0103d9db231e1abfbe9167b037e8d61));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x0f9653cb027ad8c0ccfac6724d4fe338c4cdff589de3298e223608a5d5221940), uint256(0x2601a86be8ac21242979761b821ada8d5c8e23a16c5d2c796d0c203aa2ea43e6));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x26a9b556ed5d1ebcd1ff426e4fcf9d611c757bb9265fd83f5021959f82e4b900), uint256(0x1bc1217d8c627cf3eb67609443f0169367bccf4c5e2c0230965574fb2ec6ef05));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x025dcbcbb6b31ea12b514b6a706fe56514fcffbaa6b1bc4b7d6225c3dcf6d520), uint256(0x18ebc3c22c1e83eabf922014fa4eb5c33083075d06a5c559c7c7a650c7938f26));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x25765d199110f4c96c91888e1412789122b82b7e76b1eb5d1ef110e2f886e5de), uint256(0x20a261cf45487ca16109dc7499fccfee687682ef59ba156c074a8c1dd8351931));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x00ac9dde0f5f850fd81077b3488bbe195947263042cf1d44189305c045068000), uint256(0x1c1b49b2a1b9f0d619afe889f8265cb6ef2342633ae37f06cb8b748a35d52b01));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x07ababf9cb4bdbe9262ef4f484a568c9e1b08fe6320dcfeb9d50c1e058271e29), uint256(0x01d8170f0d6b9e2e4213bbde78f588c1a7eb08c085fb9487775f88d1e7836c9b));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x2dd6fa130a7c873ff5e2878c708083e9477dbc82c0919d14f45ac1a62e0008bb), uint256(0x0a684388fc7d02ad41659832e9408441d0fc7493d13a01c15983b65db8adc00b));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x00841ca7412cf0e773ee67cfe40e04a903d3b7dd8b1e6e5c71c0e83e354ec318), uint256(0x11644b997ebd7a8cb025230ea36492f1bc6f18fb7468c6f1ccbe7aad387ecd58));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x1de0822a8c660a61ca0e5eaa4f1820937b60c71a8e8cdfa30e1af23e78ce9e7a), uint256(0x044059d8de09c20c830bd21a1cedd95196f7aaaecc8c3d1fda75632ba14db4fc));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x00ae63b510323d3bf3404d3c452e655ed1252afdab5bad3bf27cb67f9573eff9), uint256(0x2b616922c9609e3c467f553a3312fc330c7608353551afc551869acbea1337c4));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x0dc07ce4f37e4645a04d9cb75ac9e142736fa86d766d097c9b510ffb9faa7359), uint256(0x1304cb089ec80e44401a2b474d34c78db5f1bb19ad0b0511921c1f7feb941603));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x0d1e9abe1c3f181627140b1b3fde50104a6d42ba11109d5e1d3401c9c7340ec3), uint256(0x2e654337337e073772c8e08c4fb825d4ae694386c9da4049057b242dccc1399e));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x0eb7a9d0f398d702379189b3f9a110d98cbfa9565bcbe36314a84f4a7c277002), uint256(0x24c943d79b5d35a3452314c6677f148a8a723c5beedbe7b8801afff94a048290));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x2921fc2815294dadff41cbbf8a1772ec74667c153bf28144e92240ccdc9f5606), uint256(0x2d1234b2125c8780496a3d46a2aaa05a69029cb118dd4a9620c464658986eb6e));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x1643d157c518aec4381752239666b01b23f0fe258dedbab68fa61c95c68fb962), uint256(0x18541d2042ca486bef9f94952118c800d992291d52732882595bca661f18762a));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x133609550adbecbcb532242875bd87632a25692d3e6eb9b32fd417104bab9deb), uint256(0x27d6c059935f256d3a819c2506079bf4fa5261bc00e29ba56d9752d8ed182379));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x11070a2a79b6ecb99e86dd4c7db1b59fa042ed008e42b00acc4f61df5b16380a), uint256(0x275b86322fbf6bc60b0f565aae0acdc16804dd2069fb3bbf7fad5bca57aeb115));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x00182009bb6834eec622e319f941989c9139a1c0711202b64e01e883cb0273aa), uint256(0x29a6b4acaaab9b24287e9ce5a987b19b9ea66f00d9c60abba574b2a90824dc5f));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x0704c92be43345b46e32f4757a190ddf2154bcb120e5811aaa054e1a60853a0b), uint256(0x24e7701f2bc4dcf18b97977c235f41b02388d1cf39ae275d19f410a76f0edabb));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x0db197c832db86b76b47b6115267e3036b8755660a15431da98978adc297cee3), uint256(0x256666a050edc49a46774a446f08e9a482cffe23204a2b16adc98c0053f94bda));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x077720bc284e62dce5d5b00883aad748938e29ba9deffd9302b5ed038120688b), uint256(0x1c1e3b4eba9b30c2b7d096eafae12d42355f8f2998d781decb467e3b64905105));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x1db5ddf9d64394658330c61fed4132a74ca09d2f257976154ac79d6671f59e4d), uint256(0x164fbf0508dce5d5ee16fb031f119b232f6947d987eb8f55f85fdce799cc4b74));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x12c15ab66f0a3fd35cd17ddcd13b262e92b2438568ae0c5afbf2594a6dfed17d), uint256(0x131f8e896eb8226a82526964b8950877b27cf87b5a46608e6226be6353e86b9e));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x115b3f683e71de8a5c2d3e8c31997bc5890c543d3b48c26f7be4cd5826ffa0f9), uint256(0x1240df26e4ae94bb2d1cc05d468ad8ec317f3c960cb5648acaaf3fcd641be0a1));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x136302cf964e1eb45a273ef458fb0833ea7c0a8f1dce6fba7b89d23b93bd37fa), uint256(0x111a61e2585d99646f69237de19c731304d07dd61cfc4039a3e1a59cb5e79fa6));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x2b9a66245be438ea13d6ef6c3d5ae759608097615fd77fa2630e101fef17612b), uint256(0x04b35c3fbb235a4476e9733761427b76b93fba1fda67347ef9a3c551bc93f3f1));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x09da85798caef360fb01383d5a79d5d0d8f6153f092d9145f2cada659ff73b1c), uint256(0x04904ea0f2d7d2805c6a3a1adba5339bb14c31d98e4d488cb132a066fac2826c));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x237be077a8bbd70999d9230b34f29701de4da71d1ece8c8d3cefd29c358f7f70), uint256(0x161a76f8dae5af3aeff94805ab9528746ee1394d9989cb0eb62733c493ad01e3));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x0f4fdc78421b3c48d1803c82e68ea93a86ccb5da3e98899d0984dfa0ca670d15), uint256(0x0559f0ed2f0617954b57c59d29915c63989efe1f7d38ed751b2a96ca115e8e2f));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x27d8d852be42b0f203a00b766fcfaba5bc44f88deffea3f5079583018fbdff28), uint256(0x24f7b7411ec1f336bc15506db424fe43f1535d5ed1adfa2908d2e8911f015b96));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x270481ebe72b6dc8f129305bd05d2805db673ffef4a83b1303b192b9a681ce9b), uint256(0x2f3f16a67de4584628f5333d6689c8aed901a520fe04099be6fa4a401d118a82));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x2f0c30681534cbc995aaabf1206b700651041cac9d49a95ab29c04ede346a9ed), uint256(0x255bf34d6ad2260aeca0a684f152b27a975554c8d525c8cd88b126491e984946));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x2ef4f45285570e7ca48dcc42c7a64ae2b36212a00fb0005c3bab37fc761edeac), uint256(0x22f965bc5f60a34adaf5320e1fa3bb52946a35f80c2f981426be09a6994d3328));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x044cfa8fb4d27c9fda7aace137c1688bf983e3b3f4446e2ed8fa0d82c18b7e8f), uint256(0x17f5179a314661f4aafb8fdbc6056c5f181f7732b0e8d13a2ca8c259e174ba13));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x15f4131ed88c8cd4cb95fb531188e07d27c2755e5baafe2f760d75549070abcd), uint256(0x26848f0a17a363e8d101fb08bbb03d3e5237d2a09a900d949d87357e5b689ac4));
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
