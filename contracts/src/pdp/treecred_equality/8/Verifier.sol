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
        vk.alpha = Pairing.G1Point(uint256(0x1e9157ff6f075235facf2eb3468a6a8120f68b7426355b3004a5694def9a4618), uint256(0x1c4f226b5ff55e1e3f622979eaa34cb946086243a01cf8937bb24dd92befe169));
        vk.beta = Pairing.G2Point([uint256(0x067e33751691bf5c7e467b1e69b086a873393e9542f094d35bf4eab7564b886d), uint256(0x0e014439f71b4fcae8a4092a97adc79743d2805025b63b10bf0bb895fe2f074d)], [uint256(0x141f46e907110a2897eee773983383cc0c794c5be552bcac3bdd44f92c0d3e71), uint256(0x28eb53df8395eafc5eb6648b911c52577c0b2e2ca126402c7fdd78e90c433773)]);
        vk.gamma = Pairing.G2Point([uint256(0x1c93ad2d73428cc4893da3830f4f9fffc4f652647405f18926cc0d23b2a8d583), uint256(0x2bf09056933af86eaa21e2a8fc0596fd438c67f779f084ae49d344236441bfc7)], [uint256(0x2818c0d6883e9aae05141f51269c0e53c9f0f050ac55d67d332910b691d2b0f1), uint256(0x1d9b5c7369da701b0d17c1a3c4906792197a105d32fff6ddd424991c5e284157)]);
        vk.delta = Pairing.G2Point([uint256(0x25634d1d684fe9d35719a1b665b2c2048250df08faacd3a4dda8e20437461da6), uint256(0x1589ad3b149b1e5b0868bc44fb00ae774adca7d5c1c68d78b34176f48f7dc05c)], [uint256(0x23e2d0d126cd1092b258d27e462cc196724a43adf432849b233696dcd3a66444), uint256(0x2ccd3d7ece4fd8153dadc8c19b8214aaf228306221d0368821e30da2d28e42a0)]);
        vk.gamma_abc = new Pairing.G1Point[](44);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x10d12aa5850f009e5d77926554dfaf644a8f262b67a069a672855b10550e66cc), uint256(0x037fb270bba382ff6dd4813b1b797592c48f96806ba2fa305484684f12edd9e8));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x04c5e2d81003dd6944301c36ec8723d34cf362aac7a4b28aca41a8edeeec32bd), uint256(0x1041896763f761668f996b5474723536e68eef1c680b48b4e4213a6aeef8f28d));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x086a144b7b6b099282a20b3d8ad5f7df3a5b711ecfebc7b51e20654324ec8f36), uint256(0x1042b5fe526172b8564bd7ed904ab2f07c4dd833949406679cd14d48aa0f440e));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1ec8d5c8f39d3c2d5d3039180906a42b6ccb5a71c22e84a5a47dffc960b057d3), uint256(0x04c7bf1487690d2d2ca8542e7a89b9077d8742421d2d6f7dc6102052466d8d6d));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x161d6bf8d86cd436316c888fdf44b3c4cf4cbb5cc53ec39c9847f1d8958793bc), uint256(0x1737eaecf872e3c32f3e260336f98186f86934c24f55363d6321e3c12096b0ca));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x274542edc2cd04b97eb83e5390a3d1bee5f24e87be3d67d872d910912a02e6f9), uint256(0x09b10b08772addd7883053fe10fc2977ee3c165ad6e911d73227c333fb6cc6f3));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x05996503e3d3891031eefd85c75b542173f86e79924de92c838c880423daa9f8), uint256(0x2de765da1245118ee13bb7408308a060beb0b5cd474f74f3ac969be5e878d618));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1387728d51890c18ee7837fd56aa668bed884267f78b99ca7b809501e2d2f163), uint256(0x1231c7a5b3200ab58615daba69a55903d7fc49f51fc47df01ed72d6ad757e84c));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2c190a222c4b09fdb1d304e2037c79212af27cd50d7a2f1d3a0d8a0de6be2ed6), uint256(0x03e04779217921e81ac8636fae338fb08c106fd698e03d7e26dedfc6c3e9ac81));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x03d0f2929d1b941d1b93b6afbe3687655e69089607d8d8046aad96f9fbcfcc16), uint256(0x0c4130478f2ac6691e56a67596e524e9483ea71dff53d0b4563c9e8475373756));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2d044781543bf254d77e5e77f0d8b78813f7a21e4ea9e921384b8a64ee0495ac), uint256(0x03fda1992c1d3a55f07405211482fecdf991467e34846acb025f83cd5f30e9dd));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x165bc26438f74cbe5bd23064214557d1cc62eabb8b574eb5cca84460c02e86fb), uint256(0x00a00e2640023a422068b9e87cd18aaa351d1ae3c867443b27349ee009600afc));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2ed318d6d21549b781e612521bb41f0a06de8728e0a8ea09775bf3c3af3d7272), uint256(0x2c8cbedda108c225be741410f40cadce0ea6b01e0ea61608c720138506601de6));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0a7ab1236f26001560c0494af93d7fbab0bab1aac5bbfe46f9ad01abf26c55d4), uint256(0x07a643713082eb50f0ef3465cc89b2f411652604dd56ef0c056871d4b460d160));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1b392ead4b095c1fdec10e4f0f04df26cea98dd7a99a5c94f45763d6f0243b64), uint256(0x22281a2b7cd8db442e1885198de5017ef9362d96beb2f0f58943031bf0a216d1));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0e2aba8e9cc648f639116a01dfc79ec660c58a65857ebb775728ee9e2afff50d), uint256(0x07672df9b68482f9d2033c2d9e20a549a4edfb1bf75145a6613e434bad8a600f));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x11ff51a8eda4a030a336525e53d0a6bf79e1d9a8d1a0ebeca85ae5931e291760), uint256(0x2bb62ee3fabc70bd4bb8f755a6e40ad6db8eed229b10b758bb9c2413a6a30c10));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1bae0eb2fe04ca23351db7528cf2667007926512027624c229e69936bb8960f2), uint256(0x2b8b37b56f88efe57595b25c34dd9efcc65d2692de13712e7d9a878380ffa1cc));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x183b1c7d65c3f68b8e3dd3b1b235f671214c8a543bdd863de60052ce6a285a0f), uint256(0x1dabda6891b6a721b741741423db9276add655196c8c7f7dc703472c738e4330));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x08fe97d3a489906586c683608975f12403995d73816f3e9102dd0a76e63bdc05), uint256(0x12483a01ae87e532123c860c2b2a67e2e83a43cadfb72d8b826cbb5346218cc3));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x26991194335c04b97b09eb8cc8f14cf66df2db586cc5edf5869ae3db0f15ca71), uint256(0x0a025e8ce1845a7469d63ac5f60128b149b5cf937cf55c109fe3d242d1b1a7ac));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x0c8c9c6cc55bb5e7791f62e8dc8f614ed5711787ae3a677a79e02fc9a46b7b44), uint256(0x1bba6f6e5e1415ee0fda8f2eacb0c2ad07207ca9f1f9e1cef733a97d31b238ce));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x1b1f897847bb3a1b268627b64696387121fe21cc53962a55d915ab2a11241e36), uint256(0x1c35853b54032a517d30b282e9ce188b30a411cbbb5e8744b0471fd8ff081506));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x13b842f32c6b919d0a8a2bc0e15bcc916aab2026bede0e106e482bfaaa240185), uint256(0x155bd3eacd8793e93edf3f3b32a8d3d263fac7e20eb68bf94267c1865111fe2e));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x300587308396725464618b8ef955d344f2d48f548eeaeff077645ecb1f4db106), uint256(0x26a0cd2f334e542ba6f719769561c687b428829d4bf8b74488d65b22eb7d1acf));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x2060f08d830bcd0b25825d6fc7cdd4398524aa8c81290a007881535a6c1b6364), uint256(0x199836582322a426f184bade9158b2a257e5fc99cdd7022a1ce5fd79bbfd9a94));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x031704e0ab95c536ab6dac32bfee1e8f907ce3366f52b574bd653422cfb2a75f), uint256(0x0fd89ab772030e43cac17295b168666450414f327b9bf70582280c80efed5d5e));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x047701a65d41aa3859156f968453c1834ffcf59de6b96484f9a902b7810fd2a8), uint256(0x0ad560ac765baf105eacc71e5bb4c2e74e44a777eb5ebf5b10de7f09c2b93066));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x2ee50fb734f281110dc8d7e1a64213e7f6f34155d4c08eb4c1555aa48abf3064), uint256(0x1bd121490b3f380996dd547fc44e96cc4c8b14e1cf0bbde25ccd4813f2f8b106));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x02dc4713e4738cf7b0c52da32e83872ff4f691a3f60b8cbf4a6c2706b16040f4), uint256(0x03308338e6af886b8af16a2ebd3f27cc1ac251b68d239b8f8e2e81eaf1a7b2c3));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x0362d7de779b128529625bf5b3dd484074f7e563576467cb010298ca79b666c2), uint256(0x1cbd4c42f7b872208b031d312c1d0437e8eeb9f29007a5f4a50bdec9cfd9cf82));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x1e1427e697644f9336382b243e23aa449fcbd38a004eea4f7476d71ddf9f00d2), uint256(0x245d6411960e66a764dea933c2da975e35f5849b649bd208a583cf0c6a297518));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x16b1fbabd2dc0b2edbac406a932d4166b333f73c97d724a85ff0cb6644f6876a), uint256(0x2cb1b7bccd2b265ccf0206d9369088b2c86322148be93f849c47d6ceebf34867));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x188df24dd084f9c5b880e4b8945b2254876a11d4d6a62c1dc675b20a79f9119f), uint256(0x2fc08943733c3ec30022e8a80e1ee53df34715d95ecb12b901e3d4b6a51aa824));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x1a3441a8a191eb6b203550276a53ce650ab819eaf1614e4a80f8cf4157743cc0), uint256(0x0b200b138c391f7aa76a689016c1a338260c5ec0ed20519013031b835ce6d077));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x07a541ce9da91ed7901b9088253af9466f9127c3b8e46b189c6d4836b37010e8), uint256(0x0f6447a106ce2e419982cabaf431df2758862b40a9965f6a95258072cfbf3970));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x059ac8de455b77116031010d6810e3f06b943c9d2f892655d0491a61863252b3), uint256(0x2d99d8699249322f9251a861104e2af7cdfda071009d6601d5db81b07d6890df));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x2c608d32b0a7c0535a91e1124fcc9273cad9ef22a8457f05dddec78cff10b905), uint256(0x1cfd8b63a27341da5dd9f2586f15dddf3c172541264a853e1efadaf1c84f11f0));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x1822a1e78db4460c396ad11f2dd208ff8f5ee3087b334ef7833f3696edcea403), uint256(0x1ba994b65658db16fa71be87fbb7d59633c52ad13564615ae88e7ecffc025e37));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x0eeac8b04355ffcc1d25c452b1f5464e2c7edd016fd258c3f4e469aae3be5f63), uint256(0x0fff9d02340211167ee8838d4cdb75c5a3c3fbba645c100be9642c79a6442796));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x2c682020a057266a51e2b9e33c3e9b9fd624f769376407941265c2f982518971), uint256(0x14173fefdb68beb9bc07896eeacbbd4dd0a8b88f73a4735f8a89dda7189be828));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x25119efafd3457f8957d099f95efd7524c6f0947f87dc484949b364bbe7736f6), uint256(0x24ed36266b476ccf432f1335d750e4088210b0271c286b2b995283da4b697d5c));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x27eb669911a64c81ef9ea9020d4c5159acf430153b1c26cdc95b3ee7fdde6e2e), uint256(0x05d9eec08b45cff1f4eca0ce460776ef17926eb90fef578c81256a7e5695b883));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x26927623903f89cc0db4a8b47442c11b1d72f3937ca1b8b514236d76f628f88a), uint256(0x0f50cdf06a440ee8a322f9712ac2bc5e6dd5fef3e10f6960033972b20931f160));
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
            Proof memory proof, uint[43] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](43);
        
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
