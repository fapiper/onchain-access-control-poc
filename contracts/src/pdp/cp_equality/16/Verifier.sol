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
        vk.alpha = Pairing.G1Point(uint256(0x1cc8c2e431a464ad81dce5899acdd0edb746afd464cbc193edb58eb75a8e7220), uint256(0x03af40cfa529937034be2ba4b87871570f173d9e3ddba6e18ee524c3bfc01616));
        vk.beta = Pairing.G2Point([uint256(0x1ad61f6822f0f2c55de5ece3b14ae35d12f40a84d6b5eb863ea42142ee90b8dd), uint256(0x05938ce44309641d9ae514fd6c17d3e6ad381f503a6b6630d903c9657342392b)], [uint256(0x2a0643ca69925cd4436da97f10b6ddffa9c7602f7cc2fc96611253fe23c0a3d4), uint256(0x293142a1a8375709172fe0a959d6cba7b0667e44f02ea9b27d4cc6fcf1d6203b)]);
        vk.gamma = Pairing.G2Point([uint256(0x26ee881d2b61ae03ecbd9dee458c330367cb7f4c9fc01ad98e051db308791dc3), uint256(0x26508b9711a6a3435769052f145634ead887c13319217eba4bb4799e678866ee)], [uint256(0x1ac25047d0fa16f7e199023e03c070d92be74c02bb997a75fe2218e6a4474cd8), uint256(0x242e5b3b111e1eb8e203ba841a6b3f07d414a522b3d936a971fd61c078fe4e5f)]);
        vk.delta = Pairing.G2Point([uint256(0x1c44ad32ab6a6b8b3d1e13ede399a4fb9f91c817aca301cc029656a38caf1e2e), uint256(0x2cfeb0c50488425b41d29ed886d146a0c0bac8a87d8c87a6676306687053360f)], [uint256(0x21183fccfd81e6c7e71618e9f260fb0163b9b9f7e2f029810b3dcae5d906d4d4), uint256(0x043a69e9cb9488a358816b09130ca555904989801bde71e1a1a9e9ac48d29639)]);
        vk.gamma_abc = new Pairing.G1Point[](273);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x07f9343516f3bd6bf5216b01f1ec5ca0185ca82b4d051c73aa339d25ea54be53), uint256(0x08c1a82193b8d8664eb25045f5e7fc4bc76548340110c7eeed9bd0b676a361ce));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0111fa6501193914389a2ce01c17e4ff9ec1ee45805c722c3c364c0480a5547c), uint256(0x2ec74614d320b2749d438f03955e90e8df65f60b064e3f9c4a1ea92535753fdd));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1c7c69ca9c98e3d4bf43d4ffb31b103e72bf10b89df02d824d03695aa789ca4a), uint256(0x27aafc82a4422836d515756d977463294bc94c6b9be3427e9d662b63aed889ed));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1d6f171d107302ec01863bc390c5dafb6b4d32fcaadb3345aa410419f80762c4), uint256(0x1d5ead5c1e02f114d84e74eceb60c795837a04ac28e2da2373316b2843320495));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0eb3d3e8fc3db197d312a7ede43bfff30850932919328d95a7aab8d0c05be1e2), uint256(0x13806419fbf42cce7fa8bd23f5c6cfa03c01870e6a2ec0674ed149ce1694da5a));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x27598e46a1ea608e016923b0333de56be33218074517f8c7d6ee2d83675ca414), uint256(0x0c2f0ff6d0ddcb7a6c77bc78924c960162c79cf00b266a775ffb931a95c2418f));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x06fc09e6726a7cf17f8632b6c43e368ff11888c28715ddfb2f25020c7d74e74c), uint256(0x05954213db593bec9f7f3bdf446111ae3fad126cdd0d6ca53d8d485bbc11576d));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x111820c7f1f32d90891718b382b2be84a0fc3eff7ff4102c072b218c30606d42), uint256(0x011d8e9c3ae0e5aad88fd3cc754ba5f829e697bd074e362283f3d2cc31f67f6c));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2a120f27819c416361cab8c66f5c98bda3b368b4a40595f29b83bc5601bc2b9e), uint256(0x293609cdf58354e9d15e0a099b8088f819059cc6ce266c58e30db9d6c9856ec5));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x299720be3280be46f3c8cf48b2994317e2693a54f157b81827ffc0d8e711c770), uint256(0x1f695621cee9626c9cbf71ef9ad1ac194906c8f8033a4c9b32defe102fef8177));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x281de3be82945dff3406cb1d59b6e78896bc7640a2cd658ab11ed66439d6c4e3), uint256(0x2e7878bb68dbcf23d52b0e3bb81d1a53243576a88b5ddff206f2adf1109ad204));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x275f9960733e954be728775f1d60c3605bb3024329a9cb0b99dc645f899353b2), uint256(0x2c07fe2ebf1d1d7634bf8aa7298588d0e772be2fa973efa46fabe970186b6e76));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1cc58d8723d823bf0f86de626c78b6d6455f05b51c642f0ef792178b50e1da3b), uint256(0x1e715567c71ba54c69d9c75c99bb044ea6a4b8e4dc70fa62a884c87d4d4acb24));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x09fee4413bd511f68ed3905b4d58e54bfdfa3a967625707b863242a9d9957030), uint256(0x1961f11d622d166357814fc9df545d6aa6d53cd5182677c2d7573bd4fc21f4be));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x04ec40b1f77413fad335d1ae015f74e175875e8243c6953425be552875af39e5), uint256(0x08813864fdb620fe85ed15009d8e37cbca3f74fc8a61c9dbfed724541a209fd3));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x09be40f64f622c2b7d588d1e59028bb44023b320e35d021104ed397b595767ef), uint256(0x182ae77c938e128c15d6e17b58b267a6aa0fd65185db7b516f39b7ae891e8729));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2f9909076182504a0bcbb4e38952f03d67257f721b892b95b0a25a9c6a63cd04), uint256(0x13abf9ad082d14ce49641eab2d59ef57ecb8039d4f577ffb141d7aa7d4bea1e8));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x28f4f2230515243bdedc05080a3365e14316502059c6a1da0c4d4fa6efe70914), uint256(0x2062922663391dd3c9953e4dabdf927c67e3b3d3d3ad5d5454f083490c852506));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x0a68aca1f1766be6ba2949bdf1af11fe62b321d0e9968979f07f2f9c9a788154), uint256(0x157fe46bbd04a30e6f39bcb72141291071bf0ef3c112e96a092c2135c7f0318b));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x04c3f0310cd369169b419460cfbaf95db91f4dd1f2be4d3a5418669fdff07589), uint256(0x28fa8ec87338c10f44f235eb039387a3a3cb194fdf55195d5df125d9f939beae));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x17649850590394644e6325f4d2b229a4d3a2e3eb9a386eb8bba2b5a8b3e30e89), uint256(0x1a6903bf9e9117205f866f944f79d0e632b5303e0b6234f31001f438e6edcf9e));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x2b1519a6d845037a6b601c31ba363ff4497b9dd140014e01efac27fb946ed715), uint256(0x0d048098f45e1f5ec7b84d6e0b781f819d9bfa2ba266ba5e763cce3419ef3a71));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x1517080e154f3b23ce721f280ebde7e225c20d11d7d5da910ea0ef0f51a0a2af), uint256(0x1f590b8009e9f889258e86fa68a0d0b45bc5f957e6aad72d6700462fa5bc2296));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1d5d11ca51c07efacab0bd8b91b7df811fb8c5eb30ccceea166adb630f1aff45), uint256(0x2fdfa30deaf64264ee022a9c2bcea7896cc1fe30e98d44685409229a0d6304cb));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x28a0a24a862d25cdabad0dfde08b0aff07b974e79967f9f11a631564627f3841), uint256(0x26e04ecb74c2d67e4726c45bb2fd03de4900ebd08955fee0a7d81db16d3fe98e));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x1bab6a15cf36ce5cc20215a8bdde1b41bdab77149d18fd0d442f24897fba2fa9), uint256(0x2916854b7252cece8508f636255f48b43feb26999ef4f3c50359dbe163a56389));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1289b0bbeac1de971597984ef1a0d3fedae84793c8577db46a3741b6677ff93c), uint256(0x28d8e92ef5d87ce1be0efb53087d9c3da1069fe8ac27fa5be194493e4def2743));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x1300e684d842803b03d7218efb70c9cad66d3ff72211a34db53c625aaad7f28a), uint256(0x131cf6bb3ce3c04f03329d535d62eb73deb1509665d0e54c9cee092148c5cc79));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x2060478befd9ca6d28788aaab923ae30276244aa3b99e9744eb58809816154bd), uint256(0x154068b9755d679688cad573a06e79890375f875bc4c9eab904ce4cd6687eb08));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x26150ee806f2e6c241fe499d46684bfdc0afe0f21df118210423a96fa6977ca9), uint256(0x29f73e78cf4ac4f7fde2b1a7bedb82dc0bea68805329711765dc8a5ea92968b8));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x09bd1302f6a809e83ed7a69f916d531c44f190b5d176bb5284b1534e94e4d722), uint256(0x17372d06291cf9d58e6358d662604a20792d0b44a3eadcc0e8c34d006d831cc7));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x295b5d7de9c88c04b3934776057a106039170af39ca2808e089ce9960942132f), uint256(0x0fe306994599b52e17a6032483dc75f91ac2890038964c06287e2c8882e97f84));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x02514ddf36432f693950e61cafd4a148de292d6ebb153ab6f52cc202d4222b70), uint256(0x05b99c1ee28eea57ee6912345ec64e770f3d6aad096ffe8de24bd65bdb955e34));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x0c8bf0d60b15ecde17fabec0e388b3fd0e0f8af8dd587b520dcc821136b8739a), uint256(0x27a0d1704da2bf8e67d6c12fc434ea04c59d47bb3f50189ec51ba7541a35151d));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x2c5f21649c1f9e590fff974d5d32f8c9f842e9c673d42085c0b74d1d2a28016a), uint256(0x277796685459d31f4a8a07b7b7c0982314a652af7c0561be5999970675cf33f7));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x20724e63f5185f5c438bd64193ac9e8a4aaa5d8711de79408e8f2e3457920dbd), uint256(0x212c8f2cceb13be1c122720537121d6d86655a18d920c8fab1c3bb18b65e91ac));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x0bd9ca263d321fa8f0cfade871fe6c5d6303ab3383cc69197bb08acc88411ab1), uint256(0x0ba640c8b77cfba191cb4a815130339a9ebf9547f564337b278e1c8d12796bf0));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x2406c4d6e0d45d47bb99a6673eeb440cee4b15f0ca3a230377a4168683130812), uint256(0x12d3e331ed60a61aae39b866a9a77581ccb71a913bf7806acc67a485cc64e29e));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x26e30dfa78aaa6c0bd89671640983d22f8774b8659b0564d8f1b4117ff599257), uint256(0x1b37c2c263eabe7525fac9c9b436213f16698eb8a9ebd3ed1fef86740b88d44e));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x2a4fc39cd8baa3bcf82a26514ed08bf6e049067d7ded5be7a6f9cbe799e4a48f), uint256(0x27fbad10a17411eaac15a3d4696d0254adda0cd7bd6b5f36022b445b10578e4a));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x16343fd58f1570d5b9d30ee139f2185286a87579efebeeac82e83174b20e9bea), uint256(0x1b9367cf701c8662e90030121f60fb6f4cafe90b8106edbede1b9ca19712980a));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x13e73be113ab9647c232c479aa1d53c1acb459e1c246bed1e1ecb30d702a908b), uint256(0x02ae58f87e3dc62fcbaf677928cf635c3c83e667daeaf5cfb4369ee19c416802));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x2f79497dc94bd98feb9a579b6a9cea94a22d2f6fb8fce19f76d833297da9421f), uint256(0x2177d3d1df4f26cccae9733d2121f55366d0bedc10bec90d659d802c796892fc));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x054c3d510407bde8e5438b7ae7b8a9ab0c6b1b836c55ebbd74af01dae9f9cdf8), uint256(0x270270963a6878eb5615594e30c187d65f9b8459134730ab3c2f3f757bbb89f4));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x1e1d65452466b2b5c41f780c0ffdbe0542287f96a6bcaab7e8f71d4159e31a71), uint256(0x2d51520d660f4736ddf93d55e9bc13a5155adbf473016aeaad43662e4a714ef2));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x29fb6c2ef3906b4a0d0a93e9a1d4ea622ac549bb237ce5af5a436aeaf30ed492), uint256(0x034d9d3f51d5c7a491451572b642cd4e97ea67a84adcbae369a4246966369696));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x13c1e9df033ee73ee41186024b2c4ac98af29e2da8a27780ebdd6dd05ca42aa0), uint256(0x0ecd8f0223c7c3803a0d1a7e59c3b85f422033bc760374c5cdb3e2344297f700));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x1c56164544dcb6fd859d25f650869d9b006fd682170e83cc117a6659d5cf9417), uint256(0x149f1f8ee05cd1a201d7cc92c9f7aafb0296f8e8ece580cd0c9723d3ebfc0a52));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x1ca46bf0e3e82b2d05b519072af3a4b8e2b672bad8eeba663e58add9e15e25ea), uint256(0x230f956a3bd3f5af254a6c66024dcba99bd1cdddd2096aa39dc25b61ba19ad42));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x13feca180a854e7f00a844fdacf954f73d2954fcdf2214d5874d4b5bf1f0fbf0), uint256(0x109eceab496d7cbc490999676413073a420c7b52d9ea5c8cb132619321c3a65d));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x2ad67c95372ce45a2677345d4822229c6c7f2bc7a3a435ee236ca61ab34ed7fe), uint256(0x07f9df5052cd634290c2a26720aba273dac57b5f2bbc4882d4bdd556dea195f9));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x1907d1bdaa6936ae63718ad6c0e369e56556559a6fafceeb74a56b5ec00d1602), uint256(0x18d92409c52e3924e1355d13ae8deec59877f759ee839cbbcb4b6ac7d6f47b53));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x163be233f1c39783f98aaba2fbc8a2a96a36ed12eb2a23af19983184552ab580), uint256(0x019bdd1f7391c0bb6e8c9792a9395f96478d7a0ebf8d29695b5c33521dabe1ed));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x121ddaa3ba48e4513a010fe44d06c7f36d362923528b9189dd5b01b26829b70a), uint256(0x2bb0bda1e62514f74ba828f53a77f44566f81d9d648253a829363c45a6d612b1));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x12b75c38798f3ff5c83ebdda9bacfce0e69c7e30a277ca26ce54419cfe7efa07), uint256(0x1d36354bf7fc210d2d2b0a79262bc51cf4748581a54f58453c217dd7cf77cb96));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x2170c9fcfb10ce4e1c65333696986bc91ccd858dfd85e4848fb2f17282736066), uint256(0x2650a5303ef57acc0db59463aafef85d2ec5582ba760560b24d30c082b3299b7));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x089d12c6f7b88107742e74620b386297eee021bdcc8fbeba1ef41686a1dd5766), uint256(0x0fd7af8266f9aafd851620bbc1dedfc194a1b7b8422d7a0f1fad6d89f7cf3866));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x2d0d9b2327d05c21a75c25de453993e011fd80e2f1c76ca097011053bca90e82), uint256(0x0649744ab1370048114a4b32860ee9e0cd0ce23b43cd9a29489f2f9c651ab45f));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x1ed44934e99f8c53f1d54b8b53bb811e7f07377ca2063ebb6ebf6dd752d69716), uint256(0x1f237d8e0e1d9e121bdb5a997ca62aff47844a8f7a67cf8c35e56360e866b1e7));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x13b0b06b029177a3e4927ee3c1bac533ec82ee0dc4eb997df9cd2b98c5116bfa), uint256(0x0df2a474a4949f9a1b346b41dc917530cf9098fc6446fee5d4e0378a44f2a4bb));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x0314369dbd3d15576d6e31e00bc83c87d3eb6e2bbb73fd48dfdfd0d7b98c0f18), uint256(0x1dfb27eba2959ce5d0065317891738408c98a7e497ac35770e3284db481ccf8a));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x087f3b3b80ca792b43a5f89af61300aaf3555c4e54b93ee906552387111c6c44), uint256(0x263aa6fb66321e049aab3ebf5bbe37e86ae4a13de38fc8a22696d869e08c7fd0));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x02b6c44abfcd76f81125b2c7af0d637ec4f05d374c4eeef3a013572503330d9e), uint256(0x2606eb63f69360dcdc625935612f13beac6fd165c29a9ade53c123212002fbc5));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x2d8860ee0ec6e3b9bebd5fc7e7b90b7cffedc103dee8d273c99ca70cde971f5b), uint256(0x22cacb692ec54845a49fa1d50339c7ef33b63edc2b61dcfae7d1870ce6264d0f));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x16a2a9368397ac40ded1403bd0b6e510ce8ec5cb4a5de4f01aac53901b7fdebe), uint256(0x25694b35d0285825e9c6ef7d27bb745f00598a0ffd0d3c81bdf09a00aa25dfdb));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x2143f5e50bbf641cb4c562dfab640b40bc5207d4c08e382649f3a0bc4fd08038), uint256(0x18ca0985d0e09cecf721ac0b778fda62f17acd73bdd5afb977fefa202d69bf17));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x1588c1162e9c904e45d6a4f9078a18f5ab47d1c65c3dcc5de56d9d7fe624ef64), uint256(0x1085c582a0f2af1fd7bdbda9629d0a7679f9007a40f964ecbc4f9f361ca919ae));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x0744cf5892a768d6669c72c8f07200517f7aa4c988a474a7b143caf114562d8b), uint256(0x23fcbd88962fc43032ff240e6c407eee1a8dd892433314faadb922a473ee3007));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x13dcc912de47805f8b5bf5a1fd87599c6507142aff96cdf5779eb908465bc835), uint256(0x1fa35c9b1a4a55071bc0d0232d798158a0e878ba3cf5a41cd37bd538045db1f6));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x162ca9de5e8271a896a576a7b749fb0c794af3124459a917aed3c24218377cab), uint256(0x21b11edd428d168e27584a8cb69ee89af21e28c05749fe5f1efd859d9b3338b3));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x28687d6595ac2f86c387393a52df842cf605c18776720a851eb7bf53b1074927), uint256(0x0b9a7baa88842c246921a12b70950ce052bbc0395e784727f76e47459b81e27f));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x1f66edbe52ae189c4393808bc80c8c430a26909245d7ccdb1c73c170abec28fa), uint256(0x0043b69370e6a7405a509f89437b7b280fba655aeffc5edc1a7d29b02f32de78));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x064e486a2044c53412be28d7b84b423ad71c9dd9d28dc0f26cf3fd026c4757b7), uint256(0x0687ea463b14987c6467f6675bb1c53069b2e8db421b9e3dc2b3f29f420b2a76));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x261a06419153328335e8a32b704b84b0ab0450b36a3659bf690664c56a333056), uint256(0x1df3f8be6ebf5a5414faaa49afad7057e7d3627f9f32de2da4c8153500cd8d17));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x254600f744a8eb6947b6f8618886534518795411248947f591cc8c2933946ab4), uint256(0x2eb5f130b6ff74deff667b499ad7bc2be37631483c4e953b0f7c270f21501adb));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x2c0e0ffacb639fc7143574864be6c30e5ad25f0c9db9d8eaee87010513db411d), uint256(0x278d4a7b9c63a0f67fe544a3a0033126368960df81c21ad70287b54a6d6a5ddb));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x26480bf04f4a3c9174fdb5be5f9856af960c543bd205fced54b8bf5e52d23a28), uint256(0x0618bde4a7ae35cf32faaa1faf5226172b7f8fd0083a7f677e6127c58959d4f0));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x1eee73a6d6ad140ee71808f5c0bcf710fd5bde2d62330ee785fa15ab2f885ab4), uint256(0x08576d7778b83110b3f8ccf0720ce7188bf0ecac9d528b2a4907dcfe103ae4a0));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x0e2e9460a3b4df9424d86834673d2c84edb9b4f3404615deed5b405adce237ff), uint256(0x0ec39fa5dcc346ac20bd737823e9fcb788336855cca402db0191f55c3979ea9b));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x2b23611b24ea8e1752cac73d5e9bcefdc2617d9f81e175096dabddec7ca7036c), uint256(0x1bd066e667aa6f0059bc429f9bfd86be3811da40fc98ebc1fd833f1f84422293));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x2596f735ff0addaab8b5a99c933985ede7a6ddbf76d861d009e8e98437869eb5), uint256(0x1efa7d7eb84a396f6a4c39bced79c99f4b13ed30a0641ebc5e323880cd07987c));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x1bc7476d8ee819f0361e1f520db7258c6afebb8f5d3a6ca87977f842f496da03), uint256(0x19a09ce65a68c04ac3fdec80c021234fa6411c9b2cf34f8ff0be7a71552ad7b1));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x0094d1eaa02634db6d80e8ff4958d84d5e14b7071b12aebc456cd4c9d6917524), uint256(0x0f87f868522e0a9898afb95a01631eb724b6d696ecc642429fbecadcb5cce650));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x0eebf72792c0177f282d3196b7138477ae7cc5766cef540d976bc0fe4235b226), uint256(0x0da40509107748ae970c3fe503f7e095c6d3c9faf9636c5b1a59eb2ddfd25df1));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x06ed8ac190fcff341c00f9a082f73cad52b896530429e255d73f078d3be1ed32), uint256(0x2c3463eec8154ae08697ddf55ef2a02004bda84817fcdc615ef31dc8cb600c2d));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x1be06017d9ecea044d4b915f79642ee3212c4af7ecb7c74f71b89fe8c380ef27), uint256(0x164b23a66b4f81f6e903b8989fa21bc571d3ffd2310b730bed23c6d5a32c5a07));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x0b410258915c2e45f76afcbdfe3773c35f730036ee5c3208b4ac972e078c6a2c), uint256(0x0adab2d75865ad80c94b15c78fcc0959e12d87576ba3f94f794b6373decbf260));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x0d70af708eb28f66c3f35b13e95f95d0425d60c344363e90e416388ab65d8ae4), uint256(0x276f9844803384b48a6775450232752fc736ff4ba95f1105b4f44de8cd77e0e0));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x23c2548da6c2e1cb241b933b6174b9b827ceabb1cf51d232aec7ffb0a50dcdf8), uint256(0x14f853f2c4574d765b7698612018e086df99adfb02cd54f6a30c8b5cfec31c6f));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x189c57cb86961f5cd22812c958658e3a66105b0ba36db96009b228f1ea0b65ea), uint256(0x0317786735372dd1382aa76008747d4c6f5cc491f0e5c8f3f9d0d3647c7d6ea7));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x1ac9b9951a498dfc4330f7d9adc171ee795ccc616f4525b479e0543c29fae3ae), uint256(0x26a9cd87fe322b62c46182b7affc4b5da1b98ae23970f410c604c3275ae9f56b));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x04b9d709be86f02c7495a9d50459ae1dc18ce250e75e8782c84b02bf6752bc09), uint256(0x29f002e3f6a1b5a3054d9e821200e5c33d62406d05d0306a0e0434487ff6136a));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x0f5e6b053e983adadddd85134cceb4e7474049beaab8324e53a5f9562038b4a4), uint256(0x10b4708c6d262f3aea8d6595aeb9f6acc7e10bb542e8457d31a5c6c6843f56aa));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x16d0126545bb8f695f43671bd560fd5de9e256d7cd3bdceaf76b6cd45f402902), uint256(0x061bfe631795c88b399b399cd6f5de68530b1380d1c1042b4f77cc38c8f598c8));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x0345f6fbc4797ace2c429c81621884fba48fdf96276e006b83e3ec28313dbf73), uint256(0x07184bda1b73506d8231677c7eaf9db9a7ccca2b4641d16b9e6ed27a425ffda4));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x17556dbea5d757627d8293d78fd6851f679ce0f0998b8844df521d40a2c09116), uint256(0x2bceaf5c0201f9d4b29d55349a289b2a1faeaeb7721091e18f87d49066b866ce));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x0642bd1df87a6fdc3709a3ec8ff4ab81a4ab9ba87c9147af9ca425d2da0549e7), uint256(0x09503d4d1fe6e2d99b10cc8398d85de249fd0d14cdf5cf06aea70d8a9302c0de));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x29d23d8e471318a42b83c0f845b2378c4bb61ef619bb81d1d791af2c8009be05), uint256(0x16d33ecf2bfdd57ce57786591c17e78b092edb8a3c2c5cc9f04d5a43201ac96f));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x092ffd7d6eef4415fa4a6263908e90c311a315de087c03ba9e944cc39dcbc7a8), uint256(0x300ab0c418a4754bab72bf406522b067a491b6988bb95213aaf8cf1b68868abd));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x2326197a743921d9cc62b55eee478d969d6f680fda95629d3c5bb7d36db0c591), uint256(0x2d5d40c0fabafaaab410f943ce6d14e2e264b5262e5b09df4d681d8ac8a4f6c4));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x25bcec2fd5d856219798a6c5d7455b15d6ce30e4c682f5c472a78927c58b29e4), uint256(0x122621e7f012b3365942ca2d2b7764680f294e768aed4b26aff8f7aeaefa5cf6));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x1fa8f5128acc54d3c01622e419b5b7b1bb074bac9a583f448f7a5722bb5517ee), uint256(0x2b4577502321583972f4f29a0e991d6b8dc2dfbb3c8573eddfc818ea7b874ee5));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x11fb71f2395e419e09d0f9992039977273d5113f3d92dabb7967e9896a277023), uint256(0x0f17681c7f281363570f61a051f8d5f535dbe031fe876784d0a9dc2bf67bf131));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x0efdd0b9ca170cefd53526abc15535fea758c1205c0a82e4367a26957d718e16), uint256(0x23fe259c5d52513ccc39610428ad531ff40d2f5027783867bdd63a1f432348c7));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x2d69897071d7d23ef2d555e2f52d626b170af5f83632db996303b3359de573c1), uint256(0x0eda24e57d0272512eee75926b8aa65617bee081e45bd125c3eeb1a636ce36fa));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x1ce1d6fff0dd3e1b4732af42304148f9de30083966e6f1bf5bc149e09782c60c), uint256(0x0bd403035bb855666b868a20bbd79a5983fc181e11c5242ee000ebe079ce292c));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x19c585e4a0bda10730e464c43ef5189e56556d635d7f8964190fe2d6fb30b4dc), uint256(0x22363aff261ff40166bc55b3acfc154bd7628c6b253c11e685eaa741d10642b3));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x21ff8b112d1df469e1c9f0eae10be2a79461e4dc5d3ea2720c5a7d9fac1e4aa6), uint256(0x2c34e09dcde6496328697100923b77514df3e03804a62f554877fd9a93a4403e));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x26c9b2e0bec5bee9302b3b71f6618e89f42d976b5fac0ab5d2c3a25e2666fa9a), uint256(0x081dd32bfc53c3ace33b0470b805efdd8cb0884d9c797aa96aec88619ffce863));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x1af9147df4376efd60277956969dd972ff05f24546d25f8030dad82a8dc7cd81), uint256(0x18835043d0bc52660114b7930c0d5b73fe70ac3a2ca5349823e3e7d6064a433c));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x10a5420539eedecda6f9ea7d19b4ac16e11185ad9ed7e864c27b2892e39bd612), uint256(0x09acbe9c2425ee1dd8f4bb821d322286a94f7580a844c2860d07f4431e75ae53));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x2ead0ddd29572fc2ff18e28730dce4393032715967bae7a8cc4b962bd263cb57), uint256(0x2e489051ec44150e187eab6575f3df08c5c75ef47998efc90bcac4f4142965fc));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x1bba14c276c63a05f53baa8de459a1844f6f9a21097d17f8e7bc20ac3deaa537), uint256(0x0207582bf55b2929addc7e7b4eb407cb897984a213121b93e5e7472e7a0008d4));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x1902581969af17ba3577081405be82096dbcdc8c8b8bf6baa81fa021503f2e01), uint256(0x17e5dd1a18b8e8183972ff25984e1ba7a17630ef5f54e88b9d0ccf9ae3103c24));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x1004c40f93c1ba089758cac94ef350e93862fe2be6fe232999ee6f84303883d2), uint256(0x1a3b4ff52a5b32ce8b144d01da8532f6051b32b2c45025e0e30f47beb1328e2d));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x0a6d62ee0aaba03f217fdbe20a249194a89875343c70a48c631f5b10864ae84c), uint256(0x21558b39a3440d39f67a0e57985094ffc3d8791482c70b811500ac6475736963));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x0fd019fbf6151eec9ca4ebbea4322a021702c3f1cecb2d5e5a9b252bb0a984b4), uint256(0x0dbae930fa4c2ee42a6e23b2b7913c80e05f0d7e51244cf08fd7e0c76fcbce63));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x25ab631c0c793019c612f97d82080b0dc895929a85f7a5a722598ae6ce812b9f), uint256(0x1de6a396f3b5db86a29e784eead9f3a52d3617e0005ee2914b6a294a18db7b81));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x1ec25ad7eb7aae9997e8a6267539fff8da2b673f7038ca3f7d4a646deb6b93b5), uint256(0x186323ace997f501d850ee647de4a4ed150bc80752de9e9815007d783298c129));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x0fd221de285d1ce429a34f137941cde2a8539778ec41c97d42b4689dc6383b7b), uint256(0x1fe0d3ef0c5c601fd38b02f1b8aae08cf129aec533335869cd1a5b1cf1f958ea));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x2f07e660458fb544069621c4d95fe67847b22427b96b4b3857ea41f0e239919f), uint256(0x08a1bce95bf31e48027ab0d3c599973fa25d0241f1689dc703b35eefa74a2fd8));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x1f93ecf033c3d2ad6f640dedb6aaa766ff670cd75e1c461e4895190130b6e0ac), uint256(0x09bc001997546fcad24951f35b4e80a661846abc34e595e644431b2e3223d976));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x16ced9d0772a1ea80eb12acec95cc897dcdf27109c8f67a796ff75c02e2d43d5), uint256(0x1980ac824c09c59a8ef8e0a3e95fcf1e15b45a2d8491e896424f2dc4161f9aa5));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x0911db74a5eab39b8898e9a53a5f63feef99bbff6db508492a20002944a01582), uint256(0x24d90c00fe4f30a280615bab4f6bcf4a927cf8298f66c700558132dd4b623271));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x013138d5371a1c07dfa794bb5a2c778fb02654dd44e36d6bbcc3ab7ce8491f7f), uint256(0x1dd9ce689642343f4e2af73c4442739159fe1639538c3bc81708b000f244fa60));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x219407d036d824597b1099c9eeaea32a3f496f28507f7b07cc2e35838c3948ad), uint256(0x29f2745e69b5f7d18272e83343e54bfe86863e592205644f3eaa20816d03100b));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x036b21abec7bc3eb918bcaa918984ebaaba526d5f4909b4419953a88426127e8), uint256(0x2e950e501330f93af23333b28f6547d3c2db5abdded0f436140f610df1b7f35d));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x15d4c765ab6bb803fe1f769f4cc24f2fa1727826fc4783dd16ab626d24ce2a91), uint256(0x1647f851e01ab39403d2d5f238060f6bbcf66de5ee43612c3392599fc95e3a1d));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x076b73e324c7df277bece0e014477bb58045927e433d74de27ea8a9ceed794c3), uint256(0x060df6b84e50ceaaada6dc062b38de5f026148389cbf791bd58d425040f2031c));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x2269395902039155a2888f95169af129fff73c73d84e2033d7a72652c599cfd8), uint256(0x1622a0b9c1bd2b89269ab6f6b10576bbbce81befa6f50e388597b76f9ea5c2c2));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x16d78f81d29a34626a890d873a727ea096317e82bab488f3b16fdce8269c9821), uint256(0x1c2e753785213099ea2421e69b27bf9bdcc5723a067bbba19eaa0cdf4d58f20f));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x138361ff055637541875f38c8badcfed6c61829c2e56490c9d0437e9f02a041c), uint256(0x0ceaec385c5781e4c731080e145f9195816e5914a648b0eaa4e5d1ea19a78df7));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x0244b712199256762923079e9c6606e01e5119268c8076e094537784d8cdd25f), uint256(0x2da5a1ff77cb4554bf07085cfd9bb2779b1c72cb67b4e734df3e77e376e674a0));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x024ec9960788d89d65b205c93637e10a08fb78933e96665bda7317f9c038ba26), uint256(0x16aef8cb1f1324659c456512e5f020715fc28006e71b499111d9c0f850ffda1f));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x11a86559f945fd7d231ace75f2c69f33fbbb7b9feb0b68920f48d6e7d376b85d), uint256(0x16fea350adc1cadf6c8f8c7eeb936d7921098d29f974b007b5f3e45e82146a98));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x2c4c014e4c6d5ac71302f730c2f6f49106ba242e5feaaa2331078d4e0bb6cb93), uint256(0x1026413f1572d9e37c2b48ee5fcfd182874ba56c530794aec3962e5f0a3bb8ac));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x0af5e486518f543930f369b56776fd94e5d2517c3ae8cc8baff6bdc871c82e2e), uint256(0x1ae890a47c31e6f8870712c55cd5a1c99dd90ecbce4f15b8d5f80dbac7830ab2));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x28aae8fc3b266a7932d9659e467f4b3d2b2855f5814a7c5dff7054b3009b9714), uint256(0x1146b110d1025d27043cfba573d01855736f952943b48eec6a09504cd4cee36a));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x0f80273d8c161d6712e06a9fc2cdb3056ccc672387479d0ff55361fd6a8ae8cc), uint256(0x1db3c621a3664f7c90b76fc3ec8eb6436e6b8a6dd1287002f9f3d1622d9f9250));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x0e4c1935b2008a6fbcc5b3861370e93dab6d5c7c6c9e24f534e70f88176f8fe4), uint256(0x23d442587d0ccbe8575cb95f42c0200098c59b6085e596f08ae3a9ab5e58dc97));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x0b57cebdb25170436fe85b2bebd98ef648cd2ef742b0213bfbafe8c92b55f135), uint256(0x11638f9cd56eb560aa420bbab27bfbc868c313904b303ac4c624cf143266d22c));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x019b71c6a3becb7f20adbe0aa5a1b691abd3bffe42eae17149728777c7e04a70), uint256(0x2963eff09b1b51ecd15212044cf6e8e08e59b0daedf0c370c59f1bb08278a849));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x13db0a48b7079b97ea6c9a8c32603650d58e3e808812358bf7fba941afe45d0f), uint256(0x0faee7b64666672bb903564b9988cac75062cb00e5d369ca442e4f50e3ac4549));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x1062152d0319adb2393317ed8e1ef7b00e0849a21b27ffa5b9ac082ab3d75cbc), uint256(0x2831bd2eb56584277a11b262e52c3ec5b29c51186eb1ffbb471913fb162d6545));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x16952225334ecdd7ebf609ffaf87c5c88d51260aa5a8ce049ac489be80122049), uint256(0x089b2de1a8f65dfb0b6c2f0daf7005339d589cab71643b8966c20ad45b149d63));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x02fbc496df04c300532d862a888f8e2e0da3092978879b4b7fada9cd38be887d), uint256(0x021d85695a16f3b331116b3ebcbd8cc879e81d9bfb6012f012b732cc27a93e4c));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x03d214ed4dbf246bd64ba8acc0d7451609bc816e20539784addbe97ee597eb2d), uint256(0x19f9535f9ca23b675f71ab97cac5cfaa48c0f735d93b41be22731b75198024e4));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x1fc460116834ec2cb831e8999eaefc9205c18af08c4ea7b6fb7dcfa62ec271c3), uint256(0x1ea1195a694ba9213c960cb951bdcf0bc8847034dcb9ebeffd6aaad0b86a35d8));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x1a89f23bd24e22ad62d1a598caa19242164c8219d4e51003944470e6ffccc015), uint256(0x087518a5173a34272e8a0cc21e6b0116c66cd1835e3d79831dcdc7e129aa4f93));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x2bfa458edf751ffa4111df786e7c02ce06b66023bc28f71ad59e3a234dc5dcd8), uint256(0x0e59cd6bda44199529e970c45388f2aaaa1dbb590384dad5a95102abe89b3598));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x1422dea7a78a2c91b99bc1c175f3df6c2507908b44604aed849e94fe3d3a5ddd), uint256(0x2bcfe63f5c0f50a79c37e7a114a48fddbfecb21275586b535cfd655581c66aac));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x17b834ceb1d9029cf276d293e514ada4b688fb7f89f43aebcacaffd1d3a6345b), uint256(0x2534bd92e779981879da34af556bc4f3c41febb40e445c27252d3b6f59bbec1a));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x2a71cdf4d881fab171b22d39b90841058e7c365a5237b9eb4a0dd6813c9c7518), uint256(0x092bc88e9fd69bb4558134e5f55bdbf7be7749980ad3be6e667b57e328738021));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x0dc915598b613b4f14774f4f2557494ca781537c7540501fee624fe0f9fc70cb), uint256(0x0769a85da8a89fb06b4109b41fc857d977f7091e7191fb4d5aa855caeba9649c));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x00160f06bed6c0a7f29ad501656d839d0f927037f1d90cd75513cac238364ca3), uint256(0x10c16d12ec9f69f413e664964bc9b3b65bed9198ecb6904815e8af981bab53bc));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x20e8fbc73391699e68a1e3d3e404193453c0144adfd3c4d982a62fc964dc9191), uint256(0x26e42c2059fc46f721d3ae01eaf8ce1c277db9a142ab30e58fbd6eb944c28cfc));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x28a7bea3b5bb0938175aefe97365907ce95bf13930383a879aef6c07152986e0), uint256(0x20186a07888bfc5fb22a15fcec44c37586fed9eeaa51b2049548e90e351682ee));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x17904b473d2dcb6f7509049b19dbb11e5865ebc62315912a444c5ebe38a3c023), uint256(0x0e09f6e6b5561b8ea1d5115d31afe84b32e33c5ef52bc074483f8573ab835470));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x2e030ac4a674f7fed2a1f1ac9b4955b1cdc2e060e9c6bce3b775037660d54deb), uint256(0x041a89495417ea3a34f60dde58ee468b9a1d51a2a5a4041564fbcf8d6d4a5fb2));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x1a4a9f9dacfbd17a1f331c9519ae3cfafe7fa707ce8bc697c1bf99174fb896ce), uint256(0x134744a76d17727d6ac12058e8e4c38876eab93da7ce18da451e4350301fb9fe));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x222516fe3511ba869a78bf199f09bfcc5b1053afbfd4c83d22bfaeccfc151827), uint256(0x1f3fbd3f9fac2be85d4053e864bd4e7e7153f6a9a7c385ecd1eb9ddd8d44f702));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x1588f3f034928c2acbd8d3827c08b4b3bf998de6c0f3a7ac12cbc034ac51b785), uint256(0x219b84838462d8708dd34d967ff13aa05903b98ae75547b6de9798982ccd14fb));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x2d4bf688591aa16af7af455f3879d11fe4b9774e00f13e3888049e4af0ebe1b6), uint256(0x23bae3e22465dd191c367c4d7674cdd16c504b6eed169fca3bc7d7ea17205b70));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x19e067098b8a8aad3ffb3a335b43d889950cd4525f695bdf4a2e8bee45258a1c), uint256(0x23d7220ac487241c547ebdeae4a69f47d5a1747db14615892ad998c2e7515732));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x2c654e263277a6b76193ae0378a659534fe873abde94904206680b0fbae44cce), uint256(0x1852f9fd4827a0ea0593fdc3620c480375f675efd5fb32ed9b3a54eef1b1f0ad));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x2be7226fc57d48790f7e4ca6299b3d46d1d355bea20cefc25f083a92f0715098), uint256(0x2bc3987bd5b21dbcac489d4edeab98fc40d611dc315dd94345f4f3f90bc6a0cd));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x1fa0e839056861dcd58f328d78f389e41bb9cb70ebabf95222aba1ca0f5a67aa), uint256(0x03798e849ab0a03965f2719fb12f6d791446a0973697c6f563d4ddf00e418c94));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x24e706bc3d99a5594ea6134b758c8f8b2abdb243844d1f7a34a63297f08d605f), uint256(0x29fe8974806e3ad88a48b1daa4d8cb0296a59f8ce64e244591dc5da17d2c925b));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x275ba49be029adc13c1fa743cf618949a3fc331a533cbc5afbd01fd6114a85bf), uint256(0x1dd92aec3635d5d7dfba209f8b232816c75dcf06bfd7a59a1e139250fba36960));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x1da54fb7d068f0ff8b2bc1c94c552db615bd0c2dccfe1be16754515e331447e7), uint256(0x267cc778d86ac25f30126a317c8d06a807bc3ecb9ef0fd6864bbbc9b21fdb2f1));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x099d41a905a42329583487f2805f5dc5dfab8243a4cb1be0e4e268dacd8da9f5), uint256(0x097a58ece946401b320dfeeb4096de0dec1c374e9c9f4be53e279db609051cb0));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x2c08403eda0f4b850131e42b5d49e713b419e721c1c3eaf7caa2e7ac44a023e1), uint256(0x1d7138f778e8704f3064e3ddb6a4fc8123f7b221fea99c06f44033f886e3665d));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x25d62c5a4b025ac7d741d6b0706065e2cebf091151c99273426dcaff6dd1980e), uint256(0x1c3b36e45495a572edbbd7a17d532b0a005788a11ebf7af6e4abfc63b814f6db));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x2a4580a114e09dcabff3c5f2fc08b9bc82c8318647bb8306ea4a8c7f29ee8f11), uint256(0x092b9ab977c6e685c96c9857a8353644ad0173b195302b0b387722d7b7ecd73e));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x1d8dab26e1b8d2d9827debfce44cbff6183bd2c0e1f4d6fc51a2164831ff94f6), uint256(0x04cb286db3435f6356d3d33ecc3d73b31c7b03b61e40e75ad01db433a58b1691));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x0be266fed50fc431e6d1d66b820d868fb49a1f89d67211992168d86c4d932437), uint256(0x212113313ab83b86a8bbe7a02da8e0556fa63c5cf50a8c4ed630e4907045112b));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x22e0e201bc4a639154928eaff38390ba616b56ba774029c8ee6eb93f486694b5), uint256(0x1045ed187359b1bae635d2b717370d7453392342db7685f1d490f3de7cd80502));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x1793b46602c9db69ff26ea8b9961d47019107a22b8ae59f1d1524e847ec2e9bd), uint256(0x088d93e619afb5e2039be3772a3f8855fa59f24b39fddaca704bde2350508a89));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x1f0f04912b335be119c339501f21eabf5884947270bc1d60983ff1372d792965), uint256(0x2213bc64642828f02d2bd33d2ea7f5039989458f23d57a5e1c2282dab7d3489d));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x277ece52c2751e5fffaf7b3127f960fb695355ced21a93d4fe7c6523e347d328), uint256(0x2bd2f1858b6abb5273a3cc5d3287f1daa0a9d2febcdc27ba57cd8565b41dcb78));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x1a73b5ab01c9eb43f92cf1b316828af520bd32a87e7a7bce4d82dd76b862b5ad), uint256(0x00134f999109255066ea1652a493ac8c2814e7f98b775ffeea9c5606bd2b8cef));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x15bc0e97602d56baa24ecd1b103f49de3565c8e629defd2d71cebc941b61afbb), uint256(0x2988e14344b5f5f1523904bf816d27fe8535d9f16fc682af9bdb3014ba9ab1a9));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x0cee968e4e2c872aadc4e7e7eb3ba682370819d13244b7c532be8487581fb9b9), uint256(0x1e39f76f9bee34d50a5633bbcb6a04716dcc724ec4a61750e31fb2811ab33abd));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x03fcd368a87af7846819085f5e5b9594bc3d5539fb81efdcec8677e217c97dc7), uint256(0x1a6834c9a7a02e2649d50300d92b550fddfaface1548c7276ca27531ffa19236));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x2f0141d538cf9154de5c375aed33e27dc83279fc1793cd74783f4da4ae377095), uint256(0x218acfa76407f0f40197a1a185b5d74133fb88a13c01df7caa5c8c2de47f7c21));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x1fca93bc663866d466c772dbd829a5197dcfe2ef31d0a3ff08b6881961731db9), uint256(0x0f935f38238ca512b5d4dc23e3914cb96e74f843bab636d3f4e9861f57e78538));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x2756c5ea7db6e077fe71918c2931aaa714000fb33c0ce99260017bb76ed03e78), uint256(0x064e02a85748eb6b8820b6d5b6ca108b9f50d3090e5c991e7a07cd1bb49d5a57));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x1ea1d2660e07d77a7733d4666e7ed376e22ed3254871ff02ea9288c652691737), uint256(0x1928cc909b30fd54235fff9f5fdad49f87ce12a1463cf39e02f77fdce2c04a32));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x00936dbb56daa7c3c30195981adf6ccfd2e55834dca1fd0728a4a97de1b2575e), uint256(0x14bdd2c52170e9e7fa9dec9140cfeb920d7d52bfeb4ffa8c02f9faba9749935c));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x1d3fdf056031701d33822a22bd41dc213af5beff59a4d23dfe362eddb1e0f95c), uint256(0x1b145ecd3e187a345e22b4bbedafd5fdbef3f1b3b8ede3151692fa46424553b8));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x1d1fff115390a764400478dde36f69732c69ca26656989aae8b1e088fc3bacaf), uint256(0x2f18539b9cb36c7b89792a7aa22f152967dc048a84d1b1bcc329e9c14eff24a9));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x2869239f01a1579d0993ddf6cd88ec958369cb77a43c948de4a80473467ec7d4), uint256(0x20e65cad4f6608d5974310de31fc7ecc3631525bbd8e5cd5d4aede863e7f030f));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x208217bd2e95c76dd693d52ef0fe894658d15df85c7621f53ab3dbb377b0f255), uint256(0x0e7d2e8aa20adbf62fba83b05a0aa51558b4a9ef464a3eb0b6b6e720b3bd08cf));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x0a343c98786f785dd75ce6433a50aaee45cf2be0b7fc92d33725f4a40b9aec56), uint256(0x27b3374feb32aa60c16bc9f86ea5bea5fbe4d7159e8ff07d69940c6abdbe37fe));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x125f521728eb9bb9e1b9e6fee87824e2b66ee2d70dfad06b3d675cc00675eb45), uint256(0x2c54b12f02556cb1602d32bd190ea7220fa24524fe653098c9aa9eaeb21110fa));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x1a211fa526d2e139b4e90990b9589e151cd46a0a092617735dcd95775890d1ba), uint256(0x19159ec17ad714675d5f17eb4c971d0e99bee791e631a641536b031361a431ed));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x02880c5f3abc79557f861b32e0b4c13123e1148770766b46cd8bbe1b0c98d297), uint256(0x2f301634026ddbe188f73f36a47e303190785e5334da11832927ece68ac35086));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x29ef4a41e143b36f57962682f4841df207a1da8a87753321b2c3e81811fc8552), uint256(0x0be71862cb9ce67509b6f5d685bda1a52f7bdc29cb4741db228d60861699eb62));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x14354cae1d4163c57b26300c64f9bdcd91d5f990917ff70447fd2aae2546fa59), uint256(0x271c803d467a45b0a65c1144d8884b75e92f65cdf00c090d2648c61b5da10e29));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x137129b7b9c066d234077d536ee207c2bfe77a66c7150e354b6ea99bdd1d4f6c), uint256(0x210ac37163c383e71d3b4a505d4d6adf05cf0063857e832f38b99ba7aa93f08d));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x0615ab12c1f5f6f28e214e15a7ff57db472b325b27e1916f7e3dd298fc8576a3), uint256(0x188d4d34072aab65dbefa18dbdcea8de026747ffb05c561b55c91433ad681e3c));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x0ba2cd984686711ba96c29491a2b099074c8dddca56adbe5333207d02e3f7906), uint256(0x2fb20a8db8229643dcec2f781aa3d4003e75f8b117ef89eeda640acd60f55892));
        vk.gamma_abc[202] = Pairing.G1Point(uint256(0x1bfd935ef86af38a77fb4a86c0d90de244f1c3d74c2990a589faa1550c5ef38e), uint256(0x0080d1b11ebdfaa946ce5c2ff044b9da043baeea55aa0b188cd2226e350557b2));
        vk.gamma_abc[203] = Pairing.G1Point(uint256(0x109f48c9e7c3df436e3de3596b8f1e8ed105984989532ed8d5f4d8fbff871bb0), uint256(0x249ba87c67337f52a04085f1debeaf19fc7bc48965b2376f61342c3b8b30f6bc));
        vk.gamma_abc[204] = Pairing.G1Point(uint256(0x2ead0b85ef33722d6d84249e4f11aca2e430b504fe951f01c1df9100f9bdb025), uint256(0x2ed8ae05eaa04a9e9a9313f06bb2e64081f8e019ea440f35adf09a2b554d826d));
        vk.gamma_abc[205] = Pairing.G1Point(uint256(0x287006ab31ddcb3155fbb7f0cb1e6c23ea2bede22de6cc59bbf6905f1f82cfe6), uint256(0x033ce03e18c41d6de896f442abd6039d4efad38213fd6ff846e6bb7f1f3a9a7b));
        vk.gamma_abc[206] = Pairing.G1Point(uint256(0x024097a5023d7538cc306655c6da2b7d291e2b89cd37b8dfdc2eb36520b8a706), uint256(0x1b222609b70e4878cdcfd102f9ed2484ff231feb7ff12c4514f9c3e5def0dea2));
        vk.gamma_abc[207] = Pairing.G1Point(uint256(0x30519dee07d4e98f131c39fd538a20ea1af0b0c3a09e5c3ad9970edb257b77d2), uint256(0x231bf5defab4602d1bf0a106c41ec18823bca401c7714bd902acd6fc7fe30804));
        vk.gamma_abc[208] = Pairing.G1Point(uint256(0x0f1a19e73f492b1123faf9c24770d14477ea69956ad5057c478d70664ede9ea4), uint256(0x137c674f1e0d6d3b72987e16023a24bc5ac3060235933a72c33cf370f95a51f7));
        vk.gamma_abc[209] = Pairing.G1Point(uint256(0x1434a4b1d4f7e378da83d0e131d28f72489bb4605586ce4b5074e04e2cbec4b0), uint256(0x1b23156caa244d10f9e996e319ddf93176388a9d38f43b3b5ac36a7f0f73104a));
        vk.gamma_abc[210] = Pairing.G1Point(uint256(0x16caf14e47ef983b478c5e62ccb911a221855c9a84d15fb50b89c447ad37fb48), uint256(0x27cf4c4e82f368758db8eee29adfbd1a89dc34bfcc9605177e0d6746fd0871f0));
        vk.gamma_abc[211] = Pairing.G1Point(uint256(0x2fda1372fd8932d71395dd49c2aa0d93890974781d7be8d0450f761a2fc5abd4), uint256(0x1bba9e77bbdb3962898db41f9edbbbb01ff9c19a4a3caac42f8e69092759ba5b));
        vk.gamma_abc[212] = Pairing.G1Point(uint256(0x1ccc6268dfceca701dad460e8afc1018889b4a33b2c53cffe942d1c023d7ee39), uint256(0x0b12b2ce290e96cce4b6a4c92abf751b1656f5f11a4579324a1f3788bf176a0a));
        vk.gamma_abc[213] = Pairing.G1Point(uint256(0x0596573b822df01224d71dd5e93993d73737d7062d4663041d6366fe2a6e4188), uint256(0x08f2f76fc83fb77440c2451c8125987096f6359a93b4e53fda8c033dff52a688));
        vk.gamma_abc[214] = Pairing.G1Point(uint256(0x0b814aeb3f64b1f616b1739cbee5124cabace60fb736eb2f635e7318c8111c9c), uint256(0x2d00786d91f01af5be06254f3ab294c45b3c4f2fa3145bc06792894f808f8839));
        vk.gamma_abc[215] = Pairing.G1Point(uint256(0x2a3b7dedbcab675b8c18c85f523880e0d38b036aef38e1b393bb69009a7bff2a), uint256(0x283590b7eae0a71636817c3ceaa42a6c7d7a413037be4fc47212b09bb5c98daa));
        vk.gamma_abc[216] = Pairing.G1Point(uint256(0x08c70284132fe70ba0c94af2ecda684e0cfd302d1b5113869bcde4cf00c09846), uint256(0x2efb5de74e9b0c3ef6f8b00bd78d793b744453648ba8a34eb7d44f98c44f49aa));
        vk.gamma_abc[217] = Pairing.G1Point(uint256(0x2c4d114b4cde357ac68c8d1532a524ff62d93dd61d62f644e2e28111e2f65546), uint256(0x07e48623a8b858fddd9f0d9e9738e788a1db81d3bbd2491a31e292b33cded317));
        vk.gamma_abc[218] = Pairing.G1Point(uint256(0x02a143b2a9a41892f9986a9e96b8fc70c05025db30b2e69bb5968a8d83b7e83a), uint256(0x1b3f677691ad1620d69caf2eab5372d706ce4a5e526aec033da865d8733ff95b));
        vk.gamma_abc[219] = Pairing.G1Point(uint256(0x2531cd546832569fd85aa8320140449bd5aeae3ef51fc30f025c76f127754b97), uint256(0x257550c5cc34d0278dcd71427f6b7b990c1a97a0b0eb535a6ce3d83e2889cbfe));
        vk.gamma_abc[220] = Pairing.G1Point(uint256(0x19c79390fcbbb20b5bb4c9c2d733042d970be01af82a2c8ddfba21b777efd198), uint256(0x1c20cd183c52facddfbcd79537d280932ef933da44aa4e132142517c8c25deeb));
        vk.gamma_abc[221] = Pairing.G1Point(uint256(0x18e574881fa43c6cda141b76bf90b6d02fa28ce1bf34412bea28cc080f7b9815), uint256(0x2f03c41e1c24ad0157c5990408c7f1c58f85af6399120397d39f827c771eaf92));
        vk.gamma_abc[222] = Pairing.G1Point(uint256(0x0649b53766d0a570dc650581841d3f2c5692207a4b96255dab166efd42781a84), uint256(0x145ff3e6ead99e6bf7da401c53f419228f6a655e552df1d7eaeceaef6c39f6cb));
        vk.gamma_abc[223] = Pairing.G1Point(uint256(0x1c07fac956376c76906dbd6d23a5004741763af09ddf9e6a12502732d70334d8), uint256(0x2d76c5a8c247c6d17a78b128b0ea9a0304140ca9ed02e3d793f92d4f213cfe37));
        vk.gamma_abc[224] = Pairing.G1Point(uint256(0x1e1f2cf690cfefc99a9aaaf10526a01880bb650c753fb85c9ed080011414804b), uint256(0x304302c8d01604f084d259386501e601ed411b4205b61f77c6fd99824328edea));
        vk.gamma_abc[225] = Pairing.G1Point(uint256(0x22d096e10efa3e231821d7e758f077fcccc46996bd04a9c87e7ef5c10351b503), uint256(0x2949d35507f6199aeaf0556c834f340d51fe94c478ab985b8980c381f63e7c03));
        vk.gamma_abc[226] = Pairing.G1Point(uint256(0x25d4469f5ffbd6229e1d6f5723824e2d3045c48b3841f601bce50db4841095f7), uint256(0x2c3a6229ee0cf81f650380e403b238f33401f56c0e2d412671b90bc9620505fc));
        vk.gamma_abc[227] = Pairing.G1Point(uint256(0x22f2655ebb135461fd6c11c9624fc492eab84a6bed5cada79509d7b7cf4f7f4f), uint256(0x1aab726d95f86a5a35741b5fcd15d83ad1ca030272d6ca44110c7998b36917d6));
        vk.gamma_abc[228] = Pairing.G1Point(uint256(0x0dc5531033bb31dbbd11d973ea093ad1120dcd19783b4d9960589bc14ef33835), uint256(0x273fb9ba0fcb601f2eae9a080c7272f0ee5a300500c4629c2ae5f18c15e560ba));
        vk.gamma_abc[229] = Pairing.G1Point(uint256(0x169f21bc8ba57808c79df9d010d3730416c7b4a0b3119d4e6303adecfade9ed5), uint256(0x219c2db142c3f08baaebee2ffd188a98806095ae83f151356ed78680e1cb44b6));
        vk.gamma_abc[230] = Pairing.G1Point(uint256(0x1946c4f49bd7bb69df45b364a254c010564256879a0c9637ae43c6661a17ddbb), uint256(0x038a010240357150f7eeb18f1d5bea0b4702be117444063055cc74e54b63fb54));
        vk.gamma_abc[231] = Pairing.G1Point(uint256(0x168969f700384f32e421168bea486bc7d911fca235d56618c6eb25ba2bead368), uint256(0x182912cf7e1d34b8864616312fe39a1f8d4299edb288d5595369d218edeeae74));
        vk.gamma_abc[232] = Pairing.G1Point(uint256(0x2571814da81518e3a5b1afbb4f84fdb740716ac25e34219f3590896b330a62d9), uint256(0x1d4139cf3890e4ddaf4fc315c76a90e2ae8037bbf2b4857fb2287ed9be56cc1d));
        vk.gamma_abc[233] = Pairing.G1Point(uint256(0x221cfeac4c6d659b81a79024f5fca3fd483ecbd36a181289386a946d2300c858), uint256(0x073714e9a8056ff4ba490ed4d3fe9d17d59f59ee52d05608dedbe4dec2df6a14));
        vk.gamma_abc[234] = Pairing.G1Point(uint256(0x2935088b53f415b32a8d42c78780cac1e7bbd830643faa9d0b7bfb20704f1a3b), uint256(0x08d7e2627853d14c45234e5c8fba064a76989010af3184ccaba4fc52ab1cf0d0));
        vk.gamma_abc[235] = Pairing.G1Point(uint256(0x1441113cdc117bfc8340c572cd7346688f57c6c6ba61bf78ca917cb3cbc75dd6), uint256(0x24f1a97330288406b2c8b32cefb217e4de2a97b4fcfdc9d7a858cd09a2240178));
        vk.gamma_abc[236] = Pairing.G1Point(uint256(0x0ec9d514a9afea30dac63a8c4933e7032620f32710932fee1414d35be75efacb), uint256(0x15813679ee09148ed6790c4590d13b0d38c1cc257eded7208ffcc33cbae9f294));
        vk.gamma_abc[237] = Pairing.G1Point(uint256(0x09a9559417886ea8016565e3aad06968394652616cb69c9f175cb967dd471d52), uint256(0x26420de564c9e23f028f359ce8d9b327953cd95d59f00cece78f1c29e8ad422c));
        vk.gamma_abc[238] = Pairing.G1Point(uint256(0x2a6aa6ee69e44f34a438a12d100f051564b63144376161e74e5a84f6120331bf), uint256(0x1e8620ebb50f82caf7e0f208d532511ea157b391a164e6fab0072a927eb82a3d));
        vk.gamma_abc[239] = Pairing.G1Point(uint256(0x24f47a772c480c3276022b0586fc7770cfc2aed33cee6ca9fc23f678acf13695), uint256(0x04803a5473b7db41ef98927f9f463d5ede71124dc54a9e472d3f31aa0d1badb0));
        vk.gamma_abc[240] = Pairing.G1Point(uint256(0x0099aa52aa94c1954d8b35365d2043a98fcceb1206668840b78e10d4cdcfef9e), uint256(0x1e87bd9a1f9cecd6ace35264c86fde4798b0e7b9924a9534e16b8e6fbe5bf1e6));
        vk.gamma_abc[241] = Pairing.G1Point(uint256(0x025a46d462169fac8535279af2ee3aa23f803e8235cd64a62745f1436a8bd3f0), uint256(0x185ee5fa61d9aa15ba381734d56e9b9d1463a2b28e1f93ce94a79411083eed3a));
        vk.gamma_abc[242] = Pairing.G1Point(uint256(0x277e45ef5741cba0bdf1af01475abfcf56f809447c3f54948997f2461fbf935b), uint256(0x0a503c366760053a029e64873e9f180755facd30642d1e8771e108364ff2f728));
        vk.gamma_abc[243] = Pairing.G1Point(uint256(0x25314a90df5f9c27b115a4997590b3c79fdebe5ecfff5153e2a763bfd46f4d6e), uint256(0x17d86ceb7f86e6bce3e43cf8118ace715a6d2f1ac2d3311fd95354bfd09c0338));
        vk.gamma_abc[244] = Pairing.G1Point(uint256(0x0996fd6198bed6233c22abb5c3fd6ae0ddf4562a357f28b3d65c25aa1da7994f), uint256(0x2bab04338f33fc2c3315477237b6a0adb4a4d96430ff55cf500a2578b76468b5));
        vk.gamma_abc[245] = Pairing.G1Point(uint256(0x1a06d8333e0379ebaab5ec9bd6dc9c22733a87c4b3add8e60619358421b05460), uint256(0x108ae01481d538e44747139378ce69d1b45d11cb7b87f69ac7000fa8c0fcdba4));
        vk.gamma_abc[246] = Pairing.G1Point(uint256(0x110b06dca94e1a4f9c878b320d172f61dbffbd7af0062dea5ea7d6f78454dc32), uint256(0x268becbdc8326873fac259fe275ecad51bfce2d98efad95a601e71fbb4e585b2));
        vk.gamma_abc[247] = Pairing.G1Point(uint256(0x19fe8efea721608cf8c7ec5cda8ee2815f9257eebf94dc22c6f41677ad57f5ff), uint256(0x096dcf2dd72f114813c4e3e5101c982307cca68e4b041f4732aee73768da4bd3));
        vk.gamma_abc[248] = Pairing.G1Point(uint256(0x240e075a7ed2a5806ca4e737d0359aa8dd7c0aecc08d462bc4a0001d2920e54f), uint256(0x147deed748d01e89ce55f68260241814cd4863f0fa70ce18be4e2912abb6dfa3));
        vk.gamma_abc[249] = Pairing.G1Point(uint256(0x2f62b0d7895ca7461ec8c34f6a669d5f112c41fa3507d38b091ee3acca6175dc), uint256(0x0c5f36af54acf5e6935729a4a9aa8d057e5824186ba0c8797c68ee5e01af4a59));
        vk.gamma_abc[250] = Pairing.G1Point(uint256(0x27a8fee6d08907e8fee9d2dc954b5c26efd5867badd7265315b1e525e9a9bc33), uint256(0x03b1b8045c17e66112503f9e83dfc4bb24f937b644d1f5e39f9c9be399b4c526));
        vk.gamma_abc[251] = Pairing.G1Point(uint256(0x214f455418a779724f05f4e0561ff2bd2c7940517b237a04c96020ad298e4653), uint256(0x21eaf1d3626e4b33509a0c597dd7917e40381da40a80e542a3d364777b7d55b2));
        vk.gamma_abc[252] = Pairing.G1Point(uint256(0x117086e1c3daf62665c3b6155e857b55a9f649298e73f133303470a1ac2ef780), uint256(0x2dc612a8019ded17aa6d540c75ca1a5f141060a520949a6c42c8e6c5eaa80222));
        vk.gamma_abc[253] = Pairing.G1Point(uint256(0x14ad2fb4f63510be8840dfb17bf2a43f5f6a1c897ffb32ba45285749959ab1e4), uint256(0x1d674c7b781d4f1183f420b4e8f950404d6985c213afdeaf2670c39a145e5af4));
        vk.gamma_abc[254] = Pairing.G1Point(uint256(0x2062b0cea1ddabbbab58cadcccfb4ccbb102fa550d200ff649b106682a95c999), uint256(0x0dad8c1d8b49b4527fcfd86d64d1a01ab8340156c23ec209cd2284d6a54f9f74));
        vk.gamma_abc[255] = Pairing.G1Point(uint256(0x08d27b9636b26eede8035bb4276a6f52f11d7bb55902190b8fe1790ad4eac783), uint256(0x1274489c2d6753ac5c8a4df2ff68a92c41a3f60008d30c9307cbb05c11ae305e));
        vk.gamma_abc[256] = Pairing.G1Point(uint256(0x14f95c8d7bb645246027d9dc13ecd8dd1dc8ae11c36795443aaabb511cb3c0fa), uint256(0x06c154540f3afb66c6e9c181e90fcf8887a681944efef0775598139eff4cafe8));
        vk.gamma_abc[257] = Pairing.G1Point(uint256(0x195e617ad52491e9f8e7cf3b8644abe565da48ce77ce12ee197d5d01dd408ab5), uint256(0x2495ea7328e2712eb7c8b7afe978332c6d791ca3cdb9c860df186d5d5dabc683));
        vk.gamma_abc[258] = Pairing.G1Point(uint256(0x2d2c92d41d2efc9b72ce50384d57a7bf3ce50e13f847d178cefa0d4341c60ec5), uint256(0x06f7028d7d65f4057b1547a05fe673fb72a7c4200e07dcd50efc4eeb311c104d));
        vk.gamma_abc[259] = Pairing.G1Point(uint256(0x1977f4fa871130c1b2a6c2bb66452e081ad5ec0f6d82de65bd14a76ed11665e6), uint256(0x1c53c33416113853d2dc0ff0a3e94b53751b7d0e4b76ec8c471be9f77ecbb058));
        vk.gamma_abc[260] = Pairing.G1Point(uint256(0x0221d2090a6eaeafdad9d0cd324d586b0fdc3d41e2690b284a8b3da7417d88a5), uint256(0x196a4d726e396968bfce2bef329be56057c415a307dfce4a96d9d7ac8e480bdb));
        vk.gamma_abc[261] = Pairing.G1Point(uint256(0x0365da7987cdb140e7cac3535dd10057bc77d3a717c42770b173c61bced1ee1f), uint256(0x0d07ddef6e2d5b0f9a09546656ca52ac48223f6605663a16e6a35b380f692526));
        vk.gamma_abc[262] = Pairing.G1Point(uint256(0x2189873a875b5817a1bf083154022ca18733aee5b77d5352def5b875f954d7b3), uint256(0x0eb9632cfb4f053902a6e7912fdaa9006118e859a84c00191f8379c370760fb4));
        vk.gamma_abc[263] = Pairing.G1Point(uint256(0x30147e87d1755096ba5da53057ef90f464ad21609e1ec74c5ff833abecd12261), uint256(0x22e9aaaa2b481921d53ab3eea2b3cc2eec7ddda80e8dc03c151781f632be9ee5));
        vk.gamma_abc[264] = Pairing.G1Point(uint256(0x10b511dedb6a8d0741884e6c9dc480bfc28ab67d5ea49ce6e1bfa770179e495f), uint256(0x254af273c51f2b4a948dd0887643888becf200e3a0c033d76bdbfc096788e94c));
        vk.gamma_abc[265] = Pairing.G1Point(uint256(0x1d01057c901f9e7b65304d9799b28570eaacda5fab98fa71ffebc803ca8143f2), uint256(0x27ce96f08234cfa0c8ec3dcd51dd9854266094c54350e04d64820ff0f10a6bd9));
        vk.gamma_abc[266] = Pairing.G1Point(uint256(0x187d5e0b2de9f531a055a8a693a0a5eaca25c3bb7880c193d68d675db1ace6ae), uint256(0x0381bae771d9b6550d2b07fc52c9dcaa38c643f43cc61826fa58ec0e18cca266));
        vk.gamma_abc[267] = Pairing.G1Point(uint256(0x2263dcd1c2872e4f779869887e6e64824e7106a03247a3c5bafd2bd6cf39aefb), uint256(0x0958611e1d3ae71b413c750bc35ea7da99c37eae2b109ef70dd46200d58ef3d8));
        vk.gamma_abc[268] = Pairing.G1Point(uint256(0x08a2d9127cc7f12cb5f1a4ec03776a280215182ab2d7e84aaabaddbfe63f4a7d), uint256(0x0ee817d5bc4ab80bdd1c28fd82b9e3e512c9d33e2d22e730937a45697cfdf807));
        vk.gamma_abc[269] = Pairing.G1Point(uint256(0x203714b5aca9bcf8f0292fbb7dd081b0513a2239fa1325f97bf208ef0f829647), uint256(0x02c8f16622756ffb019c4eb1c4098f9ceac671dfcb62320ae94baea74315940f));
        vk.gamma_abc[270] = Pairing.G1Point(uint256(0x0f7db27b69d41680da12aa659ca95df42ae8cff663651f0cf774ad664ee3353a), uint256(0x14cdda28ec779f21b4cf4f9a3ae42378bca3e11634e9812f3cd3e15e3bc4b048));
        vk.gamma_abc[271] = Pairing.G1Point(uint256(0x078bce60cafc8b45727d76ec3a5cc33c85ed70ae7c0ae179e928a5f2fe5c0a7b), uint256(0x2599ffc75d62d94292e25671708a34db80578d1df6368f879131e94a18246706));
        vk.gamma_abc[272] = Pairing.G1Point(uint256(0x2a97a4560a8898f372a260ade324ec8f86c8a730ea71ef571c9bf197035951f8), uint256(0x1f2d7eccf7185613bad9682a2b852d99744e2464b9a721b6f82e2c0fa628d913));
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
            Proof memory proof, uint[272] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](272);
        
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
