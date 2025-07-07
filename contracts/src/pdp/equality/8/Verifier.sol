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
        vk.alpha = Pairing.G1Point(uint256(0x047a7825ed70345ffbd8198519e70804f27b988da72bb85b8584fca9b1205999), uint256(0x271c21aef9cf4e578c57b106cfa57e8a40ed99174ed0b46d5450e135701dac72));
        vk.beta = Pairing.G2Point([uint256(0x142d42f24b5f6706cb5aa1a4c2b17a83653181d66243e5bdd15585f7c9c4c43c), uint256(0x2f9322beeee4398804af4a726f3ac2090885f7efa74f6e1152982d1170f4a8f4)], [uint256(0x1bce63047cdea3875e9221de69a67d76f4fec426e097cf743f265bd31fa23436), uint256(0x06736b4772db5832fb8902cf830f80145764a9d7127e6d9d875fe898263f496f)]);
        vk.gamma = Pairing.G2Point([uint256(0x125c5749c71127fc05b7b64466c3977a067a5b17546c88e9735a14d9f105457f), uint256(0x2f7a4ced4002d3b42a208edfd876af35df47ad2550f9ba7f91a8184146649d0c)], [uint256(0x2d2332b51291cc322d11e5122559c6b48ab9b9d09361e676c0b1af2ee74af667), uint256(0x2f55591655c1eeca65844ddd8d3a3064169133b26812c2e4f1416c197bf8cd90)]);
        vk.delta = Pairing.G2Point([uint256(0x1850cc5dc1774c66b6afede4e72dec1d2c4d15563ef9ac2b85c95dce265e9bca), uint256(0x11001656c24d03f4c42de084ee7be4f18c45a5190af7e8461e453bef2db919c6)], [uint256(0x0544cb7d640d6713472c16469c5903c1c23c845aa411dd313cabde8cc982db95), uint256(0x29ee2f11d74ac77f9d81763d8812cb13a4a192ca2817b0f0fcbf9dbe58be46a7)]);
        vk.gamma_abc = new Pairing.G1Point[](145);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0c4e3ed143c446173ecff28335b730bfc4cc1e1ef99198ac1bc05c1a7486cfad), uint256(0x0dbc0e2167eaa3b744ff9490ec34dabe2ff55a0bad7b20a767b72bca16caf73e));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x10a769f5b024a376b45bae163c10c7066ffdbfdf48f8df5f0134744e864e28f0), uint256(0x1bb68778c996b73bf37daf696b25e8766652665f3309754408961fd7ba04f8f0));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x18376d231835fbe07f3df76c869d116cdafddd7ca60ad9c3c310a044ab4be697), uint256(0x1a11ebdd30c727658e7bcbaaf2e34ab476cb3dd753a26b89bae577683aa9e4c3));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0cff17a30e3a958ecb97dce20b37d25fbcf4d9e4f8a893ba8c0af01cc568f154), uint256(0x1e3cd52a45a9eda2a8001c262029c1c695077f675d5fb706d1d221fd557b65cf));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1c65efcaaf634602b8e4ab31ce351569710e75ae7ca35877c573a740786d3450), uint256(0x05de6fb70f50110fc4ddafc5e22d7cc524f9d9b543bb8eb5dfd8187bca11130a));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x008d2e579371c1fb5f47022c0362efb4a350fdea85fdd60c8f66ba011ab8d66d), uint256(0x2737abc4a3cf7b5b220f34d91aba4f73f00fb9c8ab36dbc19a3e7be612363724));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x17299dee0cd0d656e1b812dd03dfc9938fabc573cb76e28b981b0fb46283e13d), uint256(0x1d8751de89f6f79afd789fddf92d7266419b1731e526ac12acde5f1289fcd074));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2b46ebe38cbcdfb600768ccba16b9023af5e0658605e10a727e0b944c692fc51), uint256(0x0d7996ab541c414b52b6031729874102df53f492d483eb4e454825820864f3eb));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x01acf63895d2dd9522935a2621edcca0fa46ddc87662198efe894a2d636ef9b3), uint256(0x0e645734f52df564ffa6d23ee0a46493e81ebfdde83d61fe55da4ae6092b8862));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1798a776b5e56d90a188edd27a688a197d07131abd781231910189c386565d51), uint256(0x1e17dc1261e403d446576a833a0661ca40f1392a9e992e214a80177e275e4b2b));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2e84ebf1ee4298fc6ab1062d72e2320219cf73c6002d8b1a225e1521581a3604), uint256(0x0c23f5c5dd8a19bf281a7d97162fb47567624bc401a430aa77091a8f5dd3ad07));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x27163ae7b582950ba1f600105de4e48dcc32b66a2ada59e5f98ec46955ebea54), uint256(0x202dc9ff1ca8f3ca1e22b77667c09cb18e76cd11f9d306d6792835d7fa292ff2));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x09716432f6f8ad8b6d8ea632a6abb210540b0f26007d05b59b89556ca2233a68), uint256(0x1aadf9363717fc2a21e609e271cfe2265dd6cf64e8a1f7009997a50d304c28f1));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2036aef8fd0ecf3c254208208984cf220e013a577c53417b2c0d331118a116ed), uint256(0x221d73d8043f27d202de49efa2d71a652b1171b3840be8c7e88fb0bfc6f043eb));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1abf8542d4326f9444153db7c562e4a1efa4064cf940480d11936a9da25e8eaa), uint256(0x2a7a545a8ef5842151afba115bcd2e44f506a81873aaf000725973303ca25c99));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0761a41c78972eb9874b5b97cd6d69797f1b11db14f42c2c9866c6c68c8b18e9), uint256(0x101c1e4a7f325cbb2339c3d49e514f090f1efb0ae44c62fd4ae59ac9224cb132));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x14bc0e8f1aa34abf5bfe0ccf47e0ff8a3cd943618185985746bb3281ef7c365d), uint256(0x06d38b1f97faad85d40806d0dc96f3ca4572787bd3c1c233cb86831a3d539761));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0612ed0876cd87e0eb73ae41c3b0849fc8d29d56b21a419231d171583eaee6dd), uint256(0x140ccc5d86ec31d42cd9f5992d2e98698b6a663602c157cc51b481090633d11f));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1c4440626c828f62717e2771d9b4b06af2c19d2e695b71ae5d55ccff773d5422), uint256(0x112ea9307afd69c8806f53cdf61a3f636ebe1d2c2b64d7ae07b42ac5d355f3f5));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x254f3e182f3ca581dbe3fbe8eaadc4b45647a26e21c8d0a13beac9ede9b03b48), uint256(0x2173143cc4c1c313074d862c8a8eb832627786bd0c967460a563dfe57448684d));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2c1c0ff97921ad45b65b2818e4dd1ee2a2a6c4435e593f8d30ae1b0a8a3c541a), uint256(0x114165ee44d2e3f4176379e40ee1dc89620e48dfa6928f60222ec1fb02c9e8b5));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x10c5a30353fee8eb1fa93878db7776c33a1c3c80f0c2c0f0361a940064e12d81), uint256(0x22e5e351e395e30965bd0510c715d40be9f691696adcfb2161c56eacaf6b998a));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x0879ddd66141335dd333731d432479bb0b49aea19e4fc7e09d784b9650ce6c51), uint256(0x0aa3f3a748fb02c93d854c8b335f6cd4fac36079e53543f448e6223cfedf52eb));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2e6763f29c517741daaf178991bdaa1edb5729a7120840bbd8886ddc17525c38), uint256(0x236967fcb8fa57726107c62e2ddddc4870bd48ce8616c296ee94ef447aedef81));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x218218a26ce83aba0e1f4d9da7c6ce9f7a6549416a1269ce2f28b4cc67c54aeb), uint256(0x18e981f453a01fcebf6975d0b06203748751598ede6fcbe9799c8e4884c2eeeb));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x120ca6572a7f31c6047a33faae70b8a8dc862b7268157a8d43a72aef644c542d), uint256(0x2caae353bb9ac58068588ff62cfbaa660688450245f7854026f341fff9302525));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x27029bcf13b41fbc1ad9e7cdbee71a89b75a9ad4cc7fad7de86811b7ff9d9b15), uint256(0x135837cd101a74781c8adff0313929ac4a8eda3f9cf93c28dd8523e4bd8d02d6));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x1a39babaf00f8c0d124f1feb9d3e697e5d1d67b2d4a9d30415c2dd3f0ad6e8cd), uint256(0x19d0ebf96aa11309d15491241b4f3ad0dcbee5cb217f590888e135ebebccd946));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x10c35c1739ee2bb853895e7f51ba8b13d5f12a6c453297899e629d5c1bce3491), uint256(0x25cb9600fab123b0965c5690a45705e3e676ad52cade78891a9398c7d28c7fbb));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x257719018eda4e273d59925f5a8dc47a55fb82eb8157369ee6d1e31597883aad), uint256(0x18e6677717ecfde4851f305433384a3f8504ce16b9408b0e3180139b1e32784a));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1930ca780f3a059765e809eda92456521785afdebcb087df6799f462b0e95cc5), uint256(0x164b3017857c65a75af9da2e089dc0ece8f444d400fad3528b90c87a0eb616f9));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x167cbe7cd2dd2bb2db3c0941a9062a9dd2e1e7784a119b64afafd48296cb1c58), uint256(0x13c3a508523476ab2f423b5b083e3043926165d898006beae5bdca96df62bbcf));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x0ae72693b849a502c9bca084c28a12b3da43fbb46f8bbc910afdf3dfccc2fdf9), uint256(0x10fb89ee27c921661808a6967cce8b5e7594d092a46fea0f1a321b63fe942eca));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x10d0d0b7a4297cc0f2306e629c9bef716588876330ca8e1d19b6d051ed829a52), uint256(0x1a518d1cc454ff580e79384d039761884a0fb8511f4de95bf9536f2b120e2e80));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x035df979dc8c5f8d5c8f0127ab78a19bb9346692e78da61535c726ab9f0693a4), uint256(0x157e2f26bae16a53f19a5e3739ddd090ed21efaa9eb45776ba6b8f710a9187ad));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x1217d001a328996af28f8a4c86bc88efdc4cc0fcb766b1b2daa7438ec47da793), uint256(0x22904544a96b481912a7027ab9bd9502f1591e8f387a9f100e86a1d60563c783));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x1f6eece2695469bbc2ef978d61fd6636748fdee74e58e8af0adff34dc8e56f2b), uint256(0x24523444ef6fe370e0e95df89e60e924e07fc5b9afa384571ca77cf342fa9f7a));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x0d41be9e8ef54f930d3bd02c0388f4acda7f1ccc592f5836f122a4fee7dedb6a), uint256(0x046e772618ff5f633b0eb76bf47b506619b601faa499f1fedc104f7aa7a9ece8));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x3020fa988563b6bdd241c3473ade071b045a3aa5a3c65eba0eb26568720cddf8), uint256(0x0a58871cbce74bd6a6d80747e2298fa090dbf7618411a3b4319588033735bfdd));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x0277e51e6665550379a1c6d668e9ecc8c5a45b36bcd6bd9a401011c7a145c2aa), uint256(0x25de177036ea9e5235fc7147343c2e32841b466207dfbd7fc8712adb4c335ded));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x01af36d707307c6a43ef96e0a765962f0ebd67dbfe7f56e939350ddff0aea9b8), uint256(0x2f11d4c4ca57e627112be9b174e622e19926157aa1ba6effd62536e70b4a7823));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x0fab5d09a2c0f583abe757d19af7ef3218052ae63b2aa9ff35f5750fd2a7b816), uint256(0x2754d6afa8b017d276a421099d2520ad9f9aea4cff4dabb8b31162beeaade88d));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x2a521b7ee095674677c9711e1bc323c9356a75fd81e4cc5e6e1ceab006a4d7d1), uint256(0x1a1dc4601e9cfbcd00d0b8d8a70370f229db4fcf3ec69b4db2e9adc50ab0dd82));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x2cf91e8876bdde392af1f73f4e7c4f02155c6acfe111d9ffaf6b0323c3a73ac8), uint256(0x2b24927b1fd44b573948bede884e4dff395e3c9ed030473bc077255cb87cacb9));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x11ff68578109f7982b6db33551f1061f2c4f6145f06f4fdc48fb2c0396da483b), uint256(0x08be94778c6277e42796de9d4c5a590901b8d02cba86d65485e5b966d2cc08dc));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x2d4a5a711e2123745c41e7b027e00bc8282fef926c63cbaa9c36234c8fd41334), uint256(0x255cc44b11f689354fc0517458f8b70bc8f1dc85f1fd81d658ff03e878fcecfb));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x2a1bff434ca50a5a54a933cd5791069fc1ba6fe90b11c313a6a92045b43667fc), uint256(0x0789a3825bba7f6c444cd40951409b462954e579db4426e6eff84737182bada4));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x0dcf69f5c4fcf237a6624369c214858fa86ec4b4fee915ec99a90722cf4daa9b), uint256(0x09935f29ebfa34a41749eff6f8bb6c7eab509fc73da876806e779ce1ce6b57b6));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x0b462dac5266a743a93500a1a29b5b6344896a69cbbb85e8cabdb789033a74fa), uint256(0x2b16886ff0eb1cd23e21e7f42443e65cde5349e899804742ad071773257aaa9a));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x1e58e66eef8ea59695a582238e9024b41fbac5db5a1a3a060c110575202cb83d), uint256(0x232ee3e67db2550dae7fec88e17bb4497b9c8fa5f4140c3af567ed101a29eb3b));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x2dee45f815e91112b2f7f47a4b005efd77dbd6c66ccb3d2622efe4dede27005d), uint256(0x032c8b010a361d9a86dcd5681d9cb1ea538d2c56d4bc0d86719c3da9ad12e4c4));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x2d034a2b731dbc67b800599b3129b324e961cfa3a3f7035ff24885d06fb91066), uint256(0x0a4a240efe4ff79ff9c4fe88c90f433b725b9ac2d2f054d7306ce8b8e5b27283));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x1ca2565f607f0b99fe78a77789fbedf391083ea9d7faa42dee5e68ae69f5613d), uint256(0x0bcd4ba76f97dbaae56e4d39cac6687ca0b39e3f9e996589e7bb1ecc0b9104d3));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x149e9c2466787d75019158833a2e2070e59d8f445de6d3784e909e731333cc0e), uint256(0x0dcd06f6e2dc5f97180e76b7c7fd43ff92e6a3e2266d6fd7e39db6433a1ce3fe));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x29e7bcfed6acd2588e0db65e43f10c64ae44538e0117906b21753b7786e5c4a2), uint256(0x1e42a4b9cbc555e0715399ea314ec08bc9d277366550ab285f4697751ff82409));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x03a0b21dcf3c46aacb55b994ddfba0d775854c4ede10f52359ed155c40e16989), uint256(0x08366baa7d1685e73c645fbefb14c02853d728f2a0686e3be5d6393708db25cb));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x11c692eedd7d4c94da30f8ed30c0e62ab0bd495cd70c433d4ba85464516306e0), uint256(0x13b5531d4d20fa67144799dfa75dfc75ec268b42c64f28ffc38e59107a237b5a));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x0bfda07618b027f5c480f317dd6b3d0324b89b5b66e66d03bbd38d95287cf628), uint256(0x1e6ab735712419e43767574c9e70339065c3c72c450b8a86e4e164f41e1cdc4a));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x2ca14747bd00e7db473aa93b7a5f91b15b21274ee4539f162018be41982b8337), uint256(0x2c4082d729c96a5fa64e2e92be6f0b210ec9d87542f508b3f69d3a349dc32a71));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x1ffcbfc9f63af528a217d4d9d7bcc60b72ab62261c795a25a6fdd782963d5d2f), uint256(0x1b96929ee489e08635f2804424b330002f669279f6c1a6e9561d8b26aa105d59));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x0d18e454f15550d10df94123f07548d6da51e10d4088b14ed787ba699f8ed8b1), uint256(0x1c78e650504a4ed3603e2c34d487a9f1b76c1cb9f438b331d3196280b5662f74));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x2a0f5024c81b5dfd4fad35947505ce97689cacf8035d3619fd951506df25ff23), uint256(0x27481719a5d65a3a9cf23a1c500f9076b4cb7dc24f4fcace74e3868c6c80085d));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x2fc87124b1744d01e4d6719f7dafd1265292ffcc60318312eb206877000927b9), uint256(0x132d641c94a41f93c34d8df5437ba86472f9f69c4e3ea69a5c052c53a0f50acb));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x04f0ec2cf5b7baeb466186f3108177fa3f83aa3516109d17b9a8454143e6b2f4), uint256(0x2cadd70a1e12faf820e91973cb199e83174ffd8fafd4a8ff7d045d481f756592));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x1808e4f12e40f381021c424a5a6e6187ccd73636b85a97cc429971692cdb1bfe), uint256(0x0f132e7722c119aac0ad0b49f5907359e577ed8e39422569765160dc95e2c8dc));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x189e03a31c712f581d9d1dc4702d752cea3ab30cc3755dd287b031a45078022a), uint256(0x07260a3b2a2844c5a3417b128b55be3272a92c2ecaf17dfd9d574e8a0e0e48f1));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x0716a30dcc6bbe8ccfa123de7525aae6d34f7bc7b44c126a0695464dd4e77243), uint256(0x2d2d1998ea70c10addfeff8d126340e723421957eb1a89e3dbf71437aa2a005c));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x243e367ecc35e62b3b6533d42a0cd9fbde017ca84fe2671bf12bde1f47ca774c), uint256(0x020a6a021b3b9a1604fa49c42adb7635ae7a80b5d69535acf4c2ed1a00529fc2));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x069b2cce636a86b1b2fe81ec076adfc3b2082f93be3c08c84a1ed8c22e5e2dae), uint256(0x1552ff5f8753defe138759affa5453a1265d59fabc411b0243fb4d8364c4a703));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x07b5d24614f14be6100b4944c5b71832e5087dbbcec1dd2dc4f82258fef540ec), uint256(0x0fdd9b4dad3b429e088dc3eec6a58778771409aba814b58d2b024950d3bb01a8));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x2b307f6a08d1e3c3ab0fab110db1a9d8bdd352c4c3581e6d11d00ff7e48cf948), uint256(0x23e9cea96787eba08148d3de66606f5aaf84763f3be5f5d506070dfd7667e787));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x0e350d36eaf01dcc414037801eb2f1223da7314789919a52cb257ca49465d113), uint256(0x23bb23b5525bc85100505ff2659c85f2865e0b8a41147903ab85499152dcc353));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x2685c6d86cdaf23fba231b81d49561cb8a9986747bb8f41b3dc73ab7873bc780), uint256(0x03c26a4817183ccaba0ba19fa7e94c1c61842b974462f85092be4b5dce6d4ab1));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x151520796c973b90930f56c2fa8ee5683ca770c499d819cb646401f65370d235), uint256(0x02c9c4e6e723f9d09a2b0e1486be1fc97b9d000f3bfa2ba1cc56860a542d8c52));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x2fdebb97fad71fb1a0d617773ec9a0705050737c4c428c405b7517a4278192a0), uint256(0x149d1d7cc939c89fd8d030bcb39ba14875b35011b81a238d0a2181b717608579));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x22c9ea28ef1338866752efb4ca4dbd7e001c6358849229513066566fec2b0176), uint256(0x2af3304ee89cd2c5fbe8384668f5c6359081fcefe113a5cbe93c2553a5461a98));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x145aa7f1db4d747d0533765bf7ab669f549a32cbb769d896a516f0b79b9e1908), uint256(0x18dc16d786af7d38c0f97a6bf4030a8bb32ea368dd18818770d3c3cb3eda78d3));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x2a587d371179dfe6220db80529e800f556ba5d2ef8ba4c3228f8ee3e94c34d38), uint256(0x0305863dde4853cc4749858ddf9f1b53bb03cbbfd97064ba01863fcbcd5ce630));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x064703ea2f66b5cc56851fd4f8e6d572e3727a94b0e88203a144502c62111cb4), uint256(0x0afa10853f4edebfeb66e548294b6dde16532ea239cc0f869a54f459334a43d4));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x029caf4201c5ca8949011b8fb947c2d4b67c1762f245fb748e4b1e98ea92989f), uint256(0x2b24a409f5190bbc7b77003db83c8e30085b09b0310c58c33a15bc636a6cb686));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x2a24fce07f1ab0824f44493ac3de73aeb01cb9ab68d2e3ae1a2b90cd22ea68cc), uint256(0x015fa846758ea0a423848341770f3584a7c3a593d27d40aadb7bc18be4d47790));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x16bf299e53ee93b824b3fabe111e9e8feadd25577427f92fb37e337f5f422951), uint256(0x240f62e4fc0439d6131083877b44a70d42ab9ac42698b350d9672db6ceaf99ba));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x0eb8e72f4979709166e90e78c483d363e1605d988edcc816886df33fcc936140), uint256(0x0c267cec84fa2ca08aebfb8ae806d6822de5d88e4f260e6aa51f7bf16d867738));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x0217c41f2b1b87b27713dd4b4d45336600a76c70d2ebb3c63b4a0fd3ff426644), uint256(0x0c72365402f6a02257f964fdb133a33ddba5bd0c6ab19af34bac6b9cae046cc7));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x262678ab7ce622a2c33cdaa9bc424a6650de70f0bd96e7391b0f541b4ea50b5e), uint256(0x2e9310264ac9254902d431fc238bf3ba8d7efd012256d9cc919a24a4359ae29b));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x0a9fbaabef74ddca770fcfea37a5a4c4327ed6180a89e81f166cf6ce87bad0ba), uint256(0x240138300b87afe98419c3b43d7d85df98947fddaf70b29ff71f0cd2be743b92));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x21db8421f436ba719704ba9968d972a8378548607632eb6481cb006ee953df65), uint256(0x20a92ed8c0ac971401f61031453203f041b4ff650ecfb1246e899a3976616a30));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x117a2a261871290585eedfb56c83007c0ffe220752e57251989984dec1c0cec8), uint256(0x0cd2ef8d950a1f7e18f281c4dcd742fc66fe73939a58bc48fbeaeadfcb8425a5));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x2c50cc0741b0cfd9cf34ae52ff9735fe22162f1d90eaf3455bf261ce6c50db29), uint256(0x13472bf8077ef1c9a828dc368ae8e8766b897e35ce75c0cec2ac26f16387b571));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x0d18a15c1b8d1f3e12d9d2aea6d9d59fbf1636cdaaa0585a833e0a99b24f3110), uint256(0x1230f5e1e31a45be966fbbeac250f6595ebe08fa27fa60e06b6a70e0fe11f038));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x23bee214c83357b25b4356ffce5d532285db0d511d27e2522fc2ee484134d37a), uint256(0x16a7f4359bf84d5997fb3eeae057d774e08f7510263b703462c6594c41ad264f));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x1ccabcb79e8c4163377bf126f9eac91a1b9c6987892d591beb8590793ccaa721), uint256(0x1d0c5b5fe761d35ae23f489eddde764fe2228521daaaefb65e275aa5fe55a749));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x1ac4ed0c7d0f959940093b05c6636e15431e600a24c29811ec754cff1af3382e), uint256(0x133f56acb3d80aaba9a383fa025b99d477c38b4d4ca99e474abdf3baf2336ef9));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x02dcd30f0b520d5d559b3c666714a07638b8d49ebb1060f71a9b1b5215ebcf7d), uint256(0x20cff708b6fac3f50350d0d993dac62d1ebaa35f88d2c81bc3817f9306844acb));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x029b639dce5675b202df85d6fa1a02721c20386505d028ac23dc2dcbf7c9373d), uint256(0x165bd97cf849b0c301f7a323d1bebf76d94ac333184a706bc4d2be3fe584d5a0));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x1428c2cdcd9d8f4bfd6fbba6b2cbc2c00fc6c09b6ad07811e3d1a79f340ed0b5), uint256(0x1c342a9146547b34f3d39ccd100aaca4290fe94cc20155505fa3a82917291ac2));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x1a47014be0f7fa273bfcb08365f23d2193d355baf802d3a15992e740a880e610), uint256(0x0e7bee9037163a570d7066ab4d85e7db0c1c4f0a3e740d0e6942b5418eccb1f7));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x0ba4cee99ec9690a07ea8f1146ba6c605c0a68347ef1512c98b690746ee9881e), uint256(0x2d4a1b42fc726fa3226ac16b3236833b180e2276db42af063e3716f08632e39c));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x0273b99101449c57fe271940b4a442555f73d9a4e733522432e16afbf4cf5065), uint256(0x2d4687d46dfcda17fb74625bff47a337224c1fecedb2404631475018ba7ab7b3));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x016fe5d15cf2ddc67472b88be0469e3b2d243188f03420ed0970982348821cb2), uint256(0x0785ba0b1708f7bf2281b9724ce6cefee51355848bf8920643bddc6ce2a2e936));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x19d5d95b0c0d4e3c2e355c79a907da971ad7324f3e06a4a9120de6dce6bf8a4a), uint256(0x1fa6d96716cb584ad5f3c0cb5990669e917f0648b031adf4528ba0da361d2d4a));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x1aff624d380210966e71334e3905c1325c64dd3d7023373c50b23e75c2d0a00c), uint256(0x0fca011c935aca1792922b269ad2e3c379407cd31237bf8785f0c2e7d0744cd8));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x2d707c12aff669fdab0bcfa68d6ee27ac9eff033123e4d5b21322d6d314fa1b7), uint256(0x117910d796226d5dbf305c253c15dd5cec584f35d39e9c5757a6eb08e6cb2d6b));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x11c3ff1a3b68bbda7f7000a534d2390bed487da5cd8236a299d824f327a68041), uint256(0x2a8577cba2c7372429f299216ccc39eef2f6a9ee3450a4187ab94e12ea81c36d));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x1d613532d00a74e83c92e638d80f47017674bd522b1fb9684cd11a8c4e0024fb), uint256(0x1d96cc50f46b1579f39c7a2c1b22351474cc04728bab245457d9a2e7891f1463));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x2bd8508e0530c38867c322ec4c9e514e60a9d2980e29001f422b81c56551a7c9), uint256(0x28e5c34180a7cb3bc4edb3d2edcaf6fe9b63f90beb79150db032adc2fb9d9e42));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x23e9986e162ebe2bd7df8a4589f6557c079d0a3d6c3e0c1a90c15e951015c89b), uint256(0x0da0b554af3c41c149d019d6e1d68c885cd0b60618fe262fd0ed58ac7632a122));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x1ce8fdbcb918bb927552e90edee48921f33b51bf30845487b9edbedb9cd96240), uint256(0x0ac43ff83fe7f401d289a5915de3f34bec625808541d5a8d0c9cc89c412bd01e));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x2a995b8ab057e2a53f018a6a8ad20d9fe25cd89217c0ff51e2145f1d869d878f), uint256(0x1d4602cfd1edced3ace7ada316b2c9f1fba0867c80a31a5962c95d1a02a7383c));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x216c8c722c32317f3305874e3d971ed110a04339b672a8390bd11b5c2e5113aa), uint256(0x04a1a4f308e04f613665490cc5ecab1b1642de7847c22613086efe1909d7314b));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x1400f0868133e5b5f8492bfe46ee624a1edef67d90bdd073320c5c1b89d521a5), uint256(0x1c0ffccd8a62a0c19c2be99ca33a43fd8fc7ea1a7d4af7e10676b634bfc5ec9f));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x0c4a724af3edc73e3ae9710ea6f022c1d5d44f1c60b93519bad7807faedcfd6c), uint256(0x125d44a3e631b4df703326112aca68ad884d4d96d03059c10fefb595b6c6b27e));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x0a022e6390f3d86d65aa8d53e442e6f15a861fbac59b961124feb009ffcf68bb), uint256(0x059d225e8114d709a49db8c3c3b4e1f74194c5a453def50ac8a52afd19b35691));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x1293a234cfd77e750d2f6eea770ff5d98021c4c389f8b04678d296ae1c711134), uint256(0x223cc6a6df841da91b6e86dd0428fc98fd3418de0f5f8a988d3b860391173666));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x1cababd791348844c8178823d86443f6dd6d6f2cb57a6ce9e66ee6b50f87e25c), uint256(0x0ca014a1c72cb6e5c848a77165c587ffdc62a2eb16b9e75981f5e3b6bf55dea1));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x06e03cbe9f21195632220da99ff1a079579eade61328a82c2ce2cd2881bd7178), uint256(0x1771a7e4e9b051425ef324afdc9799918aa4345aaf9e707513fa12700fc5b3fc));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x1ef1d2f4197766532c8021f7f1cff7e1952792d383f1e39ab3f88a480c15b682), uint256(0x0978205b2a6546b08f7077d7374eb84133214acc957c5287697fd014adbea851));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x23405674c3353f2c056077914b3313ac032f97ff316df97f6800679481fd3d18), uint256(0x0788732f05a475b0e48e9007a6508a000cbf49bf5d3f47f6f8ad75ea9c325656));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x2e987a5e949e0cbe9acdb397215d422698925b930f936709866ac17f27105167), uint256(0x200abc6aba160352cad9156deb8642c4d72b37af8c0b2c7e05d88bcdd56542c5));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x230671ca014971f394c00da76485477b3afb07bc126883ca6db26e8ceffe6b66), uint256(0x25b17f4e185a3b2e847fb11d5ba358bfe64ce06b9ab404e93ca96950d3ad1820));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x023d66f9a24c9be28c1848d4ae8e80bdeddba9e4a65f6c7a19337a8519041848), uint256(0x1c9b9caea4b9bec612157cd4fd4bb0da1e10f62926a95ca35a130f9f40085176));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x1e150900899b0a5ace697d54a557236832aaf6d38c0bd3ff9958f9189975f1b9), uint256(0x1c7598b0ba0b568b73173bf36ae9544b0f91f3e3648c0ed828075b9a36c37541));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x0a0f8de2a5e3652871a09d0775caaf8e3eeae841b1ebb131bba1ded6e7e44fe4), uint256(0x0840d831f9962affd636e026fa4c13c22cdd8de671405c8bda055c98c13ccfd1));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x271fe4186fa1b5ef700d5c69817b630bef5a9e6ee4b029000cafc6de4c624e3e), uint256(0x236696e2d1528a375e17cc104b6c5108f4a2902fd0d3981ef91c1c463e8dd5d5));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x236fa124aa7048d503eaa02f61e8c3c90102b89de5acc5baa1008a47d6198a2f), uint256(0x254b6d2061b6fbeea145b32834dfabf35e1d66e9a7349e5a2aef0534b0891220));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x1caa8f455306aa960da924cd187f922ebc62956cb88156043f54fa48bce86975), uint256(0x0d8650aa135ea7f76aa06cf4692149178d39fe630dcc637a689a6b9832fd7fe5));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x17378dd23f1f8f2c5bb195e9f1dc642a2100b2c0e0d88264007b3da5a4f792d2), uint256(0x1ca0b36c084e0d44e6a66b5fd2ac9b5ab09bfa69b23427e67563d9d75c4ad678));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x19fc277c7efdad4bf439a1bd7b5c90625866503ddcd9483239523fb2e8520295), uint256(0x2dc0053296af2e1469df914f5764baeaa0b34a9c6da9142e342827ceb49f4dda));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x23273f27cc5c5f59482e806b195d914ac71b12df7ecd2eeb1a5537cdc6ded908), uint256(0x1f7e4f86e94660a266ef26692b1c9c365a577b0eba690539478e461453cca337));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x2947e34ffb68bc8b63118bb804069be862aeb3811f92078a2e7f328d0554b43d), uint256(0x2b0a02c8ec8c1fe34b16b83c023346d1184a1ac645ea3de79beffa38e9ff8477));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x27b951ff9ec6436f1a19540c38b87d65e5cf15a47f96c639ef83e998f42e6f44), uint256(0x0f3b92231e86a10c1a6bd415fb2f62fbd611468a6f02b8a274509e7f3f9a0d8b));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x12612e41d66bb562c56dc39e83f66f9198413f801b480f36fa96ba2d8ab20e3b), uint256(0x2c4a88ffe0f5f071b4fc59513e72d66fc966be5cbca3d898f3bc849ae5567034));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x0ef716102481d29be8cc76714523b3b391e4d69d87eaa4e8d1ac762818d59a2c), uint256(0x07d5d5bfc012824f16915d2bbc059c0f702e5e8ff479426f190364a094470108));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x22f7998e6b9bf45cfe538c786b323af30a9f66e824f1bd31f3b26863bb4e7e3b), uint256(0x12c47d76296c44671bae954cac20d725d4c4c30d262fe016bd005d84f8b622d0));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x0c3e4df17d3a8ee30a568c4b5f1560695ce8d3220dcdec026f69998118ed6f25), uint256(0x221497ca232af5350f7f7d42ad5f249e0d90a676f082a29671826e283f9caadd));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x0b3bc9916a77b65b4c21a28de7c57a099efd13dad11756c97c354a19142d3fa8), uint256(0x11bf7b755307aee2593575693cedd496c2a6d0f7950d19ce8fac95bd0db0a114));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x2ec7f7fca0f03c40b7c0d278f014fb2baea3ecd7e907142f672bb00a861a8e3c), uint256(0x2c0fc65ffc8f1e03f347727532df4c93f57772e99650e89b43baaef157d4c2ab));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x1c6fe8ac2ed2accabfb639cbbe4fb8a32995b7f3b750738d20a6ae56c5aa19e1), uint256(0x14e3ffe7a9457eb31bcb30247144e11be257120c98481f6583563b76be51256f));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x2b5ba2bcf018c5fd4047bab15b7d226353bdfec292787a27f162a0ffd1e7cef1), uint256(0x239b63c0f4cf16ba0fe8439db38d2cf8eeb23c8d2334ca217a0e1fc6f9bf1520));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x2d0d8ff7d57e8157b5b379bd3b2cc5b69b323244c675d8455b33eefaff5c5b9e), uint256(0x084b93fd7d235a5e8403c8d7e6ae542ef3ac8b882b214ba4ecfcba3ea9de61b4));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x0f8521f744185904c7c76e607a0e5dcda555a5bcbed724ebdf11d1786d35b8c8), uint256(0x15cdc41cc14ad11f83589410a943da91585cc2736fe454c4e6ff29666c6ff31f));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x13b89efa90ff690283e7c3a935646efb703b9a60e7612e2ca71f213a2dda406a), uint256(0x1aa8026a879d253e40d2d4dec50301b92350a24fe459e68229df0d2601b1482f));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x0322dab3ed19ca1746295362f5fbd555295d4c3b462c93816ac6d2a7c6a49c2e), uint256(0x233580d730d388c485c74f61e47d43d761caa3c1f32bb9cac748f6eb3bf31769));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x2d24a0633c0c5c22156196f718de52dca9e2b37260a2dd3762cdecc93329d96b), uint256(0x17579e4032dd1530c22ef2aeda8eea7d728a24af1a9d1f735ee95a9ae8d51957));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x0a0ed23e6e463129f92d42532ea6de82dfa1584fb7c3ef35d87176badf7c73ce), uint256(0x1699a057f2d3bc3abc3de7a071b1d985b527aed2667767fda04c610bf88b3efc));
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
            Proof memory proof, uint[144] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](144);
        
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
