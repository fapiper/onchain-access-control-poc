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
        vk.alpha = Pairing.G1Point(uint256(0x25986d5b23bd5fb77d53b23ee1d9792c67af73322cc761c9e8635522637b036c), uint256(0x15946a7ce79adea226e508ce998b8e9a2250e7da8258436a560879016f2170fb));
        vk.beta = Pairing.G2Point([uint256(0x04e1a7855e16cf12909eca50a3b8d7608f5fc0e8858b2c9a5d1575167db11a4c), uint256(0x259c55c02248145eb95597741fe3efe0e89ad54f4c5e0b26982bb3f5caa9628f)], [uint256(0x07f200f8bb0e99c66b5b77c1bb33b9828711dd6823f26f16d9f98bd476eaa0e3), uint256(0x23fba6e075094886ad72fd57af9a3906ecf711a8f006b867b839e85e613b14f5)]);
        vk.gamma = Pairing.G2Point([uint256(0x14f68ea0769bef7827a914cb95922752aeb355ef5cbdd5b259125455daa9a409), uint256(0x107a68cd6536685c1dbbc4376b90d2227193c93bbf8bbd1da049bf9bcae355e0)], [uint256(0x266cf143bbbb02bde40747d9b915a7fb19018637fef998828e7e0335c5775d53), uint256(0x0c8e0366e9eb0e682ba8665661e80f97fcb19f4a2220009cfa456b894ee1e550)]);
        vk.delta = Pairing.G2Point([uint256(0x05f2927ed5746f768629b7e197038f70f2bb1f9a16c5f2308d8eb45a1ba48c0a), uint256(0x0cf59ca7aa0e6bfe8d9e281a0c41e0c917a89acd2bbd9943be1c60b200fbb9af)], [uint256(0x134fd7cc5d6884e5f570bed7566623e044e0473ad8903529733a33de6879b93a), uint256(0x1caa24947a02707f2f9a68de4e50009cab63e45acda1ca77119bc45d5478f91b)]);
        vk.gamma_abc = new Pairing.G1Point[](146);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x17902de7c77fe07651f39104b5834594d8db29968c14b7429a3d6bc02cd521aa), uint256(0x200c78e9f97b2670594a10acf9a74138fdd9ccc9c65f77d44a4760177b72fbf3));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1f7833653676dd4fbfbbdcd4a567200924025a53b49703dc8bfcb8eaffa8ddda), uint256(0x0c56092f4de71c55977b394df86947b1543aa455a3cf2e6058e915eafcf082b5));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x065ef0eeeb8dc0625be47639665739ac8a50644a65008331734b1749abf00fa3), uint256(0x0e54830a05140d0ba9f1e2d92d27baee48b8df6d5aad18890a45bb11728ae65d));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2febec2107f298cbc1319394bc405b1dfea82e9654d79a1ecbeea16fa7f1543d), uint256(0x148758693c7d0355e6cfe2afe9a32d0ecf640021ae0f0acacc50b4e00c8468a2));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2b44a48f4cdc6d44df5f115a25c06646ca8348cf957274da4ac9d6bf9831de37), uint256(0x0730162a53b8f4de41f3b591024c2c03e62beb0e6393ad1f827d00aabcc408f9));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x26e0137119142610327fe04ed53675842b79fb2e9f16f2714e4cb37417bb9df7), uint256(0x0ae8e7db2908e5e482734cfb806cf307473640277061c69fcc17f78988d51b27));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0b0bb767f861d9d172ec7d3e7013f43905bdf98cec36e6c5a644a07bda09155c), uint256(0x088c0219cead15b8f143c8bea8f9b7054554bef31d8710ef8807cf55332a4f5b));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x20ecd14c6f422445767c21061c124e8be3766061f7decafcc1b374c605486155), uint256(0x2dbed8bd65d09462a6981827726d1f5cd00852315be05c1b85cad2b2a96e5431));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1bb1b5bd01ad57cfb698c91b5307fa8212d7dad542acbb6220b11083968952db), uint256(0x09c23e89bf431d56b754cff50d2b227c133add7f194e0a81609963031b8edd51));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x08d27db7b9baaaea0970479bf8c4237ba17d86395e3205b1a90c53028185b7ed), uint256(0x1de48dde9992cd0c340d06e7fd2d2c38b3c20dee705e02b0ffb0d721053c3548));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x188878d7c2da36e04fdc44fe77eba34def84952fdfe78a978c373e6ceeb15f4c), uint256(0x186f653714302b1abd562f1faa885ab817871b3218e2ca43284693940bca37c7));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x12315d1f54725681544b88af3add7cc749f381696ff4b1f177cdd9d9fa388678), uint256(0x1198e6d7b71ddcedd3ae3101b7c8196a3e11100a1782002507f22baea9929074));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x16a0040e5c4e9d3fb262f50923196af8742ae45b081218cc096dfc5af95be434), uint256(0x0ceec13e2529d54553db4ab844efa59ba7a38e30d91fce1b35fac483bf7ffe78));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2297852e33a8a2dc4df8e6868edfffa88324e8d2ff0707d2311f3e7078d28d58), uint256(0x233dd2245245b036ca503042a96ca74e42c4529c81deac071f2cb9b2b336944d));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0668ca5a6425ffd7e015424f21b4f455c33d00705c3ee2a70e49db550355e36e), uint256(0x0587ac25a7834051cb13e7f96488f47f115b76790efcb29d3da09042123c5182));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x061e7c6cbe4f64a04a4d8db559687ce6c2c20b956be5e9a1b8f9d820cbc24272), uint256(0x0518e7e4552431bda1af792233f3cac7e1a8aecfdac45cb90cec32530369c4d8));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1bde2cb632a7283355fa06049a9086765b01b70fd2a3101bde3beeec1442d8d8), uint256(0x21f71a37a68f7cc8be62e12547869b1cabf3fd145f4c6f29b37df4ffe1352bbd));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x177b6658b3df4dce88a05f30716d73b35a3908e8ef55b095a4d08fe6770386d2), uint256(0x2221b174b89f9c0cde125827dff499429f3d75ef966e798bbb5e2872321e3882));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2f8a58688fc80d0d52a401cd69a52dd63a983a89bfcb35a309ce0d30f9507099), uint256(0x2b884cd9dac65af063078fcfb6f44de3ea1711a0129e52c684a9a60b8ad9a81f));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1185cb3ffc7d795ac14623e1c03789c46edca1e73b6f784f2e0e240db42edc69), uint256(0x10497474786962b5e7623bf9e43d9c46581849ba94dc66e7837ef6c6ed573a08));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x03cb48e7c99969e09ea694e852e4ae496b9b359d148b6d945587869127699e1a), uint256(0x121c013136c4fd4a117922c28d11df289d233dabea88f5055a7f0df154e65831));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x27573cd17799450824d6de7f464f6f0a410ca9462b6e2083079d64350f547876), uint256(0x1eda80cc7f6f05e3502fd31b5c3f08475a0f2b50e742ad36ec62e1cc5305e551));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2f0337d2869833c4caacaf38937df459a83df537f6bc7dad3c0954904a552cc3), uint256(0x21986daef26a1b11cc9d606d88de24ef00d6a8bb19bd6101d5e29e29e9b593af));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1705979292d62144c6e1b730c0ed0cf2ff7a8176e834a5cfe31c82369fe3b85a), uint256(0x116aeecc4372b7852ddb6e1bc753fd479360288421c1752087a4563322dfab85));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x106b76c14ec38d3c28702d838274474c9709639bccf89205b68348a444970cce), uint256(0x135d4cd7a9d8cdb662e58c72ebb51b756390844821d1b493dd1280bf79771bb5));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x2e05bb62bf2f7c704e5cd02ada21d5d259a4bd93c90bdeb25a992535e90f3864), uint256(0x15420968ea1332e38d5e7a459ca288ca2066011f3426e42b6fcbdb9c66d1ec9c));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x2093d6b05c368b8f9f9c5c602f9598b01ab3f6ca40391bb51c433fa8c59037ca), uint256(0x2819f25d54ed03788ef245770554e108720b14c96d997a7da8d1256906829c5d));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x0e95f1fde7e8a96bc63a086636f4b64f4b9fc8f7af3efa90f4dcf366bb70be87), uint256(0x2c103d5c09293d7ad2021372f4633ad60e36984df735d0fd9f2104c9903e290e));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x254c47550b49bbaf4f20fa7150d2b3f5029d46d448b4031615091fd9ed5f42d2), uint256(0x03b13b7f6ef634306913c1905c6fab94ca223b49d9dc5874fa22f0169f936b8c));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x01e06313127b4cf22a99d5ae2201a7e8e92cb30f9a3fa903a848807aa26326ac), uint256(0x0be5f75ad903cd37fbf9c2d2282c5f6e62b54a6bd977454520468fa3cd5aafef));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x286cb9cc60d9836c027f5798321905d9dfd6eca668d17b89de6fce3a20ff59db), uint256(0x1d8a1dc2a35643c170a020ab06ba3734b3fc778f624b3d6ed9c42737cc956221));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x299121fd70bdc6d37c15d2ceb84bf11e9c8034d626c0257e270008f6893b132d), uint256(0x09ee4304dd3c213462de5fadda9878a4cf4dd0fb16a55d4e7efb5cfac969796b));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x0109915b642534b58620fcf2efe6aa918085dc67f1eba0b9bedc9f5e00f43af7), uint256(0x2c366cd117d76f06c00478c4328ff1c7809676a0486d9269faa8132fd2471fef));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x1a0dddf1dad51b6fb11eef92bb94fc152273bf9b2c55636f38143309fd04ae72), uint256(0x2cf02f5c9e689844009f42b010836fef183729098de55395e97e3b921dbe0446));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0661518e856718c3a849fffea045ea07c2fd2e31a2c42f4fb2a2a74b5134ade2), uint256(0x214a6808283bc7d4b81328dc290d2be81f1df784358d5100c5f799174dd77ee3));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x07e64467077eff5429f057899757b32141e59229a4feebadf47e1e9560918f86), uint256(0x25127c7d8d2bb84ab2304c113b9fbdf2deba96cc29d7e0b2d1f3f0f6c06a6c89));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x19ee92677bd0158847a13c4f205d4a76d0c02cace355eab67596b379f4b2498b), uint256(0x187a5ee909b58289d1bd38f7df103b917949ac1069e83a394254cb9992caab60));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x06e13e3d38f3fa59bde586ee470dbda2f932d406d0b21b72859325aedac346eb), uint256(0x1e94b778fb0dabd9f50d258dd0bd89c81669b116e76a11b9d4971c18b56c56a6));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x28af7e8997e0a5c3474aafb1148ac21239600df2114c16d9f24b7bf25f3f8577), uint256(0x01ceecf2e200f1584e30c7538eebe1844ccca0238bb3a68e4bc58bc0c4e7d064));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x099bdd6597f8fac23a36f81aa300d55586270013f232d058319350c00669d858), uint256(0x0dacb2016c84a997de4f8907d425b0f491dbc08718f4e9da215a52cd16d61e43));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x2adbe0df10e661e6557b0cf54f81c147de9fccda7c2901d2a2150e113e36d66d), uint256(0x12352d7304da82587d8cb88503e7f95d6bca0afd903565f0504b2af07add1ef3));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x2fded9d0c6b1e8ae4eb13b59ebe0b62c0295e102054545bd925f7e678b33cf34), uint256(0x0d3c2b98d31f4394896f38401b3e75c718b4cab5460e97e2e738cd0a4cb87a15));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x23c83270bab68b51f83a1aeb3d836bb04094d9c2df19ffc206a685c2ca26683c), uint256(0x1aa08bd5ea0d61625aaa204db57d91f892bee2beb99a7abaaf7e485e426fae69));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x2cb4690c49b902503e9e32fc337e701159a32babe47d56f0b39031dbce9f9917), uint256(0x157062dffb6fd81140f8203c1bc50efc46e5949363e34b6d9ce772c4c2da7b3d));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x0302a55aafedcd31a332ee9c1ecbec3d4e66e87e7b28b9ec73c100ed8b253bd5), uint256(0x1a698eda6be6440a6fb8f9984727e1a776341e0b52c8aaab13837fc6fcc070af));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x21f12511b273c284f307952508f8cd49ce22d95cba2e02ef144a72a8d6dd2d16), uint256(0x2da9b2a474a45b570e969eb40e96d1385c0aac98a48c008ef27f945c3e0d4b32));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x07b0140a795e3110d2bb90d162597a6a8c85f1f9b479ed820f5fedcbecf02578), uint256(0x173eeeffcd2adafa25a72b130831bc1e2352da2be2dbf5feb839c49f48c7292e));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x07541ec0877bd64c9e4621471f2cc21c399bceadd0bbac0c1a4f1cd135476b40), uint256(0x0235b1490ec85664bba45006825e09f83e8fc7148058faf3a58a8637caec5f0d));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x0238c1e2325c9c666d2e7e42f1704e7686c221447a0bf2a07ddb7002e3c9067f), uint256(0x073da7f6bb9b3c1a56463a0f30b06eb9418fcb8ccfe13f9afd54e32a4fed6823));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x2907f8b18b026970f98d677424374ea59b4b2a42a88f7e7f7fcb04c9255b02bc), uint256(0x0597e2ebe4adea3030fd6633291288a09c80799b78bfed6079c7ff7935e78fa9));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x06d91db56525cec39e37d73ee0c3799fd3134818ed3f2098f5d6c7fffebc19f1), uint256(0x0ec60e9b57d45de738db747008a498966b3f546905523c5764d1c3a196d0f8c9));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x21b70783084133778783cf388d2591fa6c6323503c45c3e1bb7ad72fd5f6c1c3), uint256(0x1f5e1e2d289c7703d8a9642ce25782d0cc2ce5bded5512ea802e92f8241679b8));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x0d8baf201b64110eae764f9b40efad5443da83fca9d9de86e3b3d7dcf9e686d2), uint256(0x1b3141c314ef4e7f6977fe3597eba2d82e79beb47507134eb40d539a9ddd5b18));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x17807714895c9efa06fe7bd0321b3267a65c9f7162b3c83bc163fb9fe1b81a2a), uint256(0x24d07de3d0e226603c67fde941a269c2d8557c18fbbc8c199cd92f8f61025a15));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x2e02ed08ee3af0938df7368686fa9c3a44df541e26ebecc823754e643f3efff6), uint256(0x0ab04b6db768c2c0530469f6f0eec0fcc86a3033b042773f4c72e3c5cfb182dc));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x04b9a5979f2dc5c06ebd5cdbd813742bc9f7881d5d4a0274fd73a3bfc6a46ffe), uint256(0x031e48504606d3141a6f43a9b76267693c07185b4058cdc2242077f4ed4c9e85));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x1a66d1bb189b8af3ac7be075670e413fbc97c96978643050c779a0877891a86b), uint256(0x0716e247ccf462d7349935d8220d552a31e1bd22ca684dac7dd914e2b6444bc3));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x15108e83445816fb4a2d9bc82fb1797e92fa1ec257ef03722e031994b40e9011), uint256(0x08601e88c77287acc04109d99d63723fe2bab2d1414f3e9c7ecd07a62bd8e980));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x28f896e360b157fcbee5ef5e10347cf15dad9d98fc75abe90773ef415b667ecd), uint256(0x153077c0564f055cc1708dc403021a672b20a810f20e895d3815aef15cc564b9));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x21a0e0b57423949d4698706c561ffead3b89e3c296eb48cb7674ddf0710b423d), uint256(0x271e02013bc468594187464b7aeaaf4e4fa086a5d8075d78f2548bb9d2239f47));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x25f4cc6e96bd9375d9aad1069925f716ee216309866a76966fb62bb33acf450d), uint256(0x2368049acb0ffa7ebce8bfd3c14aa95a6abd024d2a0d1d129cefe0b5c71ca9fe));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x298ae7cf85ace8fd735af05f8dfddafffdc1f1764461eedd51ebda3e3f77b75e), uint256(0x0c95d96dec96084fda28046d2fd61d9ac1eb17f5225e27deca0309f9a6b3e470));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x1416d7271140dfc468c7323d7922546850cb3c46dfc717487fb28d43c515db6a), uint256(0x1fb30c3003dcd735c65c1601199946f7666aca44bd8503f12d9d131e9909be0d));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x2c33c72a433de25385fd31b26035b12b008aa731dbab84d808a87312ad605a6a), uint256(0x0cf4179b357b0a664a338b8ad64906bbbc1d3afd0dd4e0fb228e409e3ed32a2a));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x093d7d07d5be148a9cfef7b28672ed60a8b249ad6b00842847a671aafa6974e0), uint256(0x1ccbb31ae9d7b2e886c2c6a1340aedd88731ce7813300205c012936419c99566));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x012984ec2d4a05e650adbbfd269569a7c0c07ae7e24823ad852521f3313b2933), uint256(0x258c357d8a124d2b01cb8c260b7b51dbb1556ce6d0eebbdf6cc759996d00228d));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x102a87b82ad01412ad6be2d291300cb7f39cd2fc976ea5780ea428b892828f63), uint256(0x11ed9eb2283aa2bde5a4c091d12d79f061f8ac723f22952479232bbaa9b9c43b));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x06543ba82a09941719e42076ad2b263a0977da3a6b4bc4d82265d87143a5670d), uint256(0x2ee7a5d43e58684221a79f7276043c76e86acba6856bba2865f594866ba53212));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x0e26df0adfe497bbfa53ac7d5471f16495a0f7790daa99fd39b83fcd31982436), uint256(0x24700817d86213b1597b9a2bf765c009fb608922f9eb8d5280baf49ef4b9e4fe));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x0aa495fd2f74f8a42f3dd136cccc80c3fcc9ba5ce76383a87895f296f5db4b07), uint256(0x234af75afea9b27e9d8666a022041cf3d8399f818ff1e0a971b2a89a825962a5));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x0291e108feb5816c1fbebb0cb1379c5763571ae9f04e9b70cfe534ee197e79a0), uint256(0x0f08ed0bfe8301abf8d4522625fc2be38a00f30a4543d2f690e45adfe4af1706));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x041bc37e76a32e3d22069949169afac59d68d597a0d2d3fd0fc56717858e7c1c), uint256(0x0941852ce3210b6211ff3935573e9aa0f844c90b0408cab8a16b5d0ffbf71d1c));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x2a63b1b80099b9f28b7b44d127364227dbf47c39f97c0e51da0d8afb735d2c35), uint256(0x0549dfa971d1b3a07eb28858517499624e18da5c22f24edd1520b2f812ca2a9b));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x0e4e03c5604dd052126d2f5fd3f8dd6d9a24d071604c02f3949aceda06907ed2), uint256(0x172cfaf5919ca30c0b4c6a0150984f8010f90409597b366d4b50bb5793d51e5d));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x1cea9e3fd3567e3b1be8331cbeb6d3151e2055d70c7294e55891351c268259c5), uint256(0x18f194aa65aa16ffb8ff7b9094ce4ab611cdfbfcebb4d7755f2f4d9615afe180));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x12175330730664fac7a40130648fc142e4f15b5a29b37124c11cfe155e9d559b), uint256(0x1ec38c71e5af18fbe880bfef0515da352ea82feb2e04b8c6434ca34cc6e4072f));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x0a9f5b50d5f61362e0738a4b0442dbcfd9ec534a47b64e571f1714e38b4b3f85), uint256(0x17820abb54d43a4d01943b733fbfd723eebd0e13d9d63b2745b53d10602bfa80));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x0e1a1c89228b4e70e894496ce839de0928a7b11860ed38be64a4e07b669d5e30), uint256(0x2e41a570a5e6c6122a35af78aefe0f8cdc9bea43954183fba345bdca423b0388));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x0e72b5e2673190a6a005f6f8a391c4d7ff2866cf9b244698a45b740ca862f0c3), uint256(0x0afb7d5e7b30489e39b310b79f81acbc99bdc8a539511a47f8be4ea3c1490772));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x0b93d45fa04239451b10d175dfa84625f4bc46cd2c2ff76e0b774db5f1e7409a), uint256(0x12c68f80a38947a40018fb308924d2fbb95bc5aa631a47a8b7eb5ba38861aefe));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x147e03b8f13f4b9239d72119b1adb7a9775fc471f3b4724e546916b93f4ca8e6), uint256(0x1e4e191db8e85cff023df43b4beb531fba8f2d00083793e688ff7d80736a6027));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x17606fb089b21ed680bbe60f2be97e97d17b62f6bc0a462a3482b840a79b1005), uint256(0x1a90731cbc9a8e30f7fe79796891c5734cb243ecb3f48abbc5cdc2b5565fcf01));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x04f46d6a4fb0adeacde6265ed874c2a03bda0100e96d86e4d3a4109e866f3e76), uint256(0x12c7dd8723f4e25e2e423cd45506a07f262ed034e7db271b07dde5753b2264b8));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x157dd09cdf3fc91ec4c4a0f2f20434c26b34d6ce28c18ac79ad083fee945f51b), uint256(0x2bfd76bfc9ae3986709f9db87faaced38f9d292edcac146c50d2e624c7122ec5));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x15ab90099004db6239f9bc12fcfe03965b6ab1b3f00bae5f965db676cfa82bc8), uint256(0x2b7b522f5db889567fcd2c224f45ec11a53c885075a785a66bceea3c8098392c));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x2911ff047b74cde4a49bc2f2b5a32ca4fde3d0b640a3169b8c851fa78c79f6c4), uint256(0x21dded8c34252e74d6d7c84715751df4242ee31f904a07f08c0d3f83ce4bce5b));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x13a26cfe690c7799a4f59f40d585f06d8155d061a399cda35284717e3db4c330), uint256(0x2121f027f08f99d7bf6697f14869295c41406f85d7a5b15666b68bd8bc8741bd));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x2f512444195f63d15721d390ea18ff4326c56ec4d14e382ffb52b93a78470cb0), uint256(0x114b16f7e98235e4460b2f5690e30e0d011977c149584eb444a2c857243b5412));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x2d1e207b52cd73eec45780a2a6a0fa0867c3588b0baaeb3f537b2d0c5987d06e), uint256(0x15012c1ffc00ac8994b6e11081c555aaed98ad04555e5e536b72e764d6b181a3));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x139a6fc9932796bd3e3cdcfba810fcb2fc25e0760b1ae99da7c345dce25e26d3), uint256(0x24045d3a10eab00348e8f745ef56dde714cf212644f5c105537511f449eebcad));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x08d596b1109ac7203ba58048c0730e824d295168be0e563f5502750db7f0d313), uint256(0x1750bfa27b9152ecc97ed26612f59f653c300ddc87a9a337b3eda3e70ce0e952));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x1c84356b57f74a5b9f554d6dade4657ef7704484819c11bd7396b4a593b8d608), uint256(0x1b51ffcb83453b786f191cf68e3f4cbf28d5a687d5469567c88ac2d2c4d212d4));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x1f02778b63abf56e172828816d7aaa024789550c2b3ee48b3782609892df947a), uint256(0x2e290c5fee1bea669d893ee3ea914fba085844dedde38d9b5c095c1dc2660341));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x2c1806ee172d1ffc6d180511376a4dd1745700471abc023f85e6efbafe6291c9), uint256(0x0f49e84dfa779d6c502ec45c2c6a6004c39dff91d5a3b4fffa974daf06c4eecd));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x12194962220df761d616f632299c1a80b2afd6ea1bb41935efa938de7d82826c), uint256(0x0177221d3d75626e53b1c54e6d1f4740b9b7949e4150e08f214ff38620c3473e));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x130cc56e108fc76c44175617b9b7fa8b0230151471732059d4220764548baa61), uint256(0x13da5b3db468067d4a667a7f1c201ed54cf1fdc787674f17c7376b96545e3158));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x292cf867671cc235bbafd4f88d7bf427b00c020905695ca625eba47936127b96), uint256(0x03559461b05446fb38ffbcbd825c2fa0d4ac17e9853a803849b88ff1d2c557c3));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x000488d9be918fb116c338b93954e3b0e9b83ac2e03b58c9fadc5f875480b938), uint256(0x2a67ae16bc6afbff9157b8cd7d1cfacc37a974db1bb306595d7fbcecf0750927));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x04b6171f10fcd143460789d26970b25179c6fae09d2563fdb06fdd9935e64ebd), uint256(0x04c2d302e8dd3834260aea899c7058de6b99e56c0a736c1078e50e16e4ed26cd));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x0e00cbccfb1f668cb18329dfba444ea524f5c86d46ded16ba6f121c4e650600d), uint256(0x1d7aab6b1b51abc654ce946e0915728d925e9efecd1c80eb6978822bf8300c2f));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x2c98e2270659f5967600f5130745df9432eec9e6285b7694dbfbeeeaf12ab313), uint256(0x01989ddf0dfeeff1360570a03cd24dbd99d2a8408da567d5474e06f276e2742c));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x0059c875d3db70e5470ed013ada41512cb2a9cd29df13604d8dc12fe3eff25be), uint256(0x22157b540d66fc22a8a109c65819273abfc553a9abe8ad7a955b255de50b21c4));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x247db927d9d1ede48e39c7c448a1cb17dbd86abb7c7a443b9fcd372e15b2b701), uint256(0x2ac39a012aa2650c914881ee32f50e3e0a000a7c31cd26b411478c17ae4970b3));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x2fa31738f2882d5693d819728cb180eade0ed24cdcd9bbf03d7f16f4c3fc9ddf), uint256(0x19236de5f571fc43dbbf593733f9800a60bdba694f913b3ce33e24e7fccfd998));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x2465960f0d0ef352c2d85b2857581b1ff461fb9b5e3a175ae0565a98f1badcdb), uint256(0x2493028c55e8eb83efabdb366d7485377d8c6762dab1232b514678a2636540e6));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x141239dc24e7508ee4a3b13f76cd70d174c9b23f5a9834490ab014c97b28a40a), uint256(0x15b461384e02bb86f7a95080f11c8656cfcc925efd9bb8badd8162038a5c8001));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x2d57a9ecd8db72f1840fc22bcc56ab60222e6250df7c0957d1c4e032ea1c22f0), uint256(0x29ebcb7d3bf8b721576300201f7cb99786e5f039b6351d936564fb1283d95053));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x24aaca1083268ffe57bac4a34c3f05dd41dff3dd92b751942992172de74126af), uint256(0x197fb320b5ce382558112616566776b807c24a7bf3e65b413bfed33edb20c015));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x14e771429ca508abdf637fe51f223c76c723f6f410f6f472ca2ad93efa16b9ec), uint256(0x1bf0c072b1cb04825edfb94ae6eae428cceee0e0bcb146564c56b4c163455cd1));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x23319b911ed1587ab9ec997da038726fc7caedd2dcdaf2c4d63a81b7a4c1f047), uint256(0x0fe352a99c2cc4b5bc239041e0164998ffcc1ce9db706dea83c73cb83a1cc8a9));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x06ea180d560bc44f4353c4cdb896eabf58cdf14dc89879bf0df66e1b01db9284), uint256(0x0c18d7e66f10e28f5b7aabe300bff100fb3a55971f141d80869047f84fa1358b));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x0f94418f1234f596f5bc87955d9028589367d04c312bae6578e5efda43a50b4a), uint256(0x140c444904e64c9e95d97e7a265831fa5a12000177599570c39b54e41225a36e));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x26ac8aa7bd5941e1ae7469afb42be7ca9c9c7792a14424068febbdec7fe94272), uint256(0x22a6bd706dabdc5912ddd675b969d1a3cb47a665b638818c7080fc14376b9404));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x24ccdd8e45f6b2e23b69f795995e316b0181ef634908371f82c1e136acee4eba), uint256(0x13a7fdeb32186cd59a9dfdf871affe9c564dc6f19aa6303bc1ab643f20dc1312));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x17a5c21c9c9babcee5e611fb76e4b86249faa2d7c9d0c3a316ab787d86154db2), uint256(0x2d1cff37bcdb1479879ef00b616c668431574b5da20dde4d72f3dad0dab719b5));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x2ef7c0020fa361a04827fc84b8ee292530f17b805acceffcc41446700da7be35), uint256(0x1d0d734e4a7bdc0bf656da5c4da4f747c3234365258bd85438134a5cca471ca2));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x029b88a4afb6dbcf6da99b42c947f70450190ff64d1d91aaa3c2f1c1a1228666), uint256(0x04c26a44044337422ee67d26363fc0a50380a62325c6b00b422a5558d1cea698));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x143d474fd1594a499e2cc92d66b4db74530adc8dfc2a6ced19e2b12e1c072531), uint256(0x2a4495001e9849f3aa37b004afad8d9fde1562da71c5aa55bc35f50d78e7643a));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x06742dc1f475511755bdcfa5ad3cc22a6f587e7474ca522af41a526890b516f8), uint256(0x2ccb55e014f6025f903e05dbff35ec68e446be35dffffbdbbba4a8371050fd7d));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x0147bb315e7027d6d921d04c02e5ff795f4b2c8996fc8339d907a176bea08650), uint256(0x2c8570165cc43312ff9a3ef5f58e45b46d52613f044a269f5e816fddefc041e9));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x2f50366e18e9b8a2c0b46b178ac231d739135af4f8eb2683aa58c49e8b615875), uint256(0x0cbe636fc9e248c0c5832e0a20001d8ecd6779f0a9149eaffe0ca086d0c43485));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x0850ae27e467c49d7c60ccb5ac204ad46a995b149e37c6722b3696ee7aa599ea), uint256(0x15ef9723de235609383b5f3149f25fd61d5ca2ffe44101c4eb978a954b5f6871));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x1f3d3173ac3c6f1904a1bc0494bfed1920f1ca54644ef52175a383735c136aac), uint256(0x1b5b40bccb3bdbf57ea39fbc685bb1c0b1deac4d09146c62c3d43dec0c2c7b4f));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x2cc859c78dbe45e88cc9d6a3b5fc20f967866dd176126719b9fba8fffd2da638), uint256(0x084639f1fa8deacc976d1b42bd194177bf72b78fbcd2b15735ab966138a49f6a));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x2698f0f135703fbfc70895cf1b91cb3db43e995d2a7b212db3a5abaabe6bc7fb), uint256(0x06936cce00fe1e4a8552f58e59d558fafcb6e03419790a058f9d58142af81148));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x07bc981a878e28381523363207dcb6ecf976b22708884099265eb31171e2dbf4), uint256(0x0e0401483f86edd3b866a873426361aaf39b08afd2fbdc12c1a7a26030063f79));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x2f32d6a325f09b677b9e6987a2eb7f97c3b6d9dfe8b1e3153ea383419498e571), uint256(0x0ca56584b86d1c653ad21ab6c9c5df1c4e13bee79c9d151bbcb393f73d9a1ee2));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x095f3f09e631b7ce65e88c6c56f3978fa64e0c40f574ffac40b4526c81ed3b2d), uint256(0x1a2366104a14a2f59c01e0f62f3cc8cff7266ccbeaecc047ff226b8d5bcbd5e8));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x2ffbed209aef26103d5ba33ea7f0a49bf6d7dedb19e604e164617fe84744146e), uint256(0x1bff45ffe4405f1de1a1e3027f3d0a46db7ceec0d3158ed12a6b93c60dc20454));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x2d81cded7fc36e8da66e3102067b0acfa8e12a959968d1f425cc75b66ae9bfac), uint256(0x14054c75e8b142201c5498fdea5e07d025db71530c3a67938d60956dbb40252b));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x0c855baad6340ffc3f6707e17cd4aa645cfa047ff4bbbaa05cea6a54a14005f6), uint256(0x0c919dcf954658ee4089d85a7e59877aafaf7de2a49e063800695d20f6a54d97));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x27b44dcd331f3ca4b97080597b2a3772f581da9bb0afcbd31df6de2f16a96530), uint256(0x27991e95d5b32ad6a9492c47773fc8fd7e3f9a452a5ce94440021a0541f72e47));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x26fa1a4ebdf51240b1af9aec9f722435946828f6a9b5b932f02acceb708ec533), uint256(0x15d09f46773dca47a147e8e6fec7d68f408981017ac18e39376fccf448b5db37));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x000dce533e459a83635d4b7138442f74fea5534971f0dbfe4b1ac66ac06ee52e), uint256(0x2444f96638241d42152a4303f95351da22427b7f89405af0204f6ffc468ef60a));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x0aa5d2d687d6dd3649fecec97dd7274c55443743663c61c2e2b68d8cde75adb3), uint256(0x13e319aed0d618d934dc14ebc5e7bcff076a06d3d958c78a348d38ebd113da56));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x0489891cbf7270906d01a85ea8bb40bc5df2dcaedb314cf1cda63769eaaedf0f), uint256(0x1e9fdf6b533de2a921ffeb8549476e2dc3d5edea8782f3d2a6bf48a546151cda));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x2709ad5e124eccf8ad6113dc53b52479c40ff1ffea03939a7db037f6dc64222e), uint256(0x175a5071ffc1dbfb8f1beaf1dbe44651d8b508e7bdf09ffeddae2d0cecb5cf7a));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x09962019b78d7783a1058d800a61e9b9c5292f58ade468dbb3ecdf4d3dd7bb93), uint256(0x24fe6d349706213e73e8a93e5f7d7cb13e7336568b57f54fde4e96c016f45741));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x2cb07ae3fe81e5447e3820fbf8be65041649899588a53912a3ed0db09ede032b), uint256(0x1722a79b232bbb0dd6ddc60b2f2195fc7a1e5325f7b66a14c9c0ef7d28c64dc1));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x25acb629a95c999a8406774e081fdb686f9226284df08f40d684e47e30dd232a), uint256(0x1a69630d0300f60075ad8a138cb8038888035f761e0d0b6bcf748d1c52408357));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x042150339f2845c068dc29f842ce8c2717be971a8d064cdea180a7d6a1faaa27), uint256(0x199821619fc7557e67772ab81b04bb169e4d1b954b6f8dfd73624ecbe6996481));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x284f40f39603f8ef01c0a2e23c133e82074f9c2f4f47e261d2318a4c2df6ea79), uint256(0x02425662e19bd1c4846d1ec7b959f81fe7298afe2cadf5f0cd34858c6b04980a));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x0159f1f758442859d1c6f486ac1a2b6810b7a7c3fbfe37c5551aec5a902f0153), uint256(0x20fe9c4ba01c7192ca0ba6fd93fdc937d7f4d054570ef0efbafc912e5a7a82d9));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x04910c74f16d22bbac138e87d1e05f065dc7d9849df297b1dddc6a92b564308c), uint256(0x0a200c415d05fc1d00185f13ef755cf6ccd6087b92e7d5de0867bcee85b3d56b));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x0092b373878f355f6c6e26dce7ed1dbaca7bec2fe186f9d2a8fca359be69262e), uint256(0x07cae33195b7fe13c346f3152eb4def8c9a30a95632e39def93a50e402aeb79b));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x07bc646cfd058e50887e91cd1ebe848e5b4033e0f01ed94c2b7c0ebd223b6135), uint256(0x16200bfc829638e46929db85b0c1811c40097f4d18e19426b021fd0aff5d23d7));
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
            Proof memory proof, uint[145] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](145);
        
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
