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
        vk.alpha = Pairing.G1Point(uint256(0x1fc45e44844d24090f50cc66ee8ddc94f4f83137625b39b17644e08c6d141ed8), uint256(0x1c87f18163d5694f76e0438f2014c3bda67dfe25c32bd94d5cf2737b42ba1ac0));
        vk.beta = Pairing.G2Point([uint256(0x1fd06a7ffaffdaa4e82a34767f7cfc5bddfcb3a662aad07568cfe0b99dcbe4de), uint256(0x137f4fb92049f9a55a80e486c770c521544674d5e565e5e4574793cf100ee123)], [uint256(0x2bce08a032f75173b16ccc33507cb329c83077958d916e90780fef9847e8dac7), uint256(0x25d185b14c1b1185ab10ab5ca81ac787ce78b6c512c50a253f8ff84198b3e51a)]);
        vk.gamma = Pairing.G2Point([uint256(0x2c6b7045e0cd4504ae2a877f712a88f005be91844edaedd9a0d1f516469844f3), uint256(0x042d714265eab2d6d287613070467c335ba6afdb1ef91612db36f95f199101dc)], [uint256(0x125fec141943fa2715424c533bffc4f19e0b2c85f9942a9dd4c7f3ede182d2c1), uint256(0x2a513368cdf0546f38fe1b5fd4098a5f201d8d7ebe22110b4e500f0427372f8a)]);
        vk.delta = Pairing.G2Point([uint256(0x191824251be5ac9ad40a28746661f2a42c5aab6141135fe26c2f41d6678f5983), uint256(0x26f1b92321fd0d859e0e947555527fafed4269991dd5bc7306458da0db6d853c)], [uint256(0x0912e2c496cfae2bbb0244af993ae4ad34f6ddb1170f87f80fbb474ce1e6a268), uint256(0x0f122095f1dd0cc571ae30c340589b89b109933c5bb987aabe8bfa2bd407afe0)]);
        vk.gamma_abc = new Pairing.G1Point[](305);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x24ef9efb308628610927eab216988bfb3772ed499e12fe374bf5d686f99ae697), uint256(0x06bf69331c138e3cd980a94b4397c18a80675ef1f5e3a4d35aa0ddd29485a406));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x105372f4de56ae14caaa6cef510165370ecc50738a1cf25c102f75a426bb0286), uint256(0x2135a4169925b58a98335e7403595ab6776835666fcfeaa466c306ecd39af2b6));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x041e5b08b4d532e2db264496214d1fe088b9c5e97c9368de31572c068556f336), uint256(0x1e28407648731cd631c7f795d8e49e18e75ea42a21c0960e1231f323b598ca1a));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2b30e8ad7bb585ded3cac28ca3d8622e87de74dee8a697e26370ab1e7a51a712), uint256(0x1fef08e178ee458a8034f77b60c790750890fad220f9b761401ad02a1efaf34d));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x143e6eea7a067312748948964466591d5168764e8c82d92a7d2acc7dcce69d73), uint256(0x01aa3881973c0f3dda807ffd4c50c505254e0283e86c6aeefab4fb4fc9658a0b));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1244c74d77acd0dabbcf82784ed7c46a9efd1b51bc3e378e0be53fc85bd7780c), uint256(0x1b4321522d93e975ef100be5ccf9f6366d22198a08bd627bfb270c2a7aa2a5b4));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x25d497d77226289bc5cc70913890d81bab577800ec22fe675bc137c40fc4956b), uint256(0x2787f6e456b79ab43c796515cffe0a799b93dab0f5e7fbd908071a421c68dfac));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x12b8ea5f6fa434727f69c3cba1ab6da670a0031b41d46e2074158cec625f487f), uint256(0x1775a1130effde4baf0e71ab142b8221ba91a6f756609d3de2c2b8c0872b0809));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x05ba5747052e0145702436100a74a01c06710861114210719a3cbbfded96fa8c), uint256(0x1400b9a751c1ac81592c9f84d29c7038120fd9a834918cf3f435c222d3a6a2f9));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1c68817add30dd4d167e23a59596df9c3bc4a61afce79e12f4cdc936dfc73b87), uint256(0x253f5b495fc60b765f09f0052162eed4438be057bc699ee3cfe1934061a0b087));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1ee5e06d9f8dd8d495418dad5919de2683e02e3cbd6df0466d6444986ceffdcc), uint256(0x2f9815d0e6bb1244f983231867d8f5882d1e5d7e4d063ee3d634cfec6128dece));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x008c99a1dd1f600c4b77107b917a6dc0442390dc864d9b1bf9a6de4175fd0067), uint256(0x295a3133305ed1ac3834089c2617c5958daf74b20a0a0af78e1fba42eaa4f1fd));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x079ffe7c8c99d37e771cf1783fad341e90e4eda9e645de7bf69de55d49dac5c5), uint256(0x08c888a788ffc2938074f272e3c7f2e6504980f1bfef6e09f938e65ce02b03dd));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x04393149915f0ac6b10524a5c1265525520671de6ac373a8395702026fc95a7b), uint256(0x18c90b26b738cdee0ed6d828684b0fad30065b6c8083fdb545a937ccf7039c4c));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0db70833bb816ada9e614f16b2f167031ba1ed9fa41a6b66c5461f3bf584a02e), uint256(0x02330cc1ac004aaed3220d4eae37f532878e228b3408e13ad9c4b2d5b8a8fe7b));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x2658a20623e9e47aa96ed8897f8805ebe30d40a9d3e04e2d098a3bba400e4db8), uint256(0x2f8baab46c2d5d40390843a646df69e0b15ea58aa662793cc463e052c2eb26f9));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1f9958b9954e3442f83d6da88e0d156203ab13514edf9b4d68c38fb36ba333e9), uint256(0x09bf4d9b4cb35af15602b1a8034f53e5b168ff72ad8d7ffea02419db401ca090));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2ab237ffa269f9e6b7216fe8590e5bf5f3d9fde8746c4da3031f70abfb5f92da), uint256(0x07aebb4ebf276e201df344fb2cdcdb1564a74bc317b1f6e0fb4ee0d1f7cee2c7));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2a4578a5498ec51c0951a04da4ef678dc2c56ee77ed1f17e4205b5e834f733c9), uint256(0x19a04218edd50eabbb92f57218ce33ccc6f73e3bc0527ee5dc8994e3b2fc49d5));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1b64b956a1148d9438cbb1e26fb31d69ae2833c82eea77c92e5cc363b15ba94d), uint256(0x231899839c453648f0f088af82c5706f6496611feefadd75dcb56a7199607773));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2f4725123dba81c7f79eea45e8acc74791f352777b790d7eb038b40faaec4508), uint256(0x258734c7af923b7d57175025d8c05f07474423b1b1dee4c8dc7cead3d42f0f69));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1455424ba6ec3ac54e5aac4df48780a36c844ddcc7d50b7b21144cd0e82600e9), uint256(0x26e0e1c30ff0aaf0a63ed6a527e74187cdd8212e8e077ef6d0ecdae1601d2557));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x0a18657a5e3340d1972117146159c9d4620e42460ad10e2567ed295acb40ae44), uint256(0x0bcea6778d0a06729a37dc2eaff09608d701e28fcb8651cb9870d89aff7bf4ad));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x22d377fd6ef1b5c782e000f2ae5f265a1087445419f55d884a051b46a893c30f), uint256(0x20c4bbb4c9bd1e70d9e58ebbed44e1e424da5762591282bd013d1208f539db62));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x1378016ec36f350d498eb3426e356f265b3a8f8a8c0768d0b61502bb1e7e93e1), uint256(0x140988f0c07eba75b6f3683230a146c27c350696dc0c85ec55ce7780942b0e40));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x12c61f555813a34df57b23272c95c57f6ebbca38323e20b60313b5f656369471), uint256(0x25f600b36b88d4c528f3d3061c109a9bbe0c5cb32cfdd4a63fb85d7c73338ee0));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x12d2ac933f06a27fb10288884bf9d682911f1a1dbc68ec7ec9b09fa3e623fdb6), uint256(0x260d9d643c710dc0742ba2daad87fa90056b807b5001f0c23290780f981cfe03));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2199f796c1764fb031a01c338c092f882f41199f1c78c6f44ccbc829c09dfa21), uint256(0x05020537588dadb3611dd38472f2c40964869d8d1610e0123b9ed06773585535));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x0e8f4629222e2ed1785f045feb8ef6ba16befe369ef46244fb9400774f3493bf), uint256(0x1727523c6be95ac4471b9d521e0af0077136c121ebbd8ed77a8df54f4b3743b2));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x178d850c1a310a13ffd1e3a4cd130f4b0fccf8bd2210a89d66b44322154318a0), uint256(0x11def2b9390dd72de8bfe85511ccf54fa470bd47be2a64b4514eacb2304ae79d));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1a87aec5c0324be39100a40ab01c1c553f987029c77a4484c1bcf4989f0dd7ab), uint256(0x2e6206a4972d1b97719bb8fcdb5c8605de9b63a1e2a68155ffea9bfd731b4f81));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x070fd116e6480ab78aa9183e56662248d6d97addf051023f5df2185a22b657b2), uint256(0x09c9c855062fa331825a4475aff5fc662566ed354e80ffed908b020f4a3aef8a));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x2488ebecee7bfea467ad47aa8b7d6dbc06baf08789c3b739de7d23a174f9c8a2), uint256(0x00492a4b4fb4876b08d60131ca8caf12599858fba33da505fc25b547f15077ab));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x00fd5fdf414c5e7b174b2b59af0147e95c92727a60fefb2bec9c8f394a1e88ac), uint256(0x243c3ac7c14faaa9e1bd3d2d57bb9cf6485ab65c9a8c3fb6eecab48bbf8aee6e));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x2b1d846f743afc671a3a222481768f31506d3d73d90155fb6fc29cb2cd1342c2), uint256(0x2c38cf60b83e37a5eb1ad0d452ea7c9916221c957296c8dcc950aae91139a536));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x2db1c98ca531ef9f517d7ed79a41936cc17d6c21bfd113a2103535663f037469), uint256(0x07f8a4e765847701b2e518b88f3da771e39f34505232408295fa4f4bc7141771));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x175abcf57eee3e7956201b6bb9d7aa6a5fc2ea2ed8105230002bf7477e6a8e13), uint256(0x0904b5d0b4e15de05a266e2430c2be85b210e07baf8b12e5f0caecd515a9845f));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x10c68db974a91c862413ce47bee0b4dad28e7330b51ccd3a0291c7074309df7e), uint256(0x2dfced443d95d0d79fc7e5dc88de6b898516e007982e774719d3ce892f1a5ae5));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x213a955933a59f663a5a646c9a8376657f735a639e7ddee9fac357f7dc7288a7), uint256(0x10ad624655c8013a8ff6ba2881cac8736932561ee2e33e73ad1b67b29380866e));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x0c1935b79e76a4042663d7dd44c809ce8f6cd14b756432bf484a473f898b5f42), uint256(0x16a03d41145c25e239e833f3083eeadc1cd84a379eabf1754d92440d5d13c50d));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x26c40e803edf9b9a3bff864ca347f3cc2992d10bc067a73f952d6916ef2c421e), uint256(0x1f71db4d76d3297c8dfc34c63967dbe484fc70676bab8f427fcf4efe2eaced94));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x074c690327cf33895cfac6b9bee4ea23c3ee199a12963cf7d9d05f30e210bbf0), uint256(0x216e7ec15b1bc37810dc7a594af60945211c57b8b2d9bdf85033ee4186de5ea1));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x1a9969ecd1beb490b0829b474df023fc191ca44528865e2e6d52d0ec999e61ef), uint256(0x2b3415048bdcce9d6baf64adcc717bf713efd01d2e922f81a66c3a3453ba5ea3));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x29df4f3f403838a3b18c25950dff5f54a216072d12bdb246bd9ba278da101a6a), uint256(0x2c964efbe5fc699124e3572d1254c03c882fe6bfcb19225a9fc7ccc904338c85));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x2dcdbca177b6032fdaa9be33522df98435741e5758fe696cc20dddf9f62796a6), uint256(0x2eab96ddc531235311cb3eabfe885fef35c48979b801b2723425f545505912dd));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x1f1f73bb02654f11ca1d610cb66eb37bcbb935d411de07f45738ca11531d01d2), uint256(0x2eb8d1cadbb9c58307d67772149b4ecb04ce1d179fabe99bc8341c2d7bc751b5));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x10b17ff83f7bfbd5c29e28368adb05dc83fbfc9c94fcf535cead11a4b917f528), uint256(0x1a57eef089b2f90ed2e5ef7be3e96c85ce21a841f7dc6ad15292f303ddc36eb2));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x00a3e82896d1994abdf132d0a97f12c874dd963fd6f9173ecbd0444d05873822), uint256(0x0ffc686deec7d01f26bb89c32f898cb4dc59d877c55c5eb2e4d4da03d44f4a9b));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x094dc80f7f7b10bf7adc255b625a8ef4e2d905935c3a6b2468dbb776baff8276), uint256(0x126a696e0652e0e725aea7b5a30eea6b532c4c58634cda664733bf711c1279b5));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x10b4be464e6617f0ef01ece54d4079ad4716677cc46636e7736307de6bd49934), uint256(0x038257efe6eb8387f5b72933d0be8739a3d2db04a61466832f2c80ded7e54c21));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x01b2bc1aec31ff225f15f009b4f7f683fa3f79b3f16d2c0c420c609150ab3c37), uint256(0x14b1effd3799000e318852b89169151efab93eb9634ad827ce75659833dd475a));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x303620fe51ce7ec2b35002e03450f58dbf697812e38e94a7e23e7711aea239f4), uint256(0x2b5b5a4deac9bd3647c6837ee6645a3e81edf15722025c01603466723e7f3779));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x1b2c86363297b55850d2e1066757ef9076d1e6107d9001c1e65eab3f32b5ccef), uint256(0x071724b3e64f3053bbf6f679dfc30d158061f039a4f5448789bafa957fa4497a));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x0410066a1fd0bda4285f7dc555ecef9c9c21b11c1f9bb0458bb5189d566b913f), uint256(0x28dc9cd2dccde08faac342f7569be150c2874f7dc22bc22ae342ac45a3b24614));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x10c18318cfcd6622c22ddcb3c6efe2f5d6aae3dbdf8d13b2968c6d3a7eca8b8f), uint256(0x0a114eb570e59dd191315606ff33910933a6f0e0a3abf70b21cc2177661d1036));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x2e3dc716828996fabcfda88377748e262ced8a74d4236423b9e79e181ceda619), uint256(0x2f958b9ed862923d072671a98fdb300ca4dc6cb6083ccb2855276d04ab32c4e1));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x1c651bcc4b22e8a87ba33f32259bf5a10ce40dd7e694af3e71a2a3c2e8bfd13a), uint256(0x0421d9775f4187c4a33536527db9d4f542e3606cf862a0b80421a31347d2c013));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x0a5f1ee8aab1d1ab9247091f216f46b49b5ea07f0af3a01755d38194c14f331d), uint256(0x12d88a8d9dd30cee91953c1f4a7e0a708545038cdeac640e3a3b2114a499f25f));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x25e404258023ca5bd8fd7cd2cb6189ebe314bb10b4a49a444edb5a3730131153), uint256(0x1bb5fcc4f2f669635446823545ac5dbcb1d866d75729cddc9af2982a061c60e6));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x28fab748b4326fe1657220510cdfb00ce27efe95617df30f2e11d50d2aa6828d), uint256(0x0de767720dbb5a3c35f5b2361bca5574b097493d4d1ba509cc3674b9594f210a));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x10a7e9239be896f32d045f7446445d80141806f4a9ca1c61720bd182a17c9952), uint256(0x009cd01e2b4cac888ae4433192edf30add1b699cdb943a4afc8ed4362cbf8797));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x1d18ffde98448e9ce3b5c17f4f9c48f8f2b7565fc8efe0e2725204ddf477b3bb), uint256(0x086d9ec69c877701f96800283ab6399240c0d9470bb8426e36b24d482cabea4b));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x0e23160bb80f1ead1a64d8cef9386e734285861d42f5ecd1ab317a6f53a02f06), uint256(0x29aacb1cebe26fc4e3dd68be49beeab5f0231b5a6f786c8084217245deffb927));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x07dd528e33c4c8b67c26e771d703ccdf8f162bfc35b14d62339f7c6d920364ed), uint256(0x28d59835c8530f9cc7c2f29d9cfc68661390b49f942e9a855ef5bd5edf5dcb06));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x2b4730ad5de9ae83a2d63248ae4b5beeeec7e6256f0ca637630c8e941da36e57), uint256(0x1878704a5fb75288105a9f016f59aa63d342d6c4b21da601f2c582b4b5f03c95));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x21886bdcd14c076c08635200fb7dc82b55a949812517ead56b71a01bf6f346f5), uint256(0x241ade952ce140211ea39de9966329a8d3054d4fa600175ef42e5069b2c46108));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x27e6c6c33ed347d74682ddde99fe2a5a85a93ab4908ccaa5091d5f2b88aca3da), uint256(0x0ee717d3c09b1311b4ea422cccb0274d42969e7674107761091957f6837414ca));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x2fc263e01dc914767473f591e671837225d5ebfbf6c8370ae8ced827517fccb8), uint256(0x163a597834e7027f733838063e3b60478f9e1751c86edd653ea3bf30e584dadf));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x2bafd52cf3c4d012f74f1fd54e75ff58299008f4cb85cdfe1c3c10bce385de7e), uint256(0x229b47d2775ea721c9c619f59188a8667e8db1670729a1e0c235bdac6bcc23e0));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x057e0d0f7d8b24d4c3baccbdbe7cf6f5fb79981a42a7015e719de8e77d010df4), uint256(0x220d7b3ea29a542b88df693bb7e77759b1a0e1e3914075e5e6ee6a2333982f2d));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x2705d04d566357934f8cae1eaebc8cd7c3a85d63d81c1691b2b7fd77a672d212), uint256(0x0dce9c845226da9b01869303710845a1fe7fdc06de18ea3787b226c47a09d474));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x0adfe7cb6ed4e7b721dd73060bb75ccfc7f333a8648d47d194332abfd169dd0e), uint256(0x052f0d18415052984a856f071ca883305f0bf7e7bf68a327f0605222d6753068));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x00b69bf4b76b0a3bdf5346fd927adc02c2ed306a72e7a21fbde58a176122da1a), uint256(0x1a8372abda2ad4c1330b79df1741fe26a0b3c48fa2210b1a67f58f84c5bd329e));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x195ac57a2aab5067ea43d709d647acc74d8b4820a6230fcf8bbdc6a9438deb04), uint256(0x063fe301d89d24dc52830a4822619289c3595d7785863ab15cdf453df6681a01));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x1790a1d3e622639fe563ee4495acf3a7ee61dd0ba66ca0d2ed5f5b749ed57a48), uint256(0x115e597f905cf9eda8f792ecada61bd9b9b54e18e51b9820dffcd8bee8545ee1));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x0c55c2cecf23260421e7ca53997509c3af7c14fe304959559303886138bc028d), uint256(0x28bea22a9a4593611caa31a0e79aa4dad30edb13c5f9106c671c47c6a1b9bf9c));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x01de2293e87321c5e2b974ea17d2014fbe24c6349bf0eb3ed0ea8f5d54dac16a), uint256(0x1edc8c981625b6717db7b84a05f78b4cfd2dc88e8641e9e8c37e7f0c83cfec26));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x0280ebfefe83f01c436993fc010d64a63709bdbf2216bf6c900d5dff14fa4a2a), uint256(0x00ac096a88ddb3597fc48025dcb8fc1bfcb31e8395627c73eb58a64d85d705e9));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x10ea3fc559f96e4df9f3867f48a478e87e8f544f83a9f725689d74ed49d7621d), uint256(0x177882736d9a920da50dcbaa23c570e4bf71e1c04e38bebdffb8035b7d8217ab));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x05909401ead1b515b4d94812711611fea32421da37722fceacb20e077f17e854), uint256(0x063cbff0ae60fd832ac5b1f63895d716029f1588a9f959253f9aa189d4d062fe));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x1d4d04c3b4a1ba67bb282232424a430dda5706aa07451a881f13a1a2b57e690d), uint256(0x10b835ff17e4acfb20a237eb506775693d69551a3678ac86d97c45f6c3648682));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x2e10e6210ad4f121d2489f996572c55d0b117111c0a4672402197f58c5015007), uint256(0x041365ec6a796e8907bf318de526b6f35ead1be5f10442077ba63ac636f16dbf));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x15252f8ce428229e90227da7a1c4818ac9b4d0cc06307976c52ec234c14efd7f), uint256(0x0127cf9ee0946b952d5b821f21e1533deb6130fd89dfaff079d255cd2aabbda8));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x21e28f2150b52af5fa5453f4459ad2fd9605759aee57f4cbeb99434131ffce1e), uint256(0x0fa2fc8a23256e71e4a3935441494511b5b5afbf49f0f95519156621786231b9));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x2addf3e99ba282c95c0cea404a920bc45d9eeca56a47a1d69d59b69eed6647e0), uint256(0x018c58049290a95d12cc0d60935f312b9ae235572d5b1277e35e07422bb0d2b1));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x07c441480a41444f730fda14b88dfa17c0cb5fd3eb5ad5d5e4485a5d872ef233), uint256(0x00be517aff862157798b229c16ca8c31cbdc5510b4a61f992f386aec215bbef8));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x2ef0555d466249802c79e99aa30b80bd32e959f60b00ef9d3ca7f9cf10acc428), uint256(0x156a78e5493233e005ee62a71b4d6e34910d58a97e5ba79e4acb2ccef0947b50));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x11acc0df34d23330f585e7beee71230d3b264db0af8bc34c335826ef1ec88a9b), uint256(0x1e2a1950e23d07c798f8adf2a5097ad0743c2f0b87b8cf5812cd2d35e69cf67b));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x043ec88a7a5e4b023558e2da02ffada2c9a88efc31d2245844908768b961922e), uint256(0x1cf17363124448700d968f0496298c8aae2c093a8837b63abc6da9c409892e10));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x015d5d5b5b3100acc59153d5648041efdd0a1a4f667bb7f6d2ee96696c311010), uint256(0x25dd3606b5299595ed5b4ef65a4f656924fa72240fbe123a8d8fbfbd04f58ba5));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x015ca3d039931af6fe669970ba50100edf44fdf70267442451e1fec00eab2d42), uint256(0x029eac98f7766084623f26a87e15746371585cf83e6c8c8f3d74dac8b1aed9ed));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x072eaeb5a060cd525397ea444fda9d516678acd7383776b4c1d183963c15299a), uint256(0x082d7a6c0ecc850c6549eab0de912ecd1664dc6f9b0baac678a58fbe0d2ddb6e));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x0441f02e7894e08b55a7b59a43f382571810fbbe84aa3acf0772b4fe82fa358d), uint256(0x17e9c18aa663a3e587dffbe36fc36e3a5eb9fab319cd43bf2475bee0c3a98101));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x2d5f6474fdf76d3586fe38a1c61497d847840c5072565323996e23c86f03df97), uint256(0x09711d388d92e7cca68c609618b0e131fbcb8b74dbed56497679103c8c5b6b20));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x19426ae47913755a5d0dffd9395c1fd330436576fa03b7d6eece7796904aa3a8), uint256(0x01e5f09a466474001a54771c524ba9b6a6ecb6a7a2f7bd743562113296cf4210));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x13aa7a90a089298099e01d11218f04e157fc2b567c0db41477d03ba9435dbcbb), uint256(0x0c0d82981b8720a6038b1a5e6a81a79500dcec171ad326cb0e5a30356d799839));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x0b0c512660736cc2fe513168d2c70681de7d8fbe41f80501342b043946cd9571), uint256(0x28a1effddee02e6981bf41787f4881589d66183844b2a57129f1c4ec4353b5c6));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x04a2c3310d25e00b7d7a1af45e05a4fea116510254478bf65d8837d43a3d4032), uint256(0x124eee16b53e8ae329ea04849cf8dd07e1ca05f43785e30f70ade6c46c261fd6));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x0c04551112a151507d492812059997124ba5d2cbb96892f69549c925f3752aaa), uint256(0x2d1b5cd36152e15987f023b5fa758bac0723b72a76367f8967cdf72c63f328fb));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x1e3b3f6f18910c5a737bdf6664ece79a036338cd25979fb9e66208301a0a6095), uint256(0x169081ff88d0558f6a58543acfe8b21aa3703f9f71c258df87391eaf83bc6e25));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x1070f05163418b86247f9328f8814baea37ec384a91b79c6a4d12fc7c5ceda2a), uint256(0x1b453e06b77d1f9bdf016d2daf36d60ca19800d85223cab4e9d65dbaee004546));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x1f3bf7dabc2d00490517d9fc3f7f1a382e10435c00b9da6ad5cb4c90ca13e677), uint256(0x2598a655d4a100d173bc06d0b8ca82d5741e17eb6e40850b25e1ea135851b465));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x09078f31357e7bf61860f52244cc915d001d8cb6cbb7df76543d2fd2d105abc7), uint256(0x22e585900f17e9e94c501f758345ed604ce32ec3865f0d2e0bc235a41102d9ba));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x284e2c84f2e5ec3f6cbdc27cd5eb7643b4790178cfdd69afa20dd4e52be75c81), uint256(0x2d5ad8d17209d73587d6d1c0602c9ac4a33cd4eb7d0100c96490aeb0dfe16d54));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x27b4956bda13d2ea98b1defd185daabb0b3b120a5301e29922224fc571c8d998), uint256(0x1ba6210c83cf8cf82a08381f9f9b4a5ed5028445b966405fb240f8188221efc0));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x2b2bb0a94ff180491984e077e6d9e0cfe3ea5eef44d9d9ac9af1fe744dcbfbae), uint256(0x1118a7848f917a1d37e56514fafb26d7857c198a4c84fff58ae6a1f9f2d487ff));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x1de7b0153e6978032cad700d6357de835a08f632cf2d13fbceea9e23bac50e63), uint256(0x24c6f32edbc0cfcbdc549ce04663469718b2ac3c3646eff4f44b4206471374c0));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x1595db4c97c2acbeaab5818d9386317e1548eb665b7a3b19f96bab00aa475f90), uint256(0x06e8f1f59d660d86b9eeb7bba2bafb60830d6928ece6a2adfee79d46d1e1a3ec));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x03df2ca58d61fafcf56d3167df69e7b24e1b93ca3391910305db408e2a61f069), uint256(0x2833421ccf05eb26f8aff12d205b6103c6ba93b65f21bce2ab2ba12bf5d766fe));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x2b242e48097e3570e30b08496ef3b014462fc9780aa5ef84c7432fa090c7c558), uint256(0x1dac3aff120ff2b872a5be8007f7799e600c321cb27d78e2ed8dedf59d48d8ee));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x0661f8c760acec4860bd1d91aaf10c7a8dd58cb0ea89db9d8a38d5611e255c1f), uint256(0x0c60e85133413fc3476b3d0eef69c92fe6c34dda4cf65733c7ec6a1b5b27e405));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x095f93245061ac275d0e2af1beb381867fcf86e079ec0bc1835a2e16bbd83870), uint256(0x1247f8504460e6952dbaa1388e52a102b351c89082eec6f5ecadd055bf75872d));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x1d55189849e3da4596fa5ab53745039daf17a05c54a351439044a1829a6fdd0d), uint256(0x11ab15f92c2dcf26b5b323f43e7c477bafb9f1ed14b61157c274b73864f690a2));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x28d0b5bdafa179427bbaa1836e7b6fc350ae19708fb36ee06b4c796fdeeab789), uint256(0x2855c569726b6c3797cb8cea5b626fdc8c63bf0eb373b9d09580c2e838de7096));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x2fc5d529f67108d7b6081b8899930a6002daf054d2e6fa97040fa96ed4ea9e99), uint256(0x089be742d7cb6317ce020bc21d88f0c5008da8e5d515f2b4788b71dda1b3f583));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x17461d74ab8d152f4801c1d123b998a05b929a6cd80829118d7a78395b4c37eb), uint256(0x1b75726ae954ae9996dc631a6af3c3c60819e186d53288b740f964867dfe54db));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x27503ae38c5c0d892589da1ba610dd62a7de22aca2a606ade9e4d7add5468877), uint256(0x30081fb5454941295ae8c26f914237fb122cc56317b052be44c8575276e186e9));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x03d1b100545a669f2e86e932569ae99c3b681bcab71a8ac999febf16296c390e), uint256(0x04d56e8cfb8834457654ea677f5c15629086d7baaa5c9c08a678331279be0390));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x18f0b1378136beb6e8124cff8b281d358ddcf57b86ae40d8bc0d8281d7adb40d), uint256(0x00c5013c0719db2880822e3cbe8f829a5808cce8e3b72241a2a7a740285d4610));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x1e0aa2b4cdf5aafe55b669bc6b4c7dd83fb6de13a8262e8e64a73e1967f308dc), uint256(0x1c9bb452423967befd64febf23d9025073fd8c17fd19385f3343a360483883c5));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x0b4baf7b66abb9ddd4bf15898922971a1bf458d04725f68d3abfc7001aa6fe8e), uint256(0x2b24aecb39d4700c85f0d73e0771fbbf351872b5a010597c03955a1e38e6d1ba));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x2a729ebdb83cfceb2c88fab68f6140bf6ec75fb2c75e443fbb9b8416779b71f5), uint256(0x2c0c8d58ebcff77d50f34fb705ec446ffaefc1ceb3c92a0cb2a7e19b30e14623));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x1fd54c10789bc43cc01ecf0472d264a6c3c793ad6b2d62d2843a65e96f06e42e), uint256(0x098707703d4e15c38e8e159dce3a0604667befe613b2fb46fc48b662d5cdee42));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x19ba3ff3a5ec8c31da063c0368eee680bc1b1158677e25fa4d22634fc6843e51), uint256(0x2296f1dc5ca44c61e77fe82c47b53680b6f06bad2d2a2af0447aa74709cc1ac0));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x1b128079d9a1545151a452d7fce722d9c9aef97c8c544e7e447aee57fb9c65ae), uint256(0x12795599be27121bb460df82fb4e5c2117b87da4cdb43592ad4c83904290c211));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x21acd36ac634b2498f0756238683fdce89a4558281bbf94ea3c40ee8b6708504), uint256(0x16e491bada4dc8093a416a9749bf03a20c77db1548e3e492e2268b1f4e9fa7bd));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x209ca28d38a02b4e2b1b5c98ab23db260a90cc1d34a2b55178cdd4f1613d83fd), uint256(0x17be7b6e0825697ba90f478dee53605378c81c42b3723cd80cd78d3e4513a1a5));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x1cda719f98c589669a3bf3bfa3fe00a31848cb03a1bbb4fa16de86ce4a44f276), uint256(0x1f2bf69341cb4fde9006b707acc16fe62cddada4988a515c881a892fc1e62923));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x24d67dde01fc2282f59985aabfff29a24d7851642478c53ca47bff1aa4924287), uint256(0x17e28e413a1c4caf65f6edfa4522680e28fd7c81715bbf73eddf7684e8a4f0dc));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x18e3dd4b10adadd1306a05dfe30a0862397aae8e335fb5edbe499c8bcd304053), uint256(0x245e990da23735aa3e08c81260dd46db26a75a5bac827602c412f52d540a9581));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x0c8f1ce0ae52c52f80993ff9d206ef7f50d90b7e2d4807b2e4c70115b75e2c74), uint256(0x0539812162078391d431e1378939a0adcde835353ec869db00c8ba40f0d512b0));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x1de1d022e311d93f51cbddba726d889e4314fdae8e841518714bd5670f8ad5aa), uint256(0x172d29ec5de9f8d5700344c6d8dadd35d139508455bb043e8571e87f4f5e62ea));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x2bbc819848d05b508c1730411a55625cb76d6fe8027dc134db1b40cb74db9ecc), uint256(0x07af720b0b6ad6bb8608d1220b9a1f4b9698a8bd7c102447a22aa1b55afe113e));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x236786b0dd5b52ff1828ffaa2e428691e7e60e9550eb0e607f591dba9c119c86), uint256(0x11c6cf869318614139465fb32cfccdac2f80ebaa82abeb32cd76efd1d49506f5));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x033553d47e0ecf02332d656dccc187d75105e43f77873d7c4bb077a522a969af), uint256(0x26d207d8e076ce622fe73f583abf52cda94cb2f0fee7806a4569e95c326b37cd));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x198f3d305dcdaf2b34ce839d6a508d0ad2a08b834810de7c47e6c2fc0aca73df), uint256(0x1414346aa026bfa08ff2e7936063a3796ab0a1b50076f1aea9d1023eb86be4b4));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x2b938c6346121e437e7d7e22febff7537e26c113e0061906ee21f9c18ff7b377), uint256(0x2bca14801c39dd63bc0a271ac1763893f5e772b1651d8f72f47ed2409ec2fb53));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x24bef84d53b51fc899389ef18a31f763916baf0dfd2adbb3cca81c17be4481c2), uint256(0x04ea32bfe1f96365737051519b4b2488a19fc3f646a97f9d6508599f7e4fcd3f));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x1dca6f2e153c9995801e8aa156c335c7d7d9e5dd2f4563b5234ca7741a318f3c), uint256(0x2c7fe92d24a6d64da0edaf8687c52411cdb5092c51ccc95a464d36227dfa9758));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x2583b2ad10d3a9e43ad4e503c858463f101802a19585aaf9f24896cf20fea50c), uint256(0x0dbc504d99cc70683c1568ac183300a4abb2a855e2172e6107bd89554ac0014f));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x0b0e61f16883164c42f77ab0f075e799fbf4d1ee4ed1e5bf033c0c4a05548fc2), uint256(0x0ab167742465889c80e49e60ee7706ef03c62e956fb3646d58aeb7a434772f94));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x2cabaa4bcf10a14ce8b8113563d6b175c998b8574c1f5f5d709cc51d1f76ebe7), uint256(0x0e70e317fd8a999f6e8dabc211ed9b1ae14cb5ede6552e2d3a13c6055df8d5aa));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x179b4ae9121cc01f2657b5f548a617cb253c33bdad97bb365bb3cde7f5185398), uint256(0x05fc20345b1cca8b80ccecd5bca625467e6c9952d93a5984fcc07f531e34dd36));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x252d71dabb7ab17ef71ac04f7f844920d91c8855d718b93c69f7cac8da3834c1), uint256(0x017f26fd66832e0e92aa69fe5cfd38973c202fe72bede3d5e4df2695c4b18671));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x00283b7fe99bcef87ef0097cec56cf8d33f0e7838a9f699e88bbe4f59e354835), uint256(0x14dde107ae1b67c58744e75314bf963eb4680ee2ebe239139e35fb7be09023a8));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x0e1f2bbd0464d1d4d26c4222fc2a4e9e36943111e545320a80b8cecfda9ffdc6), uint256(0x241f6ccc72830cb9525db9d4c32a4aa7111c27fd615ae32f2adae8f94b1f0360));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x127b91cbd070c2ba962a5990068ba832b05b5f5043a4b25fe63df674a68f180b), uint256(0x077473510b8391f8d64f0da4fd99505c2ae554f7c6ae57e29c89cccb5ece10e8));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x1365e024dd93180b4c81cca77ea012302082a286b18ed8f2cdddbc05f3e761f1), uint256(0x122fa470faadcba94fb1c9f8a8c6aa94aa4bf8bbbe77060131ca5e54ac2e66b5));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x2d975b0c0b74a21e07e31e652f289aac20159c42538e116a2ce4149a7d102fe4), uint256(0x1e7a79f45e894aafb6001433ea8bd09ac6243662b2029c951a944719095f1765));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x0152a2ba61468059083eb627360c7e34227f45acb7c5bd87e8381fea1464274c), uint256(0x0bac44806eb1a97cbf3f7688da56a9d80344d0d409a3e6233428e21200eabd90));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x0351d07ebd7e79ed0e99a408225bdc526a38b199b912dd88d6033f01bab25565), uint256(0x0eca4c8ccc4f87baefccf3d10cf6d8bc42f82383dbd1b12544e4e5b1604f5d66));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x2223cb9d6335f83b7ab70b61ae380a82c32c0df61aa1737e5ae9d07305379e59), uint256(0x2a637675ff4de0c77a84aa404e99568002ae6fe1c0b9dc5b20922eff57234359));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x1cfaa3722aefd209458a59f05373bbca968ca01335a78b60c3973ae90f7c043d), uint256(0x1755277e2a6ade0ef7f7cf9d2a2ee49be5b1b83a09c77aba3d9c1f8d92923474));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x1b889eba46a7c92fb5f0ca83bd045ed1e6155af705a91b3b5bef4b37262e4096), uint256(0x15de40328a2c21e8cc80505dadbc008fb0c2c1a9b41b34609141333bf726a101));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x18af513ee71d3a6c543963ace7e5bd96aba26b2c3f0bf66c384bdd1fcb0d4a51), uint256(0x064429573b7772c7896afe3dd787fdebfcd4e0ff4c1aa4e5cca4ff2233365d96));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x267e0bdd633a2f3e2be7dfbc1c7c21f949d75395cc33a4f08721085a53066115), uint256(0x10bce75431d4519006992a0062d02fd6621464c0e5f55846d2ec37e29ac47b33));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x075d2fe3f8c15b3c5e4a7bd00bbe79f1b9399f61b515a8e0564cbe0f329501c2), uint256(0x2ce1c38ec872f43bb7b04e3cc204a4a8728b25ee66b551cd30d7f1a33aee7d36));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x1e6fdfc26dad5823d3fd836a4f70dedb4296cdb5079aa6ac36b768a75d0a2dd6), uint256(0x1346da9ef03855539b88ed6ab71656e8ec75f18a27ccba8a1a940347b12d7fbe));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x212b9a37b3144e320bf7b616d120305b1a674a5dd31af0c110eb25fa05549207), uint256(0x106a8da09a2c0b2a513da94eeb7416e9c0e59d13cd54d108100b77c2155a3f71));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x29909f8721649a911463162ca5b857e1d2bbc2e1917734bef5667b57108debbc), uint256(0x182598ab342905131580c58a2e16bf614135036b38690958d871c178a7b5388b));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x0742ca539671737d6266020beac3b4e5062692c86be6c4104a6805c6d99baff7), uint256(0x2b763fd5f05c9a4c54dfed1f97cff1cf7bdd98a618acf360f2d7b040a48a97d0));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x199e943746de7d6147861b336a838c536030cf4bb5d8102e252ad1ee239b302b), uint256(0x03b4baa852c59f72ae4427c943e23b9e14948289ea91b8638bbefe1e25c8d0e0));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x18d5cd565cf9937f85adccf38eee8a77d0155e89b66e35ba01fa427c1c88559a), uint256(0x06c081e7991e6a17c691332185ce03ebb3b2e339e5ff4684979ca7a82cc45a3e));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x14e6ead1a40a68eeba0fac20bf244c9be8cc4a22110c09962aaaac07a787be06), uint256(0x2b169f53e00e7ebab4babbf1f99ad03c4bb2a234fbc04f94cc7626fa193c1e07));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x2de4e419ecb9dc0e1e471cfe7de28de5de15639290dc39e23b182bbf2a1199a4), uint256(0x2614f63241696ae1fdcc5f70bd0bafc5f443110d63377cba39cca2a20321a6c6));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x02f799bd425ffa3804877a313e87f34d260a97b3cdc18d39ec6e876bdba0e98d), uint256(0x18ccee97f2e9f1c09d3eae1e903f1bf585237ab78ef0a5a7a28e39d34d11e0ef));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x23c5b6d0f619841a460b61db0b40ca591a3183827ddf698363a332eb32a09901), uint256(0x031260cc47c23c59f6d7aa15c645ef30eff2532d3083442b0f44db51d614b077));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x2ce401d51f2d4c54cea53eac5a2b8b0a6b91ead88e23d6080db5b11aad4dc3df), uint256(0x08f924cf66f2c939e7f921fd60f534b9384bf81c0eb57679474e1bafcc474177));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x04ab72f16e8937ebb0763991fdf6970e73dc8773668d58ce7607bc68a399b428), uint256(0x01bbc12a17f95eea819beb3a010b8f17d421ac7664f10df03b050e61dad3582a));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x0399e98bb8dfd3f7d8745501942658fb5bce3f1145e1013323a798bd11d79760), uint256(0x120b559567c6b1da041e7a1d352b1fd1247789a63ba37017ebc06e1f1322dbee));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x1e0778c6a04ee42e5c114a472fc1f82300005cb6f90905adc373763047119456), uint256(0x055913aef292d2d8a9c6b4c98503efc2b515732a2592c5db572e8ba28408b432));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x1dffbf7e7ef0d93daa0692e75bb9d001c9f90b69bdc15b7fe83394becc126567), uint256(0x0e689c9c4023ee1ebf1b1c5bc73eeb891ee066c6f6b569a2b13b0efde5f40d99));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x2faee811b647dbd8ce4ad4941537a2dad97c9f7377bd4695dc79d74bba19e0cf), uint256(0x13b3355aeb87cf5243efb0952a94b619815cc76ee1717f8d97a61dc2d7c08e71));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x02dfac3ca4fc44ddb3bdcde974a5acf532618d0037b2abc283c71b6eab7a6d96), uint256(0x17efbefbf48004035835160d11161c9a7a1ac1ee2067974fe4a5d3dc59259412));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x1ed08b52fcaaaa6c66430e01a18ae939f48fd3417154b4b876f9300fa341359b), uint256(0x20bec91669c32b41207f0a67f6992aa357b578ddb9e5471e0f8cb7c38c676e28));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x29201dce163e3fe21b484007853dab7f64e367025c43034312f2b1612994792a), uint256(0x10e4a950ee51d3ea8a8979d6f9dc6b50e7d5761c6df1908782428e7b428cca18));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x2d4c90fd3dfdef1bd11ac8e109141153c2f80f5866ed5f86880666a94bc29b04), uint256(0x130d3b9fec5be585dd513575f1a3a3b2e20a2aa0fbf350faf973e81b10b0ec13));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x133e667deff405b68384de93197377fb7ee177d89f87c2f96d29555e1a9c0f9b), uint256(0x07a96bb8e1ff439635fec4138d7106df2be649e3ecc4ed650a3076ac1228dcaf));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x039164d763f843e917f331b61a29e3a9ba2cd8267684c9cba86bf50d4966a175), uint256(0x17131535048f6cd4c1791854cb2f6cdb5cb9309b2f6db94e9a34b465e1db0aa0));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x12dcd204c5f155279c942536fc6994bbf18f6872b50665398371403aa1e5161a), uint256(0x046b70313bcf124e436f4920c6d63ae6db25eba4841d7f5ee7ee732274407a2a));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x08bc64f055304fcfabecd3983937b42e0412fc4e947c759947edfde836eefa67), uint256(0x2b08749c7eeddf7fd5e65f289cc7686ed5c13b246bc4b5cc174ca0da39208470));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x17aadb60084e3f48ecd2c2ee55d6dbfbb3009a6db0526b7a0159b48db29eddf2), uint256(0x0b8bbd35bbf8e2e5c5977735c7b3a3ee8268ab4a0f40329e674a7d1646afa130));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x07dce56e4c6fdbf027d8f473ded40127b3212d7e8667f69adfc20f5628fc2a54), uint256(0x257a67b6bbc990ddd647deb8b35a9550d94e67627263b38ed8274281ca4b1f5c));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x30199ec64c4952f15cc504cee4e5997a808b1e43030ee4a358ac690356afde31), uint256(0x23ffe62f48394dbb513f540035a81da83e9c2e3cb75fac3e20b66b5a2a25677a));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x10fca0ba7d8b95b1f3b25a1ecbb6c8ca9f455bdc21b19ea82cc61cb2f294a83f), uint256(0x1e9d1ee32bc20f6ab7655e3d357eda356d9e5882267bdf45163f7a1c4316a01f));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x22e1e59b2dc98f984ad515e6ce8f66b189253021557958d1495019203ed8a6e6), uint256(0x175bfec6c0d0d2eb7faffcc9d5b916bdc4e69afc61bba6994239fdcff40ddaaa));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x2d40db0fd50d62be31046d47cdf6bbb5836d6072d7aa0c5c9177680b00d46be4), uint256(0x00bd6f65899cae994463572b86f6e95c3905cb8354cd6391018fb1a0c38b2568));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x05da5e585763762b3314fd244f30d7fbcf1285aa44ebeb0f611e9264e396b639), uint256(0x2e42abd4a3585895c55f99e692dc0abeb9ead5ee27e4ef079a1a52b8f353d528));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x2380f6c60b97c82de3ef8112f75cc19c44b7aecab43b57f18b0f53726540d02a), uint256(0x1fe860c0f348c0e3566f5def5b4592f78840efec8bec0e258eed7ddd27a63574));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x0260a9a22b405707bddd530a55de96ddceba52f94edcc07b18bbecedcf52f161), uint256(0x0aeb4bbc6b071e83dc6ffdfe054b9ea0f3875e02c222f032c5b7e0f220627607));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x23672eea9aa0ef140953dc716a6cfb92c510b87bea208ba7f94c1f88965646af), uint256(0x13006457f8b7def627370022e4168f80600b7aef596a90a403303fb715c24151));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x14c0a1062f78a752084e02b798b88186eda93c676419719f73b50a5c3666dda6), uint256(0x095ee083c5e3904b84fab2b72372e3c2436e6239adf9bd550d6ec0e7d2266ce3));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x2fcaa880f02e65482b02909124eac0d3e66f1fa8348d154e8dcaba218ba0e61e), uint256(0x2e84d8abe17e8754a30dfc6ac8d0e194733dd74dbc60c28c43e239b3355811a2));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x0e8c6461f292d9e76b862ed66c214ad74953244b7e318f452a68570a0df09779), uint256(0x1754d83b5df5c78eeeb0a18b8dfbed92938a37e298a027bdfb1b48399065e3d7));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x277ea6ebf5a173719679a3abc8ccc437fa51382b90c00dc01a204945329a6e0f), uint256(0x2bc37f9d8abc5491575c66e89282f0542b13d9a9bed6898c2a1ce14ef8bf9f7e));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x07a79060c00b6fb780993b175a597976a4ecf41c411865c170fcccd3cc4022c7), uint256(0x268af3b422c74cdd9481483441d11c3098ad4a1dbc4b79f782d278284be0e6ac));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x0eaf2dba0b5ea346e0630c0b16191bdf9bac4299e21c61a1770c02a4aed8d3f8), uint256(0x08f5d560e3e64311b6564ee1fd3d406921940100315677345a96e0187a33481c));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x016f54fbb715a7a59f8009072f8e496e8208504bd92eb406c0ebcc48be1eadfa), uint256(0x2d44ace6569dbc608d9f6c68acc3c69491f4be6bd006af7b94be8278d5a23606));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x1e69befdfc4a74b2042ad5ae29d3b9cddb47d604fbc432c0cfa205ebed37d9da), uint256(0x0d197cb73e3e7b4ec0725675c49f9dc860017a0c5975d26ecf5a583e056bcf07));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x01b6e134cb721eb37a7f271610fedf72abf57eb0ac32891d2110cd5901ed6144), uint256(0x1039b256da631a2242de0908271eca08b4bc0985641261bdfba47de64aa9afca));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x2e90e2a591ddfd004e7ebc28f9a4f7db51d3b454f244a699beb88b6388f9ddb4), uint256(0x2eb0e05b274e543920d7811fcb21b2a1e819393ab73530795c44ae2589840ab7));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x171e097bd90b555994eef5238621a87dfca7f732428a1516e65dbd834e546110), uint256(0x16693cea657557e90fbaa13b8072143225f3edfcb3d36b677670818276988629));
        vk.gamma_abc[202] = Pairing.G1Point(uint256(0x136d69d6eb9ac440545bdbb5dbb3c14e61170b460dd1be2de90c376350bec894), uint256(0x19aed78d4b273b98658081d7ab9cfb1d38b3cf31aec99c569e929d1f8952d08e));
        vk.gamma_abc[203] = Pairing.G1Point(uint256(0x28f3b96635e08e991f9c5f6fa88ea44c0ec1f6d4307d74780a5062a1244eced8), uint256(0x1092b7166c8f84313a789bd7866edcab1892a6122ce78d3ca302be8e00290f57));
        vk.gamma_abc[204] = Pairing.G1Point(uint256(0x1482551bd4fc4371175d79613f113b286ab619e7f26468091a62ba85b4349c9f), uint256(0x0056c3c04707e718a8fff6412e550ff12c7af1ecfd4021b89d7eeb72168f862c));
        vk.gamma_abc[205] = Pairing.G1Point(uint256(0x17dcb8f1a8368db6a92fec2f527f1a347dbf290190a6886d5f529593f5034cab), uint256(0x049298555134463108d93c6e0ada86210c31713d08822d76951c1b77505840e2));
        vk.gamma_abc[206] = Pairing.G1Point(uint256(0x3054bed8d9e7c69b67078018594f62c86886d7f267fd0835cb152a8adc57dee8), uint256(0x130963e102967423ae8c8fdcfdbf366e16019089e845613487ac1baf28b9f7f4));
        vk.gamma_abc[207] = Pairing.G1Point(uint256(0x2abca2566a0de7ec5c58bd23ffeaa67541a51cf382077d21c61a2da5d4dbbbaa), uint256(0x05d965280367a909aeda0bdb1267c0a1a1ec38b30e44cb20d0ce85d7daef0677));
        vk.gamma_abc[208] = Pairing.G1Point(uint256(0x2aeaf84855ddeee2d8391f734fab3fa0075b77a7ccee836ab2aa25d9c25590bb), uint256(0x18b867405af37dd5eb9f652943b9d5aa2fb31e962b146f3e6a032d2882575e9d));
        vk.gamma_abc[209] = Pairing.G1Point(uint256(0x0103da457c89a7b4525b84c3bc4460018bd68cf722f272f9e9ab4ea9ad46b44e), uint256(0x1d05b1e84ff42b6130ba1adde866279813b9163fc9325e44bc22d00f1c4d4822));
        vk.gamma_abc[210] = Pairing.G1Point(uint256(0x0022d910ebce7ce4f21fa70097e7fa38a827ce1fc3e445549b26ec4623c83d6e), uint256(0x094cb503d8d7f5898ef85e53e39ad1c3bf8fa2ea0802962fc290a2d32d6e0206));
        vk.gamma_abc[211] = Pairing.G1Point(uint256(0x22484d0842b8ade8032bf206ffc89ef6ec31be93ab147f1d6dff50d75a8c3bb2), uint256(0x099bd900f4c80ab5d5499dc8d8be2ea9696c9cbf9f2443376ac4a4db7b385269));
        vk.gamma_abc[212] = Pairing.G1Point(uint256(0x1470698182c5e30972e96cff5c29bb5e95be40cb4adafe25ab40e136aea120cd), uint256(0x0d8cc070538a09a9658eaf957ee65bfcb0be558ac6a98301d224cbe6961cb106));
        vk.gamma_abc[213] = Pairing.G1Point(uint256(0x24e4aad7f7feeaebef30ad20f0156dd34b79f59a17b16f0123c5a983223dd94a), uint256(0x110fca930ec69d9cafacab44aa82f0ee8c987d16df5e88a666864a249feb61d6));
        vk.gamma_abc[214] = Pairing.G1Point(uint256(0x139ff0ad684819bcce73e2378713bc293085b9134c08f1f6ddb48bd484accb21), uint256(0x2e65c0043bd65c43f67d5ed157459eda846a5d69d9aa7e99e72bb41a5f2125a7));
        vk.gamma_abc[215] = Pairing.G1Point(uint256(0x1915bd23c9e38339251c92a5b58819cc40fd74555941b57827becc0d9071e2f9), uint256(0x22aaf6110a9350e988d06ee011e8de83a9280d0b5e56b026fd194863ce68554c));
        vk.gamma_abc[216] = Pairing.G1Point(uint256(0x0012d13712a3b1223d3f080fa1b563375240a1c6e8de011d93d51347b97f2d17), uint256(0x2758171369d9f999188288bdd12be8dc1a1830f30afbd9f5c390db4ea9b22eea));
        vk.gamma_abc[217] = Pairing.G1Point(uint256(0x0087671eeb433a4e4de2ad644d397be65247a4af4b9d47648eb9812306174a77), uint256(0x0085a9278b2bc846aba0b7d3cb4e10890fab008afcfd353fba596146206a14b2));
        vk.gamma_abc[218] = Pairing.G1Point(uint256(0x2a74f75cce8b8bb95a84295ac544a8a4918f0b60b009cd285967c4662aa29a85), uint256(0x1ef619161343a5b14d4e5de23e877d23188a486392b46495801e8793cfa66680));
        vk.gamma_abc[219] = Pairing.G1Point(uint256(0x09f7492ffa9cd917d8cc9ba672529040cb6f5b27610f2661e3611ad672e54d5c), uint256(0x1e37ebf13630fad31236f033790f227be5636a726464a454a9fee0354ee8441a));
        vk.gamma_abc[220] = Pairing.G1Point(uint256(0x15f8f94199b60376cf384b4c24143a66dce89363f1494fdbdd2ad87e4059783b), uint256(0x303999315bfa1cccb2e226581ae61f27d100fe2bcac9fef099a102229c3942af));
        vk.gamma_abc[221] = Pairing.G1Point(uint256(0x0e5a179e8050b8ec53cd54be19f741359ab905ef563d6e21a1864373a28a58bf), uint256(0x1f48d4888f10c43f31742c3accdf3135b47d3821c767fa11b64741d11f55ace6));
        vk.gamma_abc[222] = Pairing.G1Point(uint256(0x054b101ebf23e5fd5a9e360a9fcec1a74b616a07c20332f17dfe2b05466c537d), uint256(0x18b08e6a56a75b2265bbfe43c20f723c875a349ea8e22d44b167fc6f5b6e3bb8));
        vk.gamma_abc[223] = Pairing.G1Point(uint256(0x229969b0a732d8e117f1dbd32084ff3d8b8920ddc87597fc4e4d15169001cdb8), uint256(0x2581df8f6b5496abdd2bff3f629b89fae6e72b068d7a531c3ae8c767019c7474));
        vk.gamma_abc[224] = Pairing.G1Point(uint256(0x19dbb9831daedd27cfe4ed437d1465e50277e753bd51d4070dd031e11461a0f0), uint256(0x0c15de5af1bbaec948f326609120ec8cd5e5edb498edf9ee74968a34e1da4734));
        vk.gamma_abc[225] = Pairing.G1Point(uint256(0x0a435697fc52de59bb88d28c7bfc9933e414d20ff45b6505731c3917a2b35ef8), uint256(0x21eb505044cb967c87d00ff80a3559a1a36d3189cb4cb2ef0676641f5631c4cb));
        vk.gamma_abc[226] = Pairing.G1Point(uint256(0x1a909d877d83fc3c4d20dc770e82152afe0b29a5acc3182cc27521da322f60a1), uint256(0x2d077fa5325dee39b8293099648c886cc3a4ae925aa88d8057fcd93b697dcc6b));
        vk.gamma_abc[227] = Pairing.G1Point(uint256(0x207c63c46e2648c2238a3dda56e5bb22bb89fda0a8dbb806e756ea2a4c6fecd3), uint256(0x06d67dbdcdf2fc1b3471354fce35642d4880ae9341b342f6e6f011e3fd57a8fb));
        vk.gamma_abc[228] = Pairing.G1Point(uint256(0x0a0fb3b513940a8d3a5c82af19d16cbe7d92143ade279e85aa2501e1a40e948f), uint256(0x1e684f44205cf036254392e4b453bda6f36b262d502f2aca2ebb410a35d5b00c));
        vk.gamma_abc[229] = Pairing.G1Point(uint256(0x163449693146024545b5e5e05a1ec5bfa58b68571fc5ce3757d58812ab775687), uint256(0x25a76b35a9294b1dd30e8e699547da7e20b4dd987cf889d1ea70bf3081c170ae));
        vk.gamma_abc[230] = Pairing.G1Point(uint256(0x08bbacc6610fc465ec517b045ea319fff429877ba7eff78f73ae513e40eda14d), uint256(0x2198608ea58efaa0c69eebb8a3ceb7d55bca8c0cd6e4fd0bc268f44b0d3fb5a5));
        vk.gamma_abc[231] = Pairing.G1Point(uint256(0x04391e0a80f1bef91819be67e276ca61868b12e0372c5eeb8da997d594ddf22b), uint256(0x19970e643078ea3eec39f7877fd256148bd563e1f76c6114087133152ae828dd));
        vk.gamma_abc[232] = Pairing.G1Point(uint256(0x29700e5047bb1f4c2f67bedb4b590b74c4a1c83c5895594ee384c44999a5ddfb), uint256(0x29a13bdd0f538ef3de8c7cd5ece99458430384c32a3673c92064bdb05560390e));
        vk.gamma_abc[233] = Pairing.G1Point(uint256(0x1c43fe3cea18805a6c9cf2ebf354475d43eccd6155b1a64658bc3adcd258b7a0), uint256(0x07103b1b46925706eb31a7c39bffcf68a4bd85616a451d8e6daf78dfa76371e9));
        vk.gamma_abc[234] = Pairing.G1Point(uint256(0x2765ab7b6eed00faa089242e8b588301afea194575e62307c877b664f54b7e56), uint256(0x1a47b0f02e29ed2c136c6a32239e6c73791fe5e3f985ca60e612d69c075ab7c6));
        vk.gamma_abc[235] = Pairing.G1Point(uint256(0x2e4c44b7a3ba78965719099f9c94a03d7624b4c0986058723819c4670d8de763), uint256(0x14cf3bf33ce6d7f77ca724d5cae99f0cea5ecdd5229fd78018dce8e0ac5dfbc9));
        vk.gamma_abc[236] = Pairing.G1Point(uint256(0x2dabaa5b002479d5bb29ca14e0ce43a28887d7e979c36ec291addb85185b4f11), uint256(0x0c2bebe8c828e8d825795d93859fddb7e7aba3d477c1fc711dd9158ca03ce064));
        vk.gamma_abc[237] = Pairing.G1Point(uint256(0x21e6422262c8dbcad59cbe41830aa77f997e0404482bee15871ed661d4e47339), uint256(0x00b74db5b10fe4aced0ec5b6723741ce417ebad575a4ebcd7a3d835ccb4cc72a));
        vk.gamma_abc[238] = Pairing.G1Point(uint256(0x2547b3d3994e294484ab4c823c63e492e0c2f977bd9020ed3d8e92a9894a9c9e), uint256(0x069d53c07560b5f1d2b765f74afa566b1c92e7994e17b4e44f3d293ac7076b29));
        vk.gamma_abc[239] = Pairing.G1Point(uint256(0x1525f0e0924096857c20398b7803c1041f753b7154de3fe755d2e751807401ac), uint256(0x279fdf246f7d78963e693a4308aa45194013729677e93a129a3586d4622bc891));
        vk.gamma_abc[240] = Pairing.G1Point(uint256(0x0b02bf4e911e7d3b7ac6703b49d1468c1bd9e1a0dbd040443b58b46f4d9ba941), uint256(0x2d7938d14f0d4ef86c3d54bb8d46069bf8d764af9f305dc02369cbb5cb1d5121));
        vk.gamma_abc[241] = Pairing.G1Point(uint256(0x1a2d1df5d48d00b69679b1ebeb0100d19d6c88c603f3956d67425c11666c023e), uint256(0x094a7869171b4c69fa11c8270f6bd251c1700d926d0d87d089a234a165904273));
        vk.gamma_abc[242] = Pairing.G1Point(uint256(0x1fedb7214a4672aa5304ce541aad40346ce0fe0e587f16d82f2e3711fd6c0ad4), uint256(0x03298a934bd52bca3455b04706aa222610fd225f8ba5a9f58ae1a5e8915c3d0b));
        vk.gamma_abc[243] = Pairing.G1Point(uint256(0x16a629b213ebfad0bb9d9a042e30649229af18cc04226eb5653026908bee5e57), uint256(0x17dcfbc110bc52b1905dad48a89a8b5eb86e4b0e901f94ce1ea56d1b172b5399));
        vk.gamma_abc[244] = Pairing.G1Point(uint256(0x2886065b8b948888ced9fb02c7bef6b308824e853aa16e960413808c509c7b51), uint256(0x194ba01d8b1b8d440260d878b5fbe8a27589aebe1a7415ca2612aaeb1d8d65bf));
        vk.gamma_abc[245] = Pairing.G1Point(uint256(0x0b3d74b5da6f25dfb19a1ce8e81072678a6c3824ce06052647a5b10e910019d6), uint256(0x1924a523ddfdf86aab6d9f039bd4961c32c767a295bba03eed3a2fddacaeb775));
        vk.gamma_abc[246] = Pairing.G1Point(uint256(0x2881268145fec09ad1aa512f6c69015fd0459da287c376e6ba4b2a1b19145181), uint256(0x244dc5ed8dbe5f1eb88f1d4fa98f05c9f7862be3aa62aa72a0cfed8ad8cc680c));
        vk.gamma_abc[247] = Pairing.G1Point(uint256(0x0a39657c23cfa23ff0e50d28a242ad6b6dd9dfdce7c9566a6380d6115abd68b2), uint256(0x0ab208d1bd68b8452438509ae276ca023a1977bd8b0d9c24bb5031f2fccbc264));
        vk.gamma_abc[248] = Pairing.G1Point(uint256(0x083a3139d5cbe3e1a73fbaa77e79f31a911c02d4359a42a04b265ca06ecc828f), uint256(0x21879d6b5448d4bff068de916938bff514e9e5e043de7ca1d87156e69d4f465f));
        vk.gamma_abc[249] = Pairing.G1Point(uint256(0x0df583a8be584c05ee197565e85c363271b86091d72f6a9cbc343a0a085e4fdc), uint256(0x2ab8c6d97d81a82bcb720a2f95d9665bb3cc612d327aa76c99f8ffecf2e915db));
        vk.gamma_abc[250] = Pairing.G1Point(uint256(0x26b00e41bde6166f7ebfb49c02933f656ea6d4a2c88a0ff717775c3296e960bc), uint256(0x14ae2dc5762b751703bea40bab97c2e47a59bc08bd058615ee7f132a65d23063));
        vk.gamma_abc[251] = Pairing.G1Point(uint256(0x14cdf93a528bf17901a4db1ff3cdb3f2d615e5c7bfba3a169792415a961f8cd2), uint256(0x2c86f4a4ea92325161b045c2ebceaadcf47ed0cee946faa0b5010e991ea051e8));
        vk.gamma_abc[252] = Pairing.G1Point(uint256(0x0ef50622ca0175780eef3e135b0e8dd43da4f0620c632d323dccbbc05bf042a9), uint256(0x09d5902d1b65fc6182b5f51122b0d542482d07ba8827968219b50393bcf5778b));
        vk.gamma_abc[253] = Pairing.G1Point(uint256(0x27959672f5e750eacf86bab6bc6f9591b4ce8079cd920cea0f08fb015a7d80d0), uint256(0x074d79ac59edfcbcb2ab932e6400f7765a13dabd64fae7962145f55e9a4ce7fa));
        vk.gamma_abc[254] = Pairing.G1Point(uint256(0x25d2623d249a1818e9544e9229a974bf38e94b6fb8e38cb23dba1c6c743b3a9f), uint256(0x191fa1b186c2a1bf13e5dd5e8af1465073499a2434c25a3526ac8917fb2a8090));
        vk.gamma_abc[255] = Pairing.G1Point(uint256(0x03156eabb1170bda4585d40d62a9610c27a3db6f3f9e179202548d86c3fab878), uint256(0x179c0de13d608779f71d6d99c5e8268f245bf57046a07fb2c602f5b30c797236));
        vk.gamma_abc[256] = Pairing.G1Point(uint256(0x1d79725756244268cb913769e75c7d90376c0ba70c093b79ddc0906ab143d3bf), uint256(0x2177653a965115fb330ddee3159ff9feeb5f31b80730ed27c4c815479a4fe828));
        vk.gamma_abc[257] = Pairing.G1Point(uint256(0x05e1e13e9d5593eb50bfcff50794c7eea8173f6a975f0eac2089f421f6fa5383), uint256(0x08d7aec5cb60750f92cb5931b899ed356aabd915fee2dccb4a5028cd8f95f3ac));
        vk.gamma_abc[258] = Pairing.G1Point(uint256(0x2213e3d5210a45a80646cd79a4f16e9a50fb2e9bd012fa344accf9bbf9933026), uint256(0x145c189217de7c76a84f026bd4b80d8166cb49288c1469182e8b1f4cd0bb0a81));
        vk.gamma_abc[259] = Pairing.G1Point(uint256(0x1d33ef3485508250fa0fa483e2e49e6a7804d21d4d44f68c365e1718a23b9e0e), uint256(0x19040fd41fe800ef391bcc91cc53def9d2acef48afe7b5b5a3221773de36d434));
        vk.gamma_abc[260] = Pairing.G1Point(uint256(0x17df919e29c0289ea567cb4a02d555a44ee5576d4398748bb04faf9ec83a3ba5), uint256(0x229eac23915594dfe030db7ea1d4a70bb569ce37032acbe742b163a0960d94b0));
        vk.gamma_abc[261] = Pairing.G1Point(uint256(0x0434a2d64d989c37b9dc49f86d1829df48517fff3165de7aff1c9dc07663e8cd), uint256(0x2b319cfb64328522ad28535b29ea9e6fff993e819f76c0f4031e826726b59885));
        vk.gamma_abc[262] = Pairing.G1Point(uint256(0x1afd1a18d2c35ad90a5e8c4df8b1586256b9cef0b68bb63d836755e73ceb4f7a), uint256(0x16c41966a51f21dd91beb3327f401edb60f139f32a855063eec3f9c749763d01));
        vk.gamma_abc[263] = Pairing.G1Point(uint256(0x149accdde0d1c58cd65e75eeab036738a250411ed4b73949f792e74faeea9cd1), uint256(0x1ee1828d26b9b8644feef93fdfbfdced94e9999bcc67fc6b29f2953b1d1b6d50));
        vk.gamma_abc[264] = Pairing.G1Point(uint256(0x30086e588ac11e3e067c8193c1375858c2a50603c548a924f5e2338b329ec22a), uint256(0x0c5a834dab5bf8ff147665cbc4a11eb065c5040c908292b4f29d099872cbbffb));
        vk.gamma_abc[265] = Pairing.G1Point(uint256(0x20c6ca25cafcf6e873a4625d054edb5a0ae9b2d9b1e818df7e811973df24f910), uint256(0x118bdc9606fbdd97bb02b9bffcda6991caad157645810d18beae63ef133e2660));
        vk.gamma_abc[266] = Pairing.G1Point(uint256(0x05472913e0a3ca24d798d85883172c6ffc1b036e478ecd494d51fb1bd9904e8f), uint256(0x27250cd09041e4f7e020a234a5f5c072b311528caffb1fc90223305b69e1ce92));
        vk.gamma_abc[267] = Pairing.G1Point(uint256(0x2a858b28e956e00ffc0b40ee6d3b1ef05174122fd6d18a9a3a9d9bb7c959e102), uint256(0x2ff38b31e4878497c989c22f74ad9963e36f213eea784411439cd9e434267b5e));
        vk.gamma_abc[268] = Pairing.G1Point(uint256(0x238b0ba5cebb994b023db3f1ca6d1632ae21b1215abb72515c0ac51fd83186ca), uint256(0x0453339290d57a3dd441cbd5d1faeac30926044d5e06aee4bc0da14f56b38ec7));
        vk.gamma_abc[269] = Pairing.G1Point(uint256(0x015ccd29031919959380f84312af6d4e537e3377bd788160fdbedccf605f9988), uint256(0x132cc719a8e572388786a0e0ab37ef44b2e6b43d3be8ae50a993ab800f8d83ee));
        vk.gamma_abc[270] = Pairing.G1Point(uint256(0x2027dac254459d2d2054173dc53c284fda116b64f6e46dda1c49609d98e603d8), uint256(0x1b40e98dca0666e19795f3e5b1ad4c00ee2335575c20c8b15bb41cddb82337bf));
        vk.gamma_abc[271] = Pairing.G1Point(uint256(0x2bde4b30e5700a5258d49ed3693e987a748ee11ad001ae8ecd7c99b9abb1d7e2), uint256(0x18c50bf2f6aed8c0f2c9af6589f9856ebab1d9fab12d6c6823580876159563bd));
        vk.gamma_abc[272] = Pairing.G1Point(uint256(0x0ec650e6ef57832362284873bc840a26eb7201698418304f3c73f686ee0983b6), uint256(0x1673b1f47e589be7ed2ff0e361b1b6194c345b5f810cf2e974eeb22eee85c843));
        vk.gamma_abc[273] = Pairing.G1Point(uint256(0x0a89559d105f9c1dd924095774375e3c497c0ef47e3aff1f4854f11605c6c004), uint256(0x06bebd7aca53388f7899fbaa17d93a9972c70ef13708d41c96200a7f21b6d6d9));
        vk.gamma_abc[274] = Pairing.G1Point(uint256(0x006b5de0007f6210fcc7f3b5ddbeaeb51a66987ef9f3517a7450e159eb524eb0), uint256(0x2aa99a8775db599297f2835f23a9a3ce53433f86d02bf8ab220d00ce3b3a51b4));
        vk.gamma_abc[275] = Pairing.G1Point(uint256(0x24bb417aa9b703b89bd93eeb320a1bac9ce967eaf30c48b71e296e6f5b66635c), uint256(0x1c1027edb375c840f1edcdbc6c6cc84894e3ac1688fa7a691c0c2e1097f59e38));
        vk.gamma_abc[276] = Pairing.G1Point(uint256(0x2c9af98b4549e45f6f60c8a70f9c18ff66fa80effd73d1244dfecb4240af68db), uint256(0x0e96ff414778ef997e997462e11016bc59083382e4d8f60921072282fa8a2cff));
        vk.gamma_abc[277] = Pairing.G1Point(uint256(0x172851572ddd9d3aac08ac331e4b111eeecdf60424a3e0544cd2cd0ecd1ddd5c), uint256(0x1b0b5d5f3cdd71d0a3a1a6b4e54aabf3ac413969b716adfd3a464fd7410ba7c6));
        vk.gamma_abc[278] = Pairing.G1Point(uint256(0x260c129f726391ce77e54865b62ba349bea9a4f740c8ea2997e3a606492f1699), uint256(0x125f326b95b6109af21a4e9a7b3f91b2cc61b9d7ab2a119e0d215bb60ad270a3));
        vk.gamma_abc[279] = Pairing.G1Point(uint256(0x1367a1c224b0e199491d374c5b540f1344dacbb5080ce39cd2fe330d96c0e74a), uint256(0x305a3b1d20d683ba632f47617b20efafe03dff9cf9f4e790ea7418cfda7c9243));
        vk.gamma_abc[280] = Pairing.G1Point(uint256(0x1888d104b2e3091e09c6baba2c46e4db5f09a0d944ecce80fa1edb524e09c1e7), uint256(0x159c948b1ba9c7a24a9cfd5fb5123e7b00388193c14bf28419c8115fb279bbf3));
        vk.gamma_abc[281] = Pairing.G1Point(uint256(0x29b37380dd721ffbe1fab06b2bab6b6aeba323860a81cd675f131862979874e4), uint256(0x29ba0e95a74149e017b8ecfecc3a9bd512ba68cd99714a05c05704815e5d414f));
        vk.gamma_abc[282] = Pairing.G1Point(uint256(0x172f363f426a12a74db0a9db5f9dffb6741d0f6e1236548ca6757f4197eb06a1), uint256(0x1298498fc79dcb7eb51f1da097e14b78d903a955aa777ab7153d5199434d5d6e));
        vk.gamma_abc[283] = Pairing.G1Point(uint256(0x1c1dd30c1038695a683930f2fdb5372ea2e6a16891aa4d9e086aee22a841c244), uint256(0x1eb7eeb0cc0a2425457e1a93d1e72df4ad707686c9529386c4d904d262c4819a));
        vk.gamma_abc[284] = Pairing.G1Point(uint256(0x0473bedf2ce2bfea830e50240858645c11651871f3d0b32adaa07ba95aea135c), uint256(0x08e836be29848fb26ed97129997c931e5ccd3d896dd7d94bfa0c8670d608e18e));
        vk.gamma_abc[285] = Pairing.G1Point(uint256(0x2fed5a85326cf00fb999f31c10377fcc7c2d2a84038d91b3ff670cc74fec1218), uint256(0x0b1c924b103f069c844c9dbdecefa4a18f7ea96adfe1b0ede6b71c7cc1bb95b2));
        vk.gamma_abc[286] = Pairing.G1Point(uint256(0x2dd8865fc652705e3769e31eef409f867e47a08ede54035a77471256a0304664), uint256(0x00a4e8409d91854edf608b8379b480c59b1fcfe9590ee684cacf19ff4e1239ac));
        vk.gamma_abc[287] = Pairing.G1Point(uint256(0x271e2e52e056b71c0c1ee12af8b28a6b48568fcf04c2e3973fc56efffcd4951a), uint256(0x138b925aa820b8c40c915b70803ef837bbe1b13ee8bac62a0f953a97035a429b));
        vk.gamma_abc[288] = Pairing.G1Point(uint256(0x1c42f26ec6ba4d4f879215706eace05db52ac92b4625dcd2def02e294eddfd99), uint256(0x0ec41ba9b6bdbc7e24a21a6a056391bcfd05ab2162b0ff242ca93936677a67f8));
        vk.gamma_abc[289] = Pairing.G1Point(uint256(0x2f7d9121015235fba179f513f6ef34972368d540bad82da2e52436b4976dc1c2), uint256(0x1c347a6d2a8befc5e310dcefe39810dcdceeb18fb4cb8c465ffc8ffbd4903a87));
        vk.gamma_abc[290] = Pairing.G1Point(uint256(0x0437aaf6f6f1a60b9c40f6f71bb6651ec91fa5962b77533e90ba3561794ef0fd), uint256(0x2c8b1685bdde7d87c329784a5c92fe7c694ebdf0af5778c7e5893789f7652316));
        vk.gamma_abc[291] = Pairing.G1Point(uint256(0x058410ea42a71b80f54d5129d4d8360c5ad96555e917d3fc74b54492ee8ad6a8), uint256(0x0cf095f20e96b60e3ea3d8a089fcf5cff2c4c50916f1eaf0ad0ec024e3eb35d2));
        vk.gamma_abc[292] = Pairing.G1Point(uint256(0x145948795f266573f0dd8fc0fc57ea6bca316b0254bcc335d41257b7debd5c80), uint256(0x2a2f7e69f985e4a3ff3edb7e5d43084fd14c34b0d9494f1a8681d24ded7ac9e0));
        vk.gamma_abc[293] = Pairing.G1Point(uint256(0x016f25721c5428f003de381407e875072315eff024d8bd380d8db8fdd3ec52dd), uint256(0x0c1bb30985ac65971139c12f6aa10e8b69eba3cdc988318732e9c8c577abb38c));
        vk.gamma_abc[294] = Pairing.G1Point(uint256(0x1a628cd2959095ca8e7250d125052569a5f7b68a5fd46d636cb64678fdcf0448), uint256(0x04adb8ffceb42cfb1b2ce098b02d1e8b19c66be20430280739264b46f21889eb));
        vk.gamma_abc[295] = Pairing.G1Point(uint256(0x28d869677375b3a9e3eb172a846ddc2b32167d3c4c4c484b66a9f1ef27eb50e2), uint256(0x105abe93834e4836ec3b6622ee3112a537378ce8a85484886ec8e4a6f05fa250));
        vk.gamma_abc[296] = Pairing.G1Point(uint256(0x08eae7d2449c6cf4b09814e418ba526b4148bb5ee3b3c3e3e75526c222804f64), uint256(0x278a3017f02d24f68fb5ec5a7c6e153b5ac6aaf7ca307c97517b856ec4b1293b));
        vk.gamma_abc[297] = Pairing.G1Point(uint256(0x21804885418e46897030e64aed5e77b9cb9e639e61639b68b74201a5c2870c7b), uint256(0x273174627e3731ca21fadc789482632c9a7fe4e7b9fcd9d845359c4e7f09d2eb));
        vk.gamma_abc[298] = Pairing.G1Point(uint256(0x26c2c2018aec381610a1bc61de4906d123eb8fc2caa0aff8669211acd6bf1a0b), uint256(0x136f8c9c1d254d7404a5ab4974cdc6106246a173ac1320cb4ebdc276ff7b9dba));
        vk.gamma_abc[299] = Pairing.G1Point(uint256(0x062c8fa72358390eda60f706880a7908c2831640a24ad80fe960bb0c734b0c33), uint256(0x2cb8f883fd8ae706d6fc167f1194b654043032555ab7fe7d59eaefb6d6a808c0));
        vk.gamma_abc[300] = Pairing.G1Point(uint256(0x14b984c31712c1968e80184869ce9ef76851761ca420afb3d4d94a1bc592554d), uint256(0x00e1f9ef2d26677351f823118f041f269c3c8bdab501944613c36ca09628313e));
        vk.gamma_abc[301] = Pairing.G1Point(uint256(0x1596df8d135e14be2a1162998bd945fd72ae0bdafc28d2ea21da0338b427f542), uint256(0x0c183dd34e896cc47e1c68c985d1cdc62bcb2e060b011738fd1dea6bb1f471b3));
        vk.gamma_abc[302] = Pairing.G1Point(uint256(0x01cdfba9257c0f66d90e56b68313df81703aa7dba6524a06fb73ab780e05ff8d), uint256(0x0d073cea85a5af232e20f79b6d3e1ab1b80e1702c6754505ae75612fa6284c34));
        vk.gamma_abc[303] = Pairing.G1Point(uint256(0x03ddaf3f098cae83485bc0c8701d69ff6870cb01d61ee21c5e11f4675f3f0ac0), uint256(0x26d2033c171a9cd87f4c4f9e068634a34e5d4a5e4c9c1fa5c5169dcbf1216c50));
        vk.gamma_abc[304] = Pairing.G1Point(uint256(0x1c7bba4f0791271041ae12bce0a0cf7d71a9c74c89fbd499b5dcf9f41d6892d7), uint256(0x0ccb590f7fa3d51afab4530824c4694f277efb2fe858d29ae151d156b969c236));
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
            Proof memory proof, uint[304] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](304);
        
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
