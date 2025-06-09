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
        vk.alpha = Pairing.G1Point(uint256(0x0415b10edb02f94e50ed0aff61d6fa9af45716f61ba963616248016c294d741d), uint256(0x065ba5c7c84c6aa5b52cb86eedf4f5076cd58e7521f9aaa37117a1f421b3c761));
        vk.beta = Pairing.G2Point([uint256(0x0eab563933fd53e27aca30f81bab051e366aa5324a0ce72360eb0fa70bfef3d5), uint256(0x1ea2681b5154baa03b2e34572906a61c27044be14f36b8b6ef624ae599bf1a56)], [uint256(0x1a13671861152327005c9d639b49547d387a2a72bee09df3467bce430a45ef93), uint256(0x114d51c7ac8ce106faf4871b996c5cc27223afef01760cd31def61facb126486)]);
        vk.gamma = Pairing.G2Point([uint256(0x1de29f8cc31659328975ae80506975c143504e1cc01f8f1d9316db8216af6175), uint256(0x14bded0ff5fecf9574aa845c38e02b4d8af707f39d597d3f86876dd251b0871b)], [uint256(0x1c9a746eff2c31ddf189790c83bf1963e32ef4ff0e86434bbc92b8eb58c72f69), uint256(0x02e5901fadd8f036f35d1de7c4046586f53adbc23770b83963415c80cc1c5c7e)]);
        vk.delta = Pairing.G2Point([uint256(0x1f57b1d198d941ac5c2afb8911c1dc37bcc68f991c9e95ebfe7748b080363b25), uint256(0x2fcf1273e26058ccca2f294229544bae4e748a4317976a639ad81e435807f773)], [uint256(0x0c6a6cee5c6d12e96048f364540ce55e38567f5846aad5a7c7b3884d7b5a42c5), uint256(0x0a84641b78b3ffefa9b3b2a14c154316444fa87c75167e62c94e68badd703500)]);
        vk.gamma_abc = new Pairing.G1Point[](68);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x00c0f16ae1915bc62f1e2b0ff898a7b11131bca2bca8f7c7d3b02d481993bea1), uint256(0x04317beac032dcb7dfcbeb60d03f86af2eacab5bcfa012864480ed49f710465b));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x20b01c756f4dbe262b44c2cfa02dff0df48c628fc5c18ed13301d850a6fdd066), uint256(0x2eb5c5f1a5563e3d69cb594ae8ac211486d89aec63224820a0b69c3d65af508d));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1adffc065d61c760cf1e6026605a3da1bb99152f6844ddf4b1e3028f171ef885), uint256(0x03fb5ff81c4e3439d3a92e3019f728304ce70e455d32295d99aad0633e695cf5));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2a469e20b43eed365b9ec8bd52461ff955ae1d642d61df382321159c40367e56), uint256(0x18b6c8c2811b11502d9799b1a1cff0552718fa0322937c5edb990c345c2d37dd));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x21508eced35376a866cf69a491d0ba371c544d2dde364d75f1fb9bae907808ab), uint256(0x2fff801fa0b0eb584ba01ea09692159b63fac9e17314c64ead742a62e3e25532));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1544915d996eb7b1ecc0634a6bc1222228d4a2d5a4d4ac8fbe31cd9e6442da15), uint256(0x2ef4bbb2758e0665aade6ebb8b9b549d9bb07cca23ccb56679921989aaa8bdee));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x13db1cbb9b6a6e95968716e34c6d1535d5e4abba2c7db9a62c2a86c4be84cf62), uint256(0x1302c2132d426fdbc5353ff54158b1b7a7d69c0c03a8ca79dc21d3d056b025cc));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x02736372e20ee7c3b1cf115bf5744518845f8fad3035439e1f90ffdf2cb1cfd5), uint256(0x2ee358eb5360212aeb68f6aa30df03aeafdbb6eead587211f51bd103b23e53eb));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x05ead213a9fa094eb36e4ac55ec177fbc68f1a5cf877477d3fee10a74cdc6054), uint256(0x1fd11500475b963f933d44e7cf1da7b2f3a4f6a3625075aec93b1761160d7e03));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1028d838e39fe370cd5ca3291eb288fb7edfd2df01f5fb4bfafa012cfaefaa1a), uint256(0x2b5bf4bf6f61364b40be2c483bab3b21f4e1484e438ae94a119a9f38217de52b));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x29c821ec170a24006d0b04526d660f6d7912ae920d2f7fe1223921f055ab025f), uint256(0x1907cb1d840d0595af64178a80ffd9816ba807320d154b456bfab783c754030b));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0dce00ebc4aa264dfad8014b3d4ce9c6e3451ca69daf5b534931df2f16c9576e), uint256(0x2bbb45c18b1282b02152439e5f18f09e30234badcfebf6dfc115a4ad5af3d93d));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2e59b21dae41a22dbd1508b2e97e35b4c23b6294a7f646d9a3537f2412a8cafe), uint256(0x01b974539cd0ef512ed4fa0a84874c470cff5023ce9122b7dd7d2ec6a08feb82));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x11c38ed0233688e6d28919c94d8ad102b3155a374737554c3de9bb761a1394a7), uint256(0x2dbd668449005c5508739fc548a8e1b14d234a55eda53a9489071fe3b94ed5f6));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x159c5a78b0b1393f75d7d38df372ffd8a108080cca965228dae57dc642826df3), uint256(0x1173a463b5cc15af680a3ee9ee5b0224956a87e14a1460cb2d3d59e67676272e));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x277e453a79aeebcba424ef537138e6e627e7c30c28a300978429e7834837f64d), uint256(0x2dfe1b6d7a8b97d1cf303e17251a47f58e145eb47e6fdcd0a380f5da2873b301));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x182887b00db8b53e6324cf92beb2d7caba7bd73ae288e5c3fa1e6143a10a269b), uint256(0x13c9d81a49ef2a4412518b5b6f2b3484bbb890402c253a468eada3b459fbc742));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0f3e3656b05a41fee365574608034c5ecb71752e42eb144eef5de0a2d2edf25d), uint256(0x060d950c86815bb5c09b71a21463889c4bf66bd8810e4b33ad042c6f890890fa));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x04a0adc738056a84ca87729a152e3f82cef193f6dcdcc62732a8815a2860116c), uint256(0x19bba580627a6afbc2e58d1784820357c8cd77ec5e2093262c836007a32b3fb0));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x09f32ca6c9536dc68dc28b512f3280c888026b303c65c3a6d347f3aff74e6633), uint256(0x183a5e1834b81ad1bb2ece4bf0bd29fd7b4c47ced7fef83a8a51c4de4ff599cd));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2b2a2b4ebf3e2833975917f78df3ee219e7bb687fbda63b4361f90bb02bee5de), uint256(0x05e5a193a05ea5f947d9a27e1ed962a3d6851ccf1d60e76001537ccd00242b78));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x0a5750cf3ad8e3a08b06d693a03c5ea3a92ceb478842f8695069279c67f5073c), uint256(0x0583326b5a4d656c14c5c818dca36e17ada23db6d0e108aee7c8163a2534b0c5));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x05bb2bac02c37552cff97eacaa7e3ff097ef77ac6f341ecc592c113897746673), uint256(0x2c13e2fe9cc4c9145a48a62181d61b97c79fc852e8ea1a69780d769705ed5b3f));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x24ef71376ed503cc56fc3dca3b0e1f1f7014d0adb1fe3438f00fd9051cbde540), uint256(0x1fe98c789a1148a9db36d93e775e0c6dcb8d47b57c40388db554d992f4a1dc1f));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x12dc649a531cb5f080392566f0839b17f0855eea16f313f82fec2621d6b9b751), uint256(0x0a26b3bce9793ae6b17a6301cb0a94d6cc2ca31a431acd92f15ecec3ce7bf680));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x2ce7726aca52bb433428cc8acbbea4c47b190ef73744b4681af43b89486b3b8b), uint256(0x25ab29ab8a4869ca82ee28724237294ee52201329b8a389c40af8678e9388c5f));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x00bd23569cecbbd371356b70006ecec3dd37cc7f2a051d6caf2719510c138d88), uint256(0x2729fae8775646ffd10e48124a86d1fa65fdf72dd3a2e0a78d553d25be922c89));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x21dde7fffb9f02da13eb447eba3be68c844e0eff9b3e2160f051be8694de7a98), uint256(0x18e300e93b47f59a158f83934c1d402ced1a67db913350773241058e006a9cc4));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x1f483ca0d7610e563e59a196e2776a8499e3783a3a516b081650ff71d74607c3), uint256(0x2daaf1965aea25924b74543feed419ad7886c730cd305ac3ef5cfdc72d5ab9d2));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x252ad4c924e72868921e0e379e9d7916b298368489e399a0fda51047844b6cdb), uint256(0x0cc91510c3467e4b332690895d2098ac4f0d583b2db30f651da90da7203cd2ba));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x26db4336a0f83359b62d3c9301e454fddf1390e3e2a2319e67c3d2a43c9dc04f), uint256(0x1ed784d22bec72aa235389acd3825460a9c3d99143a066a0c66e1619214b29c0));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x2b084e4921ffaf6800633e1d6e83a49fbd98e606f8e9377288f032cbdaeda9c3), uint256(0x046f1de17632a12300ccb32438965b72dc18974ae4015b68e4407fd0ef7effa3));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x18b8ba3dfe61f27fe5456e0121725824914df3c2b6acfbce010368ff6bd89c6a), uint256(0x1c8a33ed3cb83d87b248b52201d233cc8c300622f40f181a299d03475f7dc79c));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x0afcfc79a3abad4164e82679d4110db1ce0ae4cdb229f77251e0c08a795702fd), uint256(0x0c4be687b929f9fa5c35d9278da032ba105b7c55d92a5eccb2fee744155096e4));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x21e28ec00ed986d745ebea8956fd4d73c15c731d264411d2de27db33262f2872), uint256(0x0e4a0b52d16cc9760d5001dbd3f7aa9e2d760f76c32cace6ab0971315141c281));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x2b00d8db2f6b552070dca210245a457f4337e957258c6d9dc704cb3bf9d0257c), uint256(0x17f073308440d344553ca71a80b002a37b156b48336baa20e8a48c8073ec6b1d));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x1b05c887eddeddb1f058829795f75e236cec2b3aff68e544c3749dba3b441c89), uint256(0x059f42a31fc94193977a7286ead5987ed1ba9cb7fe73482049102cb196f51bee));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x0ba554dc8d9e1081eebd081ac37982cae52d41836dc34b1c68323e4fb6b80b12), uint256(0x241e37be04971d0d8d3c4fd65bc64f7dea3c0b26874991d887fb2a2db48ee4a8));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x264ddfd12dcc0520c104a615c331f0490afcb970be676dbfd4c8bc0b2047afdf), uint256(0x09b91fef6d5217e7720ba03269833ecfabbe2f35aaa5c8deffef8b4d8556351e));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x240f97886db8d7902bff66617360711ad42e9f7a8ab8ae779b4f62aee6be8259), uint256(0x3032b92794094be63eb9437f38b4b201bea11c8456e1118214c4606d60c18638));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x26fe0b4a96b031b9826b18eee0d507f38f66f1abeeb2d4e02c0c531dd39328ef), uint256(0x16bae1d058603f564c3464ac09b627a91720e611495faac45f6e693af9f26793));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x1c63cd78015b60d70df357c8141b2fd7ae3872549a4b23497f5a9f9a855aa656), uint256(0x0d6a77343fdcfd0fdb10b5650277588b4437cce58d57d70ce054be503f0ffae0));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x2dae5d89de03c879aa5babd6de1b737a7ceea3a4bf0a3a3cd9ff4c3a1307cf9c), uint256(0x08f8d296c44d08db87a007bf73723098bbecf8f79f729da9b601c6c23163edd3));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x002726f75283490f0bb4ad6365b9185768138aa16acd76af88fa49614af3aa18), uint256(0x1237ca6ebfeec0fb517dc03517c28a154ba1658ca83c9995b4810749a3cfabc3));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x172ae6b5a3ad708660a09f5d9f26b3c0f3c7d022b369ca04c44a48105f8d9fd7), uint256(0x1d6609b87400cd69fed37180eaab9424548f9fb44bc23c89f3856345fb0e1efe));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x0d636dc63169d027364f9235123d387b02c4e717291da362ea123c8bfc58dbd4), uint256(0x0378b91da240efa87398f3370e224fb9d0f83a0737c8b655292da0df21a6b23c));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x2e7d2d34ac7a7457d4169aae5c92755f5b9529d7a17a2a589d04c5cdd5e34e0b), uint256(0x03d908665805b368057f2406faa057db59c506d9413dbff7dba207b9c009f947));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x2a9631809cfc24f207f10066f0709efd8e0a30e56b5bf21e1511b451f30e8512), uint256(0x18ebc8479093cd978f3565e35e3cd03467c080e70ccaf45dbd177259006a4e65));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x00fed338942f760c6021262a9fa68cba4e486d15c1a66868a053dfba032878ce), uint256(0x283435260fb556a293ad3dfbe730acc042adba1fe3c9500afd04d6b511a2700a));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x2de0ed3e87afe01a2f9abb945d3246d95df91ced0bb30378a388579562453f25), uint256(0x2a71bffcb89ac9e0dea31e4791a8ed7cb040f864cdf0781da4e5a1098a107477));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x0e6c594e42ed0aab204c552338f0706c85a3ceef35a36d5b63b5acf8944c0224), uint256(0x262c7f76b4dcddbcfa853e16ea422df0797a74d08bc4d02207da523a01e91af0));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x13af9c4178628b62a3047c89e3dc9835d38e32c8673d25419e129d59489ccdcb), uint256(0x2a71eae901d054a14ea43b8919be94c74914f89b505f10b2c1c211c13b18c486));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x2ff3727dba6466a2f9199483a0269683523438a037c0a0274d798c50dfda4707), uint256(0x2966aacd5989facf4464456fe0e5eded5ad50146a984561c1a15dc17ef5fa3d7));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x25f010589e4d1a3c928b649aa171fe4e9a2a5a7f50275ce4e00aefb9da6ff188), uint256(0x15597e6dc184824e3a5e4219fe3a12d07f2250f924d89b4d073d64a7afb104b3));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x095b4cff64c3aabb453c0adfd16cfda89a009fe5be3961e8d0aa00e72396be73), uint256(0x17725555eb0ea0eaafea684f49f9b6baeb99fac34cbfb5538dc5a6067f834b0e));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x276b1621daf6ea7bf471bb3837d9d7e8ebef91994db750a52fced84fa054d446), uint256(0x0a5172fef5d831f634c0861d2dcb04e8d321eceecf28f2490e1a9e8cb84bff7a));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x027bc1707b47257088597ad2e3280607cef930587d57ae849199c73fb65cac59), uint256(0x2604e678ef1e079d75fec9f0b5a600933f9f1887a218be87ebb78e9874cfaa03));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x2f0ffb81d02405f24812fd20f84ba1c4e12b704959cc92313180205a4bc58898), uint256(0x2ac2db87b78783bc8b41e23f5e52114a209044555f3e10e84be0c9f28b1be6ea));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x0fb08e61b32eb8927c490d4417019e061b2ef7b6dc8ad6a13bce8cc3c439983d), uint256(0x15aa447960a5d139aeead05694d61802210db38b115ca86843bac7e1452fd106));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x2e6dd2928bfeadf6c82d8b7c8393b6fb9d4ef5e4cea934d191cdc977ab4c8f99), uint256(0x15d0a18403fe3d9a77849f74f2e5bddd7f93b332e47ca7e8adaa111210a6f638));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x193289162e1cd1ddf01ced3abe82e8ed14b1755c7eb80673cd849bb11410bfa0), uint256(0x091567db177d1c4d8acee833b8feb21ec3fe8fb6d1b6b5fb94954b8b3b25ece2));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x10beb6417e39138076ca2a81182c802d52bc8e3afde529d321c4781bbf17319d), uint256(0x2685299fd208681eca619cf8c03a6e9976da300c21b58e0f7724d86d969a1a4c));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x10a7f2c7131403d5e7623045e3294085146a12dc298cfed9ff55f532ad6a6859), uint256(0x0535bd8b55a66d98693cd88a9bfeb612b0ec59587bf979d231c6aa7944c63b09));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x0395c0043084d2c870a21e7f29087e159854a7a7423b23c4fd54d4fe371b9820), uint256(0x1a0418e21125cbe1cc09efffe4cf14d8924e34d8e736025f282b864824d75c64));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x1658e4c96143f9e5283c77c2e5166bc805d199862fee7826773da2a544a110da), uint256(0x20e3c62ebd596597980846b3046d6475f979f88863f08c1dd909586d48bf324e));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x25568eb942665a93990fc55f1b16d1c6112c0dc114aa6deb53757ec0c4adcfad), uint256(0x083632872d9425998819aea14be5b34432bf09652551ed2c5cbaf18589f554d6));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x075d744697014b0bffc218d9b483304fa94630cd815f316f45c434bf994e5f49), uint256(0x1bf976030929e9293ea9f136b8fb5ef6a5f085071eaff465f7cab092983cd779));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x162fdf6e06faf3c803103caec106a6aae2bf880ad282e257c0eccbcacf27652b), uint256(0x1298aaf2f8208d074200510cf36a11f33be9184b856546671101a8357f84a389));
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
            Proof memory proof, uint[67] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](67);
        
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
