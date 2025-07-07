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
        vk.alpha = Pairing.G1Point(uint256(0x0cf1811ab522527e2742859f4fbec3a32c965fd3b8088c13e2dd2c86e73d20f1), uint256(0x258f46901f4d76d7407ad807eca12cc0634a4acb7297aba2544a2eba751e0f7d));
        vk.beta = Pairing.G2Point([uint256(0x25a707c28204dbad39a27b32dc3829802cf7305ace7d4216ffa529f3a3b6aa2a), uint256(0x15c3d577e03e44a5d565f2aaa978f28365c58f5378c38aad54fb164b78e04ca7)], [uint256(0x0f25b6153a9d168e55d9d8881d6d6a49f0816c464334e7551ead7029f2814816), uint256(0x0ef9d151647a78ab5bdb30f33465ffc2465135ce5bbe8f166fef2f3c1579fc19)]);
        vk.gamma = Pairing.G2Point([uint256(0x162632d49a1f29c8f82e4e0ec683b0241c7c2e65a09f24af5586e44d0723d8b4), uint256(0x08894917c027847700726e30586d70bafff8be431c5f905a806cf8353c67bda0)], [uint256(0x03beb2a454bdcc0190d18dd5cc8dd54216f57a0f9a23022c3616c1b08bc4401c), uint256(0x17f511f3b8184c5ef443e85bba959f059b00a504fd972045ca90f57cbec68929)]);
        vk.delta = Pairing.G2Point([uint256(0x11742b7467cae366aab0ec37e27853ca62f36ac1a0d4fbcce57ad66d08bb12c9), uint256(0x14e18d2a333783fc08af3d8575cfe5ed56d8419838d267045f4a0e8feaf2bea3)], [uint256(0x0c8d2cf009690020d6cf1b92edacce5273b4c4ed7c3db7e8a3c8717c34885e0d), uint256(0x1cfd3ab58b01f47417a3411b9129c748c040845bb73f8ae3b63d2a8d6c4463aa)]);
        vk.gamma_abc = new Pairing.G1Point[](44);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x25a8398a0d1bff81bbe4a4b47cecda932914fd99dbc0607e5bed65900dde0c2d), uint256(0x1b1593520dd590b0625fc6d31eb5e9f3b85292d3c03bcfdcba2aa897d52487c7));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x197b029c317c01f6a5f7a8e905c734d5cbbb97fe0ebb80cf8d2f144ce3b1bbd8), uint256(0x123dd214ace3557c2fd8aba13d4a2a8002b4517fcda4b5914c5f69ac9da38da3));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0d67e0221362e4201a3953a35091dcb068ab3ed5f21addaec6f848de46b3daba), uint256(0x3023958c0117f68a6b457b2eaa987d52d14adcc2030c312e329a8b166f2867bf));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x30412b0f1db114e1422fe757ff16f752b1f59bec2a1cb0b8c21182a09b3df2ec), uint256(0x24efd4c195cdfbb2d06f086a91349e4c9965f3323e8dd273c7a44c2351af0e6f));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x11dbd3bbb520f7bacc6bcfd6bad9da59dc381c1b7257de9cfdbf6c51ce1b8ef7), uint256(0x20d275ec6c9dce455f7733479918c17bc55172fb8c545b9c975eb2414a4fabda));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x263222994bc0fe372438d67448dce3ba52d4bc68084b8aed73ec4793b4d747f6), uint256(0x1c4bf3f3289c1b331fefaa0e0e8e1c8f18b139d4a5c298121e3d3d9f6055adf3));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x11af81fefaff7c4a5a681807ed7d90e4a8628e4ac3bc7c4fe9dff8dcae261a00), uint256(0x1a45d64cabc7a6f89f6b9e07c5f6e3e4b808ae862b5c50a7fbb2d1cbf4917094));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1835d425c7ae34ebaefb6898fe0af9834fe69955b7d60e1c155dc52ef982fdf5), uint256(0x0836bde732a3a2b2937f6058a3409824ce3c8fe10c6207235efa0b93877b2c37));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2c1119b47b724cd24ba984722068d34e7a736ab4f16426f09c202e63002473ee), uint256(0x1f03b1e4b23ed0c8f4b99218359e987e0c0a66a0158131048dd1ed1e30ef7448));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0e3b9c783438284aed2077616651f50d36938a6f54a69d94693d8090e40d1189), uint256(0x0e0c31d4a625ba1c7f134f6c44bf8d132f1950e5d7eee14dd92116309b25222b));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x02d904e2ad31704c39a0ccb008c53b19f7caa7f0b1f908d0e66a8613b5c9573b), uint256(0x0c247b069bd47d8211ed6ab89f2261e7b180f35ddb0ed6e7dcd2d44343164418));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x17a18fcbd1eef1505791f4695125a6de35c1239d8240d514c3a662d637ca3352), uint256(0x2656ba2f5c4e3ca5f2ff2344fe19394a6bded0319726a90247dc1a077ea98be0));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0ba80ba8a47f852ce5be3d4e46d62184d80715a2a582952494554e039ba4a3ec), uint256(0x16c888db76b43a2760bd42f15bb239ed5c2940487c3d86c784c4a5f6ca9053b5));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x02d06d2d6c72a573da8dd206cf21f2977e95ee365adf01027d85522c4850fde0), uint256(0x19c264ed24f61e285badcef1f387fad692b49dd22c1be21b581c6f4487a43eaa));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x26dd4e1ed5c810a101d4c7df1a1c4f7eaf8ca18be6115f9fc15df44d0a34f912), uint256(0x14afd1118281d8ca50b15e3dcbb1899b61f1487ca69ec962109cda2315cdc378));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1035d82280e12645d24ffe36774e1eae8f7d162a7bb9bca3a3724fe283aab215), uint256(0x193bc96b1b3137823e9bf657dabe861dee32ebe757bcf69d732187fb1fd6361d));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2fdbb770cd6ef53fa78fadd6e8e16650e611337f2c48e9c97dc21eb870720dd2), uint256(0x0f8c2a09d4beecc1e391d816c68af5823a85100cc3ad4c7e600cb781b7e2a1f9));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x11b2a43791d3b382969482b4b6a303b9163fe8004a661e42780612e6ccea8372), uint256(0x2925dcd1a8cf7d7eafd1bec2d1fceca0ea6e01a7c6bcae1b5c889022091eebaf));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1bf4986708cf6652b25d1402a11a3b71f1d76c2a9b3c8a6ed14802d6e873984d), uint256(0x017929afb96ed9a4455765dca0f58e50790a78e65f26ff1ed8ea8481ff28b4b6));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x20ccb8ed005b5db2d42c261d1632ec568d266082d565cf688ab8dd93748adfa9), uint256(0x263131b6333726119fd43351626c9629c8d7cd6ee5d878d766b3e6784dbc89dc));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x13737ea47de343357b74a131e27cb392b4949d3fa975c08cf36b773585b49d3c), uint256(0x138e1b82f54394ad3a9bddd748466c07d8527d1322e2e2f5c09e7a91219c2d86));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1bdb0ebc770dbbbbebc6b8d2418061a96bc11e2b830cf778bdefc390a525ad66), uint256(0x23dfd555efce9107c200371cbc5e3099d42a3259c1a1cfd759f3e9f42a924469));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x21c41b16492b62605559fdf3a70004ebc39bc1d0dbc34488174f118912b67479), uint256(0x028b131a77dcfdf94730783f1be55b7fc7ad6efaa4e46ea5f17bd076a152f486));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2eecc146a7a72f83b255df72628fff9d3fc36def731d31d905c50190943dd5e6), uint256(0x1400092ba5a5488f974d479dba9b243c0f7d525b5eefa4a01a5c0096bc40f280));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x20701a20e04fb0987e1eddbee8eff3b0b65a8ae0b01bc6dfdd1c6e55b9bf353d), uint256(0x2b19c3969cef5fbe99196c0378b2cba84003f2b2374ab1755bf095405eecae6f));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x12356f0027b967270b0ca49a937be959ebfd2f62c230f4c590001190b79cf1e6), uint256(0x0b9a301b23abca9a5f9e489d7b094a8daa53830e8651110cd773df511e6a6be8));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1c8853019cedea7db7e6b199ed7c3373b848eb80765406fc534dd9e4f8e26b34), uint256(0x12e9ef46cd2e8113e9c4b04e20b18883994444539cc7da3f0c68ad3700feb375));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2f89ed0f2a741c3cb37ab28e2592c26ff302483ab2c636ca256b72de40950f58), uint256(0x1ca8de0aacbcbb5fe919e1420002dd03f02fbe9a0c9b751e8a69e1990ead8499));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x0961b9eea604dbf68e3ac730a7bb3a822a65f1336f5cce786f9f8d939e332453), uint256(0x08a39b18700cc6493bbff9d586e0a5f1e45d1e22cbb3d1048d712a74b320468d));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x0acfced90cd77915b721ff9884884166a46824286e8a694ab829922d8b0d2e52), uint256(0x05e4c76b926fb9746ea814be96d5b1df044f9e6e06c626f1c8905b7ba4b582f7));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x044d0ca22298687640c6f6a2c922fb279bbcb4d83bb159ee15a55ade5721b508), uint256(0x039872904f48f14c398b8c6bc49c9be4594926ed9e23eedf256415026d0d1b54));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x155dfc6cc9b3cfe99e29c5b8a6c85607206d8d7659466cad7707e815fa5fc6b9), uint256(0x263de18fa0263b96594c9a5c86ab35f34bd3305877d74fe84b59f9230efd8d33));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x271ecdb603ff488c247ab5b12c02a337317c231c6440ce93327a527f04927069), uint256(0x25777c3bce465c11323a80a3f62c8784c1dd2c4f2bf120c6df339508d29857df));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x23b5c25fe9d3a51bef4fa8c32f49c2625e31ed8ad925672a023f76c68c5d344a), uint256(0x0d7b59aeb14944d3c1335886f3cd3aa541db8a89e6f5436fa698917746ab874e));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x2f58709553469f8c7d0e52a20d64891af4a855097f8b8d164d7f3ec17565f2cb), uint256(0x15156e168163452f30940937d5818ea7439d8e707a6b80c571df5c7263b05e9a));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x09492fc148954283a749735b46b8ff171ed1377bff55178c605d2955bc483817), uint256(0x2ba746e6b4d68dcdffbd6fca2521dd02d3562b50e2a6aecb21a9d626e718a26b));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x0993aee0d01208f30dfd3692c99008f60d236ff6a96bb12e98cddf74421c8afd), uint256(0x2681d2d59be6d11becbe8e505e4dd4a2b6f4df8e6993ef6894de995607f768d8));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x23902b01dc1aec38364cf5d951e45d51f3a5706c46e43b83369cb0d18f29b89a), uint256(0x05aa415c7ba665f2ea30ae26134c6461737e7afa6c29e24b197935f9d48de8bc));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x1ccc95e30931e7a1c6596477972908ee34ad4f0b33a28dcbe3dd63430cb37d7d), uint256(0x2fdbef215010caea8a2031d0fdceb37241ac7072d99ed9e88748487f62335b64));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x2f80b222f32017ab8597546a21831b80e965cab90580d1c82848f7b9bdb48286), uint256(0x0c037e764cab614b08d5653cd94fedd2bb7abb612d664823a882d7bf70caa906));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x0d0a0583dc2863c47ef555f1253bc0ff50ed7b31623be474519e83ed6a314710), uint256(0x25ccde47800ee41cc788510a205e92755f298359301021f503e077d8d9106404));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x20c345b01e6d3e38460417b8735a917ab2e5fa0a0f5269447ac764bba1cf08a3), uint256(0x25b6d6f01a4b1946cc39adbf64e977213d4e90097afc7ef32d812312cf6ac844));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x23f7a60a2fe853525d73f494782288e3580a28073ce32589756d5e0d0a3028b0), uint256(0x14a04076a0ccf5faaa92e94b84010ce41b1c45ab068a603bfc6b72e0141ceea7));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x2139f901e0e0e2f6c67b00a689dce69f473b6865b30d2b32a8b0ae0c4ec8a303), uint256(0x2fb6662bdc5cf6bb660bef5f38c66e5257b34bfe983915449fdc85470fb8ac2b));
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
