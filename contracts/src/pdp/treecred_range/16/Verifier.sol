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
        vk.alpha = Pairing.G1Point(uint256(0x1c1205e5d7f00783c3c254468cfd0561adce536fa02f5c186e384fee8306ceee), uint256(0x022e9968f410613805243ca342d6882658cb567455b4ce7b2c3fd0bcd1cf5a8c));
        vk.beta = Pairing.G2Point([uint256(0x302a45700c511fe1f418fbeb5a77d1f8a89190903f2cddeb8aab6e94cb221a01), uint256(0x1d2acf6ee8507a47c39aeeef4e1082e0a1d738da0b7dcd931acb5f3f623af0a3)], [uint256(0x06665016e00e5cb94859094e535ab8243439bb133890af35df60a4649baccdc7), uint256(0x07a70b0bd85d3a4136383962804eacc7b91196373bf9ed28e27bb9f1566cfcd9)]);
        vk.gamma = Pairing.G2Point([uint256(0x2cb309e6416d658365e47a43e2d8dee5e33d663aeccfd66d4f0c0aecd6d28969), uint256(0x04b869edd8e1a42c0f5a84a8a6a10a0d832b0ab768ecfc2eaad9f6f3952bc670)], [uint256(0x1aab99cc1928a7cddc21f979f8442d4a1710531517916ff9abf73482c87d2850), uint256(0x16c79f3827609604e0e70f5e8bc2a074af80bdf8a728c0fc2f8cdff4b557d1bf)]);
        vk.delta = Pairing.G2Point([uint256(0x055c3bb20d4bc99ea7d803f9dc220bcbc27cc7739fbbf88457ca6553ed145c7e), uint256(0x0343f456257e7ecbe2741e880a33da66af737843ec8cd7d8bdc9d8cd08faa22f)], [uint256(0x00bf1f8bf1cee8c1415ac3a8adfd86ec2d3310cb2d404dee3847456530f10f09), uint256(0x24cd4b28308fca853026bdcf3608aafb5355a977b8162127e2ffa98109509f20)]);
        vk.gamma_abc = new Pairing.G1Point[](60);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0c3d452d26df65126d2e1e9e61a29274a6fb3ed8e37aa64a4b1d13375de06039), uint256(0x29da70c9d3ea3f760760d3b3ce8d2ba7dd0f56398c59f30b7faf10e4fa4a0f00));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x21bdc75e72cca181adbb5f47875e174e9055c244584ef55a60a68d8f989ab4ba), uint256(0x296e0a000d913d1962c28d00d6426c23d9f3498830986aa84803e5435ef17042));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x22a693c487de7c3b858b0c9e47ec4cad46b7e0623a6a67197116a70f78e76856), uint256(0x1e7c6d9ea41fb5dc8a2dde8d23f5a1f872679054b92f7d16acc7a2432f66e337));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x13e907d01bfe5aa0df576a3a4801f7bfe834c851bba4d7a6ac612675b84807e2), uint256(0x2d285232449090bdad3989093b7f2c9b05cb39c53dff8eb33601caf6ec07e2a1));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x187439edc99fc1f4b2b1ec234696da31d5c7c27f3b0700a6b030f9d94bdcc525), uint256(0x140fd2595d0dceed8c4a5b9304a87d8f64bb8cb98845982464294f6ff8c9430c));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x23bae57e53edbea2c0cb8d9cf9f8cf30db52c187645cbceec1c3e7386f1cfe3e), uint256(0x22c8a43820d7a77df5e58848280081cdc49aede84e25190c89fea657fc218b15));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0eea7043ca8c1fff9ae197551ad399248066f6d55ec02a6a7a2219a20a67ebfd), uint256(0x22e7fecf612a933b4145a67f264c6d4a187e56da35a2d1a736572aca5cbd1e80));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x244279e6accc224660dee43156703c9cb7ea3d58e66fdb51569659543f865e3a), uint256(0x24fe109b5548ee5f8d9882f4270499c2a9f5090db0fa79004393e9671769feb9));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2df6b8a601c6d7eead94b66f8da99b34ca1b610cba9bab694989018d0617b6a9), uint256(0x15d50835773f919e23abb60f281096aa2d537dbf39e1558a4f35bc782202fa87));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2fa1b964bfb1784b8fee81f3e5c1ca544456bcd9c778faa4cbe1ffa3b52e3dfc), uint256(0x16889f6ce1982bfd34a42e843d75c7059d2a25ae80d42f7732ee0355497cb2b3));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x01470734db291eac317b49017ae98da3aa754f9628f6b03d20de6337de7c6165), uint256(0x133476765c4a93233c688f4ab452b0804e8bda37bfed96dd371450984521f315));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1f4bb04b7b5f469fdcd3a27f46a83fd20bf83983921a313946e9fb069849509b), uint256(0x0ef2b7c5e57ee47645d7c00a98667bf80de3fb41bbec3bc184a560d64292d0ae));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x263dd2105b9b703ad9e77b02755c4a6ed26e1e700c980dad5b413211e92763aa), uint256(0x295623a3cf7887477da8528ae74bb9275e3cbf91eb088601b242a1a69442b7fb));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x095e0cff7c3d8a5a79c2787f71e02d1de6f3a9a68699092ce073c2e74e5e344f), uint256(0x091109691f0f080da4a4843f7e09e40521e04e4d4673cfb6b13fd5f7a276c8d6));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1903c86127ffe52c4c6211b97614c0b21e2336215daad2e56dbb30431940bb2b), uint256(0x018c2d063900cc0ced34bfcd67dcbb175f05a8215b4d83a331e318a95cacaf14));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0cf86d6ebc6b95f40ddb7c53acbb9a9a85e7c85c3e9acf04c72405744608340e), uint256(0x2df0590df4cfefe4f9ab6c5220ab826b425df9b3bc610da586a26f67eb3ac388));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2681ec2807cb319be5df347b1b5917cefd6f55df9d1d0fadba956cfdc48ea104), uint256(0x1f60e30746ed637c2c461ce0fd6cea0435479b1d0a0bc8333e38322913f52e4f));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1b850c7653676869162dff8524f3c6f020e0e3b336a3b82998319c8473b93a49), uint256(0x1e27f6a299b6b0fb97c840328e307102f8cc5e617c70dac772359c7b2125757d));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2e03beaafa3020281fd5ffec923818ab6cd4f6e131fa254a5f54241340da25e5), uint256(0x2405ae697d53108dfb8c352331f2353965a11c58f00977a93ae5637f704ce33b));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1bac6b7bbe4cbc85fb63f53be8978c4d6dd4dfbbe0f14ee6306ae5e31f685c95), uint256(0x14d6acabf08e8b13acee93a33a2d04e9293710bddad055356f85770912f731d3));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x1a37215fa6a2d37b5663e4f3b3c505f016bb26f8f4870df4f6d1102fb65e3647), uint256(0x0b90ae259e5d434e1178cd24896db48b1f0f57feb93914ece4e188a3064c8714));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1cfdd398636d09644ede24b0918d8dda8da78c500b9ff4ab03af9789726ba684), uint256(0x06df35930c04043cf57b7e22f0766399b2afb200599e228741eea32fdb3f825c));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x0d9e9066b2f38e3d5adfadd091fc15f0ae5f6e93c3830e0e13cc2097a5dcf4ed), uint256(0x0afb5f28a03a607955464e803460ffbb49aaae131af0d31e1e0571bba9128762));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1399a6f7707c8e48afa2608fb25faaa091ebed277d4c4dfdb9b3769685a7df70), uint256(0x248fbd3a37e717abd84ba9a7b131dad4622bc1dc808ac6f8164eaa3860fdaa4f));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x27faa1dc8b4949a73c15118b552cc414699da4ec78a6b35daf51466e75998a66), uint256(0x26049853eb3ebabcb3597893bcbb2ffc554775ada42e51dea681b7aaffdac9aa));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x1322d1fb2ce4dbcab848ae57b0394a04d759c7b08dae2b2059808477ef81da1e), uint256(0x1476f54a548ff89302aee35037194f127b7a58054c9af4614ed11665d3a8cdd5));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x204f3a0f3931934d48c6f3d1d49d263d7ff91174631c9c0b61907099b462b54c), uint256(0x2eda4afe41e8f2ec308a401f85bea830f0e126440c124138348da8c18ed204fd));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x135b86309b176e8d04bf7e56ac37f35182ffe96fe35c64f2b0c1b6ccf0a658e7), uint256(0x09885ed4999130b6d64d91b98ef98c9492976f5c641d6e2dbd2b027db78cf40c));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x160211d26f52ec9d790fbb11ecb61505d2f8840c5dbf20549478a4266ba2193b), uint256(0x22464c34757a160dc3a9157944050adc8ba025277c657381640d1d44d707a519));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x224ca488ce69d7cbb3152f5bc585c826bf03220fa1b0017e09bc89b6a36ecfd7), uint256(0x21245dd15218cb4098042a1a57e77ff138b0dd019a5a5f0b86549a249210e9c3));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x290f64bb96c158231a1cfeed8d8934aa919b7429e1d7252e581408e038beaeb9), uint256(0x1b0ed299626dd4d6000ed9ec272b1714b642e098ace5845fc65e3bb6a6e2eadd));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x26081394034e5f6ce76446c8c232a7fcf7b831a79d3d097d341095fa1def0d5f), uint256(0x1758da5196cee71e1b341858702c037720ff4d63270112637a79920a9737bd32));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x0e575ce1c3b7508197a5a6e894dffc1a4085b907c47ba4edadb1cb845c97e6e5), uint256(0x026c2b6afb316a62e02d7323a40c5e1b923f1a651dc4e6fda4609c00c16f7e4f));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x0923e58add0f173806cd5c2c9767583b0b9366500fb67290db8b9d39c8bef213), uint256(0x1d3b543377b795f681d0ea47b881373917be317dee672e5554278407fbcf9adc));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0e7019e7ea8ba3b3eec742acefe1bb26abb16dd5183e8055d14ad0d095d8b51a), uint256(0x1d238298ef5e0effc3e941443fba500cb5f7c5974ad3b4961a83d6ec58f15a9f));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x27b424a0cfef0ce63278174f8ecbee86c8d4560d8b7a7031c085059f95f78d61), uint256(0x23ed3a3e005c908ed658d584a575223bc8b37b31322a4d9744ec6b408d7e4740));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x0a2086a18a2628be93847bfc897b0e7cc22eb35f6e408892ad1a9735ecebdeaf), uint256(0x19ad5105f3af3992e07756bc4b46955be022a7abee94e0e98cb8882fecbc7b5c));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x0a557f6d84ed2f52fd911ae82797bcd9fba1b2d5bc072cbb702ad4f790a7b429), uint256(0x183dc72d3c0583525b03b13d561dc4599ca93b935e6bc0d74b27fbd49f622532));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x1484cce0b6f6f032d4f44ed95b89abf2a510f21cc664a6ba472d6f007664d4d3), uint256(0x00d66e87a19d120a93c2babf4bb0265b0f2ccfe98ea4d2bbbf22b00c87f4c961));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x0219cee96e4725a9886da140ff4044f4a383f1c21fbb519a28a20ffbe551d458), uint256(0x0764baccd35de8247a842dbeb8a73cfd9d4fa263c1da9e43771635faa51e8d77));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x0d74d1ca399b4501830e20fb1579800a86a76db0e7b12d7dab81cd057a25fd3f), uint256(0x13d49d6e28e1e04dd85e45c1a02822456ef022641ac554f73de521d76ccae8ed));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x28dc9b8804d9808fdcd16a2b6c9b1201e46113d10111503e97621506fd2f5d38), uint256(0x0a282918cb235a75779e217ee842b505c13714c84cab669921ce30208bbcb65e));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x1a00040e64fbe84ddc642f6ef8e4a103281bbb5f5102f4e41a1697fccc2dd874), uint256(0x0e3eb5447f8506795aefed663f92a21822b28b9e8cc9a141409ef548bf07a941));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x20734a37cc5ca2c75b3e19c1584b69d11d0a24ca1640ef7bb6bef278ddea61a4), uint256(0x0841fc1343f03214f961a538292a2bf3b5f5b7d17f105bbaf6eab056029dc71f));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x0861dc81abdbbb817ff9dc908ea32d93c4757d36718b3d5a319388cdcd9e6bf6), uint256(0x001265f553b64b6693ee03cec67c24e3963ef8bb21f4e4c305cddba0c702c033));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x0f607cef4dcff13c32362c9b5f3d67e8d26b7b4f673825d1e0c53adbf5e28fdc), uint256(0x0958d4758f4525d56c708558e6e0807fb997cc3f6033fe4ca518316417b84a8a));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x1a8a839aa23cbef26893e9c45ccef3a1940f3c37147307a7aeb343354ee1939d), uint256(0x2e847ac1a4594c8b8875db0d9cfd999ab8deadc98dc09b8c71d24fc2e8016df4));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x2a670d06da01c48614883589587a866ae3c63a2d68bfba7122cc24787f769c9f), uint256(0x1eb26e5e14d6bb33de08ba636ce7f902c8a9502e582e416a3ccc995f2c1e76e8));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x16bced8ec198450f2095560d1f020324c855c2f82209420e99311a6338eebca4), uint256(0x27c16bfb5fba18f202c447d5e54e052e47e9bb11087ae81c06e484c6f175613e));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x2060f3838a778a33c35cac9ca49245465f76091d3d26daf44b572d60ea9ff002), uint256(0x05690d401599ae442f7c425145e9a4901ee818986a5bea1326c3f5d040aae1f2));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x226f7fafdea28aebcbd85476f5bd0be47623b3f85e14748aacd2254df51fb5b4), uint256(0x250da9d0b807c98e4d0188967192dda2e2b85b2ae12d62377fdc824e58a60ac1));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x1fcf6b211f3bff5f099a0665ad50adf5ecf18fcccab95465b096f2204a99b341), uint256(0x1e947a46a44c8da9e65d5f6cb236969a95ebdb80cf6d715c1df793fc096c6065));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x275712c3af8659ce6b5103afdc011339d027515fc66ada9c7eb4b44dd95dce2d), uint256(0x2ae7250fee3650a279bfe468e4b66786f0b04be9bb4c96722be70d843c56fb66));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x2762018489fd789277e5ff8b1420cf4fc1f3a6379fce32a4239a8eea59620d9a), uint256(0x2d5390d61665c34161898631d2729d36134d5f70c0459a5c180a5743863c01b7));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x0d377ee7b234d92a62c30150b197d466d7dd163df66f7b10d302524f8a7e97b0), uint256(0x2bf73755414ac19068efb7be3f8072a81ef1f8704179718104fa8289c2a22842));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x13e0be2239ec10808063b7cc5e0563be9f88f58771509f808a16b02b04bee742), uint256(0x2c65525a148de391369f7b350c851f44fa698072676d43e36e8ad64d2c7efa79));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x0ef0c072808a4c6853a31a2352523048fbc1a47aa3c80a838e1026d5084b31cd), uint256(0x1142f6af93d6d49de53925e9d83045250eb64a2b3285fb8cd448d3fe00c604c5));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x0a4776277f4375294683b8fcb4b7d61afbe5a271d0ad4a7cd03ee2b8692e4240), uint256(0x0bbc4b31ca69a925365edd99a225c589a24e4b0c5c2b43a93ef8a116ff30e952));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x02cd65ae34c031ded1d53636c90b65a281848affb7e03e833953adf9a2bd5924), uint256(0x28fa68cdc827e5c3093bb9a84a87ba58f156cefe5ef2baf8efef76d6a38bba7f));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x2010e6dad8994399cb001b67300465df0add092d097cc313b530d09d905309b0), uint256(0x1c4be9c1f758c452e319c7f9b9fbefa188fab3aed8db9ea12b36a81f6a175702));
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
            Proof memory proof, uint[59] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](59);
        
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
