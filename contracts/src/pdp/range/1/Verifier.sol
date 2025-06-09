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
        vk.alpha = Pairing.G1Point(uint256(0x1f901c27f2bdfe2f773055c887fa52c6d457d65eb3a1a037e64bddf9b9900f2b), uint256(0x24f4a1e80347d14955d8c1b02018e3ecb6d4d52782c8d2736c6666c1b931f8b8));
        vk.beta = Pairing.G2Point([uint256(0x13be7242dedbcb4e4b02aca13061418a3f1702b78f5c4f9466004eb52778c586), uint256(0x08c7b6e2488204fae4500416ec04439554aabab8236a40aef7a3d7575b6f75ad)], [uint256(0x2a1026af7aa870913baf11c0966615a8184e6e1eb1ad1f18b08bb7e306af52ca), uint256(0x0e72f3432d0c5c7622f50f5d848f1510cb1aa4bcd488ba22b594ce73957f2cf4)]);
        vk.gamma = Pairing.G2Point([uint256(0x305c2f66c1c29eeb46074f22cfa41b50dec0562ebcb895c0502317ecf04e7b49), uint256(0x262f330504320a0d3ea6aa008c4e59650c139de22ff328babb576072b2584aad)], [uint256(0x164ae37b79250bf3f34b19f687ecbe79817f8ab0019dbe872376952d928ef595), uint256(0x1c40f2b92bb75a6ee77d39f314f1bc0e5af74f2b514581cc216379acab607efa)]);
        vk.delta = Pairing.G2Point([uint256(0x221d7db1a35ad2227341343392a134ab30b7a52ca2b4418ee84027db819b01ee), uint256(0x21631be40450afc57bbc10c94b9d12df3208cf29a9ee8cf273ebb2ced778d158)], [uint256(0x17f2d2c361a81c0973dd6d743fb3af18aed0ed40cc6af9c76fe514813a66888f), uint256(0x1b1616400e3021b817229e508dee55bbf0c8cdccbe6a7ca82ff459c2fd4951b9)]);
        vk.gamma_abc = new Pairing.G1Point[](35);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x273c94cd8b25428161385b85a0f789e1be3ece91351672a62e64593e95b7b65f), uint256(0x29dbbfa6550bfc1028ddec5d4f4f211bb30c3fc44371ba56594cfd869c51beca));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0e157f3b91c199512b9fdf42c1f51b3ee2c94319048a1f8b866965828f042f70), uint256(0x2f74bed10d42872943bae7537afa13d97683f8b386df71d738c4b31739ee8d20));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1f3845210a1cebc0eaf3e4eedea8fdf0bb15c572814da8281877e6872fd08828), uint256(0x0330232ee192d1a060333fb855c9038c3835a398fd0ec2cf956c5fb57ca444cc));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0aa667e104542d33111510872bacdc6d391932f4900d03f2f177fef4d7649de0), uint256(0x0f22cd645298771ca23f26dc9811576c75095c7cb88ef00b1063f20dabe63441));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0b74d2e657f90f0f5feea37dac598120b831993a99b3a91ce083905d8fe7b51f), uint256(0x01d42373ca9f584f9696f56f259af5b405f9e445b3473d66254090e88eff501e));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x124949e0fe6eb9fee2474514584bef68f756ede38eb563ef9e62537c0175637e), uint256(0x0d398795aafde0ca6250287f56e16663892db9afeb0fe941b776c68c637f88fc));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x085cd9bff2b6b24ba3f0be982a7922d690aa28ca6624329568f965382c1da7ce), uint256(0x146650577931737ba769047ee152bf142791d7bfbd4ecdac580f29c69710287c));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x27a1bb5f9c2ebc38367ec8d44c3cf77c25cf959f439b2f519cc846092bd0afa7), uint256(0x1ab201f63cec2f0fb43e59fdd7586b6088e4bbd9449895fb1bf67964ff5736dd));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x07bb0c24af900e14f96b3366631e249bfb1d803dc31c2f7a040ffe9aa112484e), uint256(0x2d8e0e316f2c6e77594ef2c403e5e2cbab1e1d44e4e5d8f0ec51d2f954059d03));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x145e172620083302b661590dc380ac129d3415352e835f27ba1c88568ac13f8a), uint256(0x07e9f92acad199eb7cf62893b2284401862f562f454f584155cbf117a332cc81));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0edfdc2e4c7f391f7623d3cbbcaa07dc5a433e2733b272baa25162f0d82f72a7), uint256(0x1b4a14358d24f01d0c97101303b29a2d5c8cbaff9e3ab90ea977394442fbce3d));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x280e5780e35032d811d5a4f1181f48412cd8c8e3e2bfcbbb780227bdc287126e), uint256(0x28f06a505e95cdfb62d8c1f73af3f00954ee938b6570aa8a684d3ea4c9d7fdcb));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1f72f6330517f8955bb1e0a66b48e795aa2913402f10bbe34d1b7143c93a5844), uint256(0x16a3ad044040e68abbd9b81617325e45d681c5a45fd6ac9d91651eb6e4be4cca));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2a38095d1b23755dbc18ee9e73d33a1acdb824ff6fe03bcae6be2b1faff578b8), uint256(0x02cc3c6bc0e1eae7346035f4de51e342e06668a596cd26261670c498eb012de4));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x082e2bd0bf359aedfc039ee25cf8bbb218e2fc87aa4ad5707a4f21226f54f0b4), uint256(0x1aad256a2d5c47f6d7255e6c07c06cf055b860c85e548bc5f2f073bba28087ee));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1620d283888241df012e2b562e8635b697907f65c7b829161f3b4dcfa3a3c3e0), uint256(0x12b3ba618115f25023fc4f0ba0f329256117d0f19477288306878e03f0c60883));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x276a60c08672da2b66e028b6f36cdeb36f8e84ee76ed561aee4006c485a09a7a), uint256(0x1e4ef2337d7149edf123e9bbd2d359c7da9a495267e25c0949780929db9f6a82));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x06a135703c93d8e2d2d3355af32c7faf2ab1a19b4a42116a293f26a20de5877b), uint256(0x14260b13b18028ca554eb1c4449882a9d62e667fdb50b86e316474e099ac986f));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x0a692f9cf6f85937271f4bca7ae708f8ef02f12ecc1967f782ccd052eae6a0ca), uint256(0x1325b10f187b8477dfc9702ab4bfbe8d81fde0dad560b1efa23da90c8b67fb44));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x10c8fdfdeede8d0e5616dbd275fe3fdcba18552338c9daaed2d99c2dff7843f6), uint256(0x2bf1d3b2f215d37d1193ce914beda814f7a699867d40694dbadb2f16fbe88ca4));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2e659a554a0dd2a29fe4d48608ba1ab21a77743f83960457532bdeae254f5f86), uint256(0x1fca40939133abf30bad4db2ae298f42da420365706a4769cde70b8229e456fe));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x0eb5466f164e1d1e85027bc198cd0f8f694274595f64f933dafc97b761f89f08), uint256(0x250d04ca2b98b18e27437cd5022ef8e30b605ac8ecf6de2ca0bf1c05ae0f563b));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x3013419b4cda3b48572ec7bbe975405fd76ac3b0235a4fe4f6fe46e9bffb9b11), uint256(0x01421936d54de5c86d6bb6947b69d8041adae4486318d268c9ac84aa59876df4));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x0f818a2c5afa0ff4fe2085c8abff4f776b1c03fc55448f37a5f2bb341b044901), uint256(0x28f1618d4776dc35682b91af16734c072ede22f904b6e8f8c902db054b4bb0d1));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x2dd5561ec8a7bb08bd6450ab54afbe36a363a7d25432c3ed89fbc17a95187127), uint256(0x26d7e95b64e838600adbf7df945492f0e2302868057aa061ded779e94424bc63));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x13ca1bc78e1c389e9bc55f4ff7c2551ef1620ea1826b619326ee7494566e1f5e), uint256(0x099e6006538ad793d91a17a5881ade93692a82039dc35a928a97f4879499a9ca));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x207b205b7761467c8676987cb7fdd894759275a203b13c50908249d855e96829), uint256(0x04caa04fe40705c6dba5ba930b14aa2fc80e22c38be22851bbb4cf219faee5e6));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x07cfc997691ea6bed5c524f550ee35e6d1436a4ec99fba3b693fc96a4763c1d8), uint256(0x24508511db14546f6999dc9d6f5832f4e1189ec337fa6aacd025b68d9adf55e1));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x20306d4c851c564002226ebfe2b33077dd724354c32e614403e2bf1bf0116a82), uint256(0x2d7d4afdf863d0395dd7066ef3130e59f2280b61437b71752e91bf51d9b12053));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x277314cf9105d72db5382b37480af00cb5b181866ba6a184937b120dce0b741b), uint256(0x293eea89df95e22b180238d95db19b3444bfa8ba56e3d4150eee489e2a678d96));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x2944adbf301bc69f3e400d86f5c817697a2145efd4cd23deda719a303f5bd88d), uint256(0x0024445c786173a98593a3241ec742c7794d90b08ddd4d91053556cffb4cfb20));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x2b9f50666ce50c247797f3fd3622f1a8e6ea032e45dbdb99b2854b64b27978b4), uint256(0x102b2f558447b16933cce0ae2f95cb55ec92160e92bef332e40fd6f1dac036c1));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x0bf0864944c5af6a854f554a6a89a88775a36ca63f54663569c495b8fd70d22b), uint256(0x2f2ae5e4d1e984bc77f22f6a47e8c8f99f01f753ca532e4a993dca1423997959));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x19e44dacb03fb0ed1e0d9314424d99413ceff3b981c2701403e941b537abd90d), uint256(0x081c1e13d802fdb822073dd7791fcdca3878a4535cfcbcd9804c7bd31c369733));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x255266e9482218e9ede62f14c835d4984ef0ddff37e8f2450c93ae6c186a1e2f), uint256(0x0eaa76ee345802904343b13461895b1c5abc02b574201c79b6edd69960f0bfb4));
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
            Proof memory proof, uint[34] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](34);
        
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
