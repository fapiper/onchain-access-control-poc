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
        vk.alpha = Pairing.G1Point(uint256(0x150c460487cb1d2e1d194653078eefe0143e1a7d8ed3487a8828b9c2654d908c), uint256(0x18c6205360ad94f53f29a5b3ca7d7692d3afd839bc564029688ec4b7618fcce2));
        vk.beta = Pairing.G2Point([uint256(0x15d31f6df5ddbc818d682d119a63037bfe997ee6e9143b7820f2c9eba4cb78ee), uint256(0x23d30425f565e7e06c791f73b5fb98766616316c39a38f708e556be5c6dbf100)], [uint256(0x2711bacea31b60d15661fd15a81ab9631edba54be0b8106daaf88050c0137171), uint256(0x028461e090205470fbec6b5ba2b9f747f5d3ee00adcc446d78ab3a692a65160d)]);
        vk.gamma = Pairing.G2Point([uint256(0x1a0e7815ad641bd86370dcaac1c9e9aea41c17efac92e720e57ccf83c4e32e38), uint256(0x1ad293ba2f302d89db1b105f295c0451ac2a47e752ece3d09fa7200269fbd715)], [uint256(0x0f9280e3823e6a4dc3b752a1ec427b58d5d80218560b84e61f4bc27a4f7b408a), uint256(0x22f5a7dcf7feb7dbf3968dca4efe5c09910d565a0385988f07a75238e51233dd)]);
        vk.delta = Pairing.G2Point([uint256(0x245505d84cf90021f3dcb27878bec04784ef6fae8495240147172935c57c84bf), uint256(0x22d1302cff9d51ed41e64a52b066125bcdb1c5286a847d87e6dcdfd665d40962)], [uint256(0x02e6904715aeff1ea3f0c6e756e33c6887c422da407ff449c265703fca3af59f), uint256(0x23ee15b74fa250c8f5dfd584f5064beea6b67574e48c31a32581affe79f8aa3f)]);
        vk.gamma_abc = new Pairing.G1Point[](35);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1a41d189b28acc9fef6cf3a946483f2250ab7ce46c0124f7f59cd5d6092970af), uint256(0x208977edd56c13debb66e092634bd9072fe5616408c37d17d89f8fb437b500c8));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x277c323cee2c5826b2e832f4779d95610a1501772f17bacab87283ef347226d4), uint256(0x0bea0a4061e4b73889e1bc18adfb75072ba589fc3a9d22022672b3621fa592c2));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x297f54b090ee458786765388a9c4f2dc2d723972da17218c3bd847118b268aff), uint256(0x225bb4aafe18de8752dfea01ac24fc6f6c0659194a6e5e532d59fa3d1f252b53));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x01424d7c2336d2bb8d440be54d012b53f07ed3cb25a5d3bbb0fde9c1669e2028), uint256(0x1ef423f9c80483ec8dc7ced44436e0f4d3b464c520b4c154cde12d771b72a366));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0e79dfcaa2dce96d888d025ced75629fbf885ac137845466a24b8b1de7ecce4b), uint256(0x2f3851d0d2b325eda734c325455779d0e69f02d805af7ccc7e21d817a5c68cbb));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x07ef7c666c7372343604aeacb0c25b258bf61ca330f27bc8f35cf40dbdb42a13), uint256(0x1842e62e5cf8ac347262157d5d7fa100efe0951da920b4036d79a96e814ea2be));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x20ec9ea6c8d0b9a477c900b173002149388a8bec0e95bb7c1ba09386b51748e4), uint256(0x215adf8f12c753138bfd40e6c87315fe275f3f38d1a4f0a6b608284d7a3835e0));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1d6ecec7960fd047a5c500e5e50b88b26919c30f54daba4ef6a38e69f82ac716), uint256(0x141e4897d3ad8dadf06a137499600553c07816cbb8e04689af7e5d34ef274181));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2f3417102ba0d92d83eef3dc62b168e2a66e8e86055811b6b04f7ab381d63d72), uint256(0x0216661508f33773c573da97b9be5ede3fca33511d57731b3a7e3d86f1078a4e));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0b2212fee63a90dab318421a645cb39be8cf1cb10f101604dd059c8e222c4e2b), uint256(0x229007e7f7ae80608db06452d4998b2a31ca28eef92a3bf2fb67e660d93dc7af));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x25defe1d083eef27533fd74297c894daa87d85f128755ecaefb2471eb5887daa), uint256(0x20c7e1b7f2ff7f11f601a22d686fa442940344a90b68c17479dc3794d2c00dcb));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0d43d54b4c4336424cde3ca73e6824d52fea31f3634060b4eb3e5273c5a7e2f1), uint256(0x0d7305440ea351bc0f69f39c6f6090fc97b871955ec62d27c219a7493f63bd62));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x10f6c832c2856e300f2f5f9077ccc4842d732de0ca2233e2e4731772bcf95e52), uint256(0x14be428c939d6db59b8392514fe89a64b1545059bc04f43a6cebb022e843f6b4));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x22f29621e885647d38509f3cd2c2fd6f1f7c55dc5e5fcef600ea6b95c3c83d16), uint256(0x24331fefcf589eaa005acd037d6ea177f910cf766ec18b68f135ca6a35cafe3e));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x19bfec3dfdc2d11a39d0cf04a56a424596ee6e550627b9544f2033c83cef7c9e), uint256(0x2774aa6712a24c12c516d4d37749f8b58dd195b0e117838e5e19d929b4263f4c));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x24787a6afab293bb7983c226e9adfbedc8f2f139697f542ecfb208735e61d588), uint256(0x2ce4fc7d3718dace1523d31e7e6d09eb42f7e0619b8b031f08d8187b35c07f87));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2318722a2a7c6afe6eeaa851719301cfa9e480f0317a9fe3602e8449ea67d9fc), uint256(0x0cde47ee84e90c96b1b5c934de65292d5d202a8ebecd1c365b2194fcbdc3c478));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1b8fe598c8c2cb68ddb260d62b165606d696597f5af1968716286c4f043ba7e1), uint256(0x1ea09517362be88b7136c98307a6bd760aace571e17f5628bb58cfcf466457cf));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x050797392595548d6ba9a6c999afa0ee6eae0b94e1055f6b53b41429ca1059b1), uint256(0x008f9198a8bf56a8639d63a02b9da1c68e57a879a434b99f8615f1297c1f7797));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x17f6e58dfb599d84a42a52060fa291359265eac20f584084534ca0b3100a2003), uint256(0x0dd7fcd208cb648689fd49105061c2b70c44c8a34e0be95e2f8af80d08a7c9f8));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x0af283a402dc9cab932a5f717bf3bfe913072a7dca9735b4202062bb04619fd4), uint256(0x101c5f9b5d878b24d3a0b829fe7277e845ae167b37398554d1e6f416bbe0f47c));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x054321d8f8cf3c46b761618dcf705bb22e80fe45abf828f584d4bafcffa7ede1), uint256(0x0558cc6faad6330063c8a278ac74023c102d6c4694d5a122bb47a7979fea4be1));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x15f7ed7a1f7b42c893fe8f80215e9f51577bf3efc41e5ae00781bb84b631f113), uint256(0x06cb7227c7b0bc0a8f4ca2067b34cbfdeb0431c6fc4766a3b58674837d2389d9));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x00818998bd7d9101191fee18c51768b16ab8014cd6f4c30c00cb61d364ba7e6a), uint256(0x27eb788576b5db0ea50a2c241ba16da6806a4a48bcdc186ca87f9519053e28f2));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x0d85e8ac7f3655625b7638d3e81f6bf44f588cba441bef66964b2971f75663e0), uint256(0x2429493529798f538532c1a4edddeadaac03e475b0c8ea6c015fe91eb6468c5d));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x0858cffd89963dd92991455156ea5cb10098a2ccdacdb5fd715ededf4bf43317), uint256(0x2895805b1ceee58c4fbbb7af2b33d87a4cf1a4dda60d9c09d468d4b0c26610d1));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1e2b181b86a3fcd25c3c79c2660eaaf0e95daecc2dab9e7850493ea6bd97b812), uint256(0x11e9ffb157ddf32ec61d4c9fa31ea2af2386cec445adab939f4a3c099523e8a2));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x18ce6d4f0340cd4cf62be6b82966b9c89ef8e9425c3e360fffe98abb8ff41634), uint256(0x2d0cb868d850579ebc424601168d5433a52e6964f78155f1597edc0177a9af39));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x17ac96f8e7496be269c33757922474846fd4614d1e299fa0733da5415f513a6c), uint256(0x1e452fb1326a7967b7ab3a031034884434fcaab2a03165b6cd3848b87398c0f2));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x1d1def0270d3dbd11033bdf0affc9dc6ccc384ab00aa562feddaf7c9687b4e96), uint256(0x0020dfacde9456f5d9f5790a685027922287cd2d4ec661fe20aa724f149b1ff9));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x0825b58fdc9621911823e2331b89d1485da9b7769da24d095ba298e65e692c98), uint256(0x1fa22745a92a31ddf10dd122724d05575e5bd3fbb6cb40afa6248326c057fe07));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x1f35f7f3e60ff433ae842f4091e56dc69df58da2a7115e761bf9822a2c0544f8), uint256(0x1931246c4eb994227de03d5b8339348db72ed191d00cf130a1a3b75a6b4c4e52));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x02740b4d1c9cf7f9d7b64a1be15fced23b97e3fbaf4d0897a803557da4a61a8e), uint256(0x2c16e9c31321bbbe9b938ff02f29c286d21e606b0784d82d312ea6c04d2889fc));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x1822f77dfff97e5abcc1215ce1e40eee2fe51aed665510aabb19b47e2319adca), uint256(0x27e39ba6e68a60515b9f7ed55798a7a55cc7baf12b5084833301bd1140e245d8));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x192e86700882f017c519b1760637e0a86ac268c8dd6d0e9e3733222413af6cfa), uint256(0x0753ab5767b0de99d9b59c68a152886b8f9cd504ac1f30a8dcc50ff3a1294269));
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
