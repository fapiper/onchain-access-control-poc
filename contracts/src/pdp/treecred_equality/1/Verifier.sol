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
        vk.alpha = Pairing.G1Point(uint256(0x13f6152966f3f3b7537dd9cd9619472eef43a4535046b8cdc22c493c38d3b2e5), uint256(0x1e51d6d05da0a10a5df8c4375a96aec4c629be078d9ed9938851f7e1ef37c8a9));
        vk.beta = Pairing.G2Point([uint256(0x24766014371f038dfa64901d646617777939e70c02944cf97f30578da1193eae), uint256(0x08f4ed2dcdc562d5d608aa1cdf6dffa55968ae4a4c2ccd57183808766e276336)], [uint256(0x1f9c5437e6e4666a5cecfee8615e331ee8eadcb5ce5acb1a68195eae3559d6c2), uint256(0x0f18f19cb0240d0f19d26685301936eeb868c0c336b13c3999965cf2ced6dbd2)]);
        vk.gamma = Pairing.G2Point([uint256(0x0d1c6b46532aede3bd50d6d0315878f702716ec410881bd015b999feecd58e12), uint256(0x0a5510804629628cc41cdb6c75db2ef6090b9262bc5e1f2c371d74f8b6717b82)], [uint256(0x10e40ca36b05a983cc69e5f667eb0b8e591b17420df17e59a75e957d05953c7b), uint256(0x2644cac17eccdaf748c308578b424e3cbf3b4039f671232b9b896fdb9b80a8a1)]);
        vk.delta = Pairing.G2Point([uint256(0x21dfec7e5890b6a8c46e2eab0d3f42f3fd874aadae8bf804998c31287f69895c), uint256(0x0eb7dc625c2642e39b52dee88bb8828ff37e2465295843a57872c4451ef6ec38)], [uint256(0x1b53f468ff87d4a40395d808ab684ebc25b5b01df71c17a0f26cc683c29d843c), uint256(0x218a905c0f8f569c6689f4b467a4b7ea8830c52cb191b126f58ad291f0eecbe0)]);
        vk.gamma_abc = new Pairing.G1Point[](30);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x21dbb53e5e8d7cdaaa3ae077c1032e9ea03c538782685bb69d947975b6627b2c), uint256(0x043378dcb120525b0eda91c7525a4a31779a9920910e73dca5c250b4d7a396e9));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2ffa670a75bc90ecf8a34b96fdb2f32f19a54fcc09ccfafb3007820599bc4497), uint256(0x0003a116821c8c85340aa0f760189ae986d064f34202b045c18be5a5f6afb8c8));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0a819fa7385d424d7b6780683e9e023302c2c4f793e74e2487d4def988be7551), uint256(0x0e4fde927dccb328d2895859beb48e56222c930dba2e41621d4b3ee8c3286b6d));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1264ccb269b5de72ce3d9886b1a3205d6e477cb4adf38973e6d4d421f42df45f), uint256(0x04b3df62a7ebd53b6ca98892e31c9353889f964332f6af7769ea0b0f65ac9762));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2f4cc989f062239554986c3c4f5c8e97f77bff349a81a069cdb34089b2bd4e8b), uint256(0x25ba4817ecc7341c343a487ba13760351cccd6b0c5e06781b6fe0bfc03c7bd91));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0d9b92f6684a85e5d0fa598d77a9b61794dc34d131babde7616b0c8f6bbcefd7), uint256(0x26364a7d86d5dd89d930df20a33060ac1112bde12da9db9c57ace725d594e707));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1098ac187ed309664853adda39ca82b5a06ca4f7e2169fd7bdb4630ad44c5bc1), uint256(0x2759d98e51d7610092052cb0cd46adba6d41182b10bd53e3d6a79f95518ca225));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x01ea860243d4b15c443402b2b318c850b2c73627e4813ebaf254483ed4f9cdd8), uint256(0x220266c7e6aadf2ddf5fa94008a4d3a1c81124dfba9eaf0400eff7a2626db18e));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x19f89eae6a7abd57fe8b7e9352783b7d997578729e680b51f50f1a683fdd88e8), uint256(0x1b68b80c9686f9c9b0ef05159c7f9b9b4c2b10fabb8d0d4facb1a8382e0863eb));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1182685fe00613c8487ae95b29f205eaa22d5c8e2a7a2b85ce78aee16f900332), uint256(0x1369374b430a02a6a41e35485ce41b75276a2c2efbb2d2a08f26e8963916a98e));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x06a4f1e1e5da2fddc4c1ff095dab04531724255319b8fc054e2197622d7c5165), uint256(0x1568ab2166a0c3e21b4591d438446e95b8bc7ab69106a824721a8154186f5b20));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2b701d1c48bf57f394520a2ed5cc95283dd474e2194ac2d1bea51a7d4afd9c59), uint256(0x0f46d625cd89fbbf8d122dbbf59d0865db84349e9e5540666f9bfd4f5979ef10));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x177d19e9bb803088926ce74f71c4dedca5120ebe305326ed4e853f021bdfda79), uint256(0x2518696e4231a6ddcf8b171ee5954a6893793171d7f36efe7734454fb2d9ee35));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0003255a851ae0fe73e50065d79772852eb702f5b374501d53fd4df2a4b4bcc3), uint256(0x16cc5e66a44fa9bce4e90581011fa304d0f92b0d078cc0fe833821b0c1b33962));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x16acaa31000a30bca141d0e9ac2af9c4b49b0219be658d923ec3aea9bd96aae5), uint256(0x25258024a5cd2795d63d9407eb4b9cc9ecce713e0d529ba1808fb7f6f42b3b02));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x2921962075fd8c74854876c0bda9827efd2359b40e04bb1ec4ba5a7a5acb9e6f), uint256(0x0fffa3dcb6c5a53fcca79b11897a148ebb6d91d39a6825fab3015b80ee2e836c));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1c0f63138a49428a88a512e769227219b9178cdaa6469857004a4c3f6ae6076c), uint256(0x0e31811af48252089c21b879e3c569781842c0b3fd07b38cbf14136b1b027e72));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1fc8f54fee06f7d6bdca5bc4f57663e6882553eb0c8603f951c2cbe150309746), uint256(0x16fc87f912add726f46945ea8567455c0020b5c951fdb666e9caafb0f214b59a));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x218f86b105f0836102d8955a890e9cf63de506afa3ea976646a658edb8bb1b38), uint256(0x16dd409246756946321441152bb106abcf64d9a71ea98a446e7f71faad97de9a));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2f845ef1cb04ba9b93a2b9a50c21b6e6470ce87566ebbbb52ac54e80e3726ee4), uint256(0x01931191ac30cb34616bc5ef06421857d4f79877c93c65f105dc777631b8673f));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2be05e969b8abb14dcee78641d060be296ffbff26ac407e8f34723e8eeb44e1b), uint256(0x11e989e385b3297601dcd88de6b49c200af7c7aec95502b3cfc02039b5b48462));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x19f23a07024f5a50ff9aca66e6c0b9f2160b6b31ffe19ec83cde6a2c4da79dda), uint256(0x26fe16d7e4df6d743496bd397f75da315578a934b462e3edb104c1259e8f7417));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x129a763afabf747592f22a569748c743c2045d2bdc7b2ccef9128983f1e67c41), uint256(0x2622a524e9d95b209640786f71395c1829020dfc770aba1752fa8987d7f161e7));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x26649502ed59e4c1d4d17596b6d5552e50b7a97bb4392db82e83c17f1750ff7d), uint256(0x1bfda82e651766a1ae898c74c4091785afef6ac8223ee1dab2c852d0be5ad134));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x12a9658ea451fdfe5987fbdd5ce5c07e97f383925135327e73d8cada23625eb2), uint256(0x263580c3d0e6a038f361c905c9b80a6553c337bb9b64124e60c01a10cfa5988b));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x1c727a79f0890c7ca42cca85c1b39f5d063d7f119e71d9d5bd7b1122c8cab1a9), uint256(0x27c1ebde614299d59f443d0f1c7c2efe9aa79920938ba335b54b4f0a737b1663));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x191e782871747d74b2cdcc72412ef093ef4e630ca020f6f85f04a16b86843fb7), uint256(0x1ee5fb91d976006a2d3330bddf8a9fdf81f6ddf03ac89d0d27e3a1551d6e7fcd));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x1e21f470116e40ea7f9656e619abfce4b66f13137f570d150003fbfa48e4585d), uint256(0x2d58b555d500810de1ae675b078cda5a58c36ee8139087aab3791fe5de6c9a4b));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x0d6b0a5162eba9eb79d66915634b6e3bd397f779b684a469d22667ec791fde8e), uint256(0x2bedcd2e23f4d9c18e55ca5613e17df37f222b2f752723c2d303ad50c93ba5c3));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x04dc3bc2170be611c77af35ba5b8d965d2c0ff57e729c6825a08aec5b7d26485), uint256(0x0c3036567184335f35b616eec8bfdad21b9fc522c1b7b7aae410a4bf3aaaa11e));
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
            Proof memory proof, uint[29] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](29);
        
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
