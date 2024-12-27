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
        vk.alpha = Pairing.G1Point(uint256(0x2203250d94d123403e2f7ad18754e93dcaff7e2b574596c2ebfa11bf8363d69b), uint256(0x0a8a5c877deef3ba18db7503b2897272f30d8f33df006a778ee12259187cf9a7));
        vk.beta = Pairing.G2Point([uint256(0x0fc8e159245cfe2d5dcd1452eb26d682a09d5c2329ff3f106445b300932b697e), uint256(0x1ff54df07609adad6ae3b7cfc11eebf492ae177c8bf098c6585d6c0c3ab9d689)], [uint256(0x289912a4b45200ea7709ee8e49da753ad73897da1ca8d06a050de249d8cd2370), uint256(0x0efd2a974d955f37898fbc6d9f4e1da12c2bc6e46df02ad962f5f0fd72a043a6)]);
        vk.gamma = Pairing.G2Point([uint256(0x20c3ff3b0a038e4f517ee5a93a8decf5f10dc95399d0050dfa4ed2da45b17716), uint256(0x1a7730ea130c7f399082316c8a44efa5cb5691f8634f6cf5ac1a5dfac7655803)], [uint256(0x0a510717769b7e6c661ef3036ea032719faefd86d554f848839ec2f64d5370fd), uint256(0x2902f9cabb0cfad619a5e114cf075b6c4331f5e961df75b60fa56a8ca5c86597)]);
        vk.delta = Pairing.G2Point([uint256(0x21be2a704b4930185dda0c0c987a9451ca5a0e8fdd7915e5fd8a7f7f4ed46757), uint256(0x26de871e1793072faba595690450505cda653696d998a8982a62775a195fb369)], [uint256(0x12dc4985a2b5e6020b36052c45180f6269f4f2b1c5c67ea71c01d2fb3b2a5c1d), uint256(0x1d440ac72e1dcbd06e2706334261b6ecf856805ff2a9a841cb9fab4ce101fa65)]);
        vk.gamma_abc = new Pairing.G1Point[](30);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0f1773dfec73048b9d7e359296fa2b80794985e86c31017db2efbce461d26682), uint256(0x0b4294fe53f2263c4cd5bfaf14943a13cd7961aaf662b6a20e614c90797dbd23));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0d9a64e1e54aa84c8cdf88237d2cb0fd5ddfaa4aac8ebf4df84f7a5c676bcdac), uint256(0x2250868051cbc32548964e8d98f4205fbfa7f76f5024cbc79e699517f905f43b));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x22266a15563c5aaadc9702bb3e0722df02d86178c35a93ab430fad5d06daac21), uint256(0x29778633742b998252c647ed9ecb5da4a89a4c88ad5c8edf36dea736c2b64ae3));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1eb17263c1ec45071f3946aa7d9341d62a9525fa9376239c87fd62ba91357597), uint256(0x23a3a73ebeab72478fff385fa6d550c8c07927c13465977ced606e77909ca57b));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0b707939b352401bf956b4b931ba78c570c58ab1e9586486642a930cd6070a6b), uint256(0x1e46feb224377e653ced8ae6ae82f9175684278da25574d0a9432355e318fec2));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1b789cda45030232b809e181d31a55ffa85cb0e4294c3ea53aa04d079851f9a7), uint256(0x2fc4f1f6e094f515a28e29bcd4d565ecc3055fee5672231da160c3836e76fbaa));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1ff2b09cc8ea9ec6a15bbca3fdb001409f59ea0c0ee81135f354e402512e61d8), uint256(0x08a687b6a3e7ee7e3200f12f2fdf75d1c195c455350fbd67becbd50c76109cd9));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x069ab0cad71c9d3615a9d5a060e2af391eda7c85aaec529bedaa9c448901f6bf), uint256(0x15857b5e2be922d37720c0ad8248eefaf283aaf9727c234595f9c5d855b355b8));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2531cded6a0dea55ba3dc9c23b4d63604d987f85d3c3541d405dbb4dbfe7f04a), uint256(0x0b868d8a687977008407a8f78c1216d81cd91f111d22d6876014d5615571c37c));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1349fa30f3dedb11cf711a3989eb14237603411cf91c7e18136593b15274d543), uint256(0x1b5e2b6eb8e600453ab8074538261cd214561987859402d7451f6ce922d40fa0));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x07506b7fb27b0662f72dc3ae0bb8b856a4f10843828f36ca628b68425d8b4c39), uint256(0x030d211067e4edcd3caac34c11ffb3176bd09c864593b48c2e4254f79f67fbc9));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0fd70399be47107970c49dd1dfd71beaeb8b003b6263b099e596c22fda54222b), uint256(0x07e22270c2723ec4a6a87319d4a1e31d2d3c275d5d58d2d6c90b89ccd7396fd7));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x087e48fe35f69921018ea4a8d8cf61c2659114fdf335de332b5ed81098e3e095), uint256(0x0474a41a0d261e0035af0211e7c5b2a574d5c4c3b9511102baf58bb046b7362f));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x120dacd1628fd8cee3dbdb3b9c8cfafe7b321c28084bff3f49f51e938a06b816), uint256(0x046a428b16cb5fba2219044f7176ac1353128f2a700ac8dd3f8cfb413c549ca9));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2d31dbc4431d6c3c7354aa509a19f2c49fd1700bb61c4ad8eaad32e6e977d400), uint256(0x26c33e4541acb8693b68d3cc04d976d27650b8068fa13ae61ec8dfc33d2ddbcc));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0ae38b3054f62be545f9f9ea53c2a0725cb78c18103cc0e1f9c96971cf37fb1d), uint256(0x144fd2fcc448076a7f16dfdfc95a5bb0972f209431842c70d9ed7f70b9aea7d9));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x301ac26382542ed0e7f0751dc93e534876755e738239776f7fd95786a6cd093b), uint256(0x2e69c193b84d7fe86e5d0044c6c7b3731a66bc13efe0f6216e18f10cfea265db));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1fcedc69b0a0f94370286013ebcdbf4d579a8f1d19f457fa9675b8fc7d8d7784), uint256(0x0d8436fd394e46b34af8de1e7f849d592b3cb8920e6a48029de5db871ec2f634));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x21f9a4cce27e3f5e95165e90ef3024c7c047a30b5bdfb78ad75fd12a4a5d0997), uint256(0x0b46685e1402512030bc92937569383d378b08ae120abb03ed5f9759f5e79626));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x24eb8504e020ca7837c71e0fe3c130026fe9593a119363199c60ca53b351b8d2), uint256(0x21e7a1f9b6706c58040b218a5099c2d054d392b5a04c06dc957fbe4dc054aa7a));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2b402ba984bc30d310b4569a198b179346817d09df5c70d088ec85aa4b46da2d), uint256(0x1dc919841bbe93ae64badc52f05a6d2e4fab3fbb766f1e3b5763574e00d0d7d1));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x02007bad9872a1e8890a5b662e028fabf4106b0006f5b17188a98e877a80fc9a), uint256(0x1e44e900c2e80a34cbc7f31e13343a7fa6a5956cd9ec61d8b7bb16c41f0273e5));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x1430bbc7ffd9546cbe28746317919bf917bc9cd7b0c331b1150c9915dd4e57f2), uint256(0x2aebc5c7a12c3129df7142a720f3afae251d244d9d96f77488826a46c6017d3c));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x09bdaf42d6f8d9bc67b5125b78d3a37e3b4a5e7094d36e9776167c2e28e95ad2), uint256(0x12eb9ffe2a29d54190de5129d7a13f1b2545bb6e9a7a13e4a59bae448d60fd8a));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x1618846e46aeaa62a6b4cc83dec6dd8207c35d11598ef60b742ec2bd4d6810c9), uint256(0x2acffab7a131072ddd640dca212fd47ae3d02a88f384aff6e1f0a459d1c7c185));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x2fd198cbd9295fc1b675e0e9d37c5ac4b25e3cfb99f519727c7e586e1cfb7677), uint256(0x1dd37f1c3a7eb6b79a023af6d4dbc41a6a62eaecf38c2362beaef122f6e4700c));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x2e4df3d4c8dc85daaa53bff1f89aac53799656ac354a8ed53d4ea77c2e03f14e), uint256(0x0dec6412833c43c4c2ce0138577e002f736173ac4ac3d6e0e7d834d6e4045453));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x02dfd43ec8451fe24dccaa344bc37346120bf279200de8e0ead743aedb4b731e), uint256(0x170c8e2557d4c5edbea79a0b696075e8ec3b3e3942c6a1280dc30ac8a1eb77fc));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x04fbce010ed62f6006fe4e819a3618d0d1ceec68e35cfab53ba8241eb5cc0161), uint256(0x06f07173692ad98191ce81586ff6d29e9db1364857c79502b5ba44ae1e925af9));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x0b32bf94cef3451b3bafb2881a79bf744af7a14b2a22f610570c276f894bf0aa), uint256(0x07ced252bfaf04772756dd8d27f05969a47463fe30cbd6d12393c2ca9b222b53));
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
