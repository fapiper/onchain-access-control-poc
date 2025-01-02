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
        vk.alpha = Pairing.G1Point(uint256(0x0fa476457bf6a8df804638fae7de1946a996b0c297f42cc4cf7de8a2936d6894), uint256(0x1378e80cafc5c6ed0e950026ceb34a72cf81fb4249d93c7d668e5fe1915fc456));
        vk.beta = Pairing.G2Point([uint256(0x26e975041db4386153b1d8f3ff88f1c88140590fd3f2eddf2d7d6e489674d234), uint256(0x2d305ede3c03c2ff99a8f0e54bf46a4f5f22c2a6f9521dc99c066c4ea2adaed6)], [uint256(0x1f55ad849e541e75bab7c2fbdda6e18ff4573a7d2f76c7da7a47678089cedaba), uint256(0x0cee84258c9fb5fa8c8fbd767e6071c8eb17df9b6d61ff7f487fbe3637d27978)]);
        vk.gamma = Pairing.G2Point([uint256(0x0f1c3d64a2c90e2149f60fad4b2418eb8624b32b348df277878191fa99722eff), uint256(0x0cb93264e3520f505430b303a4f6e7b6ddccb64569befd8c01ae2e29b66aaef0)], [uint256(0x2c4f414b452e75e5952a46621ed74992a1b139a60519e4e02a6222ca04ac98bf), uint256(0x1d1d6a6aeaa2a5afa9f21d460890ae1f7f8d2091de0d9c1744dceb9673a4044f)]);
        vk.delta = Pairing.G2Point([uint256(0x2f9878dc3dcdb4838193fb3b3a843e9a233074d611def9ece8d28fd71a28e821), uint256(0x20558905b0309d8e8c29a22d8401cacda72759ea82c77085203a46b8222fb297)], [uint256(0x112bfedd17ec0c14b81e337795b7ab8d07f7f5f83ed2f07b4bf5960c4e399627), uint256(0x2157d111e59ca89bc93be92baac5f928f36520352a82e33c9a619d81d854d56b)]);
        vk.gamma_abc = new Pairing.G1Point[](30);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x225e1a6faf871be9f52706dd9bb18ae22700eda68947479aee4d16c6e0adb22d), uint256(0x217746f66dfd7e447f2254d010e16d5b7e2aeabe849a610b0842b5d285b8c89f));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x142648af2af32028cc474b363236ffe285eb75781d6340775e87c4db9ec3e622), uint256(0x0421784452399ed679a1f7d3385c6b7be8baf5cb6e86239fd77ebd76675bda8f));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x171dd4125987d55e96baa6c3a976716c070d0b4f6504320d9ea18be91ffaa06a), uint256(0x28e20644b744f3689fd9010ee773d82be3c4846489352356931ea9e0a638333c));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x087a886e71ac3ad5b633a6bca4d3c276dfe51327f4d683fce1d3429f55647977), uint256(0x1c2cc621085dff8be1c2957f43a42699e823b8a6af8f34dc63e06fc2bb39d464));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x240a1d6c1320188960b446355fc69b1e9f975450b6898c5de6af5e4a8272befa), uint256(0x2757b969ec451fa35e610aaeb32e62c299198a46a7f206641da0d7e6a584823c));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1f9ba9c82c73253458a8bf8203046e2a4d1cadf6aa03e521fe54252c93eea3a1), uint256(0x2c2b6b944059c9ce4b071d2b67185f36ef97b84714cf8a89f69168e80467a618));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x04784d129e940d2915a971e36c234b27d14fbd24a44ae9bec3cec5178834d57e), uint256(0x063b50d1766e4a41adb6e155097e82ad4308e48366972d70299cdecc8012de15));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x12d83536f937f32140341b26d15d36a4a5b560432d2213ac584322b6dd14b727), uint256(0x14cd137abb83f9f4b68ad141ecc8a001685ad19d724fd4af1144f4e21248d931));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x24c68d5512653159e8c924800ff7b155c4ee0523b7c65101d7d886df0f471c76), uint256(0x0298a410d71b8141069d6c1608de9e7acac090a1b1c4624dd57b625bec8364a7));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x10222e2d12933d0991a62e127579df5ab6e35fb5dad96f07499a66d9af6c185e), uint256(0x07ebbd82ef6c0d4d0b07e8e25f6a2ada5826dac1d47308e2c8252f21db97f7c1));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x19d7b2a0b3bd1dd17b5aa5bc1e66396460bf446572f89c820ef45e065c39a58e), uint256(0x0a548b04a68469d46eb7c02a48523142e79c1bf7a41b75ddc6af5201dd1bf394));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2dd0287f78bd43a89f6202a7fccfcc884d90dd08f007bb8995273336d0c16ff3), uint256(0x27d02e99c3a565784c1d65ee31cb84b220658f057d692ab2a1084123b5db2e31));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1b13235e36afce72e00416b7ff055a78b47cb48782a7cfac153bc40d82e5db27), uint256(0x04cc9ce6e310f01b49fd949519d88f153a2e2536630e98e463aa5e8881a1cb75));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1e6745ae2414625f33c98520753972b828bb4eb3570d6a5f4e4ee54d6a41af5e), uint256(0x1cb1f31cf0ee8c8cc7a8298a6f6834691ec322ab1f9ecbe5247d0d5ef1cbaae8));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2240ee6ba9b6cbf6d79ac22500ce68858b1ad07d38489fd54ad39eb38fe793ba), uint256(0x0f9d4588b0ce0942d752ef5c273c457cc07f721a9060de5c11b205690fb065ca));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x23d69a10f1e92d29fe54f9bf0d47ef8d5a6ef09a20c69d8b931bdcb71a5f45e8), uint256(0x05b193e1e856dd2c05407dc3fc999b6f1fddeb6a1e00d5285e07db8a94b91859));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x11b414c1ba1a995542799625ee2213978a190a00ea883870d64f57782a01a9e1), uint256(0x0fda300d2a4f38d0d4e32bebdc2f82608ce92895b395c3cae1d9f5a26c78d403));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x28fba7373fc79d5088a52cce3286279b64080d60b8f9e6351fe70ecce54ccc6b), uint256(0x0f077e039c5daa41dd3b66ffd388788e01e18f30edc52787df50ee28b4a31d17));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1be12df7e12366e7c401a2b1adc1d48074fa32299bedd0746868ffe6c55b9d74), uint256(0x02890a7dc55e79399c8d4e84ef97b23269b2a7bb88e5cbc35175647cce8a68ac));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2ba967c2f5c6bc6c7ef3128eb2e1742294d1f59d8464bd21ea55271f0443d0d3), uint256(0x1b3cbd6e18647c78ed12be3646cc820f93f1db43510a6b5e5b20eff3ef2a90b2));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x11b861c3681a29039bde41bdd291d8ade6fd56893587ccc9b3183d07c2b035fd), uint256(0x17de62ebd7592f6de43d6562714b2d4d0c786f73e9cfbde75a65f77180786b9a));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x06908a62d5d11ad0816ba3f09e9a1ba3cea231f2202cc8539fe0ae4e7afb0e91), uint256(0x075861c468a3cebb14068cf2bc0cc38e551982586af0c1ccc0de76ace8365f96));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2280d2294ff3dc8b877b85ccd586e17d6933f68a40caaf36a8699ce75532a31c), uint256(0x09af97502d675ff04e505fc640cb4c142c260298ddf5b7172cac4fe0833d7e86));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2d8f7934a8bcb487fbc69852c096345956bd37c70a3281f089f01ed50a3e250d), uint256(0x240797389f9a055630567c61c29c143d2db6a3815fd7a5d1ffcc85736854d68f));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x27a5f943d03c92a9441f536c39dd5172f979ad93188d24488431110f14b81bcc), uint256(0x0b3cba1cc8316907e14f3cc60b1fccf26a56302a3c4f74f0f1b9abade3ae25b8));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x0f2d34ff3ba169dbe0d9881167ee5228d20625f729bf6507b2a2fc8859cf8817), uint256(0x18d8bd9b4d6dfd3f84fea6c9f82545ae9a076e96d87340a8402f04b5e895070c));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x016b6a99e841c350c78b2c43a2f846f2f4080ec890745a71184d10e85fccd959), uint256(0x2d31a294edc976a0c45ab5ea7a5ae97528445191569cf9174a4f886cce3f5090));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2265bda73962fc03543d75a9ddf4e632c577aa83c2dd9548f82ad6d224647ac3), uint256(0x29a2e8f90d79274f170e8f3350659db669191ced3b9761b84cc6496b7aaeffc3));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x2e0e79ba866c869a41f5103f71c8ed5149d67a7c4f7d6c99cb6ecc34f015f1f8), uint256(0x185ab1292d242eda0cbbd0f36fe0d9a8fbdb30edff323f7c6f3749283014acae));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x0d76dcae065b98a5274f492a83b88ec4a7e496cc2b08bdeac2a32399a3441838), uint256(0x012140add89dd420d3aae8fa768cff6ff933a4a2496d51a7cf78869296ca72ff));
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
