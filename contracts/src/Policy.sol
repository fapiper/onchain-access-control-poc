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
        vk.alpha = Pairing.G1Point(uint256(0x1a7590058cd34b1757efd4a9c6a5fab4affc678b92f72e2688454d030c89414e), uint256(0x2a90ec024835ef3802bb74e4328f69c28aff5c341cb5e9ab18398f169438b21f));
        vk.beta = Pairing.G2Point([uint256(0x0bb538abe9db338d4f3aa45ef431fb76649cb01be6550e90f7a8e84f5ceb4d10), uint256(0x0e8633cc319cb5ac08906495f8a53306b8b9438ed1af1d352d88c7a8e459cc34)], [uint256(0x23241446144dd5ad1bfd4c594116b8384c529f01273f8c68b219ea7ad9a9f074), uint256(0x1b437fe4587f4ae02e8ccf08373dc38e2369e36c6487ac03f9bded210558972e)]);
        vk.gamma = Pairing.G2Point([uint256(0x05df0b694ac4ac6b3e3d7532de43396574ad0ea1f88a63e5fd2a5c84cfa8ff91), uint256(0x22a9cab99822ef9135c8ed9a310a0243705ac4233f2519da9afc80c7f0276bd0)], [uint256(0x0777c91853d80d9702ba3cc5ff86b3f1f1e4d442ba904f93d8d1daf67d66e525), uint256(0x20598996e3c61b762f1993473a65c0777d31f6abd1ea6e7b4558b0851925e229)]);
        vk.delta = Pairing.G2Point([uint256(0x22cadafd935b8f476abe1cc510d2bb697246a5c640a8a9aeda49bfda8396df43), uint256(0x255a1a9f385eb646805c9a06e32fcf1f9ec607f7da208d117c0a7475e67182c7)], [uint256(0x18088c1a95b85a527e157a6aa22b844a269122589d55bc66ab770a29453e0cdc), uint256(0x1977232b2c41ed410dbfe14950411e5c0f5ab7311dc5c6a50205687957bb5cb6)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0361d10d169f2db77200d2f75df89c8794fe20b09d6896618e6c96407727315b), uint256(0x14f54c280b8ef63d9f7644e64f690cba095b59e56fc5218f4dbbc519ead0ad6e));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x247e31626009b26e78819230f0db63525b041bc76081b34b87d407be484f6846), uint256(0x18f8fea6bd1d0bf781baab5251964ccc8c1ee689f34c81a896a9aa8f7eaee7a9));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x25729f7a90e1d0ea4696b5e26677a879b6d7df18ecc3a93900f380cd37b9e7c3), uint256(0x2fd458146b74f720138277d0c7dfc6b9df8b4e127f7d545eacd072b5852f755e));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x24a698fb21a26e09a95487112fa422a510ea62eb2854f6a0d63c32e5aa3ecca0), uint256(0x14d1042e51576bb3a4678e96a45d9703591b39674f4acd490a71e2c2a1a8de14));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0f606bac9bba1d2c4fd75b3e5590d6276c8c502d871fc28b4ff7f4966b703cdb), uint256(0x19988d256e0d433dbf026d575433d2203861eadd572be77f2c0c422c472a52b3));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x07ad09296d0824f96a732b0437c6c9b764ab371be0564e7c01711dcc5a587ee7), uint256(0x297bc7038528b2518f501d3a2da10da13355d299c115eaa4ebe6c5c8885fc01c));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x06b8514833937b122884cbdb40f97edd5baf5bbbdab19384cccd62d8faf1e23e), uint256(0x06724ad5d0ecb38a3e7b4f0869d12361699fd32d62bdb4631fa58d9d0d517dd8));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2e0594e2c33d8911b8fed5e6a19683db70ad69519319aa95ad1979c7026e5cc3), uint256(0x073ec0cbce813b3bcc6fc82ad7315d6d31b63b65c326dace0a6a4cf8c8e3b848));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x01319c2ed57f05bc99cfd2309f19c6c304e6bdc26d66d8c14529bbef0bab3a70), uint256(0x0c6443f4a5aa6261c6b09dfcbd8415269d164c6a5cf7b359113ae40aee837b56));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2bf33be1980dae160b348dd60e1c0c9557281df06d9bb412fc9d80812a7f45c6), uint256(0x0bc3bea031a445c4e55daeae92c5734244e6644781b083184c0714e42c3b9f2f));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1064a5809b02cb97ec767c5080dba4b6793680c713f7271ec27b038f8aa0f153), uint256(0x0e25bb9d4520c9e146c552e4a4d67eb09dba84bcd1fb54261f3998ff384a8017));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1c8a2ae87bd6dc62d047ddbff27c4e1d907a2ecc45ed83d1602f3199b203b763), uint256(0x23f8e699db19280feb14874f235cc5eba798631b6418f77f0d64669e7c2dae5a));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0be15d71ccb74216db5be304e4aa0017b2dae2419240cb76a9879d450576b07e), uint256(0x16590f0f2fcc5bbd9b61b204b2b43534d8508ca899819c38a561fb9e6ee8d05e));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x161bf8b0ca3a95c0ca3ca7d5f6b1827210c574d1040f5dab7717e8acf787a2f0), uint256(0x19d38d8160448a6c1aa54f56a061e691746f1d1fcee097f332ad03ebbacfac6f));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x29d5c22547570773fab4baecc6d2ea6bdcd69ff1175743c2152dd7c23290038f), uint256(0x27b3b6e304213d120d3a53aee21d131baf8a34a85c3fa5ed95acbef2ac9f9f67));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x14389088f9faa26c72736dacd878be7a57a20aca0c313d11ab74d20511f2090b), uint256(0x12a413c66c61ffd5a3fa6736c3eb234a4f6003fb478e7a6344aa96d850fc6ef6));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1e7d576ca301bdebeae1d5397388d29efc56cb902ec2254e3faf9772a37f521e), uint256(0x14f14a93a337347428b4990110f87f105f88ff70b2e503a66b75a1b025926004));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0b958e871b5d440096989c108515150602154bd57ee2dab95311a9b9020cfb2b), uint256(0x0b89fb39ff40bcc70601591775c8cea624f9f8843aabcc218a5c7dffbffe647c));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x0c48dcc140ce2aeeae489f4d9ce7e88f1a53fabd373969670a417bd3e4b7a89f), uint256(0x059dd5df7ce66a34fd4af9c3f901a470da9ee5d3c034ea553ad350bae266011d));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x07662b76a9768865fed6398748db16024b0c20125ecc6c921e9ae032e5442b16), uint256(0x0d2f75b3ad45712775395c8364c39497dc1d6ed1501554436592eec466a20dd4));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x1f2964a583dcad659020547d45b7da3a199aba9331fd652a4e3a5a87c30a0a72), uint256(0x1be120192897a712a70f106549570163e619010e82b5a6d2c27471d97e2270d4));
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
        Proof memory proof, uint[20] memory input
    ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](20);

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