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
        vk.alpha = Pairing.G1Point(uint256(0x25f1d6c5f9e0291208a457d9ba2da662e961f54a98ed566752fd56741af5b940), uint256(0x01af384aa0315d430fc3044764d86fc4ebc576102dd66ad5539951b8c5007826));
        vk.beta = Pairing.G2Point([uint256(0x1d5a5ef9f72e44733f6d0aefcd3680774af2608b524e3307c4023d262761be3f), uint256(0x2ce5ae03525a32f2f1e88a56b50217fb24098283ece188327e3f808ec8c8e316)], [uint256(0x04725877cae7061141d0b579b8ea73587133a41f1fe19d523de03d5ce1b6aa6b), uint256(0x064a576650160907ee3af1cc4e5e71a65017756f08e4b3d68734570f35e5bf32)]);
        vk.gamma = Pairing.G2Point([uint256(0x23bba2b532dd4e5f188d2063122242c2cb0e0291f835b102256d1f5cd893cc31), uint256(0x0f765d315321825b8c672efd15ca1515657ae8bb955185b1ee2a41287549eeaa)], [uint256(0x1c541dfd8fde2042dd007ba686c4eff226881dd8672ed5dd6226e6d21c224815), uint256(0x1f10af5c5ef422f82a4aa8237659dbfef3cda2390911eff089610c7209d36f7c)]);
        vk.delta = Pairing.G2Point([uint256(0x1a14f4df0755295cfc16cddebe29285f111eec4260c6645590d5dcd8a6522dc7), uint256(0x1d3ca71c723e146ece4f107b634973640e714388d84824c5b6002218c57312e8)], [uint256(0x15e1099c8ed85f8261366855caf1d19f2bc94e5980a52e82bd069b2a44ea82d9), uint256(0x26876bcfe04b5f361a17994e60fb06d30525505cd39d4b0dd720b23828db8bde)]);
        vk.gamma_abc = new Pairing.G1Point[](22);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x06f1750aca56ffc4d74e2cf04840d9a8ff0f97feca6b43fd8253f92f94c0310e), uint256(0x0291467644903d36a177dcb2034bc8a0a2db6cd0dd491e2150a761b8967e1b2f));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x05a68f166414bd289628e19aa5227dc1b99fbd55ade01079a3d5ef9f83791c4e), uint256(0x25e983ef66390171b10afcdf8d61bc06ddc669a93c842a5da7f96ac3f808bfc0));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x12daaf5eb0275bae5e016fa86846fb00f8d87e8d0ba5db82d4eb078e4b9a4604), uint256(0x181d1a2c29f0bd2f895272a23b2934b1bb3e93e85eb27ed75abe009030c7a800));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x08b081cd4bb1cc44001dc1e3575025013b6fad3b9c7aad7f9cfa680e5688abd2), uint256(0x0f626704afc52dbc6dc6373b716dc8583c155e56cd5b94a58917401c8afb40e0));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1893440142fd697b364ba90f75effc82683f3ca56b74241017076a898c102eed), uint256(0x24230d13ee791b56895cc9a9ef2921343b5c4182eff1fa4e6b645ba2642619b6));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1d3adc8e4875a1099a1016aab3f65eec60f0c521a47bd0c19b169895c55d5516), uint256(0x0ae325296c7da9b5282ab57c97700d3927ab71f41b2278ac95231918b66d66d4));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x2f6c426d55ecef143c10a1bcde0c602d1bf0449ea27780e6715d20d8208c23f8), uint256(0x28c51c8a0b7f04c17683b911afaf419dff5aa2579ad6090b3e5cdc3c678ae9db));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1801fa2271c0e1fd3d208ad662d52fa7302331adcbf66139525b91d2a453c941), uint256(0x25d454ede0fadc7cda89b273b730c0193bdc3f9c867e6414c8626958dcaf9f33));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1b8ebaf9ac360cafb960025a8c1a61f4640570e4e8d1f895cee98017a3931c81), uint256(0x1c3b8aeafab73c4b95ee7e9960143e815b70e11978b5a684d79f5d8b66ce9360));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0437c0e69efdd3ee0cc46c91f98014991b0c241b1177cfaac21bd9da398d09ef), uint256(0x2bc09790ffa6fab1c8308de72808c10d40946d9fe27afc349eb46bdd166c0d7d));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0820febb27df9c31b6873d9455cd591642e61d1c29f443b8e09a1a02e0cab1ea), uint256(0x18806627cb338ea394aa546708755f62ff99f1d48ff457a0c822e6c06c6b6224));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0e62894b70b0e1b9ca264df245a971c4863c65d30ae805c4ea6487b318d54c5f), uint256(0x23f55d02ccd252823ff8069f8dc7fce2d4d7e0775c00dcd3c3df4771349926eb));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0158df9aa7af665fc03fbbf41c132eff24a06a7307738b04b1116d46d96b2a9f), uint256(0x0e9c787a0b4c618b643e4eaa126e3c54ff138070b14ce7ca554bcf46388f090c));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x27ff92f6d711bd45836ae3fa2497ec18cb252608327c5b599d1b7a241e2cb518), uint256(0x213ac7c6d216e8c082f7ab74978315c927dd0d858d5e12d21284bfaf54711727));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0c9fb2a76a79bb1c2259b7300c7fcbd5709a3309d577ff83d936ceddf1cf7b67), uint256(0x12ce073d2eb7b7cc4493f4a0302d374423cb25b1d73c77d6d8e49ba59d4ddf6f));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1a8cab4be4d7680e4f77067447019adecbc352fb3f6505cf8b4ff7e537e0268e), uint256(0x196835e976aad594fc7d1f1b7db94e36b2e921f1a4305e6dff9b55a90c53d0d9));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1b35502b12df3832be2ce315bf1606cb7df2df17ad0ecfc2d09d5f34343dfbf6), uint256(0x277639e4cb230ed07f81f736f92ebd5fdf14e5e8b287f9fb97deefa3d078db1d));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2bb0677666d03f4d3c4d2198aab8c069afa0f0bf08cbad884ca5bf4b4bcf8142), uint256(0x100564926ed589a3c33d3b3669b5e9f84d2150a781f2dd30b2dd6edafbe111e1));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x241f15756a83df44c6e20cc3dfd6b499b06a367f20febd77da7bdecb2f24afe5), uint256(0x1154295c1a24d059ef591a882a89708d70a5d3f0f13ec805cb58b7de74ae962e));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2fca38435b4aa4f859487acfe2b21c044f497629ef05d69a88ad8ae16418484a), uint256(0x12e929d9014873e21fc603996cdaaf23675727c79ef7bcc4ad08bb707a165482));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2043b3ee574d368f749ce2af319cf20757dd7d19b38a2a6a29e7a1c7ed6b0ecb), uint256(0x248053db2e412616f11f19316cc45c7b88f512118ef492234b0075ce3e4b5c85));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x0f53aa682fb5dfc0c393fcfe9540038b03e22086ea25cdfe75eb7a9eaefdaa04), uint256(0x1d80d915c13c8d21281ee2237c41a976c66510e01ebeeab61af101cc48ad49e0));
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
            Proof memory proof, uint[21] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](21);
        
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
