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
        vk.alpha = Pairing.G1Point(uint256(0x20c26094e5c9e354804bc9f364b789b09aa0e97d369ed461713f9030910e863b), uint256(0x0f799364ce0a6b5747e1af2c659d2c6aeba3185a3aa8c6a7db1fc7ac97c0faf7));
        vk.beta = Pairing.G2Point([uint256(0x0032eeb483d784411eb3caeb508917650aa43d7b47ec1d5f19b678e77467acfd), uint256(0x2c12cf5906e3bf862082e73e605380a2693bbbb2436f650c8fdedd6b9fda7c5c)], [uint256(0x20b261acfe4a32c15f6812aecef40523fa9a0ad6a442f5f6ca7f04f0bff7effd), uint256(0x006063849e216f77a26f6663fe0c34c21e8d83a19b85bdf608950af438ac2514)]);
        vk.gamma = Pairing.G2Point([uint256(0x1085cc13ea8356b7b9176fb8aee656fb6602df6edfbe82c8938c3718dee80a80), uint256(0x23ffa2d282c05a6e0ffaf4dfe4930f93c39ff376c340fd587d3aa715ac501389)], [uint256(0x2a981ece3e07f8a269b477c81f8f1e70a5fd9b0a68b6f3ceefdba768a320c6c2), uint256(0x1b4d1c85d4c49822c0795427aac76d0c5929653cf33c5980cc1fe116b778499d)]);
        vk.delta = Pairing.G2Point([uint256(0x14e53c36a05214a1aaa70b3f6183b3881b6fa1b7e73264938f63519b2c4de91c), uint256(0x1e4a0798e36d07be45d1da0d84788c270419b1a53d2c6e5d8e264e4b0f49b001)], [uint256(0x16cf097243b291d157f8c141e1800d86260a862b0ba7a5bc6a7823b6e1e7331f), uint256(0x25089d2ec1dfe5b2cf21b55109d87b29de42a58caadea60518f64ac8c96c0a8a)]);
        vk.gamma_abc = new Pairing.G1Point[](38);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x01358d14a77864d7ae11d4c7fd5649ff0a873e521b3960bf4732abd249f9f118), uint256(0x17c419d7df145280066c40d416b4b88c733d7c51344834cfa8941fbe3adcd44f));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2337cfec4e65bd4f51fbd65f7ee63844489078e4f8e831decf1bad08205a12cf), uint256(0x0a32bda20095aaabc2525d56a033842e2f50365871c162f1a9bd442723786142));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x102c1355134e4641f8c463eaba7a164f0076e9923df731e73afd05b62959a5ca), uint256(0x1bb5f39cb54afeec655da8061dd176709c4d840ecb1148b07492781ba9aceea4));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1e5f651b117c9284244bd3c4f37e9ac414b9a9eabed962b3761e337b55a6d274), uint256(0x0ff8d78dc49404a2f4e90827e303f501ebf73505b0f3756e18243e5efb039071));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x23a911094fe88825a8595ec5a70b14e33bc428ff422f15af84e71eec5577e42b), uint256(0x2911560386e2f6d2544852a92b1c824844d216e0cafc20b13f3f200de0c889b9));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2e99de29ea1e51e825bf148ee2860b51f131fe8cf636b1c74ac4cc0d9d49a173), uint256(0x22bfb4d04d26c416c987d0c4498f57c0bfe4ff428db72cf77b1d642daa43a016));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x19cd6348fe4d8d8019489e922977043a3703791bc6bb45a5c2dc7e49c81edf2d), uint256(0x1c8a512413c54c120e11a412a43d1322abb0c966fa284f9a8450e294d1e14b47));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x162a842060b13f59e0d1beb4618d91e16dc60d5cf543bcf77e660a95cb31e660), uint256(0x00a084b22c21c2368aa9f5db7af04624904da44f7e3cfdabe16fc732523d0bd7));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0a35daaaa87a55191120d8bb7e261653676cf04d92dccad0697e203393fae9b3), uint256(0x0cbfca319c84b413670b5aaadb19445f9adcbbd8854f5d8089b3ec4eb8013d86));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1d0bf2badb6c4170b9ab43a990edc89d54947043f46374c9fa9cd3fc41c93c86), uint256(0x0248adf7679897f6ad08b67fd7855c6e80a2fa773bfe13a0d00a419ca1299bbf));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0bf00f81de7e7acfaeeab4ff49940daaeda48cce1680c1936fd7bfa78fc0dcf6), uint256(0x12869a71d68643c1d71225052e6bbaaaf2551d04f0f98ed031f9953409648781));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1bc3385c93a1850e71bd30f22e057447cadd3f1c42472461bdb07c04996868b7), uint256(0x152748b1380dc4c3ed54eb7c58eeae8e20f910bbf6c3e20772388bb966077fe2));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x03821491fe83c16ba36b0d5ef42eb7dbc55b8b3b269ac2bdecfb74a15fc4e597), uint256(0x1efa14ec842227b75db61bed051185e30f0931f3a8233bfaef3c0148d14301e6));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1ea1d5430be5a66982e66a74161c2fed089ca932095a466d93162a6b1b22a01a), uint256(0x170fdaea84eea68d465d63afb566a4c6eedda26685b2a21807689960449b4d2b));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x20789bf07c40551834a46b87e71ef4140b04a673e55c870bf7c6aa631b4c55ec), uint256(0x060b8fb33e0cc6d49ff52ab6a0136dbd61d22e504fe691b38ac97e3638271574));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1369a3cb5fbf20f006ffc20d7901721c96cb17e93d7ad7a561243ff6ca2235ae), uint256(0x23a9c4dd63417f9d430b4da2a439dc6e677783b7a280b8b41f28b0ad518415ef));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x19fe47ba2ce06b5b1ca7a2637c925f832335fa1eee99c48657132599cd53ed0e), uint256(0x1e6736962e50f44d039c5f2f54a15d0f006ea019b55e9f022444c1bd4aabf56f));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x00ee0c7beffb6931a395988a88a8d2290db11af90661ea72fcf40ec6daaabb10), uint256(0x1a66a701206712a4a4e8e0347ab5770d9721df00a282bb826dd25aa97aa83f3e));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x019b87ba883a1d281794c09779efeabdbcd8a53982ce7aedff5a7ead2501f65b), uint256(0x12418538c2cf937df00a96e4f5337dd6c1d06c06f7167b842907d6af5e861790));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x14c50876c2bd0b7ccc372ff6b9cd3d037f27f9ca7dbbf4e246b9dca295197be4), uint256(0x04be45d7177663fa80074a5743f0678da756ea4c0ef31980629490f420bb07ae));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x1265efea97888ff576634196ebc32f32daa6143a5aabeaa423f7c0c2f44df7c7), uint256(0x042454178f319d2e1322dcace6627b419110d05e99964277c110604c8aa9b72e));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x03c9a112221346bec96ad0bd7b963d0506807eeb32ad6c8352e0a2e6380a476d), uint256(0x25cc160075baa5d14a38cd10334f6d6cfc261ca2ef76483876be4e3ad2ae95a4));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x05ee2bc0961c64cf597a1bdb7c44f12be75f7b5b8c7260bc6f442041d5372c40), uint256(0x0131b70e05b902623a87b2250f29aaa210feb393e9a0424ca1878a5bf5d10c2c));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x0fa86e694b586c5ee8734704b5e3f9f4a5f4e8d5760c74e06d4d489832617d9c), uint256(0x0f2846fc7dada8b2df385fbfd6a3ef250d253dc3c06d50a416fd775a17c5525b));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x0fffe0a235fe64f86893468aec23a3600ea937ea9846f7f0916dd68912e2e880), uint256(0x03db0eac598bd243d238fcebb3c9f50fb26139040823c5baa5f1a1ad3e7962a9));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x12e35327329bc9b371913e249401c9d106e4623f0181aa3df9c7d0661d7efb99), uint256(0x24b4b5b8dfb3904d15467aaeb062ca7a74b20d19723605a09a31de13559963ed));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1468792ab8d11012418c30a6852b8848257028fbd4a8976cd8b18e1c69f51d3f), uint256(0x00f91e2b982094b0a6c4e6680b04c506533b0f1b44f258198f347792dc6fcefc));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x1b9936902a7ade5f89612c3822f3b460480c9cf328148700c25ca87df35a3172), uint256(0x04856cffad45601d4b36779ec317aafd201518dd64d6fcb7c206b584ee475b13));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x085e949078df3b489a7795dffd91a10f3c5d357540e5adf3be6b3ee02feaf4d0), uint256(0x0de82f95807e10ef7d5ee640159ff3b488a017a2a101f40c3012a18ccb70243b));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x22299d461b01e8b43ba1cc22e0af2c5270274840829afcb0e8f831e1f46c3b18), uint256(0x117a971d60f8817a81d5cbda89430206aac67414c05fcd7dbee3cc69aa0ad52b));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x0dbd31cebcdeb6f347feedfd2d20e0f732e2983a867df2f7f632d799e466666c), uint256(0x156843dc98e509e65d10bf6137632db49eb780a7b0a123543d6d02476e454e57));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x26064bb5b36599f5237a10650be08fcd6bcc35bc697474912e48391da9369046), uint256(0x1098deab8d28bef456967509b3d66fe8c6df1b12534937b0324c4d0a59476352));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x2a6d9bbdda526c0013f2c1457ed49a81cfd88063429d6646d406882d18e6e200), uint256(0x17a01bb62f4de6357efb15350e2d39c92e0d0cbbbc3953d203ef3a4cdfcbae5f));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x1f1ee21320263226423b6613649fd9b79792a0d9ef1fa1600f1acf43fa1a7632), uint256(0x2b4f5b18a3e4a33c6b9792db6b14f8ecae1e3126dd57249c6119ef124b75e141));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x2712032e1e86eedd41fc686c066f5c98742018c0bb3c6f5644e05ffe0190ac12), uint256(0x144f28bb3a6ff8a35abc9c7a47ba6f4eb41c5e252d437a548e6f1e7a2a75a46c));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x1eac69e35521f255ada633e798561f1e0189738a9e024f883c576ffef72ec43a), uint256(0x16bf5486c859b30f2a26397293eb041d72e89be30435f45a159a8f6ff5fe66a2));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x299f225698ce06f74977cfa6cbd84ad0eeb3da810e9e58e54ea7e1ac58c2a120), uint256(0x26f009e0d53b347f2182a8208fec5208d6d8a2e047b01014e79b53eb244d2d51));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x120d159aa912a40e50ac60846244cd9ee1e23ebcd3db8bda4f2eb038400bc41c), uint256(0x1d5c1bd8856b35100898f8ded62b7f37b7fa827fddc376ae471d796148ce408a));
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
            Proof memory proof, uint[37] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](37);
        
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
