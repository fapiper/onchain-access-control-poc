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
        vk.alpha = Pairing.G1Point(uint256(0x0772ef6ac5cfc01737f6aa3aea7bd985d5ead8e2749412f7400d76f7943c2dae), uint256(0x1b8d999a646e8d4fde60f786869dda2c2175485ce6bb5bb84bd36438763a2b9b));
        vk.beta = Pairing.G2Point([uint256(0x10b691571ecbed98031515962f60beed1e35371812427f33024b74fd9b638b85), uint256(0x2115e790c79f4b7a6f17d66c6d2046ad02053b11ff1aadeadc2195486cb563f7)], [uint256(0x2ca1efe4349863cfc0c818b82e285edf63fa1fc546a8c6dfc9d8bc2817e2d1b8), uint256(0x2b6bb61fea0cbe72391c5dda92500d6f91e162474ac8efa9a1255dadc73c5f71)]);
        vk.gamma = Pairing.G2Point([uint256(0x29436d5206884b3bffc5a7b39b3fa53fb71712908b753d51fe9770c0710c4cd9), uint256(0x235c4d2da212d2d695cdc81611221e765503cd9fbcd997bca1bfbc2cacf1b714)], [uint256(0x02a81e24d92667d6c7432c5106edc4d9d5f35307acc80a47223d036cb257ad54), uint256(0x1b34a0d4316577a1c2508ad2367316d37ba61d31985df0a62a9db573b28d02ac)]);
        vk.delta = Pairing.G2Point([uint256(0x189422ae868b5f515345f5005db8ccd9c13d1da66ae6782d33743adfab21938c), uint256(0x10f7ddf6eb9e0a153a6288a6725a1e900fa9921299c86b47683b8f63199a231f)], [uint256(0x302013bb98e7d10bae749067e39e658364c2495a5ecd6181f785dca3af25bee3), uint256(0x1ef095348daffa1e79969be641fc907279570d54399623759b2bac42de6c142c)]);
        vk.gamma_abc = new Pairing.G1Point[](60);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x250060026c4ec825a093f25c36cdbb581c42e37f5e215d45ef6b0631b48ae8b4), uint256(0x25ba30e8a786bd4b83f07ae856ea396bfd75144f283eb51efd94f7bda8845041));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0d0f3aaba8ad234ce149cacc2e1bac21fdd1c1d61acb3131d01ce527eb84bc13), uint256(0x26b771900c2f1b2decf1ed57f6956b57bb2c69f34b61d4ceb768c3792d4689af));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1a45778dddc22ce74109d10c8ea025a8b8fb6c87ec4f7cff611da8d409e9e111), uint256(0x23b34dae06c8e007b501d75d20f1cdf61308fc15ff57ec4a58aa67bd0e696b27));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x00d32f3e8f8cefb178fa0597601efa6d0305fad536c2d77851c9261807453c13), uint256(0x00d0c124dfb9295622954a9a82867b5fbbe770593dae50f687ba6f6e82f16c62));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x08ea8ff2216e44754968770008a73b6d25a9425b4b8515d3027834e4737e335e), uint256(0x3060a192c41eed7da220aedffb7131b77ceb3e5e3929f56b0a6edde401159658));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x254b5027fe22cbdac5560fcf8cc325f9a2f059a707afe3c3f148a1460f54bdd4), uint256(0x2b4108c9fdb73af32f8d811f6efe00223fafe0670ea951af44f7caa1d3f88867));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x102edda7fe4ea57c7d24b6a99fcdd97c5c679b54b71707e4ce88b0f07c269ed4), uint256(0x011ba8de0758137a4f81de2b5d4c681f6070da08c36f074edbfd914538db3d85));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x124130c2a40d7c7699033214db566921534fd063b2c25613c16bcd2993d85112), uint256(0x264838b77bcfb49fa5db6de1147e93eb955508cbdd68c6da54b62714455841a4));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x260faa770ae1a13acd6cb26ddd66035cf28b17ac4b729bcc89450d210cd7f002), uint256(0x16b813bf2311d7c8f079762bb096fab48abb99b3e452571778e48971226d76f4));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x223147c7098def9375aeddcdbd01bb0bcd11051252254a67c012a7f70ce0be8e), uint256(0x074c65a7c6e208893a6e829af32f85c98571cec20b785173cdbf184e91535566));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0ee8e37db36382e523267d39d126bf40d950d4e722af065ed0aa9696092a45eb), uint256(0x134ace7eb87c1e1a083fafaacc7d595edf8cc14899485d722d62a67165db1fa6));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x11a81d2c11ebf2460a6887c0ea6ae58d8de7a2485dd98922277380c81e0eb6e2), uint256(0x2581b5dc1c5b5a7ac68fba06792ac5f5609a8ca32f7157d5a2efb64330df710f));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x05545fdbc653d513c21a54cf2eed79cc10a8f764dd749b75f1583da6e0d73d2f), uint256(0x053f877f710bfb33040cdbfbdf2835bd08ec879694b50db0fefc79764f207651));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2407eb7e6160a3660d03746d804ca030b60a6b92f4072cae9f3b13e72d1e6fc2), uint256(0x0fd53a6e5b952968e43af539dc06aae51619c1a42bfb6b4762a77ab75d43d503));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x067ff2c18e5bc78efb4c5d0bb363c3225ad07e256d1efe3e5daaf959d132d76a), uint256(0x2589830a27737bb9f8293c71b5dae3a9981a0ba75d1351f26976f90d6d11250b));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x2eb0093e7ace1f72e5b37a20ce332b969fe12639551b92f62cd296a05129da31), uint256(0x243602de5e47ad73ad1c32e45529093752ad105fb6af302120dc4c86ebece7ba));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x23886e3e0b8e1cd9d7e287d350de15ad15b09ca0268d7568e0aa92e885e06cf8), uint256(0x123e2995ec8587963effe59a88aaf4b6b3299ac09d1afce776f5ff72667c6e96));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x02762bcc9dc7c3e0b2e90ab18c02fb001c35b51123e1e835c1810e5ea640d032), uint256(0x010aa1aa637897c1a9927dba39d55f57001888b6318ed2811b5f6fe5bfc4132e));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1a192b223123d1a2a3601ea5ae7dfdf8ccfbb244cc95c337aa95fc331065fe9d), uint256(0x12bf84747184b0910a7256ec6435c3ddb0ebbe8856fd79eadf0b83a205a3147d));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x23bd478d9c9cd6c9cde20ae744562a1d63a1466a51c9e83a0dd14524868e7cee), uint256(0x2a50b7849f6ed193a40a80cb5cd09a257fd1d6ff123b3a4821ec2d4b9065b05d));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x0588469d0e4a67752c2cdefd1097ca7266a68513938e263c37f5bed5cf822004), uint256(0x0a828e120fe29db469fbfc8f94e1496cccff85d978b8bbf20976b05eb44f8b8c));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x2c3a5163ac70bba7da7e8ea67e10a129c11d747a22b90525e2fcaa2333fb6373), uint256(0x1c7c0c05b85d2e325d7be3bdd3fd8c5a3a417d62ed1bc4d6cd0569503cbeb148));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x1c732f713ed8f84d531cab5f81e0c1b27d6e60a72e50f926da00d84caddb1401), uint256(0x15347f4deabd949875647b64b848ba3361b9c309755e2099f0f5eac0c2158d3f));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x01c14089409e9b6ad3448667bd19c47a058ea206e70726f8602ee2187e12f1ec), uint256(0x127d7f346a2b19e86f020713f3d36a778fe9949839ec7a0de675264202ab9baf));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x020f63510fcc7062208c86e7045b08df3f80a860d299ed5d16afe9de67e83083), uint256(0x2cdee2581c0010f90d29a461d06365647ad06671c63888b427422a5cb7926fcf));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x0b4323038e856ac2137ece6ae606ec9f7fd2935836957d8bf11860c24b098644), uint256(0x1638e787064dd1dfaeaf1669855a0da4ccec817cb6f9707665e123438417240a));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x23947d36876eeb13b1f9cfc632b27193739a070de05ba8e11009294afc9344c4), uint256(0x1072a2266cf5096af7a623bd219ae881f75137ba5ebf8dd79cb1943e7011695e));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x09ad91cdc3ef2f38d16a71a5645fbff09dccdbb2446e814b090360d8d0faaa91), uint256(0x0bcea5f902c8b4b1f20e48c1bf2f207139818912bfb6cc27b51bc3132a3001f4));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x09e1bc9bc0c61a70859dbf19c526b5538aac6bbea4766c89081434e8272c8aa5), uint256(0x11435cb9897bc65de55a4f69ffe276d0b4ce3e108bab223837a6311f43d617a4));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x16f29ec24cb6b3817ade75a77cc9989c86c2831986fc534af96a86ace80baa8a), uint256(0x0144ead928ebfa2b68d29604b2845ad53b003a3a9e2f0d2481da5a0e8471fa4d));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x247a860acbc4babf60655522a56ea744f8911d36ec10ebcbc0dd67ab7a845419), uint256(0x1906e57048aaa0bd9cec4411e2bf24c1e049692eb804d1697f7d52ded6c5dbcf));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x21effeb8a5bcdb9856c0a8ab08c01c825ef91bc563cbf23290b7bf7d1d6746ca), uint256(0x2951a1d67d7188bb8c7e73c2d23a85bb3bb4e90520b9f181df7728453bf12fae));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x2a7f34511a346ce9e1f1ee81c530e390f38e3e3540d1972e1852e8b3130be42c), uint256(0x1828846b848f042db14c823f515340ff53715be7581908b61806a87467294bb8));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x0266f0b15e35a76917c9b8e37b89e98940202483cc88f5e14c99de6e287ee643), uint256(0x1a924267ff08481ac625b1603ea9abd81cd95ac861c1257b4b45b748d83ad27a));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x1b47acdc791c65d1b135e56f670f52d3a75c92a943ac4602b85b3d879c46203c), uint256(0x1136a6d6d664b0b736fdadc7eddbdc03e199ad64d6965fb2b4258c8b056c44b5));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x27a7f6425634aedfd107c5e6463b01bab7037978300cbafee0599fa31015d44c), uint256(0x0192a5f55fd7e5c72001b54b3ebb52ff07ff18c9f04edff95de7d0f78d87361e));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x0f7ea211f7d51c275c698c23418e8311ba2fa783562d226e99e5219f048d00aa), uint256(0x2c1be03c155ec7f57022b6869c7b2885dcf99500f6d45807e74c95ec30e6fe32));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x13472136e8f49b5b7abb55bedaf3f3962afaed54c3de4c129cbd1c2a96676126), uint256(0x1813c3cd8f46e2b509ae23a379c74cc673cad0013eafaf0bc3b350adf71a41d0));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x1468a3c86717e18447de03b73c21bcfc66f8c7d781cff1f3ea53181153b1ea00), uint256(0x25c244f6a06f5336cdde79599ae19ed3306984a90ce6e9fdf40c7a699880d1e0));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x1909d34e7ef53018245b18ab794a3776f456664a2e556c19a89f1a9ac39db320), uint256(0x12812fd6bf6795518e248d81ebe56dfca25e468238d7a0e80cc6626aaab1a998));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x0a8768f34a7e4344410ae669134c31e355cbf50c448f2adc592e0f6c31b8a771), uint256(0x13c5fb716f93f554bb00a3f72aeb370430f7dfdfde0aff92779d6b8e440fae25));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x2603b42f351cf946f0cdc80a019c46d0670a050ee1e8bce2e9c75f041f4e69d4), uint256(0x0ce9623f84da283e6925e89a70bb738255b6e632e9fc072841412fd630390103));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x22efd08834e1ce01b0b8ea29e247a34ea20ce8208822df0e6183e9f079d38122), uint256(0x2e21c314b1779edb692402922a1b6c30a8b2230ec072f4034fb7e8633c21e34b));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x2422924c6d481bb47b74687603cd6fa52d5ef037d1b02235b5429c7b9cc9203c), uint256(0x2ce4bba0c90a9faae66c01f91682b8d63d19c7684026315ad7c77986697674ca));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x0c13dfe66baa2388256a36cf4efc9e4a70a653a85355ec2365ab7db79d5c6672), uint256(0x029671d0ee1e46c43755a019d44d204cd2093fe969fbb86cd55a03eccd4d7057));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x1410dc689e9bb4dd7ff22841b65b10821f5c262e203c0366d7cd8266619293d2), uint256(0x26ceeebdf8b656383708a85636430fc0de94f7626b80aa98bd2df8c9f9a5cb6d));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x1fe1de99d8dc3db5a70093238be68a3e702e8ce17bd5c2e4c23dcecdbed6fcb2), uint256(0x0a9ab3833331521bb2f2582ca9a9867f6e6ece150021542d3ed99c44c882152c));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x0e8d2919178425681fe1d3d02358257f5d166a17ca568235e4644e0042f82052), uint256(0x2b2c175c67e196b48cac8cfa4454007e68877ab3233b21443cf1d2ed5575d89b));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x1a49412cbf43b2cd6289dc3f94a6a5085d17a23a28d9958b5dda945da4d545a0), uint256(0x169b5853286f5d87e581912a65d0dd1f3d0fa0e6422b95aa9258e210ee920321));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x07da8e5e44b12d10a669feb86011e5c1b799b2feca2be2e9dadea6ff8d32b84e), uint256(0x2335baa2f7098fc89b7b005efb5813b23fb2cf805661ed8914543b7053ff33da));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x1673e415dfa87a5a7b48a031b1fde9de25e7e9e3e8181ec0af7aee28ed19e08a), uint256(0x12db6caab8c963f5d657e1a35bf549a63b613e1bbd13276293a23535d1fcdbd4));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x2aa68daefc6a0ef681bb3c57a6a0d37cd33bbd52111302476416525b13b01783), uint256(0x10eadb057f6e49c26597d73a7e667e4c23195ceece3a739aafbf997fad6d6d0b));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x25721b9423f312d2c17faa5d60d1c1a36cb94550db506f7df382124b4d1df175), uint256(0x06db2486871ef799e2fb725ecbfd2a729dddc1df721423b588296bac806671df));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x2388863354d393fe565f8e7ff616168a45ca1be93a1b36900eb3a034338bc35e), uint256(0x2ac8babb629f8ce008b98bc42f4b5571bf836d65f4665bc87d9209b23178328e));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x0f0562dd4f9e9b301cdd33ba06fd84ed46e03436b58a4fcf237e98daa46d927f), uint256(0x2c1d2e30d82713c26d6ffa2931ea3ef54cd38c07d3fd8a498035c19b6b463f98));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x10dd6992e8f6c693e14f3fc11c5d080b5cf7201a7d9dfa4bf3c2e59aba5dd4dd), uint256(0x2faa7f93fe8985acbd97defb2b8c6a3db98b53d17e8521e031e52c35703e3f78));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x009408d8a20808ae84e01b3b3a6aa9a796addabce2c685bac6344c0629b1a10a), uint256(0x2f4ae161f84a2012f05bb7ea267208de011a190ece60ede7637e8a6fb402bc48));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x2c68de0a5ffc50dff11519c20cd3f9184a85432f3bf3acc2c05a0bb24247839a), uint256(0x0057f17a90028b8a80b4990c39c362cdd5a8910dd012a2ee51fe9452daeabecf));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x26ad67e68dc9ebb0ce6481aad499ca59885f18ca2be96c6f4d359aa813fc7bbd), uint256(0x2ff0ddfcadd7a39804fb7047a8e176c88972af865d5812c860dd1971328941dd));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x2e97b9c6a37c3821bf99e3ac4126bb1db64df5256031d81fc60dc2092a054d2a), uint256(0x0cab4bd90ddd0a2659ce65e9f0625ad844ed4dfde79171b0ec38e8325d64110e));
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
