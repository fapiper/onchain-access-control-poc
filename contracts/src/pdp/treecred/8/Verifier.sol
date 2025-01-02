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
        vk.alpha = Pairing.G1Point(uint256(0x2c7cb3c01f8e8621726c567986a29b7ba45f8e6ed489a0201f313d3a91c11301), uint256(0x26faf4d1f11676d353f427f83e7309adbd5ecc95fe65d4e9193298c0a2a7360a));
        vk.beta = Pairing.G2Point([uint256(0x15b8354956eb5e8bca5825f7a6174307b4fb44c937a74226e763ce3acab9d3b8), uint256(0x095af83c4a54791dd4397f8d765fc9f284ef7acee5bd580021fb1a876e6ffcc6)], [uint256(0x2c295188d609343678a7fa17512dc84f993eed83df46672176d27345a40f496d), uint256(0x1c92e6fe472ed76064813fff998ca45e385fbe30971ca3e0102a0a3861f90444)]);
        vk.gamma = Pairing.G2Point([uint256(0x2f15a1e68fecd64b74b4ec075669c07d5413759cdd26df60105bc99e399dcdc0), uint256(0x2456855113be5fca305eff39d4eddbbab7c902ab3615ffbe46bb1945e30ed0bb)], [uint256(0x1b1a94633b48c99a0c02a28d013c8bb889bf40f80479512b48a402ad09e12c1c), uint256(0x141e7ba08c3a6e4c75f3221648b3c8c439fdcd607ec91d827bb9118971af093f)]);
        vk.delta = Pairing.G2Point([uint256(0x2a5d996039b9abe97c2e9e28b1fd81a24e5c688ddcc2ae675c8d0dca409fd1e6), uint256(0x1e3dc1bbf1a1e2bfed12674d4baf395d20b32e39ace8096c1a916f1e43fd8665)], [uint256(0x239a64099b67ad9707911391f8a34ad507d0504aa6af5427ec61fd10ce5622bf), uint256(0x08ba5cd4cfa033a3f053fee31f1eb1584469e4c51884b0f431a3239bbcadd16c)]);
        vk.gamma_abc = new Pairing.G1Point[](44);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x05a6456215f1eb9661501fbc1ceb45db760f9b46bfe1d93264f1170bd18719e6), uint256(0x077cb472445f89d1a3afe95a53dd7112d08711234c155cf92b1de13ff6063e62));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x14a40192c6727c37862374338a12bd4dfd9827e14d8bbd0439da0342178a5ac6), uint256(0x0c193d7e5dea7f862a80339462e0a45af61ee881d8c39154f880e6092d19c3dd));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x25bd13fd36ff29050eef3552e362a9007bcf1a36f35fb775ba9e1bce38a755ff), uint256(0x24b2abe32e77dbc0b0773d6805c30c98ca5cb9ed01680b08911c6bf605f3c9a2));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2ad7878c829dd6620bec16d11f47257b423297658c314a848e78cee9ca4ede7d), uint256(0x1fe9ad19925e5771d54a3be968f5387d8901dc65c6ca85bd2e952fd62d25e0d3));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x27dcfc8ca153f7898f80ad764ea5f6fd38ce2335c7b03101881d164f05da6272), uint256(0x247fe5bff38d7df4321c0b89ae94308bcafbf3f7e03093c4349d76ecf6943ba4));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2dd2a857619a1bbdae965e707b6001b8b45747f2f98ab31e2654e1b5a7e2203a), uint256(0x2d2cf2ec530f64b9d2897fdc21cc9dd311211ac58f70877798b7704fda878cd4));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x221769c53c212d2ee79bd543df273737ac035c891a4a3def3724336d6d0a5eed), uint256(0x1a23e701ca0ec403495bb58c7da82bb90496892a9d0f8a3b4d474c515f36330f));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x18ad5d67e61b5c7d9c325a973ac6543a1da7a3f321152fa5a534d58b67cb7140), uint256(0x28c11bc849d73d1fca4e1ee9798ef0941ed41d2752c8eb2c2f12bb658ff7feed));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x161c9749985f1dd640f35753291270737779e12ea4163916130f7dbef9c8b6be), uint256(0x17f22fc9ab6be2b56d9ab45ae80d56667247b0953364bb0c060ec3cbcbdc007c));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x26e79f94d6c64f7a8a859fd8c62ecaa772e997254b7a903ae584ffe5d93a1fbb), uint256(0x10860dc1ed758c6bb1eb83adf1fbad863aa52b0bc740516f3e403582bb635f98));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1b8a6937b154c9fc0d3c23dd93e734e5f6bad321d8c04483a15334e780aad6e1), uint256(0x1c9baa08927f5746464103bbb21ca21c44ed80ebf47d92f2347f8750202fd9f5));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0615511e84cca45b2ddb7939eafcef27d4821ab7ec29e61bea4222819b846a02), uint256(0x242f5a5bd84edaa7ca2e83fe7297fae1867d677149bc7d50a1c6f2d6d00077ce));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x295e874910cfd362408a96880fb9042226e70f3dc6aae1a0b835b825b02bb334), uint256(0x0a18b4b26092d52e3e387c5c32b4a1b1e82557729f126d12aa3af00f0fb2e6fe));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1f98c024ff8daa42d1779b5703852ab7a9f6a1db04554066c17dfb1f3b1f0e13), uint256(0x240ecab6872e6339b22271af69ad7c32f68072ce76ad748fbbe22b0bad052d6d));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1befa77443bb29038b3f07efc6c4cad09ac42066bd73063e29351caf5d976a4d), uint256(0x285197d787cd6bb8488d1cf59f9e9d86852ac980ee8a473af5e19aa334a6cb53));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x2ca5629d6ccec23ef4aeaeac2ee01f19cb4e93f776630e77df5f0763a1c7a75c), uint256(0x11d078fbff70ec1b18899523ec0c4d40b2d18ccc93c8ab2fa172cdf3a5f4fd0c));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x240d75b851992479a9c769ba14e5a9f1d169ebb926f4cca6fee9092f7ab82d1a), uint256(0x1f6ea710892ce256cdb23193fb450f98b9c68a9c679617f3c20be34bbefd6c6d));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2066e45dc9e2e6637fa91e971d1c4764c86d01770cc5edd44e9085159ba53893), uint256(0x0544bcdf95eb1b9f60ccc8dfefc65e834ea44f644356059e90af0cf2e30bad38));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2d6e8c1d5c37b6095cf303ca45e17ccbb7f0464986efa5ae2042f31fb69b20d6), uint256(0x02202ce85230d305f85e77ede3906b9161b95f8ae128d1cee594e22c599dd890));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1ae430054f869c1510277f25f171482451b5e8cdd1556a37b8e734d019ee654f), uint256(0x1f71575e68a4e8ed7dea46ae183b4f2ea1650b10814f048e0619f8e65a01a8b8));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x06e0a81275f181784b53f4e19ae9cb252be9c3941f4151662f55779ac93d43aa), uint256(0x2938498e35a60c64e8a014c2682277521ab491450066a36732954bc249b50acc));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x0b50134cc490d7e61ba22fb102ea5d1b9696e46d151def7d0c5c23130d49134e), uint256(0x28f7918a48a6878f6475422550e47b8810509329b5e9cd30605b256535d59f63));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x04c516b3d4ce5213c2d50f2571782b7950baa356e8ad31d8c6998ae8d11d0b05), uint256(0x12593cfad8df935b779a8bf36814b88c32423bcd426a0f08ccc47234a70f0a14));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2c09b4562833c2dd2fda508cafb897db375fac9323a7b5b8f5d7e588a406cfae), uint256(0x2fabfa920be9b715cc1a215f7a172e9a765529b22e7992d0680aa7c9d2f115ae));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x29097bb80fd675c20300bfc6b8d7bc53c7d07ff23da0930265cfc15daa7b738a), uint256(0x2ac1fe27a0e04ab56dc4421f93d562ae07a5cb7683521096d12cb3a4cfb58b8d));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x29cedfc81d29a7411e17cdf2a3aaf99a01767cacf862a587e6f5f21efe7beaea), uint256(0x03d8664ad385ae2240cb834cd63abe6ffa28390e742924bcd172c282e47a3dd4));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x0b0da52cb938741e6257481d80abda25f0e3372d986e8d9a5a0a04db361ee196), uint256(0x18dec3fcd036c56d1397ed54409fb1f18ef9edd1490c1b91c7ee3bc8eef40ecc));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x07b36a0248c72bced102b0ce69fbbd1fe3b3e4e02637c0908ea55425b7a66222), uint256(0x0154901285af81d56bedbe260919a4dad3658a16b5cb48826f3c28ebd0d404f9));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x06e042e8e90762433ef43aff4c53d17bdf6616c3a631ac3daef9412d4c49eba2), uint256(0x2a05d8edde23990b4499070453c04a71dbde343a077e7eea35a7a56e5b18165a));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x10a4786b49243f9d39759295a183d3c686a5f55770c9c1e2ef056863e80a42df), uint256(0x1935e2fecce44c30e2fecbffd525c181b6d673a6ed4e86d35ceee32d959617be));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x2e348609f741321a8cd473d1f58190f89657eb64e6897b48629a63b7cdb6f3c5), uint256(0x19d639623e42a1de521c9822059aa321c4a985ce3fb612ff79596d692703c127));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x268473f5a1cceacf814bca57171e6a6f087cd2f8228674e251c0f7cf3c701493), uint256(0x230618ffd3288c0ee2a605d0761717519c9a4dfb199d91f25024f707e91e7b60));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x0f5a9d8653358c4c62cd48369db4f9306565e6b8d7e3107ce94737c910073289), uint256(0x03879aeb766a62c54a95295fab03fe9901d107706a3bd5744bf91bc7426c1bcc));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x07c90650b143797cb2fc1a623a8db9d5281917f79395ea95ac6e513b3edc5548), uint256(0x0a6977451a5f75f5f6d29688693161bced88953be0be8c7224ab3fdf6475554a));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x024d6537dcc01504b6c3c2b3a1a3730708a7abb1a274b54d7369eb68287fe856), uint256(0x034f212dcfb5575ebc3862bbef4b5ce53d33954f91b0fd2f53f7e4d758ff50e1));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x02fb4b346ef2ef55e9ecf71812db53cd300256f03b424bfb65456ff979c02c70), uint256(0x0852667905d47d33032dfe04d56862f9c6cf42cac50458d60e6a3e35ec7396c9));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x1850f6d0bcc088e5a7814b9a9379499ebac8a5ad49a907166a51f9e70aa9e45f), uint256(0x255ca16dac962fd478efc98246cf2f5e24bd51a6ea376b25ca9988b439ff2a1f));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x18dc8ba8f31578399d1ac2f2aadac803f03ad82904296cee530d067f601f89ed), uint256(0x01e711818edfa841bb5eeae298f333fae1912e8fffcae4e4c5884ad7e454287c));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x197ce595c966d740929c3a2732718a476ac37f5596428b3893c981d945f32e40), uint256(0x1257016b7640cb656e149a898a07b56b0c441d5559461eff5d6571c13311b3c3));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x2069446b7f011d78193749a21d3b6c25e8a9915c98fa5defa2f2c14b176c7c6f), uint256(0x22d9b40470ab438c36eeeb891de8dc83cbf52c7008f7d2e22109037d2baf15bb));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x02a61638aaa87f95198c3f2377f38dda9abf976704eeecc976e135df73586766), uint256(0x05b3781f29ca47f66bc1b8b212f1e03c2bc8c5728f4c446a2757cbd33683e350));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x15afa1bfc297b6c67cf8c5d7dae2e4a0e7658964127ccfd9a4f80d7d45694503), uint256(0x117dc03a26458ca9361aa2b3f99b76075a74bbe24ccacb826bbedeecc525d4af));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x137837c0945b9e131362a2f8482f5f65376bb505296d6816bb2df3aee8cbadfd), uint256(0x18f825bca6a50412f77f21612f76c93054cbcb38c3ac05edfd25afbf407494af));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x278e873976eab854f2eaa2897f77ffb8f0a35ccaec1eb6f8d1e88278f4b0ca97), uint256(0x0e9ee333690ae7115b3a5d5bd7b45df0d5382aa467b4866df665920cbd49cfb1));
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
            Proof memory proof, uint[43] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](43);
        
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
