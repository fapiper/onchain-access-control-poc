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
        vk.alpha = Pairing.G1Point(uint256(0x2797a95cd97c12ee563a8f961e549d075c49950d66963d4e38710250c0b3d5f3), uint256(0x2a58dfa2c1e99522ae39ba798655d00c11d5ded9e417a141d9b14b06ebc5e587));
        vk.beta = Pairing.G2Point([uint256(0x1dc50cc73f3486eddf2b9bfa0f412fecc51568ea229cd7973f869c7ba85b4687), uint256(0x2a30791fe4badadf9d803c167e756b7fa6356dc172f486a7b841e568f5e74286)], [uint256(0x2143b1b01bba723ab69d1b1c673e23717aedbfe6f26088447147d42f5c1c8ce5), uint256(0x26416a8f90f485e90d118879cf16c2e3776d09158a7d47d45a2aca5e31d3a323)]);
        vk.gamma = Pairing.G2Point([uint256(0x1577acbbc2e7dfd30c6b89b88a9e5127660ddc8816dbd870dee634a7840085eb), uint256(0x0ee20dca5b719197e1d390813111bf84026255f38841f3dd5425cacace954232)], [uint256(0x05c40d69dc62363c30744b49310c35d110b10c040f2fe15543ce5713f21e8c53), uint256(0x04516923033aee0ac1ba143ef5edbed0a7b19073c6a01a6b4d46c410eff8f962)]);
        vk.delta = Pairing.G2Point([uint256(0x07fbdc3dce324c68d0cb54604ae81d57519f8a5d1848c2cfae1b742e85776cb6), uint256(0x1c30950d51bd1c9c5cc75cc80171e5a3ee15f97d1fe11f62e70036fefc7ba0b9)], [uint256(0x0b5b2d84a3937c733746f29f4c1d415730c07b16b4634719a446163731c10954), uint256(0x2013846c1a1279d7b1f32a283858c26d86f38329dacafba509b82acd3392262a)]);
        vk.gamma_abc = new Pairing.G1Point[](273);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1dd41968a6314721fc11d0782077ce9826350a7ec8e8d6bab588f3011c5bdcf3), uint256(0x2a45760b3fb4740762182665470799aa2c45b6482233b6c010686b6ae42a45e6));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x12450a666340b475354dfc34d051af4fe7ce00338e33bb4b69ec8c53aa15b1d6), uint256(0x2cad6d68004abee72e7114d95188ee67bc082a2a6d3f6f7a937006ef2c9ef18b));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2d1de6ea5715a8bcec57d8f01220df227cdf84a4d1dd1974161059a165714597), uint256(0x189db03b39f5a6c78c6bb74df183636526c9d9b5988a90a1f626e09ea3b8ea28));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x06c6f1bd5ccc106e3c29225fddc1562c365216e8082f4f21971b63f18ed4cd74), uint256(0x21f330b6a4c0a822e0364388d9204121a39035476c372d0f9eb4bbee05b5413c));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2879c0639f3ed557b45e8c46deb98b508e0879b7aca34f7b1f220a949cd10154), uint256(0x2056b88181b220e5d3447aff1f2ad4c412e7269d457043d520ec49a2577a15d6));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x034ca701a80cd1aebbb5c6bfd0ca2ac281c1574021f5eda8154b51d88ec0ad48), uint256(0x270277d44a93dc6ad7e4f1040771e9d8387e8b428c3f0aef7b91ecbe64817e7a));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x00f3756c5230961368e9fa73842fc7759a1bc12ed7769378bb5489d0729d1795), uint256(0x1bdd9cb9ed8c0dac2b88ad0eefe04e16ca175a77afbaeab624ab0276bfd40b87));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x04e57c0e86c60e9a02ccb4a4669e388f09e11a674f851336fdf3ce453750efde), uint256(0x1bf7fdd1ed863d3fcdd307de542004ac60a89a33f2db1945cc916593adc63874));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1db55916b8f8f3c113a8d956fd4894461565dcfd0244c61a2e6bb2ad0b72ed4a), uint256(0x00ff0366a4cee781d65fa2a74b14d4bd018a909b54220febead56034e603eb7b));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0679279009301d01396c3e2fff6bb53167af419626460528e141e8a5b920b23a), uint256(0x1386b4f4d67189e5e9aec3cba4eba0d93b992b5f5d3fd8c07325f4dce0e78a63));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2de9cd799ecf6581c8fc28273732bac106688e734a6b68b9fda60376ec99b7c3), uint256(0x0188db9afb3d066e92233dafe86c7a07560ac8b8fb23b1fa33d802cb1b6ae9ec));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x14d97da85dcf717a7351d4cf673dae65c1b757158b8f59ca6c6928391a6f985d), uint256(0x28dd2ae1dc618f10f7f43fbf476e42f54104d11e734723c12012fc6e11a9c3e8));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x155d389a434e93c32a4a15d625beb76e370f4a45fc90c4bb1786a00daf2cea30), uint256(0x3061abfbd6e0168b1b00c595901875ffa95f0242b0ee7b1fb9cc2442c4918d7e));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0571ee8f18c00d83939f9811a1f94c431d5c7a034bb89a25d439e9421aa3765a), uint256(0x2c03c851b8d8feb07962b355d3ab5657bb36437ed1443d86d3490d3fbc36eee8));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0076b2d4bbb67551d4770c7cb09afe2c050f83fa478fe97427a98f99f98dd263), uint256(0x01f7990d6fd1b25d5737c665bbab8df1b8e46edbe88f4de74396a2a8e46acc55));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x2eb22f3db5bed2d63d66e97e7c327946ff4aef0f3cf8c36634ca828160344398), uint256(0x0195d3bea203d850b07424cb562b998c1bdebae323767552d7efa212a53e9a77));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2723a142dc38dfeabd877dc48c3f978c579864fc3008f0578a46b18e28c2a963), uint256(0x18a7c6f6a7d8e6f535b1efaf22092654c4643ab83634b39b55ee47cbd1a21a82));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0ff6deff8ea3eb8e6b10013599437c8b039aea092147a99f50a00fcbd98dc987), uint256(0x1000e06c35709042e07fd6518f7cae29271773f3dee87ab598b70bbedfc12988));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2955c27df85da1375d1faf786e3fdebe45751e06918a568b17b5ff687f19a079), uint256(0x2371e7b485029764aae2db699e7c4a083cb59eb9a62a272bd853ad19f540b2be));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x10be99e8d69e4702c794fcb0dd89793988984a011c16e1450c13e72db204e926), uint256(0x1ac154aabd3de1603defddeb5a201e2691f65c6a7ac1d8561cb0926b27f2bae0));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2177629d3310c7a6c1374a23a55d2c8f723fed2d4a10a5acd6f0fd9f6ff3c3bb), uint256(0x1273142a62b0d1ddaae9ded9b3fc8bafc32f0b1f55cdd338d8a3af3b7f54c89c));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x089df438d57f2c8fbf86105f23107620454e1e9607cb68f2cbc4ec059befc72c), uint256(0x04e37497b01149968defa2b2b4cb55e1b80f966dd9f6127d728292d1e2e229df));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x1ff043d3cabde2644de2d2b44af3cd90ae3adf6037ee08976d1a7ac872c294e9), uint256(0x025a1f4b7daf87f895bd7f55d576faebde0b9b8bc3437d2a4b3459467a3ff09e));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x201490970c036d98f09b62e64c97b0157fed68cb6b2f4ab72dbbe313be0857ca), uint256(0x119c0a71bcb83b07ed3c3bed5511f66f2f9d3a8db5f798ee896949ee5f660aed));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x27606d99c63d517ba53b37dd90489287dbe1286361ebb8272073297d1f749263), uint256(0x0c3173c0ad2c769d92ae23ec436f0d7ba57c65c645d235089fc26bea03dec597));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x220ad94b095bb4e158d6795ae7f2ca623fc2eb412cca0862a80cc9746dc57293), uint256(0x2a0613f8498f1ac14eb55de04647ef78a9653e80cf8b0141fbd06560bb9c4117));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x00b7f31e2c8a921ce758d72164febacf40dfcb8b453fb77b97b5d4d84998fa22), uint256(0x0a8eba91b56a263c7fc025d5fb6b71f087163425470ef64c2f0df41d24b0836c));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x1f8acdb699ac20f953615436cd05383f7a4cbd45c4cd2ab7591856a91f956fd2), uint256(0x1142762baa28887cffb154031f43b77d49752529693135dd82c8e6fff464368b));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x00b74e739ff760e8971fe5e6e4a82111c0def8b76acd2dad5b58b83431749f5b), uint256(0x0cc65165e358ebd845ffa6565ef090f5ad6c2689e69558ace1d15d0f5b41478c));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x08f35d9b2ad2bf88770c576b58bd270fb971723f6a24fa387c7352b5e4c0893a), uint256(0x02a1ba1ca7981cc929e94b022232a0e5239c9f3ce1931974803fb1ecfffdfde6));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x2e7e84afc29b0fe8297388477c0117c4b0c57b97e0f5b847d4acd2517bb3351d), uint256(0x156a34e591bc734b1047b0c54cf1015c396a827d02331e43f4151e6193bbae1d));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x03e700cce684b4475433291192d1b6f1441871d7e918309c058c183d4df68df0), uint256(0x2fcb0c1786817ee6c8670b6931ad844600cc5e8928631b623fbf1b3de286dc99));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x195152550738b2dc158ae5717ed0442c5171e6d6a374516a6c216409b4f0e5d8), uint256(0x1e4d3c15bd9ff696e3edfe867a1cdae56da9bfba7206f9cbeb873aacd293892a));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x25893ed7b275b4187f57ab7f15515c44bb559e3130d67c165389fc8b6a6b4bd9), uint256(0x0a1c455fecadbb73fcfd7c110e4535a73b57d04a71badbf20a924cddec6106f4));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0556b63bdde3f6d105f9627b480f78c854c817b168c3e1e219fe17fd380cd014), uint256(0x04b03fc80ea68d4f294bc872b44c61aef491fecb2f6e4dbd1f49739dcd56933f));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x09bb48ee58a3e4c70a6574674d64ad361a2b941efcf5f12376042a9aa9c0298a), uint256(0x248070d3c9596eab17ac86e3f044cc3cbe6f1c09e82b5dcf9a83bb745476a05d));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x25ac73678d1a1c182810fd871e7c7f7ba889393b0530cd37aa66eea01b71b9b3), uint256(0x17ad62864901faf043f192d2e98f989c6a6a57b1569b87690578b41df06665ad));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x0b821c127d5c77019cf1e4c4501c90263737451eca48d0f67913186e3a49eaf2), uint256(0x0058fd5e85c9df05221f2d5f64b1d77e5705805a7d94c1c04666012d61d644e5));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x0e7cb04ae56e1ff33373efde488c399cea6625b5045fc1c8978c9fccf1055682), uint256(0x1403ebd8fbcb96a05c5cd8942caefe2ccc554d914e518e2a7a48c7807be9a0be));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x04cf3a62bd5fc0bf689d91635ad971c5be1933b05d12f6c4ff400d66135d28a9), uint256(0x01eef1a93a9594e4cad633bd8cf86e7f2fa0e954da799c167deaad53d7c7f6ee));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x0b266540abceece99bc8be3843d224a6e96ee9b05d505819cbfe9f0da2489c30), uint256(0x2e37dc452be44905c696d10fadf679427a72109375c5aaf36d63d4bc2da19752));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x09de4b81fd814f870f047573e8110f4cddabb1a758fc692adcb4448c3177ef3e), uint256(0x245deed83ef1913f424a59461cab26fdcb5dc509cd173b03e7b411661eaaa37b));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x1d5fd0dc0cd48d9d2363951ff9139ed122cafeece532f404fb0ea4952ef8c722), uint256(0x0e6c7950ece34d5788d98fde1786b835c190bd98838674915f070009308f4563));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x26e8ac0b912512f40a64f44e53f9ad2acd9054a1d3c0709e22e526dabd9b3ee7), uint256(0x2eba34c81b5b9b574d12f220c4d1857ab040e5ab331cec868de4b216bd8207a6));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x241667101cf59490d0feb6b8c93249221078769cc8f9ca57c9fb7faaac67e0cd), uint256(0x02b569a24988a2e7539afa92d8e17190ee3b152547c585bd3a8aab7d9df470f9));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x17834357e4c5d067ce0f4ef9f78ebe9f228d6f5dac87956f9d7f8d718976daa1), uint256(0x1ce0be5114fd207a9ce01553673971f050cfaa87af7b3cebfd9edc2a1d4d2fd5));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x19daf7df48c7d7418ec4e9341ff84e10cf1d0a099dc65c1d449192992c313f1a), uint256(0x022db887e15ccdfebd411ef59a9ee52f6d7e0442d4dc0b8b6879342c4be52f66));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x195b4d12da12e6025e0555d1cfd30b8cdf36588212e5bdba9a85f3185e236a98), uint256(0x1d9a88ea7bc83670fff8cf8d3bee7900f525d7e1f36d2bea9a3dac521b0b7dc3));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x251823a3deae98fa10329bdec23775ab2979423efb4be5a1373b9c145383b408), uint256(0x2186520d9bbffccdd0176b0511de7bed6c5b1c1c7ca7c961ff688f8417d2e294));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x2cd64f159879ecd90404295d204663407da412eff5f7364768ee40c5782ccdba), uint256(0x27b0e279cda5ea42075f95dd1adc33f6ab30f7793ce31986a36d4a4de86b8e36));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x2df86e16c4921e004e591554cc641b34aa99091d044fc9de5d8e66c8ec793ec7), uint256(0x069bdb4aad571eaacdd0d4c00cb3b2ca95172f4e3ed96b54afa4ea2fcc3e4a13));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x18f10bdbd25f9355abe8bbe43c6ec97640058a47b202dbe54cb0787a43bc9b94), uint256(0x2d6b7360523bc1d96ecdf2ec9f462a0bd7fae4441c083874b11cd0883ff1b3fb));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x0caef6ae95a16fd68124c788ca65d4b63d033ffa36fde12444616c2a5b7933cc), uint256(0x1a0361e91a13b3e17ff0f5785d8e6a6b0afd64c3da6ab89c3b7668bcd8160053));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x2dfc13ae6430f80c98a6c71727958b855c8063c9c609f6e639458278f9912af0), uint256(0x1020e92a7eefd6526d7d005e99650de13237c62fc9b04248c9ba0ce7e8546222));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x0b178a7080dae9498cb354b7d59bb716216db991d3e7c9f570c02b65bf90208d), uint256(0x074ca5543cc84cea214478778f8fc22958d66ccc4f17fa6c4d505a5b1303d00e));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x03f6c099d0a4ea845e2da6c3baf206aeda0c663b54901495971a33403f67856f), uint256(0x1a57d35cbca4b3163775cdef5f23c710ac602f6dfe25adc2657d88f4a812c64d));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x2d553d1da9d469da2ba425511cce3897c9345d91cde1b24d59660db6d92653e2), uint256(0x0743069f4161db544b8a84ee892bedbbc14edfe4b9a1d0ebdbe1dcd1646af5eb));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x0a7e8c08593dd907d6cf5ae9bc6b2eff871a128ddcbd997496eed7b1e57c5d43), uint256(0x06e920ae8e7b24230a56672e8cd2882718ee03d846af9750a0a4cfd955087960));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x2b6ce64058704104cac45710837d33062d0ee1903e1eded50b447ed081ba53f3), uint256(0x249133532680860a1ced0925fba9d9e751b38d2eb875e8f0e7deb3b6bd9124a5));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x1e5a822753a86fc731de19593ab6ea212a74d868e94355ac792e4ec4207dfff7), uint256(0x03c8377c8038c089c941c4d8387439cc43abd2d6207c73f4229c210fd34694e2));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x2fcf722dced9d996f3c53302487ab4442f6bc840e0136695a35f85d8fcc42f3b), uint256(0x12218ec5ea20242e30cbe810c926926551b467acf30ff93d2a46cfa4af1ee50a));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x2f0ca950cd7241ae41bcf9bccf5680d18e71874e32e1d7553022430ea1f6c60b), uint256(0x2a46837c3689376f7e0357c49f01e522e969efa92be8cd4491efb307def03c73));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x0f2d8e1d3f34a003c8dceb378d720fa6a1773e537faf572b302ac89d48e71b15), uint256(0x0744312f2717b2fed127f7e110f55f9b201be8930eec82620cea2e48a88cfe75));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x279708e3946f7316fbaedf39546f6acdcdf040334d8212916da56fc8573ab10f), uint256(0x096cd19679a4e0f8dc9b463fcc03361a930b4a2bee772f40a11770aa0c60b0db));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x1eb5f6ac7a85e2643b63fe55c42d1e1ed3a7729ae513056911a7c7561b498efc), uint256(0x287f14bd1576c4e5370141baba348722c3a8f1e19b89a380cda290633d364f79));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x06f2f9f80fac3257103ea505a46575d7faad4e88fe67a5651d0263f6c2a75890), uint256(0x214f8e33c975ae0a8d89193be81be6c4a89e531e9b1de60027ab5fa5949b70a6));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x2ce1d3ee11e5635ac4fa004964466aacb4f23100a599b78a6a1ec0c597430b21), uint256(0x2e4861a36b8314d63200e7dcba9196a46eac6d6f447a7cf614a2dd9e6f6ab39a));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x199d7fad79b0013219a111ac84643b3331aff49c41f5056eccef4871b68c9c2d), uint256(0x16c281eae559e3fe648383966edd2dab10566350f1f30c9d997c8219107e2cab));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x182aea8a7e520e4d7dc41ec7417c224adb90fc1722f81a25570b35339f321ecd), uint256(0x21b346f23a4309b9087f95101b4e0a7775257e8fa930c96e62ff82f0b22b175b));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x2bfb80c20b015d075713233420067a785b2e77bae19187a3bd9edb830518f167), uint256(0x1982915da747779216fe8b6eda2c97f8b5af817be926bd6470eaf4ca13ae143e));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x19c6477b6bd60dfe90d7cb3731ec8c8beb95ae8164d52c8e6269bffe53c7ccfb), uint256(0x213a0a40817f8a238a87fa5d475322ed9da96fe8070da75b8eeba89a2db31173));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x1532c6ccfc64f17048a31abed72fac6efbfed0e73548598fed41a28e8b2ab56c), uint256(0x042ae452606fdc346869b2241a43b0c57537256ff12d780c59c27c728d5ce97a));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x06a1ece23c30339b4dffe5814a6966d8a9e817e06a6bd2e9aaa51608e5c83201), uint256(0x17cb3bf77e7d65929ea178a6ebdbbc41e8663eef5dd3eb663e8b4b07267bd826));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x2c8d59ce47e1a703e4ce25ec0fdfaf991e2698664eb7a9659fed54cccd9aa663), uint256(0x22702216025683c625c242dcc5f0236587feb760dbb1640b0d115747bdbf65b0));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x2f401aca91230c5446f51aa7e7ce55118cd629afc8e75e00f965ca87bc0f2e4e), uint256(0x15bb64416905b1648571e3c225d8419f68d8951632f2a0dc07387d90bc5de3da));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x2915727f2ff7f3c0f074930c021ef011c1916490e8d17e572e2cc2534f0d1616), uint256(0x1d51a360b7408d2d6e9a3cd325e91de1dde640c82719c093da6011d17f9c9587));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x1dcefc6cdd5c42f9c56cbb1bce8ecaee16c38e42bd45aae82354c3d89e4285cb), uint256(0x2819338582ca575d8406dcc3aa7102a541121de7b90b19261214449bb04650dc));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x277ebf895ca2dae65642a2dc7b06e8396c8a8eb5295cc6a034da96ef9e0f9ddd), uint256(0x170ffc6a9ddaffc9bfcff77dc574c79f7c0da3584cc08103a7605a26571683d1));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x0adc6b98b5c21c3b1e7757ff9ad35ea9fd39af0f439bec144da0d79ec186d208), uint256(0x1d1e5cd81cf25bc415c501d999ddb1377514accf3e5bacb409467eac948e7170));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x0bca365a1d6bca04cedcae938eb4a678036e481ba5213b1758ba9ec473280d8d), uint256(0x266904ae729929eb02be0a74cb4f9cb747e04b433a73a6e6938d12666deba8a4));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x105370f83a295c86566ea7eae1c4f514d365b6d0c8471bdbf30d0c96146bcd8b), uint256(0x03ea4fa10a42f9ea9d3d7108bad53f4322fbceddce73361f27e8767933fd3838));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x2dec83cd5e39c761f22ca40b45e95d52658752d4b88a69815f80d71d031ee04c), uint256(0x1a35054e5dad2b9367991c7817ca7f606c7e31d11f938d5aa217fa4d357e100f));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x19be33a137ea005598ea5277de07a0bd0146ec1f0158551b337b2f40f583cd3e), uint256(0x30623a2fca8e7eec39f3ffff6dc86e4416bffa6bbc40ec9c3d52cd590a25d755));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x1a0cf0150e4735a9ac413a634fe7dc3479b29b11a316a765733a97cf260158e0), uint256(0x29c3f0baabad9988e2d7f0827051a7fdef0c349396c06e0ffd8fcf092e000762));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x26e44bf880639b4b98d8aae93376194293b84f49e6ec142d7af0098d675a56b5), uint256(0x108d8b3dd9c25a32f2672d4a505c94b23dd64c099f7aadf54cdc8f83cd1bd00e));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x1092262c6fd11b48b8b88db5a8fbcd7e8be690c12a62952c05e12ea9fc14a17f), uint256(0x0baed59692814314ba3b5e6b9a39bf32960f5ea09ae09b3119d787987257adb7));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x093ecbf63b47ff8766d9a82b3b3fc1e6610efda1c15093ffbceb003bc72c8250), uint256(0x06bc6ad9a03bc77b5b725707f3ae1f03bf4e10582cf71906118400e4adaac443));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x2c74cf82aba82499a668d8ad92f8f70361b7e31ac3b14a1244f69d36dc7bf9dd), uint256(0x149e94f5a77584fbf6f86c1838d5d322675f5c67921be6342a1f30723a2c956a));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x2931e36ef5a73cf40aaeb92b4411b89a265219945e1b5dd449b635e57954e68f), uint256(0x2bbfca2d66d0d91b6de08439c5f4e9b2fd2365292d2e5f7881e872e8cb401b1c));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x26e883815428ac5c473f127a46dc2ad5ed4bf8c0fffc6ca4dbff0403d2e19b23), uint256(0x01747628d5c6d08218ddb7895e769d66ac83858381170ffdff87a71161a2fc8f));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x21a502d62503ec0082dad9a5a013aa61a0bd9de2a3769ccc790adf6c91c0cc17), uint256(0x19e6ec5f90d03c20e6ef8a3d52f25c37f8f7475bacf8b586e46ce34e265c13c8));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x23f1cd9963c01bf5377b8d806c9ba509b3ca61107f97a2281938a2379ae1aad6), uint256(0x29d6825528a0dc4d0d4b3155006625fa2ae5a906e2a9866203f27783b89425f7));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x0e9dcaa0a4cf3ec60afa268db5aab2e4bbc8de9fedbb13efbc49c9905420b6b3), uint256(0x112dde42d5e1438c61346073eb2c008b170030e795660f53534f2c11c39289e6));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x19170a39f58d873ae413d86ac2d60d0b3d1a9c7d34ea7272e398efa251d47f59), uint256(0x024985dbfa84506575a95fbef23716c3d67f9bfc43dcac33299f89fb0ff25826));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x165212a64bda6c0045f544de9b072929dafaee3b9034ccb372c3bec003e57a8f), uint256(0x0aabcb3d596d4f887efafd5d0b5adcaf7cd0f5c235177418778c6918c97f97bb));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x2432dc04c7b361d891b3bf140094a831f8f3e5a2c55b439caa40795227703266), uint256(0x1db3e95ece9247ad57a801e415a25eab4c8cc2928f4d2c6564a1827a654fcd28));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x0a146c70b7af7be607c421154ccdd9e268c41599fbd2a23b0fd45877156761f1), uint256(0x09c31862995e6613db1925b3d4e8b6befd4ea3ce2e38f8b5845bbe5791fa7cfd));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x02224a7e356a1b315b96988c7946588c6b8ccbd775e55324110947372d5e1f43), uint256(0x2d69e791f4b09af14fc79e545735f8a2b3d9e1e274db48a19906ce5767f209e4));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x0042f9320465bfe7b640fc7405018f6f67b883172e255f2ce929f77f8ca02854), uint256(0x2281acbba5666888147734c9eaa307dec8b1fc24dae9839eefcb585ea53b8729));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x0691acab7799b7ab3c7762112b100ee19f93622cd20b6e974dccc32575e9d345), uint256(0x0f2a999b219faa463700089744f714226469242ebb078a29e22ad2b02c7de930));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x297706ea7dc4f11ad4eff05a77f23ad6f791fd01e9d4a7bd7044d549374f6eb2), uint256(0x0a9fab10d45a3263a63a0c7526683dd51a539d3c42f8756e859ebb229696effd));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x1a32d3d5072864113e3e49230e69614936cf2541641aad5ba435f5854c7f22ae), uint256(0x2b88832b01d1eea4bd285fc9a9a3e3647c7851a1d14851fffab1f6793e5b0873));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x25465c2058e4f89f362c7ff9f3c405a5eeb210defa17789c3dd71fadf9e89190), uint256(0x2c378e8922d3c28493c17068cef0cb25782dc2220c982686358fae346efc9474));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x16eb11104e7fdd4442c17a7eb5f3ee57f79518f773d999d85dbfcbe47aed831b), uint256(0x123637f0e1118c63aa35f46d3a7d394328603e3a1c003b4db8b952afae906331));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x1b642fa4fcb7885cbc54afd2f390e439a34922803cb93611e498a323a448d623), uint256(0x12a88beb5d8a59140077e7bf1c6f9fa6d5d64eec4a4a2a8b55e55c89390a4c19));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x27376894bfcecebc3dd4ddf3d51ed71365d8bf117e5b227f7efdd835290b48f7), uint256(0x0dbf1800c8b3bdc5aab36c90879e0bbc79aa6a169d158e24b6979955ab7f4f90));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x270d78b6e2fc5187f49f0df1d84608e9f3ff942b49262af8349c2c5426b62b6e), uint256(0x1feb33ba794c14d8e15ca55f8b0b64742594970a54ce1662381b97a62005dba7));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x011d08a34026848c958324b5a71d88df458d843e3374015063ad151c3bf31245), uint256(0x2c33614c28ee642974be0afe16a96f45bda263e3ff215f832da0c256757c2fe1));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x28d6404ba371fda2692ed36cad087371699cb51c6160e4fb582a8bd88ed70970), uint256(0x186a47aa83379839aa15b2652a92c98e02dd705042ed017f67f3a897570331a1));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x027fbd1bc6ed9abead37ec117cad7101b10e0367e7568d9d70bb2b63b6e21dce), uint256(0x2613352cd3c205a8ee6424693e8862aed79de59ed0f44894b7c155ff7138cdd8));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x0b38bb7be02298f2c97c75b71b0d4d7b58ecac1385f0e3beedda0d11cd96479e), uint256(0x1c694893c0ec9a924e619dc63ae1544ff8b462846e0f4f403113206bfcc0d028));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x09d88be72b3530c9802cfd98e519d0e779e77ddad19ea52a9f78ac107e127c2e), uint256(0x287b53cbe95665337a8d1baad9a8dcdbbb88351d95ddf5308c4288fa3f6630fb));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x0c068ad8a0cb6230b06b3c80b1cfcd71ba1218fa1a5c0b0e4f9549cc1c30578e), uint256(0x1c027e33577fa8765668b20f20424b6752292f684d1a50590cc57de615e83a8b));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x1838b3d4ebe2e9cacf3bb10f80ff6f22479f40726a8f1411606ecb314af0e9ad), uint256(0x2079789fdc66f5eaa5b8d2d6b4674293a9a240bf134b5ca737237dca7e25e2dd));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x2476732164dcdd0dc16f5b72381852e936b0b927f74ef618ec3671583a304f88), uint256(0x126d4b4cbb678000e1cafd62f25cb37d5e2c07fdb684fcf0f7993fcca01d12a5));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x0efe933e75d4fcd4f62c670c6e09bc1e0954ef943006cf11c694556d89d1d3f3), uint256(0x0c7044c965cc6a055e6ba2897597e50b104ed6feba94b501ce6e17ec7d22bb51));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x213e63263aa2c581b17aec9c6171206489afafd35ca38e082be2026cb38486c0), uint256(0x1a06a13d551e9f6c978b19c6835e2f4cc8a6e68d9349e54620b7e5e87ab3d773));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x224c46a333151b6c39a250dfc55e8a939b88096107bccee1158cbb6384cd2619), uint256(0x04c880ee999ec8b5d99be8344d6113872b68fd9e0c5953d7d64284ffe3219a7a));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x29a3577e2ad95745fb7dac5ed28d9cd7add775d3a03426b96f75240012ea15c0), uint256(0x0da0a5dcf8f7b6c5716612d257560290e54db5e4a403eda8db291941a89479a5));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x2d1e48308403f93b10ed01bb8c58973dd36f50a24a4c41572d93eb25bf0ed432), uint256(0x00c4c3a5dc80e36ec45f612362d96f0c11813d477312019e1548320ad54bfee6));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x02175e2de4b8da8bbab0b764f95c456cd0563e52f0f6c05bc8dbfdccad369ebc), uint256(0x1155eddde388cb82502b9fa59656357f7cac50de9dcf8d7c8ab3980c5724b7e7));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x2a1c77b0c450570b75b146bafa949c764488052eb3402053d6d5bab5359c7477), uint256(0x106654d25d9e3bc86ae376eec7af56516a428e5c5cf76d8cffe9bc519008127a));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x0e6719bd5bb1da7c4231286b859739d26d31d030cc20ac5c2cf5e47c488dc2d8), uint256(0x0c48be4d66196d16b826c1ac05fdd5ae0c2aff08f9c73d4d2cb21d76e3ca3ddf));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x278a64b98f9a52ac4efe7c2cbd48036b0a75618869137dbb15443aca5f888ad6), uint256(0x159596fe884907b350a2effc134f3f73c95abae8608d4306b2a5572c3bb424bb));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x21cc653c6b8a326c0d13e67b6cab75c982acc3505b8b7232a4598e7e31681e75), uint256(0x20bc97e4533d0db45686f7c0f9a3ef5c078d198bf89c4eea61d3029f48813dd3));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x1d7f98ed3cc37679a5e53a71a6dc7f2a31b457360899b1aadb12d3d492378236), uint256(0x0ae2e59ad791edbc0d45788813d9b64f0aa188c4936baac9cfddc7f078fef63b));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x23b84bdbc3a07ada2abfb07fd3410e905d958d63cc1dff6822ad8d072eb3017c), uint256(0x0afee93ac76937f7beaa4e56882ef885761b9691b49b001bfb54a62a58673375));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x01e1100db1224f2135792e2924531412eef06a2993ad6f310201663ef9280d6e), uint256(0x10be162e42dffadd0bc91d58b77e3cd8cd7a84a72ff2794616e36586f9d019e9));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x1c48960236dd28ec5ed448238c82d44d3045d3157830c89ec5a3e3fd74043149), uint256(0x208e22e64044307f7f01907eae3d2197adaded0b9b80ab03aefd919c3e06638a));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x08d59e3f567b2113ab7a1708f496ce5661728dbe98bc19e729ce4b414cc79edb), uint256(0x078392f54630a5e98030a5f3b28e703e33094da528affb14319d1572f639bf82));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x19e289964acdaabbbbbc0a363bc72714e2e72c6f8fcd495c51bb55ec72a89b9a), uint256(0x09efb6ed0cce6909e3c0332ba49f2a02f6a54a15f39e71371de4705ef4b9e5bd));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x2a1eefaeb179c40b987a9b212c50df2b5afe45ef5405a764e2f42232132fb927), uint256(0x09302e04e9d09b9dc667019dde73c10b6dd5239d0d1d5c4cb74e555335071cb7));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x133e750c0431ce41122e53fda245f206622e57b96bcdbc4d4d5d1342fe4cf03b), uint256(0x0b02e62271de9411fa0e93b16df45f07b528ba40324b25858f0bbba85b5f5bfc));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x11e1ceb28dd7f18dcb63efc9981d2c03467d5c4d9c294a353a24ddab0379f3ca), uint256(0x07faa2e834674c6eac5d0f93d052b0037c3e32bf7ee15ca27d24540c4d6cd2be));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x2a937665865295192d2619e0dee2de661f40b07af38c7105520f03e602d47264), uint256(0x04090788e4f369efb2a044ab5688c8a5a9b87bc24e701f67fa95c357cd7aa5d1));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x12dee86c57eda7be6029b3530bad9a0397b92336736aaae50c8e19ce2ec8faf1), uint256(0x1224d971ca63bb1f303bf8648d11568281e20d31b7567816191406dfa3d4a91e));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x2f6a99e635e249bd2d9abb39a89d35541d53fbeb5747b09af50d4f2fafbaf48b), uint256(0x07e6cdfd320f9b2b171e29aaf9fea247070485a2f63574492f8a8ae58b8c0762));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x090d98cda2923edffdbb6434150864fc920b6f96291141b92f487430b5dd5598), uint256(0x16e237ab46540163cb6a51dc45bd5ff8258f2e43d7c516ee5b68b763595d73b8));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x266bd1efc993d1e20a0fb11b4a8fe54ff11c9cf6e156cbb886e71d63b05eadbb), uint256(0x29afec154446b4a7a0acd5c7d34401a6c83af4b5cfb8904353bd704afc4a4fa4));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x0bb3d62adf13fe810dd9b68d9cb938aa5eb2143423d72d0a082316c923b98bf0), uint256(0x0cc7880f4eb3c997f02dadbbb4c93528c2ccf303db740abf1f1c8d70bb7cdd88));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x041ec1b95e623afd73f4174a49624863273e7cc9b6a77c2b175a5c6175164a46), uint256(0x1415f882cb4f633b8b1a08f4544e685d17b4dfc0c4139567dd9787f88b3c8f04));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x0522a4f519a3eb57980a57901c1cb60ad1122e356d734fa509f307949e77594f), uint256(0x109039bbfeb37da6d3272811fce54f6703a92611f860901d2da95040ef64872f));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x24f9261a15cf10db4277096c44c8fe31ff2977ca216306c18e54f858985bf816), uint256(0x05cbb64081b1d39e79d4eddf0834cd66a9e60f762e6cb7c944a955cd54414f69));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x05e6784afee6655e32d8d267b24d528c39457dda5f9170cb19c0546017cf266a), uint256(0x041c78da720c6fb74a8a97b7e019a48a43487648d3505cc35224a8c956c9b122));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x19796e2ca070e5bbc087a354a1f80c604b9f554e512ec4afe272453d23bddb8a), uint256(0x0802a99971426ec3326faed5a19e92e06e544118ab2e09d5c7bbdf7b65a11f33));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x1c79616fdd9587dfb448a1bfe593207f8fe73455000e7e58464c0c4f389da63c), uint256(0x25bc0d60367ca4dab921c16983220d19f1289ecc69c7e0f811236bf98492c528));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x22d1bb3c0c6d9d7dea5b208bc8710ba68c59388dd61ac175ecadb6e5b2d6f83c), uint256(0x19fab8d6070e85633f5d4fa9cf0e97057228386652a1a4759e52ad12824ba196));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x227ea15bd41f144f8f4c1c106a5f0c6ffdbd7f752325a7d1a1eec6602ef7405f), uint256(0x140cbf2f3d89dcb8ecfce16624e42e8d6f704b5421243bd3f783686f0acbc5c5));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x01452a83acc9e9d3af97fdaa65db66d39803e107a57f65fad6bd9c22892d53a8), uint256(0x24a246ccb130d82152326bec37de9d084123b5a2f6cc785e4edb03065ca324c3));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x10ccf9c676484b5db0e16b556c9c2999fd29f01806b64c43f70adafde87c3b38), uint256(0x270838f96b39a57ac43302a9489740caef0f19c61e069184ac179b7926dda426));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x0df5eea31f1774e0ca77759a141a8223df5612c9ffe3d1929a38d8482e6c108e), uint256(0x0bb0debdc87ca8f4161ab24eb4cacb032844aae33dd40abc0f487e10a585e60d));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x0fdda76354b6fd9e0cb80559f3e218adf15fc12234f46a326fa6690039d3a438), uint256(0x13f764aeedb1871342c4631e7cc5e558693951f01399c2a1dc94764db7f4837a));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x1763e80f351689a26ce7bd72df32f01a89aac09f77231e73af63f28dcfbaf518), uint256(0x1656c318da8d945ea0d10abd19141d84a717673892c504b40a3ebef915dc6754));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x067d05209016e7fc16b84f30b0f83047a08934066f6bc909cd0d3eb4469defc1), uint256(0x1a1bfb9908ef92ce08dbd634878604e2304b263eede321c9c3702ab767036610));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x00018fbaab824fb9e895904bf1425e910a4e1870e5799e578010bf2be0b87cd5), uint256(0x239b8656618684913e02c6baa5c5335155ce5c9f3b3dbe0f23e0154530dcbbcc));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x28b0357d9024ac1fada8e81c54d0fa9c8b0bf288ee7615ded9e8cecf40202d8a), uint256(0x00d6bc3a6b367dc0ae9329e3c01cf392a732d50e0d83c28d92f651d5b4442c81));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x119c5862717e87fafbf24d5eb8bd22899c86bcb437c57e576439904c53c62e2a), uint256(0x256956e1ec2dc289c62a6289fc18e89c87d1f9a828fcb53e8eae3cfbe597f28b));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x1bd7d8b50cf3583fd295227504704b76803f35fe423cdc030aef1018ef266447), uint256(0x10b1a4e1de3219ff7295e01444042afda4cdffc0423eb3f740fec7f1cd7d65ee));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x2b7aa9901a39c5689de7e5f980730d506e3c50f4b135acd87ec97b5c5ca96001), uint256(0x103705b1b6180e06a1f4e5088a26423ab3050d319265d7be013d0322d7ece0a3));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x30154cb51c04a9aff917cd7d462b5d71f1af8db1e4726be892bc34e5e7461844), uint256(0x233a0c6c1660e8a17ff60dc3ed4b137bd6050959879df1b69697b50d63dc2bc0));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x17d11c730653f83bf116fee5294ba92253c6b97d96f416ab283ecb31f9006cb8), uint256(0x1af56539319c199cf4822318b3994ca5b2b60dd576c9eb9736479e6cec75611f));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x1a4ae2c7e7b1e00e6b47c1bd2f8017af40fe011268fc448a78408d03a0a7d3ee), uint256(0x06816e5f2ee3d1828c45393ddd8323ed2d849f484ab6c06f0bbca30ceb6cd2ff));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x2e06313d74a70126aa010c8484cbae18d493d921ad8c97fb9cf2865527584246), uint256(0x2caf7d4ad603c2472fb1ac3242f872da1d04253e803ac2e5c34c789b4014eda6));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x28e0b906cd0eecf7090d3974222905321471b09f3498f732a4cde9408b030461), uint256(0x24105ab1344e527c8f8dad3d9c3ecf546d80127bc723706a81bb8b310b261750));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x0c07b28104ec02a031f62a84b47754473b63d844f414f28df791bd50144fa211), uint256(0x2e68609200d9eb8546e0f78cbdea22f050e133b44e98bc907199a9c86f0bf0d1));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x0c419b0182448df48d9a77db45fd1a7f099c781bb7589c428e568aed95f31d8f), uint256(0x2d167faf2ab307403d0a0638a4ad06a5d47989fef567c60c8e840df78ee59f88));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x23f1fda930df67ff10f2a4d9790a0de2b99bc04a53023c3b305a6bee6918a1d3), uint256(0x0ce824ddf7e19e2fb7ac7b670ad83b2e459b44564256a428462dba9e4945ffc9));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x16837770c25030446f9b8c34ea8f5c840fbb3ccbba899be6e77f031b19da4487), uint256(0x3055606a2ad703b89acd8b62a2dfbc095785078b738c3ea031707537241fc465));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x06041af66b287e7808899f98a692b570c71c0f378e6b6fac9e52e60e4ee8267e), uint256(0x2a562d6a390c13da512e473e8f49c26afba5cc9543faf13115687708b73ae0f3));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x1511d3a465b840fd95e095d61a1de5c73712084e808326f9ae67cbb83bca968f), uint256(0x1d8da58f838513027300b34be360550aa346595c74916fa033b9ce60e4cc34d4));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x27f27d280ada9bc562d11909e70cdd937ec3adf719a5d8d1af871917c9920c04), uint256(0x21e4bb116eca0c269607b486be1fd15afdcf7fb13354c78f2802d3654eb046b6));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x09943f808cacac3565bbd05e8a1c5f83758baeb57f99382b285714e6c2d91ad8), uint256(0x05fb4c972518dd8997a77402d9685acf1f8f7192ae50bde96e0d3382464fb92b));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x24b86f106dccf762f3f441c92d38a99afc74b3eb5f8b8de2781cff6d70308892), uint256(0x1fb9e75b0609d2f74b8a952c4db1a20d0b0d9c6b396184ba71a8d052a6e37699));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x027e3e16012659903ea46fdb821cbbe6ab7bfb4eec0f66e1efd6c3c19f3d4ff0), uint256(0x0907fc85a548cf55d75af8f1cbc700cf1540560af3fc5b3e685032fbbc54f870));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x110f9853716701062518a7a39c65def65e70f5243ada8530c3e14973e3e213d1), uint256(0x1ae40ece9eb2f4c926137ba7da7f9564c9e8732a4db0091eb7321064fc5d18dd));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x1fd6f91ccb42a13a733376c311b1f8e90530aae831b297f35d861b0fcaab50d6), uint256(0x1bfbf56c3549fb5a735f28a0d2b3b824d6968d8903e5b75abab538b4b87cee08));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x1644f1060c8c2874b3856813481eb0cefa85b6a81ef3986d5ee710e6732fb25b), uint256(0x0cf13e29c62a7a0ec093720517422970aaaa255d6ff65e8529a62849d516b991));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x264d83a1b624fa5dc859d377417fc4090e64f3481dfb18586dc73146e68620af), uint256(0x2acc7b27172168e244b5445196356b63aa6314b9473a8ae158fdc5e30b565c0f));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x21c780e65a135647fdb0c23cdbf05720fc38b7eee8390ee8a7333071cf24fa2b), uint256(0x12bab3eac0066050d0a5c2a6fce503641b62a132eb461616da180bca2ff7a577));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x0b3d126e3bbf70e6feb9447d3151ffe14412dd4fc34456e19611c18844f14fd4), uint256(0x12109382e9a46ac051c5d2f0fbca5ad4f1a4d577d89d762920fb4dd2d8a77338));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x0f8ac7412dd7c004ae2b3e8ba29b9c50b16ac42492371bbebd2dd73f210eb663), uint256(0x24e116221125118f0d060ca6cb051785d8046eaf09b28fc13fe43e9928d465c1));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x21205363e17700864dd7bbfc588740a67cfdbe155b6cf657c84fe9b83a7ee136), uint256(0x0958022713d61394e01e0b8010a3e1f76b312a1bc85b4820ca0a89d1d89012d7));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x0072c491d323ca6112f38695926e539569c0b0f15f1fbd44b8318d91fb32463a), uint256(0x2e93f500a2f70e2f757ee65eb9397b8a6efd8749096f35212f2af7f588fd3e6f));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x0aab2021a54876850dbf7e5181d3dab64755943352de87c0c0ae7476984a2ba7), uint256(0x227842050688da957fc2241cf29c6c5e60196b542421ce9055a046ece528f89b));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x068b076125708e0432aa860772156e5d61f3df559e2803528635fe95235933e2), uint256(0x28f94654551bac53e072d319370858f0b26df6be8e1edc4f134f131dd623385c));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x195900ce994c4346d4bebccb4c9f7fefec500509430fd39c296fbb465870c4b7), uint256(0x0fcf92d459f376af4bfe6260523643167d237da6ec143f34223d0583dcb42ec9));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x2453a7ffb6cc6b3cf3f70cb752a1b1038535fc9bb14288c4148f602b9e79d146), uint256(0x14c2537c3cca43b0bb303e591fd2b9ea0c2df35673ed6ca81fcbbcdc4fd32349));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x14b22df3961c73ecd886948652cdc0a357f1b301eb2410a137239a271e08cfcb), uint256(0x1c0bcd254438c60d8c21dd9cd84e464056851e0ce1b0347385455c11cc139702));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x1a3a9b0fd225ce97a50135c22a6fd245aa84b4c1a836e24708d90ae378fa8d06), uint256(0x2a3c29abdfee857809ade466d0d2593a917cb68398a37a5ea13b59958cfdae25));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x117cba67cec99634c0497e43ecbdbc0ffde2f28203508117fd2f345924214867), uint256(0x12ada48fa920a29dac71020ae9688a82cb9981fb230112668f591f8152e16b78));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x29f6dbfbd2efd78f6a3cc6c44323bd9897cc66c933dd70bbd6afc1c292630cba), uint256(0x2a54bc5fc06db13db13c222004f67168f5015030be89903fb0410ad036c08e13));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x296ba0b8c956eab11a9055fe3da62897a6e6fa56667d20087e575406993f0be3), uint256(0x17ef4c652ae344b152a609079404184c7bbc0efff96e9fb54b991f7eece286bf));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x0cfe38139b67a31edaff16423b053772c71652b2fcff861ff2f64a79fd0e30f3), uint256(0x2a52165c23cb9bbcac96f6d2d09bee2fede18b3ba660e4c44b8feee1f316dcaf));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x084c2bbca69e5c070bb40a2793d8bfb48245356991b2412fae38bd8c0f8e3794), uint256(0x1e36bb001987f5c4a25a3a082f8c44db00bb11264e875a4a0731b68347481762));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x0f7ed7adf3b2fd6aec7bae2a048feb87da23825fd322e447ff83900ecc7db9b0), uint256(0x148f987c365bfac6b5292a5852e97b19fbee712a3f832347177941969d46f0db));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x1fdb3418559bf5b358a67ddb3257916287995db2bd77b92c5ae97da38d7f6e51), uint256(0x0a9e44e329e325ac3dbd6fa96b321f6cd5c208ce7260b86dea3d187bcf4923a7));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x21f41b9f5eebb787cce454b61fe3359232dd69a2fad98458cb44442ffc5d5f84), uint256(0x1dd081db089690f5b3ea5e01709c81e72999230187d338739d93fc71bc776197));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x00915ec537adfacea01dfb7a41c5ddad2daaed402cd56cc794ba9897b98435eb), uint256(0x2ea7a5f1fde1867cfe7e7856e97dcf662dee8352784397257b20bd5cd42ee19b));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x18580dfe224f2c240301d5678456e54fd2bad2f6514568fbc1db58f2bf39c77e), uint256(0x1fd4d390014ac2d65917d5f2d07594e6875296181677a059ba7206bb80b212b2));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x0a33f918531a39e773541e82e6fcdd6c86f2c558ce47c09f59532ecfd93a2869), uint256(0x1cdf7f884b44fdb36214d1bcd0297e3e879b221baf6d10a967f31eee53872738));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x21c44388cdca9b57c9c3912a94edc6cb79e97b7761f7abb5fd6986c7510f3d5c), uint256(0x17896bd5f1f48cca45c014c1b4a477f826372d6155227f43555b72e6997b3af7));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x2ab2ae90d6f01f414c6701aeb46fa84a7d7fc27f5dfeb1e068cf102be292d449), uint256(0x0e03065edd74a4836f309f18046ba315ad05553d6a45811364e43bee18c8a493));
        vk.gamma_abc[202] = Pairing.G1Point(uint256(0x2323521e2ad252d7f10d98a0f4a0b02767a4784b1a1d605e7d474dc0d8c52cfa), uint256(0x24372a67801e8188a2dd3756cfa7f2a6e1497b7e16be230b98a2107bc98a8c31));
        vk.gamma_abc[203] = Pairing.G1Point(uint256(0x01aede1ae71e621396729227e69081dd0efb469595506c60090b4dfe38e8eded), uint256(0x0059ef4c0d3649ad33bd2ff819355ea2440efc87aeec7bd122bf0e6cb26874ca));
        vk.gamma_abc[204] = Pairing.G1Point(uint256(0x208767a6b8df60893c51e47be81406bfff22514f123ca1227ab2a71970756bce), uint256(0x084680a1ba7518465e185b8a263769866f182026bce5b26a6ad42ba4133a48bd));
        vk.gamma_abc[205] = Pairing.G1Point(uint256(0x0bae6ce3519576436ead10e47b313f9d913c70873dfe922cde00c0c017499511), uint256(0x0be39b460148a10e43c7bfdc05d2a1c74d990568e0a152656943d716a0970758));
        vk.gamma_abc[206] = Pairing.G1Point(uint256(0x2bb3336b5ab33957f8035645f57199e0e4d3b13b5d6205470e66e283abfeff96), uint256(0x0bb1417907332a13da61c879d53a2810bbce9c0d2be8545a87de41185d4c3d81));
        vk.gamma_abc[207] = Pairing.G1Point(uint256(0x3025d5d61bba574602cfe4a21bc589bf0c1a0642d1b89f7eec97f33546479fc0), uint256(0x02d1abbb2b697ab698c3574f8dbcdd41738f88d7bee4ee2df17d2459b086e3fc));
        vk.gamma_abc[208] = Pairing.G1Point(uint256(0x2d340b5f6d1d39490e9a54f75f06fecafec1a87f421396d244e2b9d52763bc58), uint256(0x273194e07ea10388963bb52e5dd42004f505c72eba557b8626d9ac656835de2c));
        vk.gamma_abc[209] = Pairing.G1Point(uint256(0x0ca5a41025fd8d7859007e744c0d5d6fd040fd9a32ea05b32802af2290e01ee4), uint256(0x2e3ebc1dc23eb3924bda93b513b11982a74c724ad7a514338ee5da713de58f03));
        vk.gamma_abc[210] = Pairing.G1Point(uint256(0x2d4cabb3449a00f8af8095286ac0a816d9a3433f563dfecfbe7ed5f62bc302e7), uint256(0x15f743aa704b068c8e21d11db10838d5fa552e50087eeec1a67fe37a3ef16b62));
        vk.gamma_abc[211] = Pairing.G1Point(uint256(0x000ebb6bca69dae4abc685375ab70f6ab1fcda8bfeed8412570a71cfa175eb95), uint256(0x0afad198eba5d1800ab59a68344b2b0250b3ed6feafb14d4173d0e273d93a294));
        vk.gamma_abc[212] = Pairing.G1Point(uint256(0x05fe913bbdd964d518adc1482435a9b70607c1cd8c38b4b6362b3cc3a8a14e26), uint256(0x1ab2e1f7a8698a5742571ac5b7a26b13de3732f9da1ebcc197f49f1caa99f670));
        vk.gamma_abc[213] = Pairing.G1Point(uint256(0x1d22f6799955c14acce3815d8b13f5fa6efb7948f87f24ce0c73abe02c4ff6a7), uint256(0x18d776757d32ee4048284dbd4c65054e8d1efd09b55b65a3340694f0f6a07e69));
        vk.gamma_abc[214] = Pairing.G1Point(uint256(0x1242e544dc9d28f642c104551698b50635e1f7a338b8dd99b828cf3ee2a2fe2c), uint256(0x11a324f729f4622ada67c8167e791ad63b67454f7bfabe3cc628da184cc99c28));
        vk.gamma_abc[215] = Pairing.G1Point(uint256(0x22e46e3295a0579bc3382958876e63b6a54f622da8a3206e3af9f7e6af132046), uint256(0x0e6f15b3647e5f20858054f3814d4e94ff35913ce4a096b22773ff9d1511892f));
        vk.gamma_abc[216] = Pairing.G1Point(uint256(0x0a5d516d167f74257d1359e31db90b05d5e10f7469076f341ddc3bb3b55c1575), uint256(0x07782e9e72f62d4b05deae076f79eb192cd4bdfcbf0181a73c0da2beadc542c8));
        vk.gamma_abc[217] = Pairing.G1Point(uint256(0x192fd6f779173214b64bf1de94233054d460fabe2aa0fb9bff2dd3cd4ac6a5f9), uint256(0x048f2a9a29b617b5814122cdb0eecbeb90160775684cf87eee3e7a4844a06986));
        vk.gamma_abc[218] = Pairing.G1Point(uint256(0x187fca78a29c09e241d1692d9702c09f15e862e6eef3d39e83e01be2773bb69f), uint256(0x2af926a6095333ce71e01d98390d286b10d2409299ae1629b3394f9f2c8908ec));
        vk.gamma_abc[219] = Pairing.G1Point(uint256(0x180e782c4573fd51d5bb0d8cd91950c780ab2231db817af98d5dda11daa3b7d7), uint256(0x1b169404dc98631339b43eb0d772382a412e8d490d4133df968428facb615b5e));
        vk.gamma_abc[220] = Pairing.G1Point(uint256(0x0d982b091d4d710bb1b99611a2162541e2b988054c264b4753883ae48d72e770), uint256(0x1703def5f8e6d2ffcf9c7417a7bd633fa06f14c1629049032b1eb69d6846b7a5));
        vk.gamma_abc[221] = Pairing.G1Point(uint256(0x18179c786071dbaf6b5d6591736441c6c638aded117de5a44a261e4ed40ead11), uint256(0x114c0b7d25a48c085b73ead50fef4d5395bd838ef6bd2fbab33ec31ec40423b7));
        vk.gamma_abc[222] = Pairing.G1Point(uint256(0x04d96bfd750c7c75dc7883206cfbd8cc157e371b515b812fdeee766be36dafc5), uint256(0x21a533e863a70493a2902cfc40d11600c696a3f428a30cd7210f0ba9cc663ce8));
        vk.gamma_abc[223] = Pairing.G1Point(uint256(0x0789fda0a12962268b844b1d591a281ca59ce26af4e7054577231beeef3f0948), uint256(0x099130a7c5f0134a2e5ada5942a3d2644859ace96ebce53b3a7b0477c06e7f81));
        vk.gamma_abc[224] = Pairing.G1Point(uint256(0x23388a13ac2eee603640621251d6884fb1c6c5f30cf77b9688bd380a1ecb5f43), uint256(0x237b417567d9f950ecb3fae13a01b801591bd4ed979ec648c0ed68aea476415a));
        vk.gamma_abc[225] = Pairing.G1Point(uint256(0x27d7c75995310585994a3f2fde5e3b185b4d870912eedf3acb057b2c560e72c3), uint256(0x21d69311e3ee9b15c827bd79fd397c119c2bc48a8a072f982f87838ac1c2faa5));
        vk.gamma_abc[226] = Pairing.G1Point(uint256(0x1ec413cba19e4a08d2c0185e65567dfe5c68b7a1699d782092942e257d765fe6), uint256(0x179e82de1e5fe736110eb4d8ee96ad1b311389fcc931827cbef35849eb10a266));
        vk.gamma_abc[227] = Pairing.G1Point(uint256(0x0e4149c7d4c047cb11c2e71fff599ca6be8e378356bb9069aa5dcbce3c860841), uint256(0x2a5b22c5075547a4e0c0b810034c3cf74ac94c917e36a00da7be67f1458c81fa));
        vk.gamma_abc[228] = Pairing.G1Point(uint256(0x14f1641169c470e0dc7f8c88a832cf7836a99b2e0b78b2f314712186d970bf19), uint256(0x0ca693fadd9e9d117cd4d1e8d86ac8c86a541459e36eb5a870fb1417c1f3f8d2));
        vk.gamma_abc[229] = Pairing.G1Point(uint256(0x168c0792303297c629be2eb2f9dd46e03aca1a6de93e3e924a1e2ae92133b68a), uint256(0x15fb4f791a99a2fb1388c17a4cd0f34c5c2da771ee4d9adbfed3931c94e1d86a));
        vk.gamma_abc[230] = Pairing.G1Point(uint256(0x2793e362bbe06e4d170992de3100bc5b31944237bbd9c3a138c4248df543200b), uint256(0x26b4045ecaafbe757b0dda6eabb3e202a354d4a43c22f0ef8f910325de6ea5ba));
        vk.gamma_abc[231] = Pairing.G1Point(uint256(0x08e621218827f875c386d7a63dd449de50b9b34b9ce7372d78b351c087887c94), uint256(0x3043e2fb314611bab30450b7e70962ee1a363f95a9c9eb049eb63ebb4056fb63));
        vk.gamma_abc[232] = Pairing.G1Point(uint256(0x15e0eb9c2a5129ea509dfd9800fdb1796e861a182cb3877de7e3c29e0f82b89b), uint256(0x00fb25a2bcdc3e6ea8839f00725a4a8e86fd1a1e4f5c03a8643089e546751a8c));
        vk.gamma_abc[233] = Pairing.G1Point(uint256(0x2f79a9856b38367d6a645f3c47d9f7f5d4eabc8778949cd378549772e412a9d3), uint256(0x0dd085b4a365e6595e5468a7641899c5ed3f188e3086fa98ec768940ce5827e1));
        vk.gamma_abc[234] = Pairing.G1Point(uint256(0x3044135bba465ec28b709867a008d9a339d69dc26db5b3bd9baeb83ce5d09566), uint256(0x07c9fc368a060d26ff23a70206be017a45e36faed6c32ca2b3ccaae5100a89b7));
        vk.gamma_abc[235] = Pairing.G1Point(uint256(0x127e143407a0d8bfbbe39a94dc2dfdfe2c8216f5a8713a42c6b34db0ce3580d0), uint256(0x14a406a829129f74b2f04175dd751d00292e9197946cc79b56927726f655e9b4));
        vk.gamma_abc[236] = Pairing.G1Point(uint256(0x0ab4189f9b2eaca5db4a532ff8894cfde80b975032cf9180eb18efe86e028021), uint256(0x16db87005e3131b8d7f18848133c3d99f89719f8928f47e001abb1b2a670b626));
        vk.gamma_abc[237] = Pairing.G1Point(uint256(0x0a4655000b9d1fdc90962a25459858423d902b1d123e89cee9bb42c083ee832f), uint256(0x29947d9bb2e48a745f648558dc1a3268a6445453d34ec4b6698052d8f58fcc1a));
        vk.gamma_abc[238] = Pairing.G1Point(uint256(0x0914584ecc4325fa3f39d0fe4acfb9e4ca42c48039951ac755f578bb44d6efd5), uint256(0x1a9bfb4f967ba216e200a3952dc98a9637297f014275d594b0d7248d91468eb5));
        vk.gamma_abc[239] = Pairing.G1Point(uint256(0x10e0aa3af1d9e834ca6e9908ce4908f03a743e4160cfad7c16fc972187a0250f), uint256(0x1fea9e751236775867793023eda17d78a24ae267fa2be4e7e6baa0cd0458d0cd));
        vk.gamma_abc[240] = Pairing.G1Point(uint256(0x146ac6cf3584561761f8bbe7de0fbd4ad83034f9a8d225d16e020f7d2dff1fd3), uint256(0x1b1545a1c732bde30674f32c121843ce4b436c0e1dc58755633d9ddc8db40c5f));
        vk.gamma_abc[241] = Pairing.G1Point(uint256(0x1cbc53dd9d3d0650c703592085b2a4c04ee84f23497c277f0758cc3de0f47902), uint256(0x14df2a7ec58b4ea1025957bdb40fbf7f59aca6e72d32c49b8367bdcc3e887b37));
        vk.gamma_abc[242] = Pairing.G1Point(uint256(0x018ae04a88f4a7d34c71376b12c32c55d78d9c6b20af99f0235039190796f194), uint256(0x123afa2197d1555fa900ea7bde80d9f55a6203c496da7cb986787d00287f09af));
        vk.gamma_abc[243] = Pairing.G1Point(uint256(0x18d2c1dcbc01c064037b7b0277bdd8f4c84172ca7369de85cb05196538a09384), uint256(0x16bdbf33742bcb4736a366be230f761f2555429db0d278f72357906b4a8e4a5c));
        vk.gamma_abc[244] = Pairing.G1Point(uint256(0x1c56dc9084508c8b0b4a4a7a8f6d9198ad3003d65e8948db9e8c58c37aa8d971), uint256(0x0e1bdcec91f935fe9294052ede93239ebe4d1e6976f87085c7dc1dae8edddb89));
        vk.gamma_abc[245] = Pairing.G1Point(uint256(0x25d829f981e7790b04a41d05596c2d3165fd34394646bc867a5be81450b91531), uint256(0x1a6bae35195673c599e7a2d7627a0cbbc068ea5f4db1b54e906ab65d833afdc4));
        vk.gamma_abc[246] = Pairing.G1Point(uint256(0x16c033868edaf1c80657c2a844019a587769c717d873a9deb792426cdab21007), uint256(0x180dce147da3adbff03b19fdc4ef818e2eb1a82e046b2811694aaa64adba033d));
        vk.gamma_abc[247] = Pairing.G1Point(uint256(0x156fe87a0c0b5dc79660dc45e7808b46e6c63879381314f45e11651806d137da), uint256(0x29e114a5d0e73816ee5dad83cc6b3c5ca4d509854d7aae9e505b91fa0beb3d53));
        vk.gamma_abc[248] = Pairing.G1Point(uint256(0x2d6b4e2de32f5be9bc014dd866b378b69aee753da805d83b13ca3563127e1e8e), uint256(0x211b982be35146cdca49b770949fe7f78332fca7c4ced21e9f7c6f8818584fa1));
        vk.gamma_abc[249] = Pairing.G1Point(uint256(0x120ebd7c61e05dc4819e18f67fd70ec6322f65ae57a351911db806787c520199), uint256(0x24b2a5d8a346d81871c22ba5a906ed4b6dad0cd09919f87b52007959a0e93ce9));
        vk.gamma_abc[250] = Pairing.G1Point(uint256(0x2f2a8b194046b19d4387c0005a46158b5a74f20f580a9e6d4639af537011a58f), uint256(0x24a206459c2fbbee4d4e0a71fb4bba4fa672107db715315280b29f84a7d1c8a7));
        vk.gamma_abc[251] = Pairing.G1Point(uint256(0x03cd1c48dc505a674975a6df5e05ff0e2e98948698c05a08f67f05e27e274986), uint256(0x188eaa0052c9e0da1cd5011653101d7fdec7a4b388e22cd5e4593e62c5b38894));
        vk.gamma_abc[252] = Pairing.G1Point(uint256(0x250811bd9453231b206dcea260e17c0b69ccde257a5805843c6f9d9cb7c4c209), uint256(0x28c8e3cbbfe7adf32d1ececed25dd9fbd691457edc275475cb84e7c4d0dc5ed9));
        vk.gamma_abc[253] = Pairing.G1Point(uint256(0x0f8e6b0201df6c87b1c07fb7dcd9bab105eae1ce927abefd96ed5a18f2d1de15), uint256(0x1d38f5138884bbb0b21451affb70a8982621587b5d77f6f4249ff4ef4a68e88b));
        vk.gamma_abc[254] = Pairing.G1Point(uint256(0x042635f8b9973f41d59b84817725c10570f393d7204204fdacec13d8f3d21fe1), uint256(0x089a839a6c0b012a7cab562f022be30c39b01018172378645c79885f74f6bc6a));
        vk.gamma_abc[255] = Pairing.G1Point(uint256(0x00e3d0f1426bea7f60623cff04fe01b5a615b6cf9833ae05ae0c94fdb1bf7325), uint256(0x0422eeef8d03a09c1ea4929c8a447aa464fc1b5421ad7a9a5b8acdf82dff4655));
        vk.gamma_abc[256] = Pairing.G1Point(uint256(0x0b9f5d90fafee45bb9d5bb113775dbc00c0865e1d618355735d7de8ccac1faed), uint256(0x25d3fa2a9bfcb9a6e7686f321a57d61ac44eb97cbbbf296b19d83d7c5b04640a));
        vk.gamma_abc[257] = Pairing.G1Point(uint256(0x02244ab8ddca574474378c89d4bb9e8f5c4b46b4a323349c9d9d0991dbde9150), uint256(0x0e97f5c4ce857940febd2e525d6824321e76e226e6de2a4d87241fd967ddbe2d));
        vk.gamma_abc[258] = Pairing.G1Point(uint256(0x299dbfa39f4f85af515b4b53440b7fc84197df1d63bade5d89897ed4ad408fce), uint256(0x241f75ce9f0e39858b57c4389d2f35b40f8c5c56357bb36f7f6bebd071fec687));
        vk.gamma_abc[259] = Pairing.G1Point(uint256(0x220a0d8fca369c2d5a9cb28958997445b89892de58dd1c95b44bde04ddfd9e60), uint256(0x22fe6975153e5c51af8afcee6febb2658d734e115143ef70f2939a3e8682af5c));
        vk.gamma_abc[260] = Pairing.G1Point(uint256(0x09dca00bafe14249f5b0bcb0028ea8960a024556c41ebac76a6e850146d3ca66), uint256(0x1cffc3493998e674a52926184c96b771649eaab44cf74816605d8e9d2bd0a836));
        vk.gamma_abc[261] = Pairing.G1Point(uint256(0x0812e9c00ecbcd3930ebf1d260ec81804009f58c4e1bda09581ae2d317cac28b), uint256(0x099a707916693018df990553ba44711762ead5d9c87e13e2631936ac6930f941));
        vk.gamma_abc[262] = Pairing.G1Point(uint256(0x176ba6069decbbfb63bec461108350bc3ed27e816c0ade012867266e5397cfd0), uint256(0x21ab91862f112de10ce6f26c7e1d51a8e217480462126848859f7fdf37448f42));
        vk.gamma_abc[263] = Pairing.G1Point(uint256(0x1f1030e1c795199666373d33fe7362990ab32a6aabdd635a55b7aaadafaa9f32), uint256(0x240dd0683533dae5c2452e01cd959037b503759d88561d4f8b6662c97a4c26b3));
        vk.gamma_abc[264] = Pairing.G1Point(uint256(0x278ec373c6d5d28f9ea66c195ffb6cea4b3ddcacdda12c4bcdfcc96286505c8f), uint256(0x260919493b47f5bcbe8120672b680723643e138bd4d886f5bb4fc31b5802fb44));
        vk.gamma_abc[265] = Pairing.G1Point(uint256(0x0737184d436d36568498ae73dbee1a11e95f11aee66362a96fb21c2555bf56a8), uint256(0x173c5bdccac3edbb10e2ad352d2566f438d0fe54cb0a019df6dd1a70e84aa015));
        vk.gamma_abc[266] = Pairing.G1Point(uint256(0x21134d4c783a2849b460987c508006b37cff5ee23a1e34100d29699245302f13), uint256(0x0b991ccbac78741440e3cf43918ba34f30b1f25d09693bf4e558c987d493072e));
        vk.gamma_abc[267] = Pairing.G1Point(uint256(0x0b1ad9f6c1a578af609a0cfb100d27f54ab9b0ef8315e231767ecdab65fcd8fe), uint256(0x2aff31e25c6caa4f14891153650ff44b310be42d6a6339a0cf7b2c0c978484b3));
        vk.gamma_abc[268] = Pairing.G1Point(uint256(0x09fc1e7295101852ada115e5364c139a0d6c04f5322bd50e39f699a401bb316f), uint256(0x236fe4932d87d741aea9e0393e057f7f0b271cf0115d403edcc8035fc901a92d));
        vk.gamma_abc[269] = Pairing.G1Point(uint256(0x1088167dd3a54ec4f2e9ceaf0599ee5a5a16e2d8866dbbcb494ceff7ecb35198), uint256(0x143e662c851f23f5702079d4535d44ad9c62a0ba9995f9f5fc6a19e472964ebc));
        vk.gamma_abc[270] = Pairing.G1Point(uint256(0x212994e78cc5da7cf7f7c4f72cb40460744c524626596bab9e548221d7516d0d), uint256(0x2f4482aed22bc1d9cf8d06006cd4d0b10b74ca34393ab4192cec160599c43070));
        vk.gamma_abc[271] = Pairing.G1Point(uint256(0x1ad63304e1823fd2a1b3587dd70fb934a28c43b81ad763d40aa4d1eb5b5d3096), uint256(0x108b39542cf51d08f5bf0604a7471d3a763f9b03d76d3e04eadaf28bf2987384));
        vk.gamma_abc[272] = Pairing.G1Point(uint256(0x139a021b8bea1e3e3707b85716d962fcd86fcc80611969655ccecf2f83513b64), uint256(0x2a3287e95944b99d4977e39ebaf992616f8797f740ef5e20791ca8cccd4fdde5));
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
            Proof memory proof, uint[272] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](272);
        
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
