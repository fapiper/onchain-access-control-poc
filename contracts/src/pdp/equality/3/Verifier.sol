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
        vk.alpha = Pairing.G1Point(uint256(0x23f538da244ebbf3478e2a345a3fc6d1c745483e84901e4b382d75ea867cfdcb), uint256(0x2d72aa7ab1a6ab22e37df36cdad314750319f63f29b1b0bdb5335e685e6c2f89));
        vk.beta = Pairing.G2Point([uint256(0x0f0b41189964d64d1fdf668a68ef79b70569b9337d6149e45310c26aeb71eca0), uint256(0x1d7660aabce538ce865fceed168e91bb3ba4d910f65e59e7317518093289da87)], [uint256(0x1795df16f5643aa01d7b8705e07e131fbbbbbd603d96490fbd459df199b81652), uint256(0x1b7c34c3f1bf44d68323ca7feea06885cbe61045d7a89fc0b1036db1d441fac0)]);
        vk.gamma = Pairing.G2Point([uint256(0x2365e2bf7f4b18aeabb059fcac038c2835c18a5f0e28f44c97f8f47e6e6dd01d), uint256(0x1d09397ca3a4c74662c888bd93ebe6314ea3b50b979fa80f92627fcf06a62dde)], [uint256(0x17f87851b925b5e0ff3091d0a9d26457552e0621d08054627b2b93bd05febd23), uint256(0x10e0431700325378c65192c526026f5a51a349d361c10fe2ed59e39dd536d10a)]);
        vk.delta = Pairing.G2Point([uint256(0x304afdca13ec924c953749c9d8724f89a7f372eee50cfffaf64454fcf07115d9), uint256(0x1b0a37cf4bbfa8170f4c5b3e901029a46a35c7135c87258908227b700705c9fe)], [uint256(0x1ae89ceb044337b35b45bb9b599aaf7eed7615d476aeb01ad23216198c66401a), uint256(0x0908ad5d4413082152abe177d9406ac5abfa8d5c30f54cf8c9a1e35dc016efbe)]);
        vk.gamma_abc = new Pairing.G1Point[](56);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0b2bb5b61572829d07f830a57b6974321621e1619def85ce9be9502c076f1df1), uint256(0x272f0d2f078ae0cd3d992b62524d823c227d3329eec40566ff0b09ef9bfc1e36));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2868a5ab84d8977755d71069008de9c301c69356e8abf942fb9232b5eef0b4dd), uint256(0x2775c6b52ab753063ac9920f2c0f2647c23ead5108e038814dc4c771d78c593f));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x19c8af3519c012be07584e6fe81bc5697d19314fb6e1992f2ebf8bf91b0116be), uint256(0x2d58fed18eb3dcbcc58296a575e29d95eac1b337ec18d5dd898d88a7d161faaa));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0531cad9fdb6eba35e3ac23e8896cefa0a5815b24972d7781eda01af3b7c9596), uint256(0x1d496d30d5d27ea03c93aaa1b2aa0a2da55e39f0c6b84384b193bc12954b26a3));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1a2c90d3c492aece3c8a3775f17073747ef14410fe65d98280c6cc37895a3080), uint256(0x22fbdc902278a4b96c388dd321a6cdddc77816c09a9bcce1216c532745462610));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2e6b593abed2970261442987821bd9a5d781755587ef26b52e1324748ba4fbe0), uint256(0x112a2fecb27e6a266e9b38572ba5e0d2fcf11c329ea4f927c411a6866195ab8b));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x2c2462c32183d33dfa86aa50a0f7a893677a87e30a62812aac9b53d0c72f3071), uint256(0x122d1b7d302591341e2e13b290a66fecde3aee517074e00391193540928f91a5));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0a8f4c20a04786c89bc3e852dc9624488b737301f841e95f1839a6b7177d1b24), uint256(0x2cd874c1828bb993f4370d42d156d5b67be6be228a25e93def76dd92554e347e));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2b943eaf39a5021d373251470913f434d8e573e3d35199015609f83f4d957abd), uint256(0x26a563606ff99d0993c5f734070dc3da06d5dc2728421dcba7302f3f201d0d87));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x121d34ae7eff96512b9dcfce6a67bc3d3db2be1e1a0eeb29efdbffdfc2502c3f), uint256(0x1708f26eb3801b160f11bb9431b119761661152081310f702e73c776595147ef));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1ec2eaee14d6d09affc9c2c92eb56db5ff74c4077174752af375ba9aeb3be03c), uint256(0x1bc82ebedad78291c7b85c78bab2c133cada07e7267ea6c292122e54d5e43988));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x29bc3acd3366b81c2f6dcafccee34d37d7f9a88fcdaa9760edf5970fe200f76d), uint256(0x0591574fe2e8d9da8d80e351e478a26d0262d5af27fb6177ac62f3befb9cdac6));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x24182e18bd89e8db1749d530d768e096391386445dce88f7070766e91f6fa1ad), uint256(0x1b81699a08e36137766db5eac168fc1a28b99ad015ad7d1397da1e433369dbc2));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2e5ad1500a5d9f7719e1a482ff5e7f034fb2fc6007c9e26c90c2aeafd7f8a52f), uint256(0x179bfd84d74b014a41b451325e0ce16b3aefae3a12c28aef76d2eb5007a86d40));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x20c26fd6e38e6a9517c22461a648befd7b8b97ff5472ba9b432a7bd62ac69e03), uint256(0x2045cd4026fc5c57b6e7fbb14c0e592d76cdffa709952d503050ef0ee2601287));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0aea6556d97438a65bef3b538785f66801a5a1cf643fe2d751588baf88eb3935), uint256(0x13eac733d21264b701178a70fa3df2222956a2c602f68d304f39700c4e21bb9d));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x303188a4790af09f9f8ea93bd26f4e1ad52b295739d83cb6c9d48bd43214d737), uint256(0x25aec0b423e7a825320c276ce697ac303d6b2df5523fe72bd86bdad01f557ae5));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0d7a50e4c320183c00a8471e4ddff3512d0638cab875bc54d7237869a41044c2), uint256(0x06608c8a174ff25ed338021818e6e1444f500c9642889d616f4bb7ee19f70476));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2b23711659605ae54bc6ef4ec3135862b07044ee519a815de03d7ab6b875dcf3), uint256(0x26358344553ab391a52b5410e8eab3afb5627f4ca77cc7f6252faf3f75d7004d));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x01fb4ca0f089f64b8585205f524c0985174afa8a09a32ed76047e07819a8657f), uint256(0x11d733c0890c4030f98e54f3f813776493656c11bb0befd9083509927c7e0436));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x15e09eda8787f9e14740cf88c2896624a1f2faa8a8c22a168192d2a02cdf37cb), uint256(0x1acf20f5802b1bd351ee02c9029e5306d29e684f19651255f7c24fae1bab74b9));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x275ba58c242e108ddf8b26f8a0922b505c3fa4a7dee0834d1ce5d28cd75e5a2e), uint256(0x0b984916b9ff9e0ce320297fb0eb57fffefd4bae129570eba0577941d304a86c));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x06c33c1da7493e60d5bda721fdf0eb1919b983549bb539d355142b776439bc6d), uint256(0x07824527fb28ad36b835ea096979105711e1089607d35934c1e5ab9e97b33cff));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2932152cc08100ee35558f6b4e0b8d9c986f88e8f1f1696fa7fa7443237a9237), uint256(0x1196612d26ddeff8bf4782276021012f483d67ac5d81fc17bebe84f79a632892));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x24e29c8a6bc07f11a5ec21fa2d2f744b583f626258a2a88e4f971649e23e14d0), uint256(0x09a28f41705eb8a72b577cfd4f5b8e70acaf5c65fc9317336101a64e731270e0));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x199302c0b4a0c7655f3dd3c4696ed64fb90ee61fdcf85cccb3dd082063f84f88), uint256(0x2a661958d70e7c62539647eece95cd0dec0c0e939f757f49a6f01c591e5b919e));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x147629b543dc7967db3763a0f88ff4742718430e1e66977d7cf0c6a37ef9cff8), uint256(0x0abddfbe10a8187f66c7e8357ddabcbc84cb762912b84e66f5c01f13529541b0));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x199e9772e73b2cfcf95022bbbc240799e9046b0c9e67227b8d01cda476eb9080), uint256(0x13408fa4a07df5afc8a6d9ab3785db24e7f00f04dd23ef89310d997cf4bed158));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x2d62a3acf5f04816a1177717d1e8f2bf4a1e9068825583d47176cfd405bb2dc3), uint256(0x1e28cb7a3568abfe19dd14c8b88081de0945e3e1a9735b912f1a979d92468486));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x01eeafed64ca162016e400b316946dadf988d5a761fc0e9653e9be5127dc49a0), uint256(0x0009e68049702fad752f2c9dc54b1e6826ff383547e6d3f473d03e2e67f98027));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x0dd7861f4b081593fb11d3fcc86bc9ccac4d1aea755d5355de83e46e1a47d828), uint256(0x1ca680d13ecaf22be26869c6377fd2439fe0d617bc667e970fad877bb18fe564));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x003598ca6f5da5165a5c9d1ad5e77b63339a12151146068d15b537678a33aaf5), uint256(0x1f41b85ba591e90028706f7f8d5bad4a0f1842b89d2ebabd99ea6a81ced6819e));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x2a560ae22e7d51ceae0f97c49d95516ccc90c7a8dea1a41843376bd2bb6afe4a), uint256(0x06443bec29c9be4b06105926559430666d556a963644b26623b94d5dcc31e540));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x148c6f2f7227e40b1d05ae9727dd6c4777b3e797d8f2747c426f96c69d22a8c0), uint256(0x2693290acb582fd5dff8236736c149bc6a13348912c161e66785475c82792bfe));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x1570730d3ef3d99a206bec500ecaa073cfcdcaf867849fa31bcff79e48509d19), uint256(0x18d7075085d274bde9ea8051198de4be93f91c75034b4cd0396f4b74999daa84));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x2901ed3143b9787182a15ee2d0a5de5ac4d9cc1c1e13c3e0d82d46fb778b7291), uint256(0x06c52f3051fe23928bc86e31f86d46443e688e32bfb12ee24befc2105c07478b));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x0a58d87d84ae8ec67c4d8111e1449038e5d74cc243160228c50f2a6311447688), uint256(0x1f3a4db68ce212d7fbf74e93390c1c143224f1c6a7839fa06c6640804391e119));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x2565aacef45dddb12c0296099b8b9a985432af7670ef267742a306f8811e86b3), uint256(0x16f2529317f905828f347bf7c351bfd947ea121605d88e7c49a2296152e25c8b));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x0a25b7c367d2c764d6d58a3b342ba9de9fbeb248be5f9b0cb1b215ad130ce411), uint256(0x28a40ffdc5f2ba42dcfb016b22876ce45d7fe41abc1c06269e43391f74f97dca));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x0388909622bdbabf9c0e45cefd8eb6a68517cde9a77b937bfe4e047010e35244), uint256(0x10e3642eb6dc4305b45dd71882b87fb630f3b1b98bd3d698c6a28b1e4bde8e96));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x269a2464f94cebeb43f9f4f30d412f70b804233d20a44b9dc09135c9895a5937), uint256(0x2853dddf5d021c36a4677b796114828223c6d5c9e83580ab868aed9c7488a30f));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x12197e5668efc9d4a56af2661cac6c7c3cb067aae48bf4edb2afb37cde2a0bed), uint256(0x00e67d57efe03ee86101f4e6dca8dd915e55878ab0e51c83bad6ad2bf5b9c51a));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x281ab7ceffa9308f73dcbf25c0a10b9bc06f4d4c7ec5417b4bcba418422352ef), uint256(0x107fdb44c91074f0e078726a2b9cd4fa1f94ede243a5489f56248e0953f91504));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x233a9b286d53022aea445f327280031f2f142d7326fdcaafa046204f22267930), uint256(0x2292090549e55aa2ef380949c311539cf8f0d9074c8ccf840e967e8529f6df2a));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x27561095780a1423f1123933c58e6246bb31eec9416a7c785c6809b9b07ea6b2), uint256(0x08e7b64da80da8219f828242ffd4e5212dea10d4b2165697885a5ed85f8a3780));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x021d2b3eb52436a4865d77d033f634e5bcb32db7dfe530237cbc2839c872d634), uint256(0x0368ccedaa281d3f8bf7e35d2e66d21757810f8a48b27478271820ebdbb22139));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x09fa9ce74d746419b86417571bed071081b9745939df3f25f0f05dfa7a32660b), uint256(0x05d636b4b53ff3bb4276b33f82e95025b0d1dd82f87317932bbdb596f05cb954));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x1158610bbb384415929ae54496767ba9cf666631b7131f3244ce7e0dec559830), uint256(0x1ba058ad5392458007eebf870b43757d17cb868d8ffc97a63e72d7995792ddf7));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x0ec148942b3ea8bee275a7bd59b550a4ba6588371009630ecf43571631281f4b), uint256(0x13e8c27370d54748e7edd5a5ae1e3a25738a57f166df13210b500e04a940b15f));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x2772338eb8f68c26e4db509e34d408fd9fb06b829f6a042bc434d388e8c4fc04), uint256(0x01185e0e16c6181050c1b50f4ac4b2ba05f133d390f932c1641b53de9dd811eb));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x1ce30f99f80a910092fc6a147cc318910dddc918f77cc3e90a704f7c38240835), uint256(0x028bf0290ec33211ff8d20c0b5f9d368ca8a51a4168b168a964cfaad5ae379fd));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x2bbb70a8443ac899fab6ae47cca3fde75f13bafefd6f286f326950de1657613a), uint256(0x12b454db204b8f5e6a83ceff9abee5d145ff07ca4a685f93868c2516ff533c5b));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x1a043f3e521c505c5ba269dc96d1675a9cda4c1a7f28512f46dd16aef9f4cbea), uint256(0x0701c06232b7695e5cb7145705babc92c9a52811529ef51eb13b547f7b21d6ed));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x17d38f4fabaca12ac1d2616a2383d06acca8399e467acb3a644333cedfbe8d3f), uint256(0x22479efa382df93662efae3d4c93b453fd23f1a6bc934bca6f388cd90fe20c97));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x001189011fe4d24e2872ccad38d94e920120d96542aa2151d7656d0fa68aa3f8), uint256(0x16753c75d190e3c81695b1ed27f4e6ee65e355ede6ee21f4ba65212797adea11));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x10c788e8595aa5ce43debfe7db58ee93d5e3b67617219869cf0fcebe52df0c04), uint256(0x25a37d9bd28f0c2da815ed53ef6e99de69bc5b0e698e0b3d2efde3677a1392ae));
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
            Proof memory proof, uint[55] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](55);
        
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
