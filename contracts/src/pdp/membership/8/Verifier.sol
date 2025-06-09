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
        vk.alpha = Pairing.G1Point(uint256(0x168271d8dd05647f8da2edd5d06173ecd4095c2633f1a51bb9d45995a3350ea1), uint256(0x07452edae2579c5f32ecbbc6651bfef7c270d30ee198a63a6ab63d89f1ec6832));
        vk.beta = Pairing.G2Point([uint256(0x1074ec8f0173d28a1975b5d9bbe5901726006e225ac50e032fc13bd6412592dd), uint256(0x1b918c2e26f2002a2ea7e654f5c36a520f73a8261685d47265affa8c3585bc27)], [uint256(0x010fb1ed6eff8596f94f067fa07f339272c46f685502749bdc3b5424657120b1), uint256(0x2177719be47a98a49e96c0f65a9086748f7bc9a5a0c35c7b625ce48dd70faa8c)]);
        vk.gamma = Pairing.G2Point([uint256(0x1d7538d9b8da64838d8f288e96e66a2110a67da043b75e4f6b79beb82a405b68), uint256(0x14eb7c61652d17e4afcbdcd238bf03bc4b46745ce579bd8700f02655e2f11751)], [uint256(0x0a4cf64c5ad97f337bec37c532deb8b22a7902af87768d71c93820bbd97b38db), uint256(0x088cfd0ace02454a0ebe3697262811a50a08d9ec4801a0e2ec7d7ba0b4408136)]);
        vk.delta = Pairing.G2Point([uint256(0x03bb95545e0e9433dd325580f33864044bd162479ffc56f32dec9b1ac09fa8c2), uint256(0x0964ee21fc16fdc6baf511b56830640991b443f0859c695bb080bf5a33f57931)], [uint256(0x045c3e1e8ebe6140e3cfe39e45d1d7dde5767ef4bc644b53e451f8593da1fc12), uint256(0x0e486b5fa1546b863be4312ef254e1f84442b0391a4aefa9035a8d3e7ac1ba28)]);
        vk.gamma_abc = new Pairing.G1Point[](425);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x28f6686390456eaa0d26794e0ed9f6f6296afd6f2e430642bebb90712c830920), uint256(0x1ff8ab299474f922916385d3ba5053f97182450265c353aa8d9e4fe002f60731));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2701168954c8ec9e9cf893b6c95a5ce106ac4813ef7e17c59026c5091cb038fd), uint256(0x207d92a2dda20b3444eda0291e2d10f16af77dd5961f7ee7c183de9558c5b3e5));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x16f270029f3c946c582e3decbfaea8688c11cb9997924eb89652c21429a15429), uint256(0x26eabca8463fc4bacbe0724adfe8dbb6d89045471556075fee8faeaa4775e3a2));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x19a48f39c603e7e72eb060f152fad63a9715c85b4337c48b23a1e56af18920b6), uint256(0x2ddbd495174b314b4ff375fcf9e87ddcdea4f9409ca3539a51897ea4183d8fbd));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x176cef15763c98b179aab04ebe9c8056c9f93452a392c76eba88f8f4250e9385), uint256(0x1fe2a35f8923f13c395b98d65643f3231c0ea00d10b8f658256f7d305f598459));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x270d0922e65dcd0f97983bafe89fac068f197df01969746e52ecd9884771a0fc), uint256(0x1e7d6c109eb34b728caf2b1cdef22076ac66828a9378dfefe9e62dea30ffd50b));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x25679b7bb0341a8562e20c5d5cc8e0bf8c597f8989877e2165106d53a874a580), uint256(0x048d46b9b10272d2d5ca9f17449bbd5910e84d99e968785d35d16f8f781bc632));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1c8fe5ffe6aba952f873ee49d4bed394fb1faa1a9def6a3f0898b2b9a83d6e79), uint256(0x1e0e58208fa49455ac3e984a91e4b020802c7d20e396e5bd4a9a64c5a6b72eef));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1b0cda541460003f420992ed223666909fbe775406258c09970d285c5738a5f8), uint256(0x2bed2462568750f6e578f6a04958fd773523482db154003c1b97966876f7803a));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x089f2231975a80962a15dcb10a1c221d317c3def7be135e74915660dce534582), uint256(0x127a999ff33237ebf7ca5011df92e4dd014acae5648f16c2aaa027582edb377a));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x18c1866abd36e60f103a300d9ae91ff7fa5811c646cdd5b273ff7fa709f7dc8b), uint256(0x0681ec57f5568975ac46d1ca84eebdf32084f3dfa494fdf26a426843ba0ea4a3));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x276bb9b8da1b37ddd47a09f3bfbb252511e245e8c7943cb5145f4b4f3fda33fe), uint256(0x0017031d9e6eac2e29f612cce8c309f8264e568c22d8026386a7ffecea976351));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1a20350d93cc167cf031f44796d6b8d45ad6ebd0ed297b01859b74796a27f4b6), uint256(0x0fc669a4f0c00ce07222a7dfafc49950fc237ebb9bbe21fe25a473df4ceb8f2d));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1d8d464e26e30155f65bebd39aa3e93b13009df6392323da47274cc9ef52f8ff), uint256(0x207bacc928f999f9537c7f56faabd975baeccb972ee1799514c24c837577068a));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1bfacb20785d85f6c71edf69fbef559e0ae64363a02cc787248b32696caeacbf), uint256(0x20e5f7b1d00e2593f035bcb79da4a7aaebcc77ae5d6fee1408e17b947a61df1e));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x153a36ad08f2417e7251899ed881ed10868ce21653edf1860b6d70c117372024), uint256(0x2cd59ab50a1d03da755305dd77683d9cfb088ef87f2bb6f42380ab711a6021ff));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x211c8a0bbbc0a8c4635a4fd332bf7c722f9a43d5d1424fae539ff8fe0cf690fc), uint256(0x28cf49d48d56bb03b8456d08f80f72aedbd651ce93c76c7097595366837a08ff));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x081498caf30701f1e52486799118bbe47b35f8b8b44a1f72286a3447c0f747be), uint256(0x011d48f761ec0123f6d809ee24b19c56b6c4b9edeb62f7aab39f01b22e39fc26));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x29532b994c34f1c2629abc6dfabc0765a7e48b6f2a142a5a80ae4cdb22109fdf), uint256(0x0cb7666714869152ef53f5f5a21e79ce8bd6461f1320f5ad56a1dd28689ea2cf));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x07f03cb64ef0b84ee40245b12ee65b3d0f24581f3bc38c0bb52a540ffcbe0f1d), uint256(0x1a373e1578c1d0abf2420a066a65324005778278025558b8bab48d9d83dc8c37));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x0f8079e7491d4e2268a2a8de5c4f226b4039a8b239ac6bf2cc90055833d0af32), uint256(0x00283a663498359efd2181685dac51824d5f1f08365079c0fad8d493001f7e02));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x221a7100f4dee596c1ff47cfd6a7a04f24e3176a654561e7491461a803214055), uint256(0x16ec6f1a378ad74a0a76c23b79fcc18db5ad4db61134a2b47c38ce646ab5aee7));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x1c0a4c92956ec2c2b34d2dd068f20f0318b3c8f120e58684f0a12402beb88beb), uint256(0x0f832a7f19ab280b6e48a74e4b11210eda07be100eed6ce4ac3ccd850dda2a3c));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x057203f3898be694491817563b3b05751c2946301f69c21f8a82e3ef40cab91d), uint256(0x076a231a11bae561a33d225303f4e316a252fa2bc6da0d5592c6c13aa30f0aad));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x050a5f6871f60e8d752b88fe475e7f1e8ce96de3b3a18ecf7e3e44f1e33b2160), uint256(0x1ddfa5eff6ad58cee931c2fdd5741bfb26126c2aecfb2e16dc426b4c629815c4));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x299a13d6925e891088190edc19b177ea5d7e91b500202828339fd85163f7c944), uint256(0x2c7ea1b9b480607234027b99bb6ef1f06ca39941592ac69d1a5ca55e2b6a7386));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1c11022c716077cc43af0d4e309c17765dae1b860e31c4f5530ad15a6d13c1e8), uint256(0x0d6a6204ae5c9e1d052588d67dc196e38d497c3543b6dbbc01d9a50c9ca3c977));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2b5b4433885aa79b8fc522341d3ed558ea6a7b99360cd26067d31f81151e71be), uint256(0x187e2981a05ee452890ff614888a69d7181f3394d8320ef7ba517c3378cf8ad4));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x08194dcc8b2dd8cbfdab7756c0663c64f288d7c9831adf69f43a1bce90f88505), uint256(0x0a6a3fd9c506ff5233af82cd04a012d036322568216fefae314be39ca332517e));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x1a5937714d6ff5c4207653f6da6d68e96297e6bbd1d2b901523525e01c6a6ae5), uint256(0x017d040c4f1ebeeb09951d19a3a93cb4be019932dbb12a0099ed143915dea396));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1af1ef1724e689bbfbd4eca076c8ed8ad0aa0b6703e7029c7ea36f983dce0c80), uint256(0x0d1602da48eafc8baa3c0cfaea07b65a3e26ac8ceb5606f3efab29a87e31d931));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x290e29fc904da4a1197eb1ad26fd93cb900d86aa2fec9ffc9133507762d73b36), uint256(0x1126b2f493383b0b893151c80e17b4bdb0c136478220c3bb741eca63ffa2882a));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x23ff533034e66397812cd3a6a13ad2ef0f279eca63f266a825e3acd517ad6280), uint256(0x1e63a235508d88af6276eca9ac91e20ce50b00b5bffd7f52cbd642d07480eb97));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x2b1c228f0018ed72e237f36bc5b1ee3edee256aaffcb9bed636e369ecf98dfdf), uint256(0x20783f2ce0565ffa97f6991b5f2edf77b71b966fb4dc339e7f4490b78d2c7666));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x16b44df5ac6657011af3bb358c45750ebfd20a9be180c08374b87278034ca73e), uint256(0x1be89396e220b0a65b16dda6e4692d9ed3c3330ecef4de5b7b4f0e7c521c0e7e));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x225915095b5fa914545c50d0eb84af3c30f74616ee0822c21b11568f1664e788), uint256(0x2d31b539aaca1c6adfedec4d55617aae48ae855ac98a5ba320954e87a739daef));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x1b9522fc9c566fd6386c756fb6e34cc40d0b6b603bef12ea2d0914efe90010f8), uint256(0x0a0b2d6acc48b22f6056586d44fad15474f645d550f47f1a1ec8e474695c60e7));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x18ca91c41c736607d0a715a53cb8916f1e5a32f080a687260c7acac6c7d43055), uint256(0x224c75b85acd1af3681affe86f406c7c0ec32b136819b5a85b1a95c453c83a58));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x3015cec6c08ef294a15ff2318cf65b63a0f26044a1344f3d7db5ce011bbe2043), uint256(0x00454195d7eab7b858323bde5d6ef6d6633e8eb07809f49c56a16d9f89f26409));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x300d88e7e7bee70d77602ef3fb6166cfe6ce0490fb62a2e8633fb1af51cfe509), uint256(0x03186aadc7a8e113f738ae142845edcd9ba4bcc5993a46a2a2d0b80ccd9e23ba));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x2609a96225c25cd88dc775681596509da55c5b3e0ab05b8ecf9e3540398e9ab9), uint256(0x0476ec74f77b782c511a862c7a447d39e7269e040ef1643f3a24ee1ef5b5f871));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x257c5fac7cf5f61ff0f85dbfa43a4f855f7ec67271d724aa16e5ba97e3948fdf), uint256(0x1a4909adb441aef70ea37e1a72d00849b15988ef895fa7c0099b914fed1c215f));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x161da289962b174959b4fc1aafd88836c8841d1d0b99aafbe30d7b6b3f75e8ba), uint256(0x2cb63f8bd05cb2cc35d8db77033a28c82c66013e4cd9bd03be9bb19c16666eee));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x10aa9b7325eb1950a4a41922df9f45b5cdaaeecae13a343283ed3240009a34f1), uint256(0x0ddc8d5dded4013d7293de99235dd97c556fb8194d483f13c0ae5a4c907aaffe));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x2f50adbffbf86b39897dd81d345451a7c12371dc01bd1f87eb20bafecca31856), uint256(0x0b4cad2993c7348e10545b170e12556e14a26431bc1147aad836866ff6da96d3));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x2b2e6731a5e5a026c9b385143b201ecc98b4d64554c6add57fc0d34bdd07eee1), uint256(0x24df20378dfe15dd0d1db637f387bf69b7e3930f118a46311e05a9027e125f7b));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x0d15605b363de8be8d69659b12ec93e14887082fccff44678ba28db3c04c4409), uint256(0x0e51a2d7a858dce5d01c5cdba657de3fc033815fa40af08f6d3ab5108874e2ef));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x24e2f585a73b7b4fc03fb4b0eb6af84f90156e5c47c57ca9695218271bb0544c), uint256(0x11c8b83a416117878ec758d2ca680d3e93b77596fde3ca080cb3f78ec4118d1b));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x1d7766d5d7f46af4f37893e98c43e3cc1a2509ea368c71d1339abb454b53e0b2), uint256(0x043596cc2253b0c5bcac9c1406e2b8aa58a288d46732b25f369894876a1f30ee));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x1a5cd5e70000190c336e8f8d1288b90a572fd7e15bd0e42535db7b1d73e68eff), uint256(0x2c3b74a85e1a0818d156261eecb88c9fe42b56c964163909e2e0b7ab9edacb8d));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x2ed2bb9aaab73e01384818e1dc7cc24a7dd7c125502798ae79135087ca18b22b), uint256(0x05eb92d4dc2bce15aa44578a72e74065b3a0220cd8639cc75801ad64142560cb));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x17e6b4723138140f6b30c311a670bc942d145b335d1e689fd141a27d707fdf0b), uint256(0x183c358efdd28cff7d06c5831a17e6a77458acac6ae8f5521518186e0526ba16));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x2dad4272ce844281bfb0d6853493421957a2a51ab3c840b726150a67f1b067d5), uint256(0x0133766568a94dd42901853802d74c701905c54f1fef8ede65dd8abbdfcb1d6e));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x1f4e443b51df4f0ef93e8e3dbcef54ac93e14e5a3c89ab6880741df4c8c04147), uint256(0x138a935fcfef8cda7113416c8fd871ed699da59c7a0328f25a37fba56540c9b5));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x1379ddf7b1595aba111fde033268e8caae2be9ae542bd7d12264f6d621f20ccb), uint256(0x1c857d59cb3f89532a6a5fe5903a6074db86342aeff39fbd8f17a1c0d87ce65f));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x047726992d7eae4aba1bd02f94f87ec0d5d66078ecb4bdf27face954a8a74e58), uint256(0x1809579b4dba09c941bb2f28a0ccdc1a79edb6e4e52fe5b1a6010d1d15125daa));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x0fdeaf5998dac61bdc2a69bdfab12f36f7bacb024f7356b7a2c03a546a0b271b), uint256(0x2cdf8ddef1c5edc598a13308024fd2b91b575251e42094baed8482e0b23fc4c8));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x1ef85deb3e675170300f6996ffebd0c3b792c731e74fc9585cae66d6cfeaa058), uint256(0x0d5530c9122e0f2449ce53a5120f5d10d8f48751903172da6f08c5c248fccec4));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x17840c4a647ad8087a4c40b0ea355bebc0b03917af423f358974bf520185c3ba), uint256(0x03e0bbfe54f761d6260af035ab39cd006ee42cb485ad81916dd75d3f56892295));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x0d46d47d6d9acc39f1912a1b4b204b2f6c2f1c30124e2c415413b0c597ba7700), uint256(0x0a5ef56311df65f7451e0ab9c6d07c633d621ace5d7d91299322e5377ba8670c));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x2f9028dc332015e772ab94d5f73020dea28e056f389290db79b02e7888258b3e), uint256(0x2180b5a2624db0ebdb7a2a9290fc9bfb77534893258b419a1afbb20d3de80bcc));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x239fe24425b22c85805dc2a9a916e961b44f4daaac9678e892661fed008f5208), uint256(0x0364cdb962c1ac87b5e2c3de241e81f8ee78933be262d2b7bc4004b6ba729d7b));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x2b5aeda30e15a755bc1f1d06222d93e5ce2a53841e4ede4d03faf84ba39815a6), uint256(0x298a5cdfb7f74a8135293e5400c039ba600e13e25112c7babbdc1db8ab198641));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x09e88c6645e32d2dcbb15db8fadc99589e70cc9bf449a40289251d005f5bcf6c), uint256(0x2b5e0ba7cf5171a252c8ff49b8b967ca2eb79501c32a065cf4ab3ca073f2f8f9));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x2e1115b8214426b1a090318e89794cf8b41fe23331adde66abf04de0549d1940), uint256(0x1ee940093adecfb08327a5aff067f0f37868808be7bf63d5ff8f5dc701cc49f8));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x2eec7ac2ca07daba3c12414623d8458dbc99cc637734f0b4f7a1263989adc90b), uint256(0x03b93f577a3f95f3eec1862d6851155e0a3bf16c465654363ae1c850b0ff0dc4));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x1ea1c019c091a849758073a4b1307588b58542299e046cf233bc246639d12ad8), uint256(0x192e2ad3d8982315347698b99e455f4dbe713e483b876162fa4eefa069a13a5c));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x2169ea4b02062f849b1a8efc6f1d5865bb8331549b7dd9692d97d470a77167ba), uint256(0x0c6be9171549ada009e9d5e0a5455aa60ffde22348b0b4c20ad7dfb5819f7517));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x28f7d999f68a12423c46a9afdf0d82019d4819db1d9d247b7aa712edd73901dd), uint256(0x0d9e9324ab29084ef6e53a77ae0df18cbe4085940e81058fd34f706e4c6ed314));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x067e93af7043213b9c187c695c15b301f9c5ee9a4c2000861df5b5a4860de1ea), uint256(0x15b2f9711243a73fbe9e1f179eca54b6932733ddbddcf97b39c4c596e0b2e236));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x0e991fa44e9db8ad5a7944563fe9f3bbdef2103bdc7774c8c43b3f60ebe529ac), uint256(0x227e7afeae703b1712bc44001d099da89593488b0dd638a6faa8159bb6019d08));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x1137adf1a10f1874d76f4d31aa1afd7a471319e357c437b5b7f024de2e3a2f74), uint256(0x1ab67b15390c9c16b52e81eccf99e6a265b1da2e4061ea4be7f250ecd862ed96));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x22806dda42edbd25914a917ce568e38b559a6d86daae98456a8b9401a9a42ccd), uint256(0x167123f8e9d291f20104f73bc0438f557dc8b344be8289d9f9b20582124ce558));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x2c3e9dedc1a557ba1329a86c305c640c4c57be72a05981169f221b0ddf97699c), uint256(0x0dae118732213a99e3a9c2b7e0ac763ab5e83c6cbead0da27851e5963c6616e6));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x20f1791e5ad99f1ca3d7832b3a65524ce9ac1010a9c6c78f6a8a9e9202832167), uint256(0x227e57156c21212a7d8ccd317f97eb5ca9771941aee3d44a869e65a20e9b5892));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x02c2c4bc195ac63216c29eb81f7481b1ad967979d392c879ec24b9f30d980014), uint256(0x23023047c6d2b36a936326aa9981ac3e7959061f739c84285536541f7d67fba6));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x1fe284cc61cb1d091e9ec9a786a3afd8f52ca507741d98d4a5757eda7ea184cf), uint256(0x260842436d392d323526f519b708adb457510932dfcb69190a81b4be6bfe1997));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x171094281421f1928236a40a6cf4b754fac84ffd9c178f77f33c38427d315b8b), uint256(0x1089d7d53bf992eeaf99b7f7fdbfe73476ddd2aaffc0a143826bb83fbec68272));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x1cddd756cbbe6d8eef647be521e8a7a3b550cca7792bdeb174ad57eca64c5997), uint256(0x2c7eb2b334039edd7eed230d80dc2df4bd15a3ee420124c8338f606738b0e577));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x16bc01a799ab0061d5838205acfaa905965028daa26a2f6b8435cb60651a1142), uint256(0x2512f53e8498c218995968eb298ccb6faa58c502207a87c6c8baa939406022d1));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x096f57acf84fc8d811ae99c70eca721bd96e4f1696cea9cb97db226eab553f23), uint256(0x138c0e1e620b8072950fa64aa8902864b98bfaa093568409f26317c1caab7b29));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x11dd62f633d4a5b1498964b93df155996cf8fd24a3aee07683ba923f95d0d448), uint256(0x1e7252253d627a38061ebb08aad1b54778d4f2b77283ff3bae9b5a00cf0f770a));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x1d870eca0b446e5cd9e66ca50ec56b4afecb1de09bddeadf67913989cf38fa5f), uint256(0x28c3502548a6de86579acc1e48cc3538894d14416e416f604a8a589fd1cecb74));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x1f6296401ad3070bde607b4b4d1aea78b2f525394aef90d7b234e3ea07bdba16), uint256(0x2068c6037dddefe960bdba1ce956da903999cfd99b60efeacd812c616f361ec5));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x1cecd3450ce78666ce01dffcd55b590777bd16c980c3efac2ae7575e933b2dac), uint256(0x19b7480bdb1079c237caf661beea194fe1153145aad221510bf76f80c6291afc));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x3058818eb998b5f2694910ef13f9b9efe1369e03bcd9fd26ac80af9e611445d6), uint256(0x1986ed8030d693e9980bef997268c14677759580cb848c0d3cbfa7910c41c8e5));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x295fdf7cc34559c0b7899e6a71123b6dd74aa3a1d752e8a80ee89a590da57214), uint256(0x177c68b76c9aa60dc2c54ae64bc46a52116ab0352f4372937eb0ac1ca9fe81ff));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x279e9a1f1f1b566c82238e5fbcf3b9c589e6096e669e6fb8689bc4fec4f55a6e), uint256(0x005d2226dd0164f25f1e7f8e62687fbf7b8bb07dbaa913ea10136f5dcce3b68e));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x1ccb27eaee8de7458e9612e16b6e3aa185fb580de92d3ccd152d613c05ab6036), uint256(0x17fde142176ef1dd498e26734093e026c59190262a3946cf307dfddbaab739c4));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x213169f19e295758eb737b4317470d1cc1e501c12549239690c303597cb1de2e), uint256(0x298ab87d72defdea421bcd7ea99598db6a5225a5399ba001011f95c45a2fb8e0));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x298de9cc9fcab702e2a0d5460d0d6c4a07ce08a6d8a3295a671ebb67d0b738e3), uint256(0x094472961986caf1f5957546a1136458795ff232b17399888f60001f1ebd4965));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x235d0abf0e783968267bc7e79e56714414a61e1869d4994ccefec320e08fe59b), uint256(0x03b54ed3b719c79351e6394be4960767208b9db957e14fc76f13db4c1b086689));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x269eb3195ca20fdab19c4b19030b83548f6a65e6203545f02aa66b8700bb8cb1), uint256(0x27d93ac185f6d54198c495393907a7d9047c479890b4a1c8ae27b2784de50ee6));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x2fe0997412f7d3781178d1277bf12f7b302f581a95d4130044818c4dc25839f7), uint256(0x20682c05a3d95326e151b1888081fc86c9a1944533faff1110372a7f26e2c12d));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x2bf06bf384be8c960ed029019fc3bbb4ce1b6ec182b1e0a492d5d529050fd047), uint256(0x02c4b6b42d8472823aac81402e96b07198c099d2b7bbe3800a7edef233f6dbef));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x17cf6ec681e93c9ff6d742fe3295c4ee9b2e4682ee9c365991d79aefdcc71c0b), uint256(0x00e8ad8713970229867c7518d83686ab897d8f3de960c1caa92d272e3daa0498));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x02d84eafb185884718d236661e3191c2576fcb1ccb5cdd84ac027c0716eba50d), uint256(0x1e0c70755903e115d194774c1aeef334b3ace19952f6f90cfd1260dc3c9d81ee));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x0ec1eea2bb9e28cd08e74cc556286e40af4b3a3e1c624c16ff02cb1c18f7cfea), uint256(0x2ad33cde43de9cd72e85a7b6abbfb0f4b0599b86eae89c638b9e4709eac1fa39));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x27508cf6037ade937e09648c611a6efe24b2369496fd00cac186f82732f78813), uint256(0x23ddb8a4d01334734eac8d58d6124f094040d42e2e430111cea846368189d289));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x23400377f39f75986cc28b0f9796a44fe85a1673a57b4657496114b58e100f67), uint256(0x2f0ef5d5f72788124dbd109c53ca71139cb92138414297cb1cdec0ae98a53fa1));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x0ab4a0155bad0dcae96b09dd02b5b4ad473d6690714c1b29d311b466e7ff5c2e), uint256(0x2b1c610e5d01ab88978daad8f162298d62d6bd75b761028b8508cf600756ff37));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x13896aefa99d73125340f40ecc412ff1d07b97e7e42483f4f38a724abdeef7ed), uint256(0x26f99fd4df515f2263c65f0fb163a3fda8eb4c302b77cb493b2dcba4cf5973bf));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x11ed96a2b8f0fc0e5ad1663c3c4a8716de1e8db6d8f16fbcc515be82ae04bd62), uint256(0x1ca53c4d6ec307ee2a4b788610a079b89d6fde144b113b8556e73a399e2b9eeb));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x0bf8f99571847b6174e295281a8ac5ff499739c8bac796cac796fad32e899e58), uint256(0x1a3ac0a5a9012d0384fa8c31f9fd252c46ccce331a8f76d83b2b776302f85662));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x08718dc0ba2b2bc054fd58ce9cadf2259d707da00a9a433635bc1deed4fd4f62), uint256(0x0ebf965ac0d13e6dabf5d7e7ae4df3b5db27e15b3c17f13f4af8ace1e4ad861a));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x1eca48bc7ec4d0e03371c0dac7b2c6c27160a0a562a7a159f06c5783763a587a), uint256(0x2eddc7e45d882609072bf7e347ebdfbba3a66df8f815eddacd7c8e4933d7cfa2));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x1158e91726817f08f12bcbd6d253e33a34f7a20a066f51d0618fdc4de84661e4), uint256(0x22d6a8d9f7fb9d876c416e0f0f4e0327d2f1433c088043d4220a9c1aca3ad1c5));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x18e41f78fc3551694f2ef27536dd66fcfd561714a803453b1063d06532a835bb), uint256(0x1c46680cf67d94c1eb712a69bae99bc01dfc3065662adeb35debd6d66aaf2c01));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x25e4fe47e6f000b6bfed9c9c987535f39bc1acb62f59a7ca6d9ad76f76629c8b), uint256(0x08438383e7a44b8fe4479ea565ad59b95310ef99fdbd8edc65b18c11f2d28c33));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x092046808895c4894a8b76f40174ba14cc4e5b4cfcad8b98d5e159454479c821), uint256(0x02a6c0309c502dae0ff0d3eac709cae43a8baad75e41b889803f05a730f9f3d9));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x06632c194b6ccf4b855b95bad9c34644d4edafebc40c23e8f3e078795f5f47af), uint256(0x128790183b18116f1a2df7d9fa3cc877261ec072bf8bc535a4459915af03f855));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x2211ecc6ad26abe7282179d69e246162c795838ac576e7cb030ce6eb69fdc08b), uint256(0x2481452556985539120bce3b6bfb6112622360fca6993e78630baf3e750a5c6c));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x16ac503cbf18779412b64196ed576377bf83ce87c4a934b76394ed0c9db4004b), uint256(0x0f56fe765411266dbf1b58e5d38984e038702b3f250336c76ba71a16f3e77ede));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x298b877e5485a9fb00a9687a93974f31f0bea5468920a18415b861ee43293553), uint256(0x260c2735b503c0a15fe7375cbc3552a055ab3fee06d8ec29821cfb7252e4a4cb));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x046e22e1543c2feae2d84b7fde653cc423a1d5e86caaa2118e2a19c0469be6ab), uint256(0x0a8535dd99c52d71da638862f7c61e9b06615058f08d2504c1678fbeab27e983));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x24680b5a55289a6406f434df66c8e602beb23632d582d5df548fa2987171c8fc), uint256(0x19cb895db698838240cf3a77a343743d51588f878bd4c37bbb3443890d7f16e1));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x11e0db945ebe32d7a9d5cd14988425af40f75425e19e9b1e7a08a126fa0c4dc1), uint256(0x094566074a271cd289a98b29dfe07248bc55fec715ce3f15cb4dbb2cd8c57cf2));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x1852215ea9872e06184941341667e8ddb3b892393be20913087d4a5c6069ee55), uint256(0x0ead9d4ce277ebec90b0a8d846a7d155898313e7bbd80686cff8d61023ea047e));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x2c149fea393b35b1c72c98969d94d387ae21f9c2d2c8e399043ad312f137863c), uint256(0x2014b59018e1b8a28aa7bdc4e37f76281e4370b0716446dd904077d04dd4847f));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x1e1a5f5969113f9797563028d1c9bfe64294bf1f5e53794c480448d096705abb), uint256(0x14a9e3d8c8e584f073e0866e03bcaa1ca6750da47126858dd089717a9386b19b));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x1fdafcda4c94056bf3b4bf5e36bf9ba2bb565ffaaf0174ebb0ffddfab06a5052), uint256(0x298d2be2569b97f4679fd8c1e66f26481ec96a37e7a223c3ea1c8e5f31fa0c35));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x05787ddb3bfe03d9a51bef5b1fd20d96eb7273e3f6b52defa34299893aadbfe7), uint256(0x174e36472c2dafdfcda943cc1ac242e338b0dd0a1d909ebdc7014d3e7475f97d));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x1f6c56cbd3086d6decea7f71a656edc56ab14474512dcb92d044464c1d7fc2f6), uint256(0x12e540b5a67ba3b20690449caca9f9e422810c25a3a526e2aac547cdeb191496));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x267fa1a9fb2f2f267e449a4c65223e1ebdc842bc734ce622c7e2d4fb95b489ee), uint256(0x0a8d351cd2fd7333d9f710085c429b5aacd5bb731ae9e6d090e802c084e73da7));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x09a0b46cf4ba5df3f9d88f5f921f144734230263dea6a5fe1bea33482c1d3ec3), uint256(0x2bb97dab33b6bb89563c38a7d652e5a8b8b824c2e1f45a66a9f48083fdccb0d8));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x0fea8996b8710a1ad68e8ca57b73e231fddad6fb20903e1e97a22afbb3d1a9d2), uint256(0x03786faffee66cd799cdc8d72d30a6c86b2a3d11e9a4078ce9bfc8f312cdb7dc));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x20f9acf05a7a42477fe7570421c5af0bd779f02c28f7c8c0596469135c20bb34), uint256(0x2043c52bd8a7e8db7aad853f641a3005da968145e75b64261e8cd537d549951c));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x2dcd9f02b8c7c473640d10d1bffc538a222c6874c635bf0bd290af274f5e873a), uint256(0x2b74bc227e433615a7cff519a6bd8d4d845723bda77ec2cb42942d5c146f6bea));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x0100cdbc30c9d52db8fd51d446a9f0a3e40c116acdef64ede4c6e248177a0f73), uint256(0x1755d84ff14aa4e51eb20e0238a4767754bb9f657c34f65e133165409b8fc028));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x13b9b0218d0f74c52f9b285645724e3214c9e97e70d29d61f40d30e1d7a38744), uint256(0x0d2bf89c2084868fc23a19ed7731c3c9c24312e9b124b365d48577de0aeef865));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x079c92c726722527978767c06aaee2385bac32d04e3a486fda777f8be0d0bac3), uint256(0x2aed68fe32534d8d5b94268341916ce9e4dbdac030c98cdca1cbe417c36c66ae));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x2fcc88caad72cc009d605ac9f2aba232655344ebc0e88945cb4bb3f84ec3b8ed), uint256(0x0caa7acd2e79d1a78a201a902ae5cda2b632568eaf9e5679e0469df8682476a0));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x2190bda83efecb490e701e6df6a3d9fd870091bf9da94ffe469b3f43b9009fac), uint256(0x1ee189808921f24b70e3cb2022f3caca81d3d21421e21f4a20cb6c662c4f4269));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x0be186ddb9c8a12fcca2340ac45b50ba7a86bf4f0acbbd39e45fa37a02105631), uint256(0x16e4b9c54769b0861efa97a2889c6bad82925199d3bfcb6fa0a87e5d6dd6a313));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x1ad66b47a4dad851158c44143fcf141e474c5dd468e4be187dadcabb4ecdcf6a), uint256(0x086b20538a8887135ec33108f831ae120aefba7766607c7879a5c8ea9ae648bd));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x25a7b74a912f08015b099f1fedf1642e308d533597530fe1d6272fbb27a9a8b8), uint256(0x11d7d3c4e54f1fcb49c49177112cd99419e6c5805e77486a1cdad2511196c32d));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x01394c2bf8e36046235d14775b917a3627b06fed816d00abeee0602b92751e46), uint256(0x2c546ab4124f3929dc1c78c1f96a8e5012209c1e1943e1272c9430d8526b4851));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x056a5a6516ee23c9ee9746dd2d3f14b6efd93b6e94100c88d072ea3f1b99e06f), uint256(0x2ed467ef52ca18e37437b044dd8b99c3285bc28f5300693714c2a3b40f9a76dd));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x2f2f564a22b3c94864d7deea673e8566f5ef26dca6f3ab42f10a5436810e246e), uint256(0x13b1165d551a290cbb34923539bc3b2199782f0309554c52964f81a82345dea6));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x29128774b83c60e2ac2dfe798c26bffaa5de2fec40ff7ac7fecdbef97cd436dd), uint256(0x0903a826bde7772cdc32d970d4496fc520f7231afadebe06c133ea81e8e40123));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x0afb7b0f42f44c8b7a590e22417dcf8217c5793de37f1d024f99d9356580c1b0), uint256(0x0e3958cdf6b5430c517b1b29be3ee28e28d856e6f72e7ef363dcd741e18dbf8c));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x0c8c15cdb4ca0d0f5f1dd3b9984a9efb48e8a77c26c8fabf49cd2cd03fdf15b5), uint256(0x2be6f59f8aa20dcf40eb3b7483c73d7d1aac8c6674ffbc31143a15ec5f89f516));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x00b4b20fb25dba29fa485edd2d31ce93e0ff0d36003937f20b01e2dca2a00f04), uint256(0x26531891f4aa29abfed8109dc693df861e2c14d5dde4b336770ab185bba482aa));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x2e08c4672ddb63427cc8a8da8ed4e687fafe3feae669a800de202daff6f9049a), uint256(0x19e6e446a8ee227bb7baa8634bfde105f0bd8b456901e1dae96eb43f30076b02));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x05665df21f30d49f8d609330e6b410ffad85f39545141df9c9b23563df8249f9), uint256(0x1a87080042dd14958e1657b71c9f595db82478daf925981804bfc141b38adf68));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x081279d36b3d2c12588582cc617a23e1bc35e3022992f4ab400aba45b4ddf958), uint256(0x20b85a738340cf7644699475c035a608c8fe42da36d45490a14dc85114dc2d9b));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x066684f697ba11411ac58bf3c05e6303482c3e825d7e47b86cdd875a8aa00b9b), uint256(0x1e5470cdaae4deda2761313a82975ff27ae915c8fae2bc96ea3ea43d741b6842));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x2706fd8165bd8f17bc4c173603f0abf4d2a005acf525003aae0ab6c59d7ae9ae), uint256(0x07868fbad90dd8c134b244083800e3391e262d9768409ec60fafb2c4413769af));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x270fb07b7214b79bb4eb20f944ad110b0b910de14064c85f1e304815da5c0ef4), uint256(0x029d02889700e3e8fe7738d1988b905135943c2d88115d35b50655a8f678b578));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x267aab41199a0d9200d06a94ae76f341300b116ef009a3122d960aac3dd49070), uint256(0x2b35254ef41926b1e95182ea76b079e1d9dfd36a434549338ea1d98d5800bfed));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x2d45f508a05f9a0d9fed4f83e3de4cf018973384250642b1a0256e79aa65af80), uint256(0x2bfa7782145de1ed13211a3ece63b2f48aa145eb89e0f2fb690cbb4805708899));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x2c43a395c60eed2c20c71ae5e2f7705cf391ad4214883a7728602f47f4159359), uint256(0x224b0989357ef17608a45a4838f13d66f51c0128d07b579dc08cf930fb824ff3));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x138a957b6bed0e252dbb0c6fb43172b3b5d5e8dda7954d11226971285748077f), uint256(0x1e9052ffeb1a02d1c62c72c7d542da694b70badf8dc5990a7d4b7bec3a6aba28));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x0dae293589fe6d42d29edfb984456bddcf7620ac649de78b97309654876f28c2), uint256(0x028a8e2aa004fa1d20591cc6c2c3f080cc0f5cf051afa78ab42d0b5198a2f4fc));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x20c695f90c63640523eb8625b73dccc64337884e5f633bd55985e66271a8d981), uint256(0x0c95bfb0a785fb6539fa7ae05493c352dafd2f5d17fba9cc2ddcdb81344672ee));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x01ed5f9df69a2ce32f214b4b653929d5b1e997757fd3b96ca86cbdd6070d313c), uint256(0x1982b453626a228a478611180896b11d01017c957d4c4d168dd4c9ef327eb07b));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x29c350f8517031d18a86d013537c35fe5bca9239c1d9b6a0c35179d0a69fc346), uint256(0x29af41feefbbd61dd982f2edb7a88df8e144e4c9d95bb1698e9112b451939a67));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x0dcbac5955c1ccf7ab2be8551c9016ecf7acf21787df2cbfb89a9d22b5c278ed), uint256(0x063d8e8db09cf3ed8a8c0a4d936f0c24c49265a593ee578eaba02075796e216f));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x0e63d5e72d44f58c22133ae535a796620aebc7f5d8fd2161f1c44b47d2d29316), uint256(0x03de5743b17260a2ad735d618b2b0b2a20ac1ca985c1e792cbed64e1d8ae07b7));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x2706f98cdbe5b05f97154e778ea4db0dcd09c47e7a88b8780133d7a30b540bca), uint256(0x17f9c01609d04a26a10d1321eb5421723780743581ba2f8a70aeee93246e2b77));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x144fe26cb14b1a36e0d444936e26912a2a5aa32446958ac054ed4d19c19ecdf2), uint256(0x09c03e18d5b5715d24317713f6c8e5fcf5c2a6c25b3c315c4adfc29e11dc3a0d));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x25c3dbeccd69954d1c20673d1d9eb6f032fdc5309f26b381af19dbcf1acd2ee8), uint256(0x00762f4ac0c9ef683f1e5ac10685feb66041461a949d1364bcc9891ca6998b3a));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x0cf56fc35fb6ba13e8da7abd35ac3b0aae8fad435466f6734474f0c2bc1bdea6), uint256(0x27f4ef7f69d46c3df348fc0dcc63da7a2af683e7a7bd12773d7383980e357454));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x20455d9602f51e02e9a9b928df3d36aa00b059294af8fe08a0aeb74e6466a2ca), uint256(0x0fa2e8585e727ba8808f04bb82b400b5b027672c9a31e8bc9a62dd0b07e97ed6));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x06ea9ef20967aa8a223275fffa1ce2e13865c72ce9e1bf631c58120bfe4e7b3a), uint256(0x0c3d88a12da8bae73382580a12fde3287ab9c1a4d34d8acb4117457d50c33eae));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x214aa68981875abeaf340cb3c37fd244b8a623973b96fc644d1c17a84fc166b3), uint256(0x05b6a66938e05c349cecb656aaebb30b41e72d98509cf3c3a31a8736ad13142f));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x0174308362fd2925430ae82cd1512a0b074c6f3a67f370676eecdf488fcdec13), uint256(0x08408e0dabf08a41faa91bc993d74a577b853b66450089f925b5ac6ea25907d2));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x06bc6a922ac9d726384b491e39391e3c85ddbe7e06ce99580fcde33fb57e1297), uint256(0x0ea4fcae6d6ca816fc39234b3ae16964f8ee309ec3ac8ac8a12ad3a53189284e));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x070244530b2be7be7d376fda0349c5c026dbb1f02c18548780b083a417437b83), uint256(0x11658e2a0cc9d2afe973fc1ba99a7bed8694041629947c51a869dbfe4e0923db));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x27bb0522ba032d60e30a9198bcded37d1eda2f7e59c611a34dd0ca2445e81338), uint256(0x1a000a1aef91d25e3c9f75e2cc162bb8ff41bfd939b239561fba26c8d4594021));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x04124304eca9e7bec15cb2d86fbe3c4bf763e38e1fe4a393c41bc6bf091c5923), uint256(0x158c768dce71edb1474f8b47feac7c647a2d0ecf16ea6d1b398a479274b372d0));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x07fbb7f726aa5311f854b42c992a00c52fe75925825ff021b7e6cf5842dbb99e), uint256(0x2f8b40fff7c502ee7efd9e475d1cf1a77963f385920b7bfaae36d8101b1cb12a));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x127a67a31749c640249fe0313bcbe779efd31e570f91e57976de182226507890), uint256(0x2751600c9b7412d92872a9e9ec8ebd981963ca983a88505b0603f65fe1386be1));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x29dd1cdf90eec25e0fd28c8cd6dc11f1bef7ef5fb2dc8104542136b7a29e6afc), uint256(0x0824c4e60ebd4c37a06d8732dde915237e7cac154edfacd84deaa53d81908a8f));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x21f45cf4d557b6451c1ec6123c29a20e0f60330536d63a5281785a12e627ac44), uint256(0x1bc05f87e70d46317b93c363e8b22c5bb4951cb35402127ee7cf849c2b5e9a00));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x0694f4a8e11f195f497eaf2f64027941ed5c95157672f784fc5ea552d7942ede), uint256(0x063228e7793312310ee57243b08e5023ca5ed51a73d18ece0314ed03ab1b3c10));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x0e508a3c8133a1200d1ab23456cd1d2f83d1e624d8dc1bb4e23df286412aeb19), uint256(0x097d9813023002ea099858147672ba7d7f1a66b811f4dfacfbea1cfdb8a76146));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x2811b54bd4648d86ab427a2c531426d835c8d18fbe187f1b518c515b80d11cd1), uint256(0x2f4eabdcb1efe12ba1eb112fe9d18cbbda017836ce69724c74b81f2a09bd29cc));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x11d7fce51d3821865d3c9e16820d4ad4ce48024ef14c79d398f8154e33f51751), uint256(0x27c37074b322a8c735cfc57672a6a858092c8bc527e8ee7419f440d34a1e383f));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x06d72599fab3682789274841bac3aabf08d69068e1eb429d2f1f5fa21b974a67), uint256(0x207f22d894c98341e6e918fd978285c434eca2e1c35fda7df28245939fb62332));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x1d5925f51794d8edc567287bfacd394f2e17f27b11a6f3d4b1a0cf62575012c5), uint256(0x1512f29640448c72c5467493489391ff41ee29f501c75489f8ba63b0aa8663fb));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x0bc919e6bcd26e7b11974ba948a34c08cf902b5a844a736ff0ab07fcfddc8cb8), uint256(0x11849d1b885efbbfa8bea6c6d35934420fc1684ae249b5ef8576ebb802fc14c8));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x1cd94c8b5dc1f78ffcfd2b091d909f3f038b40e107c039f317cbcb40b9e9b868), uint256(0x052a72b2e130137689859430d6a841eca5b259e4579995eac2e46763d9445721));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x092d4b26b3b50132395e1cf92379de1130040edf1a29cf091b4965cddfe31a3c), uint256(0x21816fbd3eba52bef3f9b1ee22182c5a28c879937ee8752fdc416ff924a6c111));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x116d4994e9482730be7d4b081f28253af1567521c1a99c28c8585d0d7102cb57), uint256(0x05fe54dbe20df54700640f725e3ade45a0d85e85cc6be4f8822728c7441df4e3));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x057de990c616227c8349f82acfcbafe82d1826b8df08730f8952800a7b67af5f), uint256(0x0c6095121acd4eb3a22c85772ec016c593caabcd9e03ede94d6ec8ff47566cfc));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x22782854976c27ae66aaa82e7c3fc9fa3c7bdf182c8484159c383d01d36e6495), uint256(0x15fc2475eb693bd076c2a9ec12a13c5ccefdd5649c8c74a94e4fa82fda9f9b0c));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x22f95287d7c29bd85d112e874671fea9d2cc008ede816df217b51ad77b5a3bd0), uint256(0x01565a0ef4a4242103bfe34c22cbfd79521fd5c87e03ea314cae8067327a0213));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x054ce7d844c76649ab25824f66ff6de66d1a1414e5a09a27d8f2d39d82b74fb8), uint256(0x2af3bf2f347ced8a6f2b966405f79cb853aa0572bd9b1e5a56c1cf980a6d8298));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x2c74a4fe21bd657ff1d4264fad222d20d1279127cdb0f8f3c0465e7dbd858b6b), uint256(0x187fc515f912f7e830ddc718802787d17c83796ffef1caa4ba820f3b3949af6e));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x292601fb851fe05d555f51388bfcdd5d53c5421c0b408b551f8e9d519dec19f7), uint256(0x094525c39bc42de91de538852e86d90709fd1a3df23d8c81b1fa81ee6e305e59));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x28711cf3153bbc7b738f76f1bcbc4311777d3fe8dde6f43dab4097c09432f6ca), uint256(0x019bef1c49b9fe00081ca404e78a4a62d6331778c0edf8e7c02ea3986beff521));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x1a2dc5063d076c071c5afa47fe728992bf2f7aa855663ef5ecfeedbceaa94ec2), uint256(0x30257ab7798f9c34cc63fb2c0097e135ed4ef57e5784058fb8f175046ff26504));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x2e7ecf6b8adc428438dfdd12fdfdf7c0065e6bd1b24321e610b5076f3599e664), uint256(0x0a01060bea67bd9b0f88f3e2d934d8ed5003245cecfaf2a860c2ce8eeb54409d));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x0c38b8e345113f7889f4fb0d2049680cc93ee6b7376a88dc179c3bf9ba1d3523), uint256(0x0fefd294979918c5b5f149f22ab27504ba4fc0b0719a3d499ea0046eaffd4931));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x2b6e3f2efc1e8f9033355897bfaf01530c14cb821b1749eaf699a823e1a944f4), uint256(0x169aecd4525f6ce00c072759d5a38ee8dbc2360ff9d1c87f1e7c2b65c467d7da));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x09655565be1968be15758f8cfde7a34ce98d5ec43ed7e1187331a2b946342554), uint256(0x260915a618e99734f868ed2634008be969d648429a308ec009d2e49e1185454a));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x2eb4a817f4c6cfacc97c08376fa9ba9d97670cdfbd80f2465c85bd463bcf3193), uint256(0x11dce6217d88e2da65379221c3c726b05de8898e90b1cfa37a068e0ba375fbb4));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x04f623b2540519743eb0c9f05311964bc8e2e6dc19601d0cd7c209e8b8e0d391), uint256(0x2d74aafe99ebcf8041b2b1a1e77764bec1fd9146a5ff4979ac2126ee0d456c04));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x29ed5fad430f34901b1e4edd56e88e3daf89238a08c78133f6ca2c954025f4fe), uint256(0x2bc01e356c6bbd5497597239203c30a37ab75d66dc777c1bb6f726cb6d1c8fb8));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x15603b89c012935b315a8adbd7e4650382b0c3427ce38f88ae1767821c2146f5), uint256(0x063d6eea6fbde27f04e21e691530200b77f1ca8df10bc5ec0524950b422f736c));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x2fda2e6b1a99d42e9e0f520eeaf592082147e4d46f3c13cf5377efeeadef50cf), uint256(0x294f0a398866aaacaf3c5440b6a36ee28655edada96b96e9eb589522b714fea1));
        vk.gamma_abc[202] = Pairing.G1Point(uint256(0x221f7b4335ef3e085808a460cfac919d7382f85adf2bdeee09fde96c112c4a61), uint256(0x2db019086d359b1b1a7f6e8a3c558ed30feb229510b46081b60b2c1971ab90bf));
        vk.gamma_abc[203] = Pairing.G1Point(uint256(0x13e0dcdc8769246c07a69cdd234bd765a8027892c83122b629ca09ea2063ed52), uint256(0x2a4ccbd87789d89bd343bf8049d9866110c310bd8fab41119812b838d42228c1));
        vk.gamma_abc[204] = Pairing.G1Point(uint256(0x259b0b027beef09515f7366cdcd44a17a3a1e4c58d7f3608cf1ac5fca8957a3a), uint256(0x03b3c50073bfe74dff902b1ea1238f62d53ce11a553be7fb26bf7785ac67c023));
        vk.gamma_abc[205] = Pairing.G1Point(uint256(0x1b776e858c3ec98599b933e71c3b62c704f81f1dffe426dda1ef1db70ade0e7b), uint256(0x233a1f3ef23dc4490bc96a06401a716d1b1f25d89b32d6d9e219d588c793e9da));
        vk.gamma_abc[206] = Pairing.G1Point(uint256(0x0c52fa2202dedfbfee0b54ba3bc08a7391dea97bfa358f7dd724c8fc43110f70), uint256(0x2b89005cc71f40b10ab1d2613231c24f902aec3cca60a5ce32846e7e945c018d));
        vk.gamma_abc[207] = Pairing.G1Point(uint256(0x2b7d1c16260b50c28151a5c93856a242a17c49e29f9df11fafdd9acc8f36d883), uint256(0x2c76080b33bde6a5348b5972cc9d2abd15744d68c1e5f1ea3837090cf3318109));
        vk.gamma_abc[208] = Pairing.G1Point(uint256(0x10d9c7534aafa6392e63d7d8601aefca52595ddd3ab8c952c906fbf90dc3cd59), uint256(0x17c35070f0ad59463666995e6aac5826a97eb60320ba3975303053754ae638c6));
        vk.gamma_abc[209] = Pairing.G1Point(uint256(0x08f4b4fa1deae26eb872e179e4f5b6d4076fd79ae1286fa1633716deb1a833da), uint256(0x00ef14bdad1f4931e9fae5d79c39220ef93a4d1da7ea306955c03f04261cded8));
        vk.gamma_abc[210] = Pairing.G1Point(uint256(0x2272448474e5cc7526dc0a1811bc5ebf0d5ddfdfd3bd72c3c5dbccc5da43b3f3), uint256(0x27f80426326ddd646b395cd31fcf87cf8ac70825a04b6fa7965d98105556af58));
        vk.gamma_abc[211] = Pairing.G1Point(uint256(0x2e150dafa93754579ae25a0d485cc7887c5ddddb18a9d3beee54461a6bc24eb9), uint256(0x292ff9f6425345e68dc58a666e02e0dd5f5e2b71d146bef364f28b280a152d2f));
        vk.gamma_abc[212] = Pairing.G1Point(uint256(0x1333747dc1595501d2ec38db00321211f67c753450c613704b98efb7d2b0c8c1), uint256(0x0c6b58fa393a402d85b78c82b3a0db00fbaeec4c632deb986f63ac3061824e20));
        vk.gamma_abc[213] = Pairing.G1Point(uint256(0x10616d46bc5b89b2216092330df9e71b712e08c9ec91510d38dd1cdd360bd740), uint256(0x054ffcbf6c23c484c22eaf168d84872ab4042ccce917e6a2dc00edea70ae5212));
        vk.gamma_abc[214] = Pairing.G1Point(uint256(0x183a2d7cea80a8320cd5028e3541a8c804464c265ee0ddec10d7c974be01000d), uint256(0x09a7c79830dfbd05d1d1619bab34547e7182d69436001d64feef53bc93a9b207));
        vk.gamma_abc[215] = Pairing.G1Point(uint256(0x2d256be85861acaca7e5ee018e7b58f249a31c0a99cc39e7080550bbddbb70f2), uint256(0x1a926ee8385c90cb9cbc1a29b020a8c192ba5838ccffb1f564896790b5d1418c));
        vk.gamma_abc[216] = Pairing.G1Point(uint256(0x029a39ab5ba86c3a395581b4ed62937a2a5e174e38728c80f127392cfefe3ab4), uint256(0x26d117e82d6669e0b93f3eb61ca466cd48c693239a784ce24a119fdd0c7bce5c));
        vk.gamma_abc[217] = Pairing.G1Point(uint256(0x216547adec9e875d76ec15bf08358fe223b145a08c93b1f2f4ecf5796752973a), uint256(0x187f2ce57481754c775d9856bb834cdefc2271bca0d7df544887041d9cd47786));
        vk.gamma_abc[218] = Pairing.G1Point(uint256(0x24628381bad1575e6e4ee54a14200d7e73bbfa00af632c7209b57d93858c7694), uint256(0x2fd6aba96635a5c49121dda82923765bf6b1397d65598fcc4bfb3d435e19ed41));
        vk.gamma_abc[219] = Pairing.G1Point(uint256(0x131354fa485e0c69daa33c129d87ab16d633a660da07449a41bbf44cfc33401f), uint256(0x27e7fdc637dd6ce62050a4a98b71874b2e0d11c6f125dfcbe620f68c8f895411));
        vk.gamma_abc[220] = Pairing.G1Point(uint256(0x0601ab622148d1e32b7865bcc841f78727fe211eb50286dd60e386fbe4151cd6), uint256(0x002e38f2cb4c2a6feb3c4e38163b25c0c9c4261680e2fee749be0dcf636883e3));
        vk.gamma_abc[221] = Pairing.G1Point(uint256(0x188ae8e67687bc866470ef1b5e526c70277ebfb58914d689baf397e4dd289395), uint256(0x2baf504e89dbbafdba4d81c4b34d8f7d8088fc99ef8a74e32f4d4ca3f2c02107));
        vk.gamma_abc[222] = Pairing.G1Point(uint256(0x0ef76ff2a1e6f5ca733963f56419e2edb34c0592e95f2f98c4a80d543219c8bc), uint256(0x0a478804e2b720b46ebf234ece6bb0614473298403a68b1976a685dbb44c847b));
        vk.gamma_abc[223] = Pairing.G1Point(uint256(0x18b5937167c6709682b619bff938008ae44484e5b2e1825181a8de4ca436eefe), uint256(0x2b6c96683f3c7eedf29485534550cd39e5e416733bb73417c109055fbf1b9c4a));
        vk.gamma_abc[224] = Pairing.G1Point(uint256(0x186485817842e354ce9a2d8deaf823038a92b8ab71d6b2bf86451385c1c9ab63), uint256(0x28f891f20d9fa4b5a5178b28c5a7c2741e2dc00c5a91877d7a247cb456ca0e36));
        vk.gamma_abc[225] = Pairing.G1Point(uint256(0x03ad7f5cef589effaca18af4ef2dc4dba35fbde7a3c808bf3469cbb23c1d0fc7), uint256(0x02d6fe1230fdc3403edb0cc29c7fec2b5055b3b6015009aa7db37357a9e058ac));
        vk.gamma_abc[226] = Pairing.G1Point(uint256(0x100e6d7bb1a2d627385f03cd1fe475ba9bbdf606e35827ce1fd198afe84b9951), uint256(0x0e94b465c86f298f74af68ab2899b13a6b8f359512193de0678b86128b529971));
        vk.gamma_abc[227] = Pairing.G1Point(uint256(0x2dbc6eba0279ec0946ca678d43ec253d8fe0f7aecfd4fe8c6589ac39ff6de8f8), uint256(0x030365dbec003c88ec9344616385b322f01d4b2df16d60b0f17cb4b7cd9146b7));
        vk.gamma_abc[228] = Pairing.G1Point(uint256(0x0a57456df1bb260d815c571d35b298812ce4383e0e60484bc1c8d83e804ba80c), uint256(0x304f6dfafcee42cda27aaf423457ad6b6ec3170b255e5f9bba713c071232f54d));
        vk.gamma_abc[229] = Pairing.G1Point(uint256(0x1d84195f51e462b0d7e695e5bc55168a99b3acde69e893479d6d27972772ebaa), uint256(0x074cc9424662200d6d42797adc34a920ccce2a3306373d67e4ce956bd036c3ba));
        vk.gamma_abc[230] = Pairing.G1Point(uint256(0x28d422e9182028b73ba31dd3e91dca8e524e042af364ef4d6d0e64d57fdd75e4), uint256(0x117a3d78cf5a909bc463b3899e47c6c912d38f7a6974c12836c8dd0c34d8e9ad));
        vk.gamma_abc[231] = Pairing.G1Point(uint256(0x011d3e02fd1ff23646fda9a2eadf6a35006b7af7a9d00fb5ff08691ed4b53656), uint256(0x143a64440d00931912e89751a312583e6062262ead5ee2c2e7ded8410a98ee23));
        vk.gamma_abc[232] = Pairing.G1Point(uint256(0x28f7b3a32595d91de56ae610e3ec74b70db8f26bea306116418886912748b0ec), uint256(0x2ee62d319f6cfe7b5e8bd959f8b1353ebda7e85d75a8a125e9fe3b002956542b));
        vk.gamma_abc[233] = Pairing.G1Point(uint256(0x28a39dfd2f77de7e5be1b7635914fdfc66baa7c61c999725369ea8a229ee2adb), uint256(0x0aa6674574d517a264fc232e0f3662c20093cf7e06b4bb7c5f3806d4dc7cef16));
        vk.gamma_abc[234] = Pairing.G1Point(uint256(0x2db62fa4272e6870202d51b46497d57a6987e7f7d97fe5b145c133251d0d566e), uint256(0x1993d89548ec642d35dcc6d357e9025269f96f651a9038a0f3496bdd6c7beb73));
        vk.gamma_abc[235] = Pairing.G1Point(uint256(0x0ea45b59b8c682bfa3c938f3547cf6db66a0e1a21322b00a0f3b223d6e09ff8a), uint256(0x2b98515dce8dc53ac7d070b7fde600f5751eef348c30fce655946085a3b7ecec));
        vk.gamma_abc[236] = Pairing.G1Point(uint256(0x0134554ba6cef2287de16e712b6cc74388d680c90defe57638f3cbde54401a70), uint256(0x086a9fddded7a9a81eaad750abdc2bf7bc0ecb8998b438e97bf9e28f1eeed435));
        vk.gamma_abc[237] = Pairing.G1Point(uint256(0x2640924a7fa5cc9901df5b56a6bec41b0cf88cf8f69067ffdfa179bb0e551ed1), uint256(0x3010ae2c54013bd37e39b3fe652bfc1287dbe2ac9da53c3d718dcee6a761e8e4));
        vk.gamma_abc[238] = Pairing.G1Point(uint256(0x2aaf358b5b3a006c868b8f567950651e449e2fa18356c5e1c54c5e0634f4131c), uint256(0x2e16a6ff4801de298f1129ff02fc19749cd99723115aa155d59ef52a8d550896));
        vk.gamma_abc[239] = Pairing.G1Point(uint256(0x2f20a3bf394c53350a8dc5dddbb633286bce09cd54b316c10cd4f8cdbdbb3cb1), uint256(0x1602aabd6ba7a6b55abac2c677717c7624cbd5a3c2a5e7b32ecd66cd3f853eae));
        vk.gamma_abc[240] = Pairing.G1Point(uint256(0x2c3deb068731996b02a8ad3357856d151f59a51ecb81a3dd125d9a89e2e53f59), uint256(0x1e816f9ea98e00b2cb3e44d8a0a9fbe859b08fd799226beaeca124fdd3a4bc81));
        vk.gamma_abc[241] = Pairing.G1Point(uint256(0x0a1d7d8f1773d9e4d97e7996f2f66ef73511b58d091806835340f57174a76be0), uint256(0x10821fd79dcedcdbeecdb7cf30801dfa816bbf42081c45cf5f7c56313e9ca562));
        vk.gamma_abc[242] = Pairing.G1Point(uint256(0x12c8ff65e1adc2014e98c2d37e0481894dd46e5a3bb811d391df5ca36c10d8d8), uint256(0x0e15d6d47a04dd69b08615ba2645b5e5ab39badd368ad249e967404c8214cbda));
        vk.gamma_abc[243] = Pairing.G1Point(uint256(0x18adea33c8beaf0af0eadc33e3b22b9bcd0890bfe276172e2f360fb6db8d187b), uint256(0x100f93ccbaa9555789fbaac9878ddb4cb54ba54858215f1701c4da40b76dad4a));
        vk.gamma_abc[244] = Pairing.G1Point(uint256(0x1632c42ab2d61c17d05087214af29987fa50185876fb11b4133a19d9f2975bcb), uint256(0x0168b4c885584ac7f1d50e49f6dd18ae9e958fe38117160b0d5cf228183dce8d));
        vk.gamma_abc[245] = Pairing.G1Point(uint256(0x2a60410f08c019f24399c75192c2c38afe767775ef90f28cf1fb9837ff2b1453), uint256(0x0d0ec75e6128c2fbc2476b3a1e8fca0ff7b760e92c26dac750f7d98055d61fdb));
        vk.gamma_abc[246] = Pairing.G1Point(uint256(0x0e23b9253ed2a80da5c05bda6195ec5caa0a95007e9558c0241b7685f5e2a6a5), uint256(0x2b1053ad8092a7ee44a587d41977a2dcae30b88674248486af8bc1354e539639));
        vk.gamma_abc[247] = Pairing.G1Point(uint256(0x04db8b7e6e55f101d30df94715466b2c8bbb667a4fcea2a0ebd8fed810b19a1c), uint256(0x02872092c2a886df6df69504b804ebd836c5ec2187f45c068b53756fc6d4ad7c));
        vk.gamma_abc[248] = Pairing.G1Point(uint256(0x0e0af01f32f1f914f9e5d103c47c6add01c1cec8454f5f4407956ccc3ee16392), uint256(0x07f24086ee23dbbb86af0e2e3a00c42ed1bdeb72ae6d9a6199558d7e03d67854));
        vk.gamma_abc[249] = Pairing.G1Point(uint256(0x04c2201e30c31714cd5e8c34c09c298fc48efb62d31311b46caa0dae7de7e034), uint256(0x1cd853ac3cfd6a5d88cbe6821ef3726a1bd9c9f00475150b7e2e99f6a3d039f7));
        vk.gamma_abc[250] = Pairing.G1Point(uint256(0x00be9e4472b4b742489e2451ebefd51eae445ecbb436bdbba2f63a445d578970), uint256(0x10faede536bc1a341783f1edd935b6b5f20c0e880fcc986674ba9a1a1f2d7ef2));
        vk.gamma_abc[251] = Pairing.G1Point(uint256(0x1674bef879f8f5b25aee6a1b87e7fac8092f25c3c8e2c0dafacbd39f9dca292e), uint256(0x28d5791231e17277f0889b764dc2c0a032b1134e0578da4611a0b00c8f3e91e9));
        vk.gamma_abc[252] = Pairing.G1Point(uint256(0x0ba9d94cffd9faaf6c14f41ef41944345e1de609de53d443016837635e4454a6), uint256(0x2c185b1f025c2bf24d46ac789980496f9a87e4e59bf5683bdf911ea5df2b0b67));
        vk.gamma_abc[253] = Pairing.G1Point(uint256(0x04251c906e47a0bf569c35946ae937ae6772293deb2c92e4cbc41292bc95e9ee), uint256(0x0145a70c4180edef5f13a1cbb7b1cff5aa08cdb9ebb52f520ea793625b598f33));
        vk.gamma_abc[254] = Pairing.G1Point(uint256(0x047031222ea55b49bf8acf919db49c6ab43578978e97a655803dca750a1fad67), uint256(0x14621ffb0413bb963310cee928428b41856785f0bb4073461bb7bdf55107b847));
        vk.gamma_abc[255] = Pairing.G1Point(uint256(0x20aaf8992c7f3d710b89fff5931d7cfb16a857e3bdac3016ad9481783783f8e4), uint256(0x05f3689932299b7a065916528fce5c2d0e28dfff59bf37184f0a991f3cb538b6));
        vk.gamma_abc[256] = Pairing.G1Point(uint256(0x2075cdf7303b6928f526123ef4d67adfb49fd5d5bc17a4cbe3207208f856fc57), uint256(0x15cf9d6dc46caf8ecc207c082507f20a151faa7243723f20c596f96d9671f31e));
        vk.gamma_abc[257] = Pairing.G1Point(uint256(0x0d0a4958eaaa6ade5a6d5512d65a8548fdaad0b5e90034854ab46a3643dbaa7e), uint256(0x1218c50d0148165e211b3dc548e962a5c7f6d579538f8fea747f9465fb766229));
        vk.gamma_abc[258] = Pairing.G1Point(uint256(0x1174d1449ee4baddcef0488bc7f6ed19438873671432c96a87216a2e2a08912a), uint256(0x242cf3aa312935a4c693ea10eb378c994628f6d2e491aeedf5820928aa76c86b));
        vk.gamma_abc[259] = Pairing.G1Point(uint256(0x2ea3520d30c61a52d15515b3d9411bd85c3fb5d16c65048301731bf5b7a979f0), uint256(0x2de1a7bf76e50545470d40783462a99d76f1e1ddf6dbcf3b2b7140a94fe94772));
        vk.gamma_abc[260] = Pairing.G1Point(uint256(0x28d966bfa3f0efb0ccb35264751ac5941fa2f4dd7bee5ef17c7e6676fd694bc1), uint256(0x03b874e638e1393c4aeb063a69f38f47b4fd823a2bd956cd0bb3d3261733121a));
        vk.gamma_abc[261] = Pairing.G1Point(uint256(0x03acf8b0fc67a35fc4c1f149a863f0486d510921d021e58b47196c246e4115f5), uint256(0x129e21f8914500e325485f214bf8aecbcffe711d8b5c8ad41ee70240bfdfad1a));
        vk.gamma_abc[262] = Pairing.G1Point(uint256(0x2b8d39e331fdd1e539a95fbacedbd8fcd8ce46bf70a5d7cf2b233d7e6a70e38c), uint256(0x11784f9cdb9510eab7547b106605f3d365807c348fdb9f7293d1238a61eb9f10));
        vk.gamma_abc[263] = Pairing.G1Point(uint256(0x201b680fb8b9ab256f6288ad38143c947b6413a11e29ec1efba976a37fa9cb09), uint256(0x2c7ef453954d66dcf225092929d5a24cd415d12ff1a61e153172a864f7c4d2a6));
        vk.gamma_abc[264] = Pairing.G1Point(uint256(0x0246cb4f307c6e61344b4824d113ede3e710738995c6d77bee810024ad8aee00), uint256(0x2e72e3c2f4f59fe2e5edc93429c55115a91f9901523e054170c2279bd8ae9695));
        vk.gamma_abc[265] = Pairing.G1Point(uint256(0x06691466737c19a004ec6edfc0ffff6a1e2e98ada0e4c54e537543aeb7c59d2f), uint256(0x260d268c06c36cdc7e09e78394ef8646d954f4df4b72375e4d856938c1fc2370));
        vk.gamma_abc[266] = Pairing.G1Point(uint256(0x09742aaac3c9dd4b283bc10fda7656b755491c4c507b69450cfd9297d25f85d4), uint256(0x0969bfeccc0ae8a71ab3bc5407e781077989fbe549745774c86120aa43fb260b));
        vk.gamma_abc[267] = Pairing.G1Point(uint256(0x034a18346f0bdbedd5bf15c2c0ca8539ddc3808d6971daa89eb955b5f7238a0b), uint256(0x1964c12040f1742fae42b90373672908d6a8b340b21b3bf04489613aa7e7241b));
        vk.gamma_abc[268] = Pairing.G1Point(uint256(0x2eded24642d3b2aa7a99d9ff5730d6ac5b98b88a899fb9a05a3b73f04dd3314a), uint256(0x01d5c0a6e75a6faf9095eaade20f1205a918cf92f7d3fb3ab873fda540332dfa));
        vk.gamma_abc[269] = Pairing.G1Point(uint256(0x26f1efd95cada12a16008e32c505416a30c3701b1e62a862f0c4d5da9989c85c), uint256(0x30632cf98fe3ec50bd9b2b7e26b55a9ff858d7f2d85f32cbab87799444a13687));
        vk.gamma_abc[270] = Pairing.G1Point(uint256(0x04f123f7427acbc1ebb2476af3eaf2d08dd3353eb379eac14a137b227bd2d813), uint256(0x089b9ee408fe60ff05590aa9621729eac089483cbadefe45da1cdabbcc38c101));
        vk.gamma_abc[271] = Pairing.G1Point(uint256(0x01a5ecd07f99f54bf68bf7ec53040532f293122206ad05b7965cd81369db9bc6), uint256(0x0e6cda5fe6a7b43d8d4358848946a6b98542c8756cddf01dff107eef14a6df42));
        vk.gamma_abc[272] = Pairing.G1Point(uint256(0x00580fa0c8484a91f027967b1b6af45afd2287d46f531ee805027032cea8f808), uint256(0x00151f5c9d84f1b268b5871b1d00a750a85719352ccbf561c65d7a96813ffbd6));
        vk.gamma_abc[273] = Pairing.G1Point(uint256(0x1f220bf3fd7fe0d08dad84b8e932da108424708d89f8c0a54c74fb76aa371135), uint256(0x2b00a3650e1cbd70be2e1670878254f7700ca06255c63f1c2192140820ddc720));
        vk.gamma_abc[274] = Pairing.G1Point(uint256(0x202c602ade3f76d09269fbacec795f4ca97c1a1b34ca09b134060102a9620731), uint256(0x0db330d7e6650eabf0d84172213a0a98c5eb6eee3ae95c55630313fb5c0eb5a8));
        vk.gamma_abc[275] = Pairing.G1Point(uint256(0x01ae4fd9e1ad398432765663a4b99f1120ac4910e4b7d3ad5e850b460d77a24a), uint256(0x181be96d08cd08aaf6594b03c0541fe4419ba0b505199ae9a97f2642a279954f));
        vk.gamma_abc[276] = Pairing.G1Point(uint256(0x12d6fea6e64c1f63bdc53f2d720b2be1569680a6adccb50399324be95a1aad07), uint256(0x1493ddc9578ba84831e9b2b2bfe17bb85f1ab68c2a15d26f92c4bb0ff5caabad));
        vk.gamma_abc[277] = Pairing.G1Point(uint256(0x1f42fb36aa577c50e6599f99e5dae3791c7f9ad380a24d0a7eaab38b3978f1bc), uint256(0x14aa9630e89731701861ef4d1b59a25d62b0ccc42a9bc043004d92b9ab41ea5b));
        vk.gamma_abc[278] = Pairing.G1Point(uint256(0x05f8dd6d9865c4cd2d3b64d387d9ee06cda8f87e85a2addfd9e8a938a1038e86), uint256(0x118344d3e111bda073002a9f60ff97b5f1d89bdbe4784cad98b69730a3bcf5a9));
        vk.gamma_abc[279] = Pairing.G1Point(uint256(0x11693c5a7d7af73e26dc2d0a06a52c76d28677ab795c13b7c00384c352056f64), uint256(0x11325a0e36bec09cbe0b1652258001501b943d7722db5180a1060d7846c8ebb6));
        vk.gamma_abc[280] = Pairing.G1Point(uint256(0x07863b180585cca090ffa32095a69e0d335b49d7375252d655cf99003eb3147c), uint256(0x23899e6c7733d87426264a6739eb5e9da709410927852b924faf5bc7ffee649f));
        vk.gamma_abc[281] = Pairing.G1Point(uint256(0x2f5e0b3b636fb509fe0e18da82daa9c07c4b9ac9140b97dc1fec1c297c5d867b), uint256(0x26a8b9c966ca990da01113d4d9acefaa89785b6855521f9c2ee0d36ad7f6b984));
        vk.gamma_abc[282] = Pairing.G1Point(uint256(0x1f96272079b911d6f0e157c5fa5cc34a4653f2be98b2b03927ebf696ab45c36a), uint256(0x0646b118ec84b3a0cbf99b0c30028a77c8a7d34b2abf994f340a0440228e879f));
        vk.gamma_abc[283] = Pairing.G1Point(uint256(0x234a1533dfd4ab47c376dc20c63e6d940f230120e3a7747bd296596da2ba5dee), uint256(0x0a6bfd80be496e08ae71a11ce15860a1c600c29bc273603103643a4dd1fb0ae4));
        vk.gamma_abc[284] = Pairing.G1Point(uint256(0x149f544b98299bd052554370dd4c41cb1926de6b52ea252a461b1cb8c7e8923f), uint256(0x131f9160f90e20bd5856965bb0f302dcb772e06e96599dfc23961242f03ec5ba));
        vk.gamma_abc[285] = Pairing.G1Point(uint256(0x1d15acb722a22322c734fe4b7c7eca0dc7b53654ab9880bb579c2281bacc28e1), uint256(0x1ea04ea7d494ce32cca9ebbc2de36be51f588a830dcaca717c7d35c27e17263f));
        vk.gamma_abc[286] = Pairing.G1Point(uint256(0x06f8f6d847cdb19282962e32781add46ffd83d2aec5f3a09f1ee11cdaede8f76), uint256(0x2c2068215fbb84817928c92031542471c238c44d10491769ef404c2cf5d9d364));
        vk.gamma_abc[287] = Pairing.G1Point(uint256(0x1881f8618c1b68e88ac5128d35bab5247d8381d72de675903a9a1acd76e62ef6), uint256(0x2171679720c12639e1f5ca65d9e4f7d3051c638bb474888f1e54fbfa228be7e2));
        vk.gamma_abc[288] = Pairing.G1Point(uint256(0x2132a72b883c4d8ec9cb8b3adaee3e1821bbb33f51ae08741cbd3a60674d8345), uint256(0x0a291e4308d046feb4bacead7f349ee40a55a3ccb82f60afb8bd14fb84e53acb));
        vk.gamma_abc[289] = Pairing.G1Point(uint256(0x0a69a377c7b29ea4185ed8c5b2b30bd4a974bb59e2851bc071b5f5ce41957b8b), uint256(0x2434e4437511d03d351a3bbb0cb2e8e34ecfe73ee718fbcee1117dc3941df231));
        vk.gamma_abc[290] = Pairing.G1Point(uint256(0x2fb8b60cc0a137acd35f4bd0555a55e1f89c29029e1a6fb18c6d717198a87b4b), uint256(0x15597e17dbbb07a54de3ff2b060c1493c454b599f99f8656e36232177ae266fc));
        vk.gamma_abc[291] = Pairing.G1Point(uint256(0x09a2f2ad18059db3aa0e80f598cccfc6ef3429b3fec63d0a9ef71ff0ac181145), uint256(0x23a5dbeaaae01434b9aa7f0469fb9ebdf325bde6b24548baad46cc229ca65d5d));
        vk.gamma_abc[292] = Pairing.G1Point(uint256(0x1ab179235a394548de793decbf239298d4ee67df3ddbc006a5aa334b573a5bee), uint256(0x19146b62842a314c2633e55e330b4c75b0695152fd53c88ad4a907595fd45332));
        vk.gamma_abc[293] = Pairing.G1Point(uint256(0x2819054801ca5de6badb57b408355570486e59077afe72fc08306cc6f34b09e9), uint256(0x08cc4de665fd29c3dc5b3c7b32debc74ddd049dfb20c48d86312b583911d601b));
        vk.gamma_abc[294] = Pairing.G1Point(uint256(0x1affc020761f8c0a74edaa6744925e60fccb07583ab8b6e564b09a02467107a7), uint256(0x1efa746f4a2d2b40262f9656dcca591d674239e920f2ea0b389d945b28b247d8));
        vk.gamma_abc[295] = Pairing.G1Point(uint256(0x209b4aead7d16eaa5005c01bf8981b31c0bd518cc159e62dbd711357ee81ce7c), uint256(0x0fe716ecb38d38ec5cf1d03e912df8988800189ae9df74033a3857fd8d362b03));
        vk.gamma_abc[296] = Pairing.G1Point(uint256(0x02f536f8bc531b00c5c38a0c0fa5c5b67015c0fa9a339368095f1bda2713d802), uint256(0x1d4dea5f79f7a4ddc85cb3423f7fd0abde06d9ad91f325a3204445150276dec0));
        vk.gamma_abc[297] = Pairing.G1Point(uint256(0x0d2222b952fa8eb8329e567ab40420685d6e2d95e37d1d54bab0846467c045a0), uint256(0x2b5174cb5b467ba82e658914c2fbfe6713c8a8351200151122277226c272cd91));
        vk.gamma_abc[298] = Pairing.G1Point(uint256(0x1661b7271166f404d5b966aced12d416896915213f23fe267f4260e03751bf1b), uint256(0x0fc67dc05836468d965194a12f5f6a076b9857753179308e69e90fb5841b1ba9));
        vk.gamma_abc[299] = Pairing.G1Point(uint256(0x21d6357f0a9dde4a6ec9b47fd4193532fd4898f4bad28d865ec45dfa3f036ce3), uint256(0x14e2080d560fb04f0d4f6b932f54f8e06cccba73ecd245b3f9e65dc3ac47ca6c));
        vk.gamma_abc[300] = Pairing.G1Point(uint256(0x00109d63999c6d2825ce27fcb4252d5e0eab30db50791f4c536188629307b6aa), uint256(0x232c2aa38f8a550478e0fdf63907fd941660c6aeb36c88101832068d672b1b94));
        vk.gamma_abc[301] = Pairing.G1Point(uint256(0x1163aea73cf1a24efd96641e6bd46bac7781c0f907ef1271cb6c779ff6991566), uint256(0x0be69cec09299d94afa12e4c60ea86d9c299d75deca2966d51d83fae4d236dc4));
        vk.gamma_abc[302] = Pairing.G1Point(uint256(0x0849eba2343c914df013c3c07fbca2721856c33e18869fc4f98313cb0a90d742), uint256(0x30607b77894b1edd93f88527166f276bac1f85cbb5987c1492acdf516a0e723d));
        vk.gamma_abc[303] = Pairing.G1Point(uint256(0x249428d4c0eafc0cd631d8b62f98fb7235bfad8739350dd0a6f807b5465816f3), uint256(0x11d01ce56f340e6130c462c90b1bf30271096a0eda6016047601508325441eff));
        vk.gamma_abc[304] = Pairing.G1Point(uint256(0x1d7dc4a3670ff9925a2778cb0228cff0b21845cc263d71aa01f8de30c82ff7d8), uint256(0x2fb29eec9c5f76f6b0827c8882df92f8e0d70f6b6fc1d2a46891df13992d826c));
        vk.gamma_abc[305] = Pairing.G1Point(uint256(0x0131c1dc11cb151db2f5fb7a9c083671c89999ee73fe95e0119bd61280100860), uint256(0x01e7dcb0ba0d9bd7a2b48728e3b4a68b5b221b228e6f1ac306b3c0f7d8fc410f));
        vk.gamma_abc[306] = Pairing.G1Point(uint256(0x15827e49143b518b9d8a8c215f705051f95b39cba3eeabee0d512dd02391ba09), uint256(0x08f25ddb056f77abf2e6f9f058dd523895775d71097759f80da0840776abdd01));
        vk.gamma_abc[307] = Pairing.G1Point(uint256(0x2358a5bcc99958fcaf7c0146c96853d4fcd28060a5503f43e7d78491212badcf), uint256(0x1acd06009c0e6893cf954976070485fc52aa4f03f231a1f665f60f235f210f2f));
        vk.gamma_abc[308] = Pairing.G1Point(uint256(0x208568d059d33a69b9ca5fc060fd008e21b993aed99cdd03d5749c26db235417), uint256(0x0982d080e0d501701993026b4d4f8e244c301a6a853850102baed5820fca3b26));
        vk.gamma_abc[309] = Pairing.G1Point(uint256(0x22f87f0f6b7bff1a8cf03c53b2d1e6fe913fbb2c2cdfe7dbdb70adc7e5bee231), uint256(0x2db20138dd26650a00c217ed6f29e6a1a571553278375e76d4e41ce9cd74c72b));
        vk.gamma_abc[310] = Pairing.G1Point(uint256(0x295115a445042a90b753b63b3403e5a4168c1c721a749d49f46934945f6bd6a7), uint256(0x1372a5a2275af9b25f476a119c845ee2a88bb6ff3b05d64a97bbf172ad8b8761));
        vk.gamma_abc[311] = Pairing.G1Point(uint256(0x301e33378a5972b685ab7f975c724aa325a69a63867e349a8979ca78cb4398df), uint256(0x2f55ecfdabb4b7ddf54e7ae43fe0d43c0cdcbfe4312431424629808dc391b299));
        vk.gamma_abc[312] = Pairing.G1Point(uint256(0x0d2789e16dc41f6efe23d475baeeb1b496f45739966c94802ebd34e596be9a62), uint256(0x28bdaad4bdd980c7fe1886af600181a5f8f6c39cda14cdeb149024e89a25923f));
        vk.gamma_abc[313] = Pairing.G1Point(uint256(0x1fef602317e36eb8375f9a1f0aa4a63b2773c27b0d6668c6796b73b7397a06c0), uint256(0x2b84695dc38e43823ea17ab83323591be759e434294a195bc2a36a9eabeecedb));
        vk.gamma_abc[314] = Pairing.G1Point(uint256(0x0e9ab3c9e7023eaddebcb88d517729539b00b2a498f6fd60a84995c900f27b0c), uint256(0x003004d963ff1a450e89d6fd90fa4c6a5a2bddc4da4f1e11c31969ed2479b6ae));
        vk.gamma_abc[315] = Pairing.G1Point(uint256(0x230d73b192d9bc8a26f3e6bad08b0b9a43478fc29d28356a971caed46c68c405), uint256(0x280d029e0b40b844efcd5abd05c494368df774c330c5aaeab1d80944afc61a38));
        vk.gamma_abc[316] = Pairing.G1Point(uint256(0x27099f27ead86bbcfec60851545ead1942c40628a685839b294efdc00cb4e368), uint256(0x0b7866c2d1a94555c8151ee0a73b10e70eaf668765a5d09430cbe9737da0c2c6));
        vk.gamma_abc[317] = Pairing.G1Point(uint256(0x0aa85589869892e7221922c893652d802c64e6914ec5aaedd93fd4281ebc5c39), uint256(0x247348bcb9d782dda9b6dde2df7a652bca4558e6b7ce7d33ebf0a760bff91fa8));
        vk.gamma_abc[318] = Pairing.G1Point(uint256(0x184c2223b7d4f5cf9eb097d06ac7a706e8608d88d8dbfdcfe9833a74912bf203), uint256(0x2a70eb5281e6b81303a705c497c5bd9e269e76d733de46f93f37801f36d132f9));
        vk.gamma_abc[319] = Pairing.G1Point(uint256(0x0aa7e2abf30acf0cbe3102b14dd791492c80926e53e3a9b7722b6ba0bebd4219), uint256(0x166eba32b8a65748f299f5baee6db93d3ca8f56521b093106c4cfd42215a57a9));
        vk.gamma_abc[320] = Pairing.G1Point(uint256(0x2a155a43fddb21ae3ac4e34544e3ad3f9e4f4306108db6250d4f66afe1b11281), uint256(0x0d1e3eff9048c16c53c47217961d5ffc5b6c150b5525fef941f755b63ad066f5));
        vk.gamma_abc[321] = Pairing.G1Point(uint256(0x1a3951944905d744fd0428dc274c4eeb9eab1f6d01668ebeb494a9ca61255d5e), uint256(0x28b3ac59dab6e282edc96c2d9adc7d8b6524440d26aa5668492c36101587d660));
        vk.gamma_abc[322] = Pairing.G1Point(uint256(0x166574c6edc96019db09c9500d58d5538de78fe240ab173a05da59b3cae426d2), uint256(0x000b58fabec7654fd3913a413f4a784799058528828d07b889bcdc5b21c77554));
        vk.gamma_abc[323] = Pairing.G1Point(uint256(0x2735c41cf27828b9b5da7aaffaa3dccd4ab66c21d65daf2e119d36d9c722f47e), uint256(0x128f38a8579d074cc59b9e93db6fb0899257c49430d9a316e6b3e931bedb6cae));
        vk.gamma_abc[324] = Pairing.G1Point(uint256(0x074b3353cd2ec76c6332b17623d298328c34818e557ae1f59a8ab4e4d50c7259), uint256(0x2eaf822c55edebe16c6fc0214f33bb4805c45851953d604f9f0abbf2f67737e1));
        vk.gamma_abc[325] = Pairing.G1Point(uint256(0x07204cb5ba5e518270f34aaa5903141bebd7116d9f2191de79e10cca3eaf2937), uint256(0x0493b39a45b676f4a0859eb25fadaa3cd4fce80eec959f41c23799c32d71e36a));
        vk.gamma_abc[326] = Pairing.G1Point(uint256(0x01345d20743ca6a8630f7cb5939af24afe111a762c2cefd35b174cd603230289), uint256(0x2fcb5c8ada75845e5374814869bfa5c8269c3263c37cd2aeca3f9ab055688fd2));
        vk.gamma_abc[327] = Pairing.G1Point(uint256(0x1aaf9c840679030625a5cff2fddf88630da0907ed6fa69cb64f23598fee2a448), uint256(0x2796a951ccdc1cfb1a2f0d7be4a48fa2b55410239f4b1d2a9b69c6ea1852b53e));
        vk.gamma_abc[328] = Pairing.G1Point(uint256(0x1e5e5d26f76d50acd5644a0332b0393f0d66620322ca82c7f5a807a2d0c93187), uint256(0x0f7f0a211684d616e107bba5fef59462dfd912fa13f10d314796c942ede73cc2));
        vk.gamma_abc[329] = Pairing.G1Point(uint256(0x1a439af3d4f676ff0b4f8b85405df410771255db2afe6d05f97593404647ffc1), uint256(0x099363e113ecd255ab3d528bb82365a09b3156c68c74feb4c82cbd5dc3bfddf8));
        vk.gamma_abc[330] = Pairing.G1Point(uint256(0x2b0e0fb0fe7527555c501c19d255e58d45f7673783ec7a28e54213916a6546bf), uint256(0x0a54da41b9e0ab0c86595255e4102f5b5b25191f9d65f7e42e266e53b0609700));
        vk.gamma_abc[331] = Pairing.G1Point(uint256(0x275ed8b054fc8557bef0f3877d0456d623744e73f8dc94c4e11a33df21a2025d), uint256(0x144176bad0c0e187498eb9159c610356a0cf78f7b6f77996fc48e4f211f9f9b6));
        vk.gamma_abc[332] = Pairing.G1Point(uint256(0x08e9e57051931c2b97cff43df9f66a949100c77d48aba971590dba5f4223120d), uint256(0x2b0cab00143225a6a6885024a3cbd88158d33ae0c9eed6fbdfde1f2290907605));
        vk.gamma_abc[333] = Pairing.G1Point(uint256(0x009e632d463a6a9bf614830915824dc80dbf673b9e335e7c89cc59f26c0928d5), uint256(0x25e460834323e189fbac670820608c2b3905dd8c2163de225273fe40b1f78d0e));
        vk.gamma_abc[334] = Pairing.G1Point(uint256(0x12098265efe019d3d3aa7eceea2d9ffc0d066e40a490e39504ccf816b0ba3fca), uint256(0x01d7b2b1e0df2bead6ccbcddc5561c9c0a9b2910aae20478030068f76b71753a));
        vk.gamma_abc[335] = Pairing.G1Point(uint256(0x2063fc178d31e2370994b44d00705a57b87029f8ba46dfe60b4c587a15631dda), uint256(0x0f1d4a0074111405d74d5f76286d693845e309b65c1b25650c9bde47c831fcb6));
        vk.gamma_abc[336] = Pairing.G1Point(uint256(0x203c4f3d77dc14e2ac513b5f9ce3f6807a63feebc80bce968534eac7ecea8478), uint256(0x211e0371a9054c130c0f5e9e7beeb6403d010a1baf3836003cf97bac53ae7b71));
        vk.gamma_abc[337] = Pairing.G1Point(uint256(0x05a78671b1221bbe10b7ea1b0bed2151d33a743ad1b6071743372922668f913c), uint256(0x2ecc1b9579a2fa837ccf11b51614a5a747ffe6249dc7bbac8d114e47eab7ec9b));
        vk.gamma_abc[338] = Pairing.G1Point(uint256(0x2d172dcae7aac8fc3a7b3067a2779152adf77559fc6f6b2ee9f265c2e0039b74), uint256(0x1d2373894e9ff6c0136bf270ebe027dd6aecdadc92a3a7b1b16fc179ea664ea9));
        vk.gamma_abc[339] = Pairing.G1Point(uint256(0x1963be6ce331ef44ee14741e43e7e2f9f217edd4df6cb7a2bfb094851f4489e3), uint256(0x2b99cf389abff6120af1098495aa4b47507f8a306a631f835b05c82c67250be7));
        vk.gamma_abc[340] = Pairing.G1Point(uint256(0x0455057ef6aeeee198fdeb05199708edd3d7028ab8bd00142dd73a344860f3bf), uint256(0x1a929c225d98e34a5fc216ce11bd6a495e6ad9b85ffa9692777cd1688012e463));
        vk.gamma_abc[341] = Pairing.G1Point(uint256(0x21237945a2626f9a8d99ce8eec6d2d3e6d701ebe878f7a469584e57954f56497), uint256(0x19b5d9bd21534a13b6ef9e8a292c8789491a35e79e649cf671833dcdb9489bec));
        vk.gamma_abc[342] = Pairing.G1Point(uint256(0x1b2709a17b6e988c5d10940f274f09b3fa6da718be656946ec6ea1582e20aaf6), uint256(0x0fe66450686bafa78e2fa76184ce822157a0d79ebfe7be2acd9af814d2eeaa28));
        vk.gamma_abc[343] = Pairing.G1Point(uint256(0x0cda3dfe2193489cd99706949cbaba9b4ba146aba3798dd27d4093b26a8eada1), uint256(0x22e2dbd6beca583ae031779ce2878f973e5cdb9cdcf1b34bc30cc0085622a875));
        vk.gamma_abc[344] = Pairing.G1Point(uint256(0x0982592c34f1a32100ecc01e4f91238bf39b8c8924b55aed1e6491faab9c2087), uint256(0x016804b4812f45724fbf5b7485ba4208878bd48b52694bf6a7a6eab8468b97b3));
        vk.gamma_abc[345] = Pairing.G1Point(uint256(0x06051bcece20caba5e643361ce4b20234f610ab4792ae2a424fb5a493826f011), uint256(0x107593ea487fa6a913d20f1292748f7e82b589b895c56ec532b3f93545aab2af));
        vk.gamma_abc[346] = Pairing.G1Point(uint256(0x285f6abf077aa5b5621130e4597cf55683b3e410fab23abdffe676c2138f7bd9), uint256(0x1604c13177fa628f8ce61d7394331570be75669943e7527ba19cdf98003bd5d6));
        vk.gamma_abc[347] = Pairing.G1Point(uint256(0x0de34a20a439ef5c2d75d0e901bef2e510820a7aedf390cb8e9dcac31f945755), uint256(0x1b74390a6af584933e87d120b29fef0bc980f33469db29f3fa9bee1cf53c9198));
        vk.gamma_abc[348] = Pairing.G1Point(uint256(0x1b978df50d7a93cd347d9efed36b988c8f2eca6e60f0f5994175b7bd43ecbd46), uint256(0x1a1ff688b2dd9351073ce293218fd4e0c5ccc7b497ad528c6a49277ff10aaa55));
        vk.gamma_abc[349] = Pairing.G1Point(uint256(0x2a03f541afa929d52100e317032f39ec29dc94a7eedea2c6208011dea0bc635b), uint256(0x02552ad3dbc05a48e2f4535cc7974959d406a4adcfe2c3524b557c8023bf0f51));
        vk.gamma_abc[350] = Pairing.G1Point(uint256(0x2bd0ab08ce40f2f1f8cdd4498956af88330506805bfe06642b354286d45a1c52), uint256(0x07f2b90e20df792698047610b6d034915d11a510965ff637afd2047b34f0d996));
        vk.gamma_abc[351] = Pairing.G1Point(uint256(0x0f3a421431cbd1c64d23d7bfedb5d34354b33361c6af68eb2b831978e3577d7d), uint256(0x1cdec30c90fcfb44e95e8d45bedb112834b76d7427da54b9d24000363f9d8192));
        vk.gamma_abc[352] = Pairing.G1Point(uint256(0x14303c45d41b79cece00e28df4cdff14c62b0fa657b4862d3404d096eeeea030), uint256(0x02e2d47040ee89eae23819cdf5379d58dec6936031cc54a4e0d4e8f9f4ecf1f7));
        vk.gamma_abc[353] = Pairing.G1Point(uint256(0x304bdde780baa8d7e97cdcefadf7318adb988e5983d39b40eb43078329280cd1), uint256(0x2630ad948de12861d40bee2e394d7db03ecc6619237652609dd3de750ec96aed));
        vk.gamma_abc[354] = Pairing.G1Point(uint256(0x0233bb7674ffcd5dd5c537b83d0d97567ec39327dda34982b8282493de3b16b4), uint256(0x1b81c5c185399391b39f9b3e692acabd729ac1b9cebaacad4bf873054bd76c57));
        vk.gamma_abc[355] = Pairing.G1Point(uint256(0x2f8881ef1ec09306603ccc51e41fa034fca69d372b7c534ea88ac13977b7d509), uint256(0x029fd18d5b95a158a5b7bcb8a43e2bb5e220be5c92a444202d4135ea73be60ff));
        vk.gamma_abc[356] = Pairing.G1Point(uint256(0x2d8689d82704f12ae42c152c132a837b03ca2bc85ddbcfdb637194d2e2d70cb4), uint256(0x25f9bb9b36e02d9b0f2dcd8c592e896417bbbf0cdb114a1f8eec0547386260de));
        vk.gamma_abc[357] = Pairing.G1Point(uint256(0x001e190fe16a7d04b6da97175e7f2e4acb21094ba4457c8ce653207ee4d80aaf), uint256(0x1091356c8b807374854ad0d76ef9ff2515173903a14f95d14cc666cee897fedb));
        vk.gamma_abc[358] = Pairing.G1Point(uint256(0x2187110083e35e3c15960cdef662bd2cc7758afd9c6d27e1dabab2d9b10a25df), uint256(0x1d485f56eb919c04fe5d9bdb1b8b9e560589ca6a7941ca9ff09a4264bcb38b87));
        vk.gamma_abc[359] = Pairing.G1Point(uint256(0x24600d731387b437545bc4b20f1eebd25ef56741eef630039b16054b4a083ee1), uint256(0x153ab8b9f05c18ed5a6adcd63135d0f207842c9de9406663cf46d81aabfd7de7));
        vk.gamma_abc[360] = Pairing.G1Point(uint256(0x20ef8d8f626e9386e8894606370c570be5dab96a4ab68fc45f8391f294f1f71c), uint256(0x080a35410d0a4c62437a8aecc7f2f8cf6920f4b34ad10ca9827be1d336863494));
        vk.gamma_abc[361] = Pairing.G1Point(uint256(0x2021794fe81a7b9239bb1c74ac98a9c70f1d5baa040f73cd0a3c3c9cbc6e52ef), uint256(0x08f99dcc551aa74dbff3d4452986d48dd9f15f6d8946d140c5b0a2f8d1a42274));
        vk.gamma_abc[362] = Pairing.G1Point(uint256(0x0c409b32e03e1e4b9ccc32a90d992e5b3479c47c7ccb1371752e32e669c7e4c1), uint256(0x25a3cc38a93d764987075945500e9c87372b1352ef9ed15e27553567b557c81f));
        vk.gamma_abc[363] = Pairing.G1Point(uint256(0x2e68db5c9079db5b831ae6e9f62211c87457b259f542852fa80c3ac94160e515), uint256(0x1ecb4cde7cb6f283bc31c21a313f036cc4c7abf260d68ec8cf5dc9e088dcc7cf));
        vk.gamma_abc[364] = Pairing.G1Point(uint256(0x05e87dab62c2255f98ff67aeb6365fc211103458f612c361bfe23f39271da8b2), uint256(0x278113d823f3150b411ee21613065b3231f5945bd83eaa4818f88d36b33773c0));
        vk.gamma_abc[365] = Pairing.G1Point(uint256(0x289e24c4a7348c1cac23c0e3bbc82f0bd2565a5e56607ff19457fff89a6aa294), uint256(0x1898750c17798a774029cc6fb1476e4db7fe91043406d194e59caf31293cff6c));
        vk.gamma_abc[366] = Pairing.G1Point(uint256(0x17cbad1daa459244a9c5026e3094495f07e161e04c8b904a5d72bf3c95c9c687), uint256(0x097bf6f077623ddaf863c65e1fe8307686a590e3df1334c6b481621e42c70fb8));
        vk.gamma_abc[367] = Pairing.G1Point(uint256(0x1338e19503e33508505b53cee17ef4d03ed8e556e4f9be489ac4b23908d2b7a6), uint256(0x235bb8abe08158c65bad4b56339aa928452fd09a13459f1cc7ff71684a5390f4));
        vk.gamma_abc[368] = Pairing.G1Point(uint256(0x0bda981be5747357d03038ebe69a96bdb6c99b027f1ebd116ddc16510d9b546e), uint256(0x07dc8ea3bdf881e44618fd70a37c2867a9b91266e5aa067766d05c0037f3bd57));
        vk.gamma_abc[369] = Pairing.G1Point(uint256(0x084e0002f44ba402d8adb8f35a5fabdc40a7dcdf38153765a727726d22422eae), uint256(0x232b83d39db5908cc430fe37d7a9872fed3638568f409bfa5cb86458702c970b));
        vk.gamma_abc[370] = Pairing.G1Point(uint256(0x11caa50d3ba69fc572bcb859b201b674db8e12205d0eead8bb285ca736248265), uint256(0x1a4265a094de4256e4f85e1733066a0f14da2fc4d94fd69503933d93bcbebb70));
        vk.gamma_abc[371] = Pairing.G1Point(uint256(0x0197b5ff288cb7f0745742e6c7b06655297dd06119b36e4cbe25ade0700cc4ff), uint256(0x22200ec5c6eaf7a6b541c2444416a5604c9b98a4e1c5c162ed5006a62dcfd3d6));
        vk.gamma_abc[372] = Pairing.G1Point(uint256(0x247979d0fb8a65d8c975654e822c8f82f12472b09fc0c95046cd785b31fa2fcd), uint256(0x0141c8a8133b87ea3a32e98cee68aac6e91bdc9ac335a1b322260276afd86d59));
        vk.gamma_abc[373] = Pairing.G1Point(uint256(0x031484c2129fb8b9f9a7d421bae321189de6ad78f36ace87d91088ca7c450581), uint256(0x1dc0c692b17faa9ac19099a046207c593f562290839c4b46be28885ae880b75b));
        vk.gamma_abc[374] = Pairing.G1Point(uint256(0x2216e09cd12d29ab6e39913e61e34c0d04bc6f1effd68bf339fc961762afdcf4), uint256(0x06537edf67ea6fbcd10ca40900be146ae4011d494a1c5bc1e6db6ac7187bde35));
        vk.gamma_abc[375] = Pairing.G1Point(uint256(0x011a57451343948418d54b3ee353bb9fbec50e34e5f1e5322a0edb2e71613195), uint256(0x247faedc497ced73ba60f9a44dd7fa4ef28dd7c7d70f94fc2a93bf413eb10b26));
        vk.gamma_abc[376] = Pairing.G1Point(uint256(0x2b5d4817a821472513ddcb195c38af74a736b72f039bc207c52d8e72f8dcb76a), uint256(0x26ee99e233f7d2b21d014f60874884bce10befacb4919ae2390b88e276729955));
        vk.gamma_abc[377] = Pairing.G1Point(uint256(0x1bf0d0433dd6277494a2ae02cce441b82e1f6b7bb2840af5c929a9ee8c5a8e48), uint256(0x2a8951c1d059bec60e6d8c5ad2d0ce3547da824ab3c4aa7504ec65fb8f2f8a4f));
        vk.gamma_abc[378] = Pairing.G1Point(uint256(0x0b2d26c7f72ac4c294d5431307042f749820630ae406a8f5febb8cf61ee8b64d), uint256(0x0dd61e1591ffa4e2bb8f3ee68a6792ca8abfe813daa19e23a447f689e1c45dd7));
        vk.gamma_abc[379] = Pairing.G1Point(uint256(0x29ea850b34c69d05c3110fbab0bd13f32ffda8eb55c6863fe7bce2f4fba584f2), uint256(0x03da84a78d7f36ebfdf4c4cfe7105348c9d0e41c9052c1f2ecb48d6c3d83201d));
        vk.gamma_abc[380] = Pairing.G1Point(uint256(0x1f6e820d7f1c10ad1aeec630479899d64f1d71919341179c5726efd8f8d9b7ef), uint256(0x062195ecca8d304a37bdca7578be76fe012fe474f4ee0e5fe4587349681b72ef));
        vk.gamma_abc[381] = Pairing.G1Point(uint256(0x1f23feac0a6d079a13e5cfd46346ccdb33068f25fdfa2bf9427d96dc10d320a2), uint256(0x05b11db811e5b785c335392f610ce90779d327b9e02b5fae9a6be3c1a99ed662));
        vk.gamma_abc[382] = Pairing.G1Point(uint256(0x23ea0c0627823d3f50932777b8fedcf9796ada51daabc7f7cbffe1ebe2132d90), uint256(0x035aad98ca76d6adf970d98ce8b60418e860275481d5b21abc9d32d59976e18f));
        vk.gamma_abc[383] = Pairing.G1Point(uint256(0x229fff200a30106eaed5dbe66ad451d719f7b0f7f50e1d9c7c0e55d8310cdc68), uint256(0x11109a6d97e4f09888464b834a61ee0baddf2fce8840e188b0931a88dfc0a98f));
        vk.gamma_abc[384] = Pairing.G1Point(uint256(0x035b592ee427b8ab1400cd8c8295d459c3810005b01da95591073f25d4033a95), uint256(0x02058b93188bbde18ba62007e3a8d32ffb9849450b4b71a2aee7b203f959878c));
        vk.gamma_abc[385] = Pairing.G1Point(uint256(0x269c3a66d8e520d0967b398476aa6be79fd251bbde520016ca4b7f0b55a40596), uint256(0x0d1b433c5ad69336abcd89c5abd480addfe0eaf40bc1c5e3e2c1af31f56d56dc));
        vk.gamma_abc[386] = Pairing.G1Point(uint256(0x0c4dd6ff26235ef550b1eaa93e744954c85eb107153b9a70be7d04b54aae000d), uint256(0x1866c2431ba3966113b66e35c1953f1474baee037dfe13dca45e3896abb1354a));
        vk.gamma_abc[387] = Pairing.G1Point(uint256(0x238d124e0f696c8c6968f321167ff5f629ab77c87ab1f70996dc0566f74eda4e), uint256(0x0cc82f068c344f4d19f40bde7aaf7adb56689bc1b681320e040c0b5c9138cb4c));
        vk.gamma_abc[388] = Pairing.G1Point(uint256(0x258f573e0db2771f6d2f98eab27a92041c4ef3178c85a51110b44517378fa69c), uint256(0x295737279c3c22b20ff9e23d7b435414bce4aa2a1d7d2b6527facf130fa0847e));
        vk.gamma_abc[389] = Pairing.G1Point(uint256(0x1e03941a67f90113e96f5a776165de737149f1f9b2e68e1f89ba41115852f330), uint256(0x08527d108c64b14968c38e939a7a76e1fbc7302d2124386cfed43e18765dfad2));
        vk.gamma_abc[390] = Pairing.G1Point(uint256(0x10469cd5bbd4d9505a6abafda1ecb1abc60dac028db2fe85c4d95cb84ac6f409), uint256(0x2baf1eac1044c03e3d85cfbbd1ffbcf347a5e7c03592cdc16baaa5dc2f8cc3a2));
        vk.gamma_abc[391] = Pairing.G1Point(uint256(0x02a62fa694a4d4212dae8eacafaec574b4bf526f3a4294728b7ed1e98f8996df), uint256(0x2c1714424b5e6a43c7f239d9bffcb221d48ef31f09089cb72480a18b85618a75));
        vk.gamma_abc[392] = Pairing.G1Point(uint256(0x1d2405ab4b9297c6a9b7cca3f1ca1aa61a93929f1f05b82b49cf751f66ae979b), uint256(0x2ac708d2b2d0746bee6c787674eb56050e491aa742b592f772834df151e8ac1f));
        vk.gamma_abc[393] = Pairing.G1Point(uint256(0x07e635bdb521d9f6e6fae31d5030d16fc4a58da924651c0f3da05aacedbb6630), uint256(0x1c559de160f1b95501df8f44b7e8173e574a960bae13da0dc5480a1fd708e2c1));
        vk.gamma_abc[394] = Pairing.G1Point(uint256(0x1cb8be42ca2c306e053d9bd50d46a356ee4c5230c6d56ec8ac02208179bb7e8d), uint256(0x05d1d7aa19d7c9f82d5953ca16450d2dfa7350a84a7e333ed89c44827e1efff1));
        vk.gamma_abc[395] = Pairing.G1Point(uint256(0x13122e3d6e2a7b407947c8804548705a25ad8b84c2ed250d48e6f6a54dead132), uint256(0x10aa8a2ac9a6cffa26794039a2aeb8728b34a80ec3a166fe75751b18bf92dbb6));
        vk.gamma_abc[396] = Pairing.G1Point(uint256(0x1d75430b4c74521b7233830131965aa6ccff95acf7a8e1ef5563443c5dde2210), uint256(0x2316f665f4406974a1d9b3cd904737a2117d4a79d2153e7034d1d21379895b0e));
        vk.gamma_abc[397] = Pairing.G1Point(uint256(0x0ee178f161b633acbdd9ef217a9e01a88bf8986582259197303782076122192b), uint256(0x1536492946bc6b77f237cd468216b0f6c884cf690a0b5541830d3ca967df608c));
        vk.gamma_abc[398] = Pairing.G1Point(uint256(0x0c88f73f47d34b7f59e92dc1ecf14576df65c27d30d17f22a6287278568e30f8), uint256(0x1489d63980fa80b474dfca4714ee62bd8e2835a74f3c30884b63a0a5bbd02739));
        vk.gamma_abc[399] = Pairing.G1Point(uint256(0x262e3a13bdebcb555bc465359eb3b125f2cf6bba30549191fa5c3612a02f9506), uint256(0x18529d441421c0f3b1e5339223059a95e7a24669b6121aa84b65d315e7bc1e48));
        vk.gamma_abc[400] = Pairing.G1Point(uint256(0x23a5b6d2f6b1c15a66b1006ac36ef2c192877acf2c00a16847e4d449b0adad45), uint256(0x000e14c4851f59ded3cfc5574fc5d172fab67d3d313cc9e105582312ddaa44c2));
        vk.gamma_abc[401] = Pairing.G1Point(uint256(0x220c1d6f1188586178a1acbbef1d89ecdbcdb898adbcfda315f7ae5f3765e1d2), uint256(0x116233aa1301ef0284470baba8bdde5c5b5a9d56f06a255b99f9f2221129246e));
        vk.gamma_abc[402] = Pairing.G1Point(uint256(0x14335275693d1df8629abc7226ec8000c981d3d62e78a767bbcc8098d38c79a9), uint256(0x0ceec2fd9e1354613f7bd2b281b971da48c0edd43c46d56c54a991e040ea4782));
        vk.gamma_abc[403] = Pairing.G1Point(uint256(0x2a61eab73262883d272326f7a3e59eac058daadff6705c684449eba467f085e1), uint256(0x3058ce9554c8395855db03f27b49ed69cddf19935f15ae7ba528087d69940936));
        vk.gamma_abc[404] = Pairing.G1Point(uint256(0x2c656d0a6adec8a6484fa7ac7f3499159616fc43b096c8e22a6be875a7754b15), uint256(0x04e70e1ed4e440d6f4ce69149c8579254be2a71d7bfbd13c7f19ebd88b470b9e));
        vk.gamma_abc[405] = Pairing.G1Point(uint256(0x13bc6bd1c35a8198d33cae7db41fea5fc3af7f746919c5bdf65aae3444725050), uint256(0x279d1d31e0d9505374cfec84511684a2eb321e99c080fedeef71faa30a7b1f18));
        vk.gamma_abc[406] = Pairing.G1Point(uint256(0x11156f34df1200cc170a96ae0425d55e86d6def848530620bca95fdc21ad2530), uint256(0x1fc5b7edecb4d7859e0ba75e21e7449704112e37947278c821af01d18bd320b3));
        vk.gamma_abc[407] = Pairing.G1Point(uint256(0x2aea0548fb33b52077067191fdfeaacc06452e02dd738a26f9fc3276f48258a6), uint256(0x16b0ab54c3c205d00d9cabd7d15912faddc9ed16def17a201c7fe28961fc780a));
        vk.gamma_abc[408] = Pairing.G1Point(uint256(0x09704aec14e482d928fbab5a31deee0b9d5b3f7437c7d485335431fb87c91012), uint256(0x01f0b3d64b8ec287a7a4ec3eb4f6fe5d2d6a09552f3cf39cac4df655b8a4a304));
        vk.gamma_abc[409] = Pairing.G1Point(uint256(0x10016a004f9a4cd0b5944d6b2a8a19d5b291d39389283989c8c125bcc1e40e63), uint256(0x105e2fb14df14b487a9a65c764a38ef6c9d92992419babf05df7f93bcd9458d6));
        vk.gamma_abc[410] = Pairing.G1Point(uint256(0x19486d83e164572576d4c00521ed4c99b9aaf413fd20f181a8ddde789bc17fbf), uint256(0x2309d33dec58e7be80d5b175e872128aa074cb4de587335a6d6f2f45d2fc2694));
        vk.gamma_abc[411] = Pairing.G1Point(uint256(0x098a5e409711efc7eb9dc2e751ed200c1aa64f8808a4b20dfb6411bdbd379eec), uint256(0x13be41e9f5e94689961147e48323b250a2809b48a7f4fd9e96051938f33fb197));
        vk.gamma_abc[412] = Pairing.G1Point(uint256(0x1cc00f2724f2cbb1bde94232a352c814ebdf3757e5c9f9b0824cee21c9c5a3ae), uint256(0x155612fbe56d8bd1b137636dd93644cadeba579c3aa32f740b48a3b672284884));
        vk.gamma_abc[413] = Pairing.G1Point(uint256(0x2e62dcb628252c158a09b57389abff0707090322c092cafb89c052c0786ab788), uint256(0x1b0c1edb825521b5b63aa42eda6bfc9f15d1d46814cbfef900508e5694c2d44d));
        vk.gamma_abc[414] = Pairing.G1Point(uint256(0x1db97830a1394636ad5267a98208a06221c1e267cdc3ab6bdcefd2208bdc51c4), uint256(0x238889f790e24bc5272298864b2584b569598cd6ad9f2d57d47c7162a3872ec0));
        vk.gamma_abc[415] = Pairing.G1Point(uint256(0x2fc48b4c697f23df566156cc7f2cad8c70deabc22d4282006fe677dfa7d3d147), uint256(0x1b19794a634e82db8cb19b18125f038ae572d6cf2b205470e4bab711bd103ebb));
        vk.gamma_abc[416] = Pairing.G1Point(uint256(0x08835285e41cdb4d46d218696734510d49809535e4ffff775f19baa821f80231), uint256(0x10f3ff3a427c960c873544a0e5bf6d044de9b0e777850a5e8ad9ef4446137ac1));
        vk.gamma_abc[417] = Pairing.G1Point(uint256(0x2b23d02661ae8bb828c8f9bc9964872dcdc436bb0bbc48a3a539b69cd0fd813b), uint256(0x118cb1998790de5b473a7e33766fca9a1d7702695a425095da866827359ee9f2));
        vk.gamma_abc[418] = Pairing.G1Point(uint256(0x271a965551f7eb14c2b483f0693daf2f46304e8e613681efdaef624c0ca4eb23), uint256(0x1adef4e1e53ddb75fb3a21c3b2b1093e7524846b5ca415e115c3dd1ec344e613));
        vk.gamma_abc[419] = Pairing.G1Point(uint256(0x2ba6425883a544400183b22a94a8144bb484da355e51ca65d626731e2de74704), uint256(0x0131b7db1047e42f81f01686d1bb74c4b26d0250a67090f2dc7d3526a385e6e4));
        vk.gamma_abc[420] = Pairing.G1Point(uint256(0x2ba30dfdde04dc2a9690030705f28c567b539301aa8daa988a815ac1159f5272), uint256(0x12d6271549dbb9d6faf588292117d2812b06efdeb6bfb5a45536f91abdcc179b));
        vk.gamma_abc[421] = Pairing.G1Point(uint256(0x2da7eef1738076f49a950bb94f25699f17fac8047374e4701d4938344c976c76), uint256(0x167d51541ca9654c25e440a6c5eeb74940b62cd8598da2933e2b212584ccc4cb));
        vk.gamma_abc[422] = Pairing.G1Point(uint256(0x0663ca71a711e173d1cc0f7e75dd172b5c950d75b725ccd31e2a912f7b8fb378), uint256(0x20601c2b94673ea06c52a40e2c0737df80a4adcfb5871227177a70afae914650));
        vk.gamma_abc[423] = Pairing.G1Point(uint256(0x0ba9233b8d6bd2a3664420ac25bbed0e3be6372d0fbd650f732973e5d52faa51), uint256(0x1cb84c1a32ce75fc843513cc66ba0ad2e8c28b920d8b8245960514114beb47cd));
        vk.gamma_abc[424] = Pairing.G1Point(uint256(0x1a4b41c2519eeb1b0a2d79aab80ad32b6107be8a474197608f9b91abc647525d), uint256(0x27b2dc77d1ffd9cd09536823b8ec35d3ea7faace18d1bd0d1aa7805c28e801af));
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
            Proof memory proof, uint[424] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](424);
        
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
