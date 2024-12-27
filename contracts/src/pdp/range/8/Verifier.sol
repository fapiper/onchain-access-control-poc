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
        vk.alpha = Pairing.G1Point(uint256(0x0a1240774ff6c4db584dbe01ad24ef8a74f2e2135b754d20efc14c95e337b208), uint256(0x22642646086cfc3616965b011da89f87b813672ec2debc92631f3111f3aba9b3));
        vk.beta = Pairing.G2Point([uint256(0x1015f040a3fc60866acba053feb0885047f7ec6eb291cbe5ee964a51ab7794f9), uint256(0x3006420e81be6ca537d6cc00d389adf131e8d2c12e40069636c74d61ccfa4516)], [uint256(0x15c923cb9a40e93b6a5206c346038ff8a9eed8163624e54a777ca305e8316bf0), uint256(0x04ea48f1cf91d5a7bc090f7d218eb8942ed177e27ae5ee48a3811c193b4fd499)]);
        vk.gamma = Pairing.G2Point([uint256(0x2216ed96b86dd0862937d34a8dcd3cbad89acfd26f62586de1a197e07ecbb573), uint256(0x0138019b097335fad697813594342f1a0d402fa0682c12345f19a8c18fefd3f4)], [uint256(0x162463e23d4ce0dc7a9ae2c914a3bca1b0ed02a471e812c7064a19be78ab2657), uint256(0x0ef087279ab7a74167e3337aa64c5ff317e7b401acb0f9601cc1d44d30345c19)]);
        vk.delta = Pairing.G2Point([uint256(0x0de65e7134ae0160428ccce60a8c671b21258f530b80210addf2f118aeb8c932), uint256(0x1850180f43311150b85c169b913367a987b60dc3cf57e317d8805a00fc242ea1)], [uint256(0x062d8dedec359cd406a126e7874fed47953558d1ccd5ebcae419d5d31a3b2ea3), uint256(0x1435b8e02ce7642272b0b146abddc5d70542bb59cbf120d92b9b40a2d4fb6509)]);
        vk.gamma_abc = new Pairing.G1Point[](162);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2b0b8f2e4f66d8f94215549c17b9c6ca9be7d96244c9999efc9d530fbed1de1a), uint256(0x05c9e4b5146cc422f02fa978e7bb4623260f9e0f9efae46d14a251fed007745e));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1fbc2049e1f93695d3ba792323841465b7d721564f339521c15c410a9b92e972), uint256(0x13f16c122f69bfd83e1364a9f2fd613703c3b39837d7080456efda59556394cf));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x25aa2a2093240485738bc0adccfa0216845489068d5c71c048570432b1e2cd08), uint256(0x1dd7045932d02dc5e2928c7fd705a8f25b7d6310180cb00ccb82c61e795aab6a));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0ac19d4d0f69925cca020060d44f5ff57beca6f476bc835632006836c1bc1045), uint256(0x08af29b65acb752b79ad26dd846020577ac0aaa78bf1a30fdd196e43abbe0040));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x288515f08cdfefa404b2e75cc0da67398d87baf78aee7c870101ef0912ff40a2), uint256(0x2d99b2a561208ce21ade180268c132eef3fadf2b5390442a2fc48d25f867d572));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2f8c0c4cfd129aa772779eb11f9048927bd116fb31bc416d7583758ea1a0e931), uint256(0x0eed19856a94eba0528edcfe6b303dcc90f596b23062c51a64d6276c7dd77926));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1c1017e3ed0c9ef2697b9199a8d0933ac465305245938ed36c2f0d1cefd3de60), uint256(0x20cd3c3683bcbbc9bda8cd132792db75b71637f27ee62d35861dfa10eafef619));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0c16dbd8416cba066c6a837087702ff0dd1002808affc5b74132735ea19a330b), uint256(0x286b5414e30e7c1fc51db3b8470175b27909acdc470cc3c19eab6b0ca7add7a5));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1d506d6250449d9d4244ea762d42affd6286b276f3415bed633ca02b232858de), uint256(0x2417a7935a98d4e4d3527e0e6d411f9771d1d9d1a438807e7544946db5d277f6));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0e951a55ca73ad6da2728fa96b80cb31e3c45277c46502a14056a023eb5c501a), uint256(0x0cd1a41782ecceb6877fb03b03389ad8d7f3cbda15b229f791865571a81fe254));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x03888fc6c734288048bf503a9b2578aafcb2a9413f28a06a3f43d1f8b95a6701), uint256(0x20a4b1932ef92f8a2cb8804e1c022356c3ef697715dfae4082ebd2ea897d7c0f));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x21cbad10e4a26cef72a76fb2f703a9765a346ad04bb84f72e1129130894d5d2a), uint256(0x1970bb751829cd9a6bac7efddc7cb025d334716f456b92027a2c78ce72a116da));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x003a9e51fc949357aa4ba22c9396ecd1b78bb0dabd7d493f5ded51dfcf8a2c92), uint256(0x1524e9c5444eda9d4630858fad21701b6be894d8f55a169dfa4408aac48f3d04));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0180f72e84dcaf70ad8db26e636af1915922d99bb542e598518bff1e11ac7d71), uint256(0x149296a22bf85ca5f69e68997991c027ca066733f38ed05a7b3965411ff10095));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x272ad6be2f5062a7434d58993f71863142a47c83103cd0a9525afaf34e593bcb), uint256(0x0f5261e17e6318576de2cfa0bfe25f6e8529affcf2f998a5d4a96af422517dec));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x21fed9e4fbd4dcf983c2885fe09a154aeafa4b146efbbd712400029e87c01263), uint256(0x09d4389d1e8f6891d2095054f654408d4e953bef449a6863cecccf1f49ea03dc));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1b7ec0aa8f52a5e517312823857aab8905f08077ee4874e75426fb1d831618b6), uint256(0x10939ae2a613744f8d7b524209c44406a766dd5192eb03de38c481d7a5160278));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x10851866ff44e950d9bfe036128736f9aa3ec8c4faaaf0a7c3e1b176b2a9d487), uint256(0x04cbc844f74612adaf22706114b34a93295ef575ea4c30a5896dc627facf52c4));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x06c03e39f697cf92e3642610df3f6930f192633dba3bddb63cba1a960b581517), uint256(0x0418fdb4ddea443ecc9657fdf94bbcb5ea139a35a9a519cc30684ccf87c45528));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1760e037d8dd70d35c5e46b5b92d4a24d0df94562ba6706f584d00e48abb39e3), uint256(0x28f86d6b8f257e4c0c698c95fec035f3cc7cd6b3681e73d23609df26f5e2379e));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2b24b9745c6e7ed442ba393c860fc609630e976735c1cb766ba02c671faee5ff), uint256(0x1ff4d6815b0ee0d8c9e2a93b9f062a79a207306e2d1d72d530622f31b1585027));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x04c5db6485f1f5e40cba5cf4c83dfe4451196cd2dc097fe7e32ef3fee51d0126), uint256(0x10f240bb19899762fca0e08448678c0c6e5eda4415591334b36f1726ffd4a27e));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2ab05f3f8878bed59048a7349615ef55c75822768be26758fafc3e302abb5175), uint256(0x0554e9015231cb32850d0768bef64a0efeee4047b386d207a5bdfaecfbd4f6c3));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x295072c85181306739a3a4e562ad6775a22f189092b0ae3187a5333d91b427a9), uint256(0x2e43a8c022ca28fabaf818ca24295dbc2214ca846cb17857d244facb902fd64f));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x01cdc8b12323fd0e1b628029fa67952e6ad9d19cb6652e82e42fd574b4c20ee8), uint256(0x20e867c9e308ffd1c11ddc7b0d69ca9fa613c48ee324e98501967002ac062093));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x2fae5cee38dbb598875606a31083941ab86fb0d01c1ee45bb0f6e24ee8a341c8), uint256(0x187865ee81b60ee3d3221b11109512f219b847b832168b4964fb7b3cd1da849b));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x29ec5ce41588b412bf825b4473658a0fd085781fee701f94122a34b2914600b5), uint256(0x20de63b36cbaa8f1e0f968e7ea9248e1301c7b52054c8ba4c30d5343c4de3ac2));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x206d6e625fd4ecb6fcc303f29e47c402bcb58179170766a158cb766ffc1f3e70), uint256(0x2536be0fda63d40cf318800a0b1adf07fc365bb7302f62d70afbc5b7f6ffa69d));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x0dc89ff1534ffd649bc360e7426755aa9dba21a6009bb89210332165a846b1f3), uint256(0x23e3593940836b3d585844db03342797f7dd6348d376de9a3199edead784c268));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x1fd9834338b83517a7d103f581171fd94453e612a80bb2309e48d660fe9d60ab), uint256(0x054dedc1ae5ef838d4f3240bb0e1108918bd8427854d4e34fb3493fa9736b3cc));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x0381856209813288ea895cc36cc6812190d16ef4278095018eb1ae06e058e98a), uint256(0x1e5e3eaa597b44dbd7a61f6d913ac737aa1583e81eb75ac7cdc81a0578d0fd53));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x1598f21ddab683cd0d91b48035960e5c8fdcec6d1246a7bc564c951b294548cf), uint256(0x0285382cf95ddd4503284f159618361898de91ef6ee6d12528a4a1a386700fdb));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x1ca30622af8fa97d027c9d39776f1a2897d215d79304dfd401d430567fc7a7d1), uint256(0x1b2a1a180709ad6ed38a53f761fdb627edc1b3264db05cb0050ccb980216fb38));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x21adfda68dffa89379980beb79a506eabcc62e8d0fd0c08d80f3f70802c5e224), uint256(0x06a217987228a4fec5b36ed8dcd8791f775cb16b815373cf745b1b18ad64f48a));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0a36813bae1a7726187db747ee4fe133df59c8e988ebc8ff43176542a6fb1df9), uint256(0x2ae9e0e1499d1d2dfa82b08c37e84b05c642dc201fef572e991407cdd283740e));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x03b10c5afe5ad80a2e6396fec2f7976afb3749e685247bb270fd8d9fd01846a3), uint256(0x1d2343be9c8d4f8fd83689352cbbe21c8cd63354b2fa4213d1c4992541a30c41));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x1048995b1253c307d176480d3b8329a6c8a235bdf4429de7235a81efc4da79f6), uint256(0x22180ea3b80e4c66ae4f2293c9aa523c9f6234a84ff904c98e6311326e36423e));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x25db082b39d802562300647b52d9ea3e523bf3e12af3720fb62cf5742d972c32), uint256(0x1ea51f0d79cec5f3b1e6b6246b7763a19084dd75625603dd0ee72d95905a5cd8));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x11b4bd5d9726392610f703ee5a18fbc9dc728483eabea511e941e81b0d0b127b), uint256(0x166818fa53cf0eba15c66c3b3383c141566c1dd224a934392bfe0fc4182b9c47));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x27742a4ec14e5416b2529ebf24a1ca78d931aef206f922b0580e6361718a0f4f), uint256(0x2fac1b18589392f7d434510c4d59765eb524d4e623fc7ae5450ec43a429e086a));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x18808a73ecfcd3a30713fddd8c3e86878e508bd5f40bf11f73e56e8803399fa6), uint256(0x08b196e7bd00f19c3a1b97b573b0e0e1ed31f735aaf4b964cc3bac854e46f47c));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x263ab41b465363a340c144e6a77289f39425c8687c34ed98f7ebeb11e1254ea6), uint256(0x2da86a23c0b423e3b0fcaedea04253c713bfce28b4fb31a040428124610e54dc));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x16ba7b3d29333393254a0c3b8f6120572805b976928836dc179aa6eb7f79b40e), uint256(0x05338a52282b2278cdeb412773f3801a31cd1a13b8b367dc42af410526ab9afd));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x122d47812cec623996eb51db3add1ddc3f5a7aef32a12f5df830fe009374f1f8), uint256(0x2d4a2ee2a1ad64cf28301b53a724af30908e0c610dccf9a77c46843aa3ddadac));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x0f6a608fba80705468c938a1fd693545ce28c6ebb8d008e1e63037983acc6343), uint256(0x0c71a8f5077eef533711c2dba90107885172eaddf4dd1c22312f320c82b89524));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x056e1088f9dddf554864781c48b5375978f0e934e6ae6767f95944b107b61c06), uint256(0x1d3f6809df605ed71c1952844b7f2a7eaf72b3efd406baa6bb71e311a4d34dcd));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x0521809e1af859777c12c6ff637c349875a9122cbdf108e8fe254c6adfa0f10a), uint256(0x18fa1828364d6cdded848ef0feddd0261af17ced6e3c8b40d7dae8d7ce63cfd9));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x078f6ba65dbc235b19d38af98746ab0f9e0f344bc365817505927a722d4de51b), uint256(0x1bd0f2a7096d2756cbca454e04c2323c3e65cd14f226a4ddefe7ef6633de921b));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x1d1096aa85fadeca582acb96f9543ab605d4d53b2eb20bd3b520257595066df6), uint256(0x011743d12e441845eaf7409c88a949f0ae83a46d727991e35e133f5934063590));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x1d5fbe900cfb2271a067623c7c38d9f41c3512e90c61ac9afa199ea855b50daf), uint256(0x2d82b4acbbbc5ace4418b4387f484d044c4c6259008d479bb9febb4626c4e087));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x0b967e1544b0d52430aab463827ab407cf1474c744a861b65750982b0195f526), uint256(0x099c174fe00258b030def1cf632b32e4fea560fe84aed8879e46a4d1068fe142));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x2bc68b92d722c8b97fbe2fa0d944ad7d6b0cd673f8d4cbfdc4ffc1adaedb16e9), uint256(0x153a0faa0f174f549f0b928ea97bbca6382dc307c0553d34c1b2cba815e4facd));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x246d53ef10eb90232971c9c964de7b55bcfccb9a033000d3bd4fead74ff9fe9d), uint256(0x2d0c9eaa9d404e6fa3b8c77f056d8606b5859adea7e533840ccd1dd6ba92db9b));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x25496097fa430902c097dd4b659af831a09aca7e85acb1e5d3e7060c840866a1), uint256(0x2f41e759b57076007a08271aa73d32bb0f6812fbfa952f48a0c171aea9aff637));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x2aa15ccaea248a64abfd5f3c2f5b6cb96fea2fd2cc2778a6b6b92c319d2e909e), uint256(0x30626b643186c179a0f1eede1dceb249f53b340af6ef966037779655b899ac97));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x0061326f2bcd70619c0de7ad361219a01c181dde8270e27f5a3ebaf65fba9ead), uint256(0x18d7e4faf8ec116c767f7e2e2eb5b44628467a42cd3819f402e38c3b0afbc946));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x26d1f0393fd46310839cab4d555aad40d19abc6ac11a28f599eda507ec99645b), uint256(0x12c0df1ab91948d84ff16fab808345d6ac3fa51490458eedf56f5943cf6be6d4));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x113c7e2736ad074f472c59710c7e2137bea0b4081b50eb480d7ac8edd2c0df86), uint256(0x268e96fb921eb601ceb7d2c54248cc1cf6ce898174c6f4e8f8a207ed9a488db2));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x16570f4546f8e9fc08c909928c1d02b01ccc56543d9554fcfd263d6123769d86), uint256(0x1a3b445fdd480781d2a386af6b8e5ceb37da02e1ede7ddabc394d4128a452a0b));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x1f34f12449afb5f24738dc155f7453c013a162039b5bde597e04c54b2fc267f0), uint256(0x0a508ba0c796f428557d879ab92b80f2d7875bdd573cb6faa8db8327edb66eca));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x1fcb190590e882bf73cbd870578eceaf62d0f4a38527854ff16a30b1915d2218), uint256(0x08e9ed420a475c2c85c8b96b4661c6146f6fcd6ea38a35620a75dc7087c89199));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x05d38534f6e46bedcb080379047a97160a667d925a87402d4ac3deaae2e776a7), uint256(0x13899a94a443a997150c3c65b2a6ed075f0f919c2c928303c5222b86bf7a709c));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x2ca878b933b003bbf2a72f19c3028e3ea799b83cc4ff6412f91a5733163722b9), uint256(0x036bd41d18a5ac11b152faee2b573c4e89815f238657ac1425a7a3f8867ec3b4));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x146241d142b138ff6adba9e85a4bd759ff40907683f6ec60a9c43762c96a6cd7), uint256(0x1788a6dabe5244d6a04c8d8ab28d5644fc39b9daf80b10831b0e58f38d1936c4));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x1112b81ad90d299312bcb73881296652dacf5a2c5d822245c976093fa580900b), uint256(0x292288ba5570d8df6a0ae142c37fb6d2c48a369b75324da873999bd692424a59));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x22fec0eb72149c481a4b0e8778962fea2e2fd9e7b5ab38d3e08b797829425ead), uint256(0x112da66627c4baa95a237bb638856e85912eb2570261fe8af9638db25beb82dd));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x239240eb0125e2be3d998316893800aec3055aa0e9bbebaf65a2446c961fa2d2), uint256(0x25fe9f9106606c7906a38f2e624b30628db393a1d0cb299f48bc027df69a4985));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x186c721ca6e77b49ca30f25d25788744b59469dfde6a550680f5f7013a44740a), uint256(0x017bd36da934df0e1ab9ccce816fbedcbd8a321afe0a81a442213cca07526995));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x211a76a4a538f3d7cee5b71b4399930a5142cc0ea84503ecb4fc2b9b82dde774), uint256(0x0ffb575d1b597dda467b48b61c11bfcef1d712a5e8c7e3e7f96c1a348a49a182));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x025d1a04840bf67ab2760df8acab9ad8aa2a0caa7ccd9994422c96e034d6d637), uint256(0x11e8367c4acbf65018d662011221d581c4bc24231af377d9bcd55724e9d184e9));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x0e338ab7ede92b0eef9f51d7d44f2086f6aaa0b3162b64e6d1468cd0edda8150), uint256(0x22b2081601202ca175985455583bf747d7cc9d5d321cabc6578fdf6e049fd5cb));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x17e2dffd877612a78449f4eb5ad2e359a24b1e1428cd12abdd1d315b104d2b3a), uint256(0x082658eabf50bd123c5f26a3ef83414adaadb3b0db58d81942b9ec0e80173d47));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x2e5d1c492d1cc49f36d07c46ccf1efea7e23c06a04a6b4e44670d750c98cb02f), uint256(0x2f910f80d7e748fb5b4493a8d5b200b6a3e544dda3109abf4da4cfa8bc6c7c8b));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x2bce1b4d7e11d0e93829bca276dfeb664086bf1d5bf3163790d1ba02567f9842), uint256(0x252973d830c63ada8d0adaa7847d3677729be97ce840054a028a06449cc2517a));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x2ec4265e502a00689cc631bea80c6b92ff6ee2bd95acb378a85ae1d69067a4a1), uint256(0x1d43342f9fc50ac872720ef30d3b02d61315b4d700ab19d249b86b55bd8f5ae7));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x1d1df75890bde9939a575a0e844f8b6c8efeb636aa720b956531739cc48e8ee6), uint256(0x104f935d1da2eb347654275dd0e529255a8cdaf9ce638b6dfdfa0cca329b7fb6));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x2f571fc8415beeb17ac926324883b4dd75e719d1e872a3f77f01f2a63e04363d), uint256(0x07a4c20fbdb881e74ef44058cf3583577e6d5d6b2895641fc1f2c75998feeeb7));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x21ceb77a66beea7a176d756a359a203fe3e0e4b15cdc6db0955afcf04875c630), uint256(0x130d266876edd0bb591227346a42e68eb4e0a728c69ab5e9180758a11486075a));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x21d423c314ab395d5a7dc7a445f4ac4643aebf4323ebedf60f8508a3fee41bdf), uint256(0x028baa3825caa3a423c16df832ee55c977fb6d9c28304c82fc01e9012c0b449b));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x181da2d99b6d7fcb9fe421fd348a552da3840e1c273859baf0b9c539c60e8544), uint256(0x0ce4e2153acd5103bf420b6ee0a3dfe8fe3f8fe887723255af484a0b0189bb72));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x096f92bd67281885800f48772981a955ae5ede31f6528bad3beac37851e3b3a7), uint256(0x0f039f0ea6e6325419d3764be1984d361bacda6bdd54f7c4f3c5388cddbed526));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x0097dd4befd5189b79909c296ff9ce7e27abe9be1b2dcd772e89ab6a6968e7ab), uint256(0x0d1d27740a9ad7668ecd89602291cbfa615877c71253cba30ae195352a4466c8));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x0eba97b9468a17f8963b1257c6b15c1c5ff2c7b8df586b4fc1e70bb7fd9badf0), uint256(0x07b903c2886f0c9aec7f76c941a123c9d6f1167c36287488f3d957d7283a3106));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x2f5c7325869e20b39d06e14ca26e441695c586b3bb876a6f0c3d4d1e0e221c53), uint256(0x2ecee56634bee5744f959ac8a1e646199174986c2fb19f5d4c1569309fe976b2));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x1781e6b68575dd6101fa27f5d916358931864ea9df338ec3473da2c10bc210ff), uint256(0x125d69818e44c9dad0e1b7091b55290d04e4c8f6898449fd92fcc55128a86406));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x2394a9b0b2cec7c4a140c3fe5566b4335f5d5dc2c27d2951743df7592cdccc1a), uint256(0x109dda5b53513bc88d60a64c475a140ed45c3f566bc41f657607ad39d70180f8));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x1737d2751bf31cd79e5189cc9231106ad3246a44f197a67af6c98112b522d6c8), uint256(0x2a49a1b2922712036359d1e4ad8eff753bd3aef678fd56b1406bec9606668bd4));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x0c6b34e360acb6fb8de7b8bc4f3d0cefb7fa3b4fa0ac2f54349d14ba4399c3eb), uint256(0x04e0d06fe09af0a9dbe5e6651641c7f7a68a4d2994f7225ca297cc4fc3dbbc8a));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x071129f7a2efd7c16022d0f30483716483cff0ed3a476de32d04fe190e9cc350), uint256(0x0e752e5fcddb54f4a290e5d32af499ae1954291b1b338cd42817881e11667601));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x2f7a29461a3840a05df41a99e320ba849d34c2901374870c03bb2dcfb0a056af), uint256(0x1896ccee1f7b7c21faefe07eef65356e67571bf7dee36b534b21bf138cde8662));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x22a514f9793583787d97a1686ef5c59c98cf6ad25ce24f546b7cd0177b7fe299), uint256(0x0ca867489edb500a1919154ac64d4dcbe850fee300c17f0d9dd5a788c8ceaf47));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x244a4b1b216a16a33baefa2acd278107c658e928608c9bd9727b31bebce052bc), uint256(0x1791cfbe1f1c09582ceafe3ea31a4d84e93bcb62b7036eb5e3d3f64b0180ab77));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x0b6fa76625d392a6e9ab019d611b1758c5fd91d184e46099399d8396d8db3b86), uint256(0x04da36a505cbfdf34e67c158732f03d6867dfd506ea563643e19d3c361d07a53));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x0ed69a1c303bd50d86c48fc06e35a18fbe518203eda5bed92e07203354e12963), uint256(0x141156a57d0a51d279b3a6aaa80080b4de82b67c983eb2a86dc7777c9ebb7b4a));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x1fe20d76d45f9028c1ba140a5b01b8b62c77365c84d96f41f2680542ffec9678), uint256(0x0a69fd2b37ea3782f95876cc464acc734b50ef2c050df6bab33e2f73728a695e));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x17f2dcdb68497133f951f977e15e809fa52edc8db567b86a037d08f8f2f4d9e2), uint256(0x08aad1f0d7c33c60126dbc50cd19c5afb52d3abdbb8b449b6275d5597da4cf17));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x114f048bb7af7e14c23e745e7b72f553a566c29446af37ef795e25a4e9007d69), uint256(0x1d5cf622dd5439ce59cc39db2d7b91f65240b7c4d471c04a134ce40e5d5cb32a));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x183793171d135828c35763e34855b107b5fa516db9ad320effebf013d6436110), uint256(0x1f52eb85fd155e5fc176d6faeec785a71e5926e5dbbf8b00b410913ca21823cf));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x1e841cd8d69269899e2870a58fe4c88673e7d2c5c7d8eefae67f1a467735f2fc), uint256(0x2e964b72737972d72f47b57e03567a427a60a5b5ffc425203a5c44dad8362421));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x0430b098f90ecc53263bf68212169d54042012a2bc5ded0f5dd629300ed16d8c), uint256(0x25607b79f68cbb60ab1e5c20b2cad05dd208e342e186f7adf0fb04bc047eede4));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x2dec7500d6a402004f27ad29a91df20556d65260564c2c030dbf872906251c5f), uint256(0x2d5d7511b7a934060e2ca697ca69e99f1d840ca403cc926c210714aa75fd5b02));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x2533d8d6682029201882fc445df94ef82e2926c21a878cfc5c7b4616a693bd92), uint256(0x28fd7afef65751cca7546a79386d7bdfe91c5ca6d9c892eb3a7fc6b1dc71d7b6));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x2c95000b42df14e7c6505c45de1c5c53ad2d778d9c9f5bd31829d3e5bbc581d9), uint256(0x2556c36ad4df6bb95c2efaf57f403dd6caffb21edc2d3c9badf95b79aa8f6c0f));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x05263028de93c0b5be8613acd4159d9b7b5ee4ac86e2adca535661a4dad00bd4), uint256(0x1edb4f0c54a0f80b60ca74bf543cfa591942e8568c1aabdf46ebc974cbdba65d));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x0bbbf27a8813a8e0c458df5caf5f9476c385429915787eda9afe55ba3f1fe085), uint256(0x030d7f881eb457c6d6d14340ef98bfa55f984fc8ea81d9924e660c4b67e24137));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x21642c773c96a138390b3af522efe7505fc26fe82d1c03d8c911e8b316d3ef60), uint256(0x0b9490dff91d5282a264153d0fe137865b06a8ad817ba4ff40e8281993afd4e1));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x1d806ce1e22ac7fe932f83524ca0c48200b50d26f056a7f1f8e2148b0347f72d), uint256(0x26e5c12da44d0a61537d1b1c2bb189e10c5af0779391ac344a207ca076fc0ab5));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x0fa67a3c4b294576b362c2c29fa985604489c2c56fc156d8c6823c48f32aad9f), uint256(0x172ef7580154ad19f2475802378c138b1e5d07ef12a213bfa241d1727d33dbce));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x15140ba7ae1f8c6716aa97e61b4ace63959a86c5b1c4f699b24d1086b30ae941), uint256(0x22a1a879ced7c81c430bb1ea3075ffcab1f605841787d1193e889bc7ac3995c6));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x061b735b2d05a9c8d858b228f49ce482210d438a6c8cf63e5db4484734981ede), uint256(0x1ca3fe44bc814c4f843966d0a3524539971a5047a5a1e8cfd10550c9705b8876));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x21a50aef22550562d88a847138185ff57e4c7478f5b9a7cf2da5c1325bed45a5), uint256(0x0744c0071843eb5e30af095e566ac7ca119de8b53366aeb2a6adb4c65204865c));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x0b02c3bea3692c5bcb09af9656f639fbe794f6f8d5ec933096a1ab9b3f46d450), uint256(0x23f0e21939ebe5911d7d54c449bb7808176947117b42932b116076f2f2b8fdb5));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x2464986528d27b9ec7a4f5a7037edd3f85e2ba4aec10c5a9b9e2a86bf33da862), uint256(0x29d3ec25a123b3a053fb22dc4ff7f688356dbc6b32d3199d923fb324491d181a));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x0ba803358d7e470bfebbd897df9fc892695c97f52e21478e3929ed484cdc50de), uint256(0x0f219bc9c04407e22d92516264d2f7ae8c56b96b0acdbcc7f74ec60b33ae2b54));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x12dda56ad0e5093e9d7fc79ce10ce187fa981f69948080a9c84bfc6dad25e901), uint256(0x141dcb5b61b819b0f22d5ab14758b32dc584113c99985747dede1c0d96cf33f1));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x0d953f44a42db16f077c42bfd216afabdff7af33f0bc3bddfba16d5a6505d869), uint256(0x148c26512d6facc0c315f300b61e87a86315c36aad16a8a1b0e31e2366419a1e));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x2803d8544677ecc5a502ffff6ca83be798d1ed76e7faf61bd0c40a8bb2157812), uint256(0x0fb4998b3ce54e417232cf626c110496bfe9e36b044301de1376a93d09885efa));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x098a734030ee610ce3b601f227fbfbfc3409c6f3a94c643bce5a94f4ee2f79ae), uint256(0x0ef048c577ad80f16f7e52017dda7a020bf06b100fb88426b8d326de8513b2a7));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x15ed634df70afe727429f64901427d9cf4db54dfd457e0f980e1943679b043ee), uint256(0x0070ae4d2c8805e0566b7590d81a46844eb47b54e4e42ef4449ce9aa14d63cbc));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x14ec74571fa32808d1ba41fbade70f9def3542f658f5e688200a1fa12d3b80a3), uint256(0x049e54b1af2817e442d52b94cae4f5fb9380ffd63bd096f9a23704ce9e2bc9fd));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x297968a93de25d5f3f95dd2820a71ba47654119facf7fa26dee8e965dabf780d), uint256(0x1b4eeec1ce1f3cb9abe2821301fa7aefccf7554363d19ece5df87194a25819bc));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x1ba0edd5372bbbce91c243548a3fa793f892bc62dd49f3c96ff866fb2f1f23d4), uint256(0x0a275cb9aa5fd89153228acaff1dc5df16b0fa3f0cdf146a8dc21f2ecef46196));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x238eb3388194de734c5535101ced8f7d564e7d0c3ea76586467802e000edffd8), uint256(0x1305aa4e45f9a90f9a917825c15655f0f35d3dfd893711fdf712a7eefbbc926b));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x0e58ce9a3fc957272354eae8d3697786d86c65b631171a6cbb9e74fb91fbbda2), uint256(0x13f24d681914fc42c8205d604e2378dd3027af6763dfb8fc3ea184a36e18c492));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x27c24b17a43e3cfa1b351a1ad80b5ad34394605e8a2c846beb0d316d527f1f25), uint256(0x03ccf71a92f892676568243da1a8b2f9f3a87ee1dadb86fe28fd24851ebd42fc));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x2d661d99a8be83e309c48192d3e73b02e6a6b3fcfb84feed398b68bdc1cadc68), uint256(0x191a745f7d827f8a0462df834f014309944c4378e7dab64b03b86fa24091c086));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x16fca3e1daf2d450fd2a9ec6013db06b72c385c86ac9255f6f13f6851be27f93), uint256(0x054a1aef8716916986d5157af3b03a7afc1093fbd83543114fa6db814af7c6aa));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x2a7cc760aa75f1c68d950fee4ab38685d2d06207492fbb350f43ad7d838fadf3), uint256(0x1a7045d139ea7d06a7de74653622ab256dc4d1e5751f6a63261224808f346307));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x18b48917ef7e999246ad9f5608c5555b3a807b3665c69195bd8dedc2826b0403), uint256(0x0a265ea51aa01e26072567bd6929fc7793dda125d5dc0840311e488bf4955e45));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x27b03b751312c15b107772daeeb8410f39ce57825dc912a734548344d66f348d), uint256(0x20dc74bfa8bd35530b34356237743604cf47b7b553a6757837f0df8adfe2a621));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x134ae9111302cd4ff0ffc7ed28c90950c2e5f4f2e15e89de431b8d5b82c1b6e8), uint256(0x2589706cb077b5d4e0fb805d440ca2b40ef8420f4634d3f1919ce0685966e47b));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x099667a50d444b6da3c6544ab3cc1f50023e6a58fcc6e5e2ff76bfca354a82c9), uint256(0x2c69711e4646a6d04e88b7818a400ac279fbb65833c1b8e9531d94aa12cd49df));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x1ff363fd98155be676aab388f5a563000f8e4c0b1d8543ec4c2c7a7ad0299dbd), uint256(0x06681761968c67265ab37da18c9c22b7ca7a7fa58be94ebbc2b0ee9161eeb8f0));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x157840eb412ccfe4c7e1ebc2658b21fa410bb04bde5d1e7686fcc1b2706e9bff), uint256(0x106dc48541db285473faf4456ba1cc8d1321a75b7dd04f3d392e0f561baca2cf));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x2d6101da0f69251f548f1fe944385a1c678e6fa16d8454668e4ab86e3b9278a7), uint256(0x26c30aae6d7c8a9de2b8eaf77129ec6810b2ac8fd341c7655e1f13bcc3e93d6a));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x149a4aede316f70b99628970c9dbca578c48054bffbba6a857f120fe04a31ce4), uint256(0x18153843d4d2ddf06fdc3c50a94e489b90c905b6da90aaf1db41de4155dc4049));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x2ae097ca5e2a7e81fa71688687818157fe6220708ac273ee5390cdd180ac24c8), uint256(0x12ffcbeda19fd7db3f5447b022de850ec89aedc57794bed407d0519d98bdf9a6));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x1c46b2db0f10be1084ef0cc181e6be325cf9befc947c58a8b2711bc9aad3b3aa), uint256(0x0d0c2b4af3e85f24bee78ecdc39c4010fe03c66d5ad295c8733ca60b0280b3df));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x1f2e64df89637c0e6c06b910fda41888148971b8237539f2046ca6606fdcb93c), uint256(0x0f0d658846a413a1e9af1e16da5f8c54b2a5b3018bfa54bf077ce86d0089bc36));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x2f2cd44e2237052afc8b737916a1d1042edd5546d6c13e08f287ba0792db95ee), uint256(0x0b6887755d0102af50cd67dc7a0ea321d6d1877427f621fdd1ef10c422a115cc));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x0e85f582c50c03a3e2f430e2433393f7ec7fbf825e8837749254272dc13c0d82), uint256(0x099850b277474b772261dcf1048f42201e493bb1f04af196a53b05bf62ac1e39));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x16c6e3e1b61a7acfea645d82f6ce9733ea22637f704495e530344660fff5f3c7), uint256(0x25a42cd10f87ed39ff25d50df9a91f36a9e58dcd93866c8d78daea1c7b7b69b9));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x0800c488a7b1aa5893b691efa8deef12d5fe482ff1e92398d7aed81187bd8ff5), uint256(0x16992a6c2b4b38923997b5acd791b8a09004ccf740b78022a5eee328d9e17529));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x19c05f80eba8e86995078ff9e829b80753e6a98e3605f51486c66703b8ac006c), uint256(0x1a37ac46f84e6b851f0d2d5d80fd6843f74ff1d4df91e492745b4244154bd275));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x11740cf0c7a207cd97728c462ce46049b9253c90bd46aef4cef38fdeb46aab64), uint256(0x25684c5d5e33ffde9cc97f2c9b4e1aee3f18a6e5674edc2d05ab7901373639a2));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x13b87f3257c8e69669df0a3aa566cd28546168232e75a5f29d757636bb31186f), uint256(0x2d53028825766bac466949e285ecd6dd121966cc4089cf0416cdf808c2cedb04));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x0498b2cacd53eed5ad50692e4f4656ced14e2c2458dae98c2e35d401bc915955), uint256(0x28d57cdae15d6512e098ca7dde5e4216a7f46738c5776a3ff77babfdb070ccc4));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x1ae38341a2838228be0d1dc6f452480f66c199af3ee80a6de9d800429b5274ca), uint256(0x23a3cb4c2935c1c216f69c68c001bcf942151c3ed5d27a3f8f856880996d2d33));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x29c0c1e86cc4b0ade3792bb441c5e884c3a9ed9dd8d1534c1d7a2de9989e6eb8), uint256(0x2990e73967db9ea104c521957ed92b10c4799be79166dee0af71c381c82ac452));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x1d9e934bf4671b7006c42c8eabc73799d29498fa8fbeefaddaa26e4ddfc5182c), uint256(0x27bbd8fe66883f430639f85239f38e71a9dcf7865f74663271392794b1850703));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x046663d4080cab01423d1331e699367a1f581fafd9806bfa5ee7e04658a92767), uint256(0x2f53409a8d65c7533dddd39260b45f404feb7b2c477cce43e3b23d7ed8ff0e8d));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x10c45e9b882d7bfcdc4f8d62b9a09d2e49472185c6d250faef486316d3582517), uint256(0x0bd16e71121bb7ba3939af1dd08ce685944748dedfcde2d6a88110bcf971e6ac));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x281176e4354e72a47b78be7eab8414e4c9906a820b8f707e655da5a4d99d9efd), uint256(0x2f931b9f7860acb25442b039403839c0464e6d1bb1eaa7391591003996daddda));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x148277e175d2c14014f9c174e37c47e866d9e32d05f6992b82ddb5c10f745308), uint256(0x0d696b2588b59b12851803943a69cc4c8a87a45a2766fefa433946a075698f78));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x0730a8a67250a56ad297e122a711c7c5a792a94c581db7adae789ab02ded3229), uint256(0x2bf44350f2a634c5430a1bc38dd8308a6514c7a9048b4186239859bc074beab4));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x2be8dd6c241ffcfcac3c0fefda8e0bdc8e27cb529d219686e25d4533b3df79dc), uint256(0x2248fa3657bd5895633ac77f1a4963b8ea3bcc99068d150a169a798c9638789f));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x20c6c4781d390b3df00d3ee8ea9e9d411ec1bd935155be3637f02cf259de03c7), uint256(0x0babba0bc0ad820c50ecc5623aba428c02173594042fb04d2c953a8d676ea295));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x18ac290e005df0a19420b92ebf007ae3ddbd56dbcb7dbf072a03ae205a370eaa), uint256(0x21fac25c0bacc6424255591d474215803b4ce6164881e61900722f86c2ec3679));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x2aab52074e0aac250a5d8d4d2e09ecfe746a525823e059d44309538de2ea8a72), uint256(0x2a5e82d04325cfab08d5969433c6b7b023b90100c5d6d1bf4dce70b392c13a2b));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x0c16a8ab07d4d7541fc8232e08da242933117bf7e1e3fa9a83cae2482766d87f), uint256(0x041400672d85226c47ba53238526da57c10524f060de3dea5c4286274aa54dcb));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x0ddc2d1373de2a71966a24c51cf6dc25f48e4d3eee0f30fcf5e56528c803d6c2), uint256(0x28cea832cf29126e2c2e3790cd185e76a17b345387238ef567d0fa4c6721b0a8));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x0d8d2979cb13c5a41fcd078b4a6f1c00a43d9e4f5c872ec86982309fc2bb5fcc), uint256(0x01c8d1ba2ca1e6296792796a5ff26cd643c01ee1ab5add38ab293d9767ce37a4));
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
            Proof memory proof, uint[161] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](161);
        
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
