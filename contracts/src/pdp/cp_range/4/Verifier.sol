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
        vk.alpha = Pairing.G1Point(uint256(0x00bea6cf382de190ebde3aac3d23f1cc7dd49d427a5130d73ee3b82fdd768b4d), uint256(0x21b167fbe163f4b9caf75c70bdab4cae2b0277d35dbd67c3ba20935975b81715));
        vk.beta = Pairing.G2Point([uint256(0x0dee98f47c1a45386a5ba9724c02aa16e82cc281940b147ebcff46bce0f851a7), uint256(0x2f81133078f4381e2b49c885b7559dfdb9bf56998a8c13cb5defab31deb89451)], [uint256(0x1a726f4dc4296ac5a67f7743d09306a7f42e3b3bf6b114d205e4c91a3a118782), uint256(0x05db205940ad49fd3d2f70c95c2cc2f588d22f692dcff8688781fd793cbb1e54)]);
        vk.gamma = Pairing.G2Point([uint256(0x1ad4836088a99043f134b00626913a30339ef0e4b6ad02a2865605e3a5972605), uint256(0x144c8f667997286ae8994529fc30066c288496878adb72878b12990a12796d39)], [uint256(0x1a9069077cbb6e15bc639842104c2067f1418e96a2a55339804f6dc09fc9c6d0), uint256(0x17c037a4fd53875e95e57b081918e5af7d591a345e54628b1370eef6ec4d87ff)]);
        vk.delta = Pairing.G2Point([uint256(0x0896d447e482e8ac939dbde6cc3305eb04987e52d223c71f5be16c92d95a8a7d), uint256(0x29440bf6c2075e041c819a2c3429e8621cdff3ae2623ad9941d8688f770c7b55)], [uint256(0x2922791b895cc4591430c4671d6f437e11c2e01df8cf5137d08963125d896a02), uint256(0x2f8d2b7a4a2b7b0a4aaa6109ad85d429472f0feead4f1c6b9ec91dcad419f7ce)]);
        vk.gamma_abc = new Pairing.G1Point[](89);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0254d5ebf52f1288872f7132fb7bc158f2fbc68a989f56fd24cb0e81ad0da105), uint256(0x2028cacf3c4ff6983f00b2de04444562e330a12387f78ebedd989cee58e7126f));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x155cf0d0c5dc0a5467b9a2690a77ac2687ebe54c7dccbcd4efa8686cd731c005), uint256(0x0494f8e35b505e96e4dcacda18909cc5eb3680efa5399b3efe4f4f0b2a7fcb6f));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x14d416fad089fb88ff31e074450e381bf334d290192d5ed2c886b607eca729b9), uint256(0x10695412b7cba526e0992313a305483021f6a8fe9fdbefd03246763c78336067));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x23ba3f9902361a8ebd4015487becada9c2979552fb6ee4c2d7144c438bbf9d5b), uint256(0x12f8cf78f6a39272c2315f263157c1497203f3f630e03d9c7e1fe2599992ecea));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2e50a98088afe202ec37a0ad708d971b3bbdf8f8b15a7592b2729d25344abf3f), uint256(0x1ddc4368b42915c0d5f8c907338bd074cd0aa5afbb300a1ef3c0b5e958f8a992));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x12d11be22902b5ee666e0a30504f244948e19082764ef37d72cab0cc52de979d), uint256(0x03526c50f212fb4b26d8a8adc463a12a0d82e88b604aa1132fa0b4ebe4ad61b6));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x2b491726d957e299cdf5c83a4bb30032057ff2f0fdefb898db26dad7d4f20fb3), uint256(0x1038868b34bb6b3b961a1d6141943735967c582164d0214ad6a8ba9e50c67f85));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0960536032f4d944322a5418703d8e978a51c6895f3b1df8f845d3fb32ecdcdc), uint256(0x2919fcbf0a0f3cefb13b4b753d2f72805360a00881a497457ac4aebcfa040009));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x06b1bd84a0c55a005133c8bcaad05272bfcc98d8f6d275204b3ac535cb35dd2a), uint256(0x1e0c9ad59f2e2aafd414c35d0b773de403a647c2743877e6f004b34df7c516e9));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1c6a69fbe0cb50c6a534baa8f5d312a8eb40093b6f736833294a84c3eb740a0c), uint256(0x03f644db7cf8ce847d4aead28cda5dcc74dffa5f34a4d3908fa26323022a5652));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x07cd0d0f01854dd7d6143e80385154361636516a52ddd4f09add99d856be9d33), uint256(0x0134f756ee4437ba62135b4c6f3bbea22b5daa20106a6fdc65654f6c43db1172));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x25ae1693bfd964027ebb5923d9bbeac798f77538848d1727027fa563f134302f), uint256(0x0d6141f297de0bfe11dc541cc26b2eb278b00642137ea440754edc0467491ede));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x24be08868fa21fd3afb2208e19f92dad8a0ae9f2df45db243dd117bcdae3e635), uint256(0x16269d9fa5d34483cb0fd56015df999c863c6bd4c8a9bb3abf7614fdc52fb98c));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x05f245c2caba071ad03a0d84f928109352bdaf87ff10992d872fbaed3bf5c936), uint256(0x1d2461e5125cdb50f9992804f8590e419939fbf25f41cebed302961c8e7de89e));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x000ca765f6b27b567d04ccb27a80534efe6910b41825cd65b75ec0af5d1054a3), uint256(0x2e1541601f802ab4c0b9799ee30b12b84b102b8a676072349868bc2c5fbc4b5c));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x2d43fb32bb7043bd228fd74c3b0b43e58bdb5fdfc9407136eae63f930972a412), uint256(0x29cd7b70f013aa1b16c08fffdc60a954c3c202439ee383dfe59e512df0caa6fb));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x10cfe2da304c5b72e42dd2667931d8383988d0894f9e593c95c0f005e05fe57f), uint256(0x17d25bdf386a09605a533c7bf312c40db81f5e348e916be69a75159c8258fe37));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2d2d0f2a905b77235d9b0b0a20840ba97d41f5502eec52b6933b02530f5db47c), uint256(0x2c4df1dc6234d0afb6bc84b30fd0672d98ca45027d02bb2bd9b66b9fcac12756));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x10643d4eaea08b68a3733a888e871ea1c81928b5b659c7471e76e14bb60524a8), uint256(0x2e71ea355aaa827a0c7d75107309d7da6582aac5daf570d99d38b433c727c91d));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x0d4479277c12d955c0d670e98bc7dcc7201f96a1d1243fc48614de5a2f4cdcb1), uint256(0x1f6bb5c59fe2a7de4ef884d2f53c3f950aa359e04b8c9baece42391916b8572c));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x24573b5eca9631c14ca92314c3c363cab18e539f49288abb62e66268dbc2d8db), uint256(0x0e7d5dad7e2b81788a897c52bef329d6092ee2d29c36bf5383cde727d39ae32e));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x0aa268659fe4661b44cfad023272bfe316ec28607e8e97b1dca73eeb0fc285ee), uint256(0x2fc2ba73617d5916db4bf0f012cc299cc1b3bcf6c837209740f74f519b92d74a));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x15c32ea36eca175062eac38c3dcc93a2b4dacf2370c4936db5f60e1f4ecfff66), uint256(0x0bb1e865509ff7dc82dadf5a004b3478ceeea402df8512d4d85ccc7451a662e2));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1758fa1c8acabc6ba1958dc9f4baf523042c589b6ad7bad1f9604e8512b4472f), uint256(0x2075310c8bdaf7bb01c6ad8c724ee4be5cefdda44e6e8f1e13d28d384cc30bd6));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x238ae17e13e4d7e540ce1717144b68e5d707bbc7d26739a9f55455e86794bcd4), uint256(0x2eacafc01b42ee226b0e7c1a56e3dedf36021bd76b26a7469d261f666cd5ce4f));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x22068f4d2f31bd371efac373288c61823fc3267a8ff210937bc1fc666b90d0dd), uint256(0x111f4bdb345221dd33917235b7694fadc232290cc95d0f8c8799395450d0ab0f));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1dbc4be55b628b62376b84a39ee30122b4ee9cd9e1786b8ccdc553a0b09b2261), uint256(0x104b51590faf75020238b9f61214659f94ffd271e18036967d89b953c4e905a3));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x210f8af5610e49bda99a329dca78551bbb27c67322d49144431845a369373e25), uint256(0x2210257ba1ac7c47b152cf9694fd679ef93bae5089925e77fcae8b5cb2890cac));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x18640eb751c4a96275cb5b3119f4e3e53e7aa3fc56c31b82b1ad87181850b59d), uint256(0x1cd386d6cfa05e9df58d5b24de362a5e15615df301b1d52975baf1f79f056946));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x25d602f04d8f9d8aa56bc4f898fbe1da80522e694a436e51542bbc0925bc11ff), uint256(0x260db1c8b7ab72546d1b173b1fc6ccb58686db703fdb5b6886d739c16d775b03));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x2d93d68f6e340050b7cb05a06d95be6322d917bff36bdb10202c2a50ea4789d0), uint256(0x2c224d1d320cd117cfb5857001a1e073ba2431449087805f533265a62e341a81));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x304bd7100f495c5079769d896fbad5271de4d97c7d22e29356e9586963aec66c), uint256(0x0b5f18fe8a50bdb07c6d412bcff4cc2cb8037d22268d033449f56e2f64f93bab));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x14091e2f87203995fa149ec483a68be9f517b4016d52b7b67a61df23f56ac5ac), uint256(0x0c76f5078d3d519d304fcf5408195df502fe7f202fab31eedfd4e0e58d8d0c73));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x0827dbee7c556786dcb3532fc61a9ec4f0e1bcff6d2996079fb92c013762a1ca), uint256(0x0da5a13b85bc3da3f63679c30539876d79a57c41c30c3882e78ff6a704f76a20));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0b71dcb1d3515fae83e628dce72b01288ae3cde19b4edfebf463ace3b43f09d0), uint256(0x2666dc9d7e92a62f422bcd7af9aa75ecc97361d0900658a5e67102cb54e8a981));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x2efac3bb66baa50784d4f3c08b95bcd56e86ef0780d4b31291409422789889c0), uint256(0x07322383365bd97bb0c49646fd305821f9b295944847b63774ee2df75846393d));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x2c52c2456272048271cb92f28103b9b7a83a02bf8462d9e9d6efa49fa993aeb7), uint256(0x1ee63edd5a0b8950439bdee5ec3687c65c36cd4bab943e224117f58b6eef7053));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x217d0fdc0d6512ad45d8f8826bc3a12d5265637191d163dd4b485b751efdc9c7), uint256(0x1ee49b935ff1745b2760bd07d262c6bf60b73bd7be0a0d53378415763c445c81));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x1e5161b746326fe7f44e9e66da3af27444206e36425f26b3e81b918a6ca580d0), uint256(0x0655ba64a87f9d5a39fdd16fa2553633b7b0095e458b7147734a462419a31a68));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x084089322e83f34eb5b5baeb73d27a354dca019ca62b13138dc90bc08c32d060), uint256(0x25d8ebbd768df4fc048924461f9da25d1a8be1157032eaad9b07f71545684b21));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x17a73d37925b009f122cd67aa073aa59ba135139c9d6b483d05c72bc6267fa96), uint256(0x109e9e6d3c26ed47ce24e342fd75859e574af66c49f36e5cba609621da9cb2af));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x02409c30d7a3335d3940acbdb9052e24afe684a476df25b2e65cdb869cc3aa62), uint256(0x10ef3ca403132811deb9c409a3b8dd73beac33045f3ae581260c6d5b9e2b30cb));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x0440dfa33ec43e186fd16bb0bc648e836f5e872fa7a443aab0ec4e3fde578247), uint256(0x1762b12d383bd34c1da27bd2950f04595b0e101e1f5a1389457fceff31987dbc));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x3035b244374cd9aba0ec8676ac4b320b9cb1646e272797c58e610c05c79fe2a0), uint256(0x127792681af6fa268005771ec6834f6c1235f5048e4e0fdb8a779004a6662014));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x2544808c24a6465182f7a62185c41e5869d54dad4529bcffe4491dc8170f1f07), uint256(0x1650e8acecca861a2f9edcff965b8115c37fa95063692c4912136cbb21eb4c8c));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x11bbf9863aec42d92d988d6b2eb531b0f59250a09117353f550256e193498731), uint256(0x0a472c83de136429489cce22de66e1cac2672b597d124d6c4ab8a6a4e48c50e3));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x0876d97883c620af3776ec709947193ac709bbdde48da3a2ff49ebd0e83c103b), uint256(0x03a6969e785474066e12226abee506a51a23f320861c1734e4a4ea1d95908aaa));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x1aa620832c05fb7164e7efe46c3fa4b90e58a01a0d45a87c182654fa706f2a8a), uint256(0x01f72867446f2ec9bc33ebfbf48c3bebbe6e3f924a59d6872403eaa46ecf43be));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x00105e7b5be9d80258609901ea62630019e65dad1e0dc86660225f1fe7ef2927), uint256(0x154da9de8b80b4cc8347e86311a7bc4c4c9bed836967eb83ed0c70ce2499af56));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x0f54c0bbaa28d7532bc2a05320b359fd94d76f178bde6b4d07d4dba9b9c20e09), uint256(0x0bcc832624737c8a29698e793f5d58df86670c5756090eee95c98ef0f03100d2));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x201a031c4d4f7611bd7dffbe8f5e84b2d0e4dee1785cf013bc83aa90c06aa496), uint256(0x29981fc53e0627fd15cbd570ff334f23563acf661211072557706079efd27a12));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x26a4e331c0ad6bafde3c5556a98add3cac59cbf1921f0766cfee7f4efac42a84), uint256(0x27caf8f9eae0e44f2fc8c1439ff18a516ab1944242d9990b57ee998e4ef486e8));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x061994d6c7a895a1b380343cbb9a1a16611a9bcaaf151ac26969426634cdd8b4), uint256(0x02cde9277bfb909eaea7b3d24e3ba90094f6a2a20c0fe49d4268e80af8ba9a9a));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x2a0bc6ccbd48f4dba77c29c901ed0868cc2faf303b0b2dc0e798322e4f4cb3c1), uint256(0x0f317b7144c2a369bf5ea9a97199e3e71a7321d68c489f698f7f5d494317709f));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x25ea78a8ac1b079c862651be4c9cfd4f0ff4eed6c5e2738b5ff8ee023ac7146c), uint256(0x2a4b34f667184418ed51d557d9a098946f487c85e2ee8ac13fe8cbd072ee9f28));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x1683f0cc4f1a2f076144a790b1eee9af4b566ed4d4753d9ee55a21e3c40af706), uint256(0x1b801a44675d1a7943d054a946ed3822913449f2c0aeb4ec9453db6af02d0d44));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x29a530001b3a7e3a483ff46092e472ba7707e9b2747bf24886661b82e3c763fc), uint256(0x0f0545e7291d53abc8641502a44ed875a4ec2d96c28403d4815c18b3ad8d4437));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x2148a46aa0dae03201e90a5c844e5218eb7b26a37c3129924a724bcd1355b813), uint256(0x127b870533111a9b1322e9784c3304bcd36f92a8dba6c7a2815c499adc9a5f75));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x1247dd74f1c7bce02458055baccebbe58c3d4ec02758f15682087d524aa171a4), uint256(0x08b4aedb220083770c644e94bfd70dff20f5e56bfdfaae4dc1d2cc6c7b090bfa));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x19c371237ed6b0e14b83d4582bb4dac5b53c9b5fa1c5316d1303e9d88c2404bb), uint256(0x06f95fa4b0459a7b3dd5cb7f3958fdd0cb017d8ecc629ca4d8a67472240d16f6));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x27cf8abd00fb27876a0aa3b0ad2113e59cd5e5cd7dd2a47f4e3873c223adf0c6), uint256(0x0add879feab841f051c98628eaf8b90e3a8febbad1e178e5900007dda7646a86));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x0f79d7662a16899eebe42916215f76f391836b1bb34551c7d85bd489dbf59495), uint256(0x03aee6bccab524b59a027e7bc6f9f26c48ebd34f0178739851204b737eea8fbb));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x28aa00f8ec6e5d0be9c080c3c77f11a69cf6ed26ed15374faf3a7cba392293ce), uint256(0x147a81a69e490f29b593e15a852306c93bcf5561823a32418ed505be65549251));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x2ac9972d84178a28b65db2d490406e923b0d30e75fd0031803ca1d0b901d7a44), uint256(0x116cb30925d4951bb7effb332f67cf05a028560d4b3dbf9245d178310a4209e0));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x13d9be4a92f04f4ebf82ba5f5b4592a233b09e121f78db74ac50fda4768b4699), uint256(0x2c01528cab22aa7f58273c3a22f9ff9acf2e35ecb402a154cafed045f3b87a22));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x0e89bbaaed99652f67661a34c973aea1469686492c981f522c202fea4280309c), uint256(0x0b2ae4f77ebbe15fe73b68ca6f947c889875a114005ae680e3692617661926ad));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x2fefbf5cd19c7a683ee5b0c3d69e59872ea2fed38cc683960abdfa7653149411), uint256(0x04b91883055d12b9e4074e2fbd2f9f2373e77fc8d735292aeb928500dfc78cfb));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x09553caefe2b4c436c1bacf8ce40b721e631dd2d6d176e5878fbab4057129e6e), uint256(0x2bacb71e0c97086a91da57acca77da7db66fa42dd2c04e3af97cf1f0790fcc29));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x2bfd5ef5788e870aa139849eb7077c2555b4fee55fd9cca7c0cbee3189ca6542), uint256(0x199296e7bd9fc48aef417e65352498f43f4d2d02b4e83687530c2fc77091973c));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x214540524e93c13f4bea356fde64adc498967bec728b61cd6da939b3d2945828), uint256(0x21233d61c62cccabb4dd70598d5577581f5977a9eab1c62b03a984fab4b0abb0));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x2e431b7bf2382fbe842ca31d5534a0a026bc2f431d88fdf3ff9f93fb624f32bd), uint256(0x1090d10d8d987dff42ed7ea9bb65cdf0b1cb8b48999e5de50c4a28e77336a516));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x153eef6e3f9c315bda17fa7fc72ef0ed3696f1837cfb528d26949eac87a4e3df), uint256(0x14757309e04559eb89eeebbde35ac29d785227e16d387fa823fbae99e8cf7fb3));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x293f516f31eee7c1b79f3f15121fc9803fe36773f193786ee20a200736c05b99), uint256(0x0984599ce0b2ca4af15db54b09a5e9a0a64cca16fd45743a9fd66171b369c686));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x1ef04d7be1ba5b716843ff79e35a3af83f87656a935fd0112e8cb8e656eb7a52), uint256(0x022d0e2c1919c8848d4ad103038bc5b0c415d4188e098e81bda5fc78ca81ba3f));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x29cca5fa0fb149758e008ad47296d157b1f21e19f221d91bd5a87777d4ce7ecf), uint256(0x2b37c7733d827dc0e8f6c18005842c2c5dbdd4a5a04845c34a72a6b1fceb9358));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x169af834a411ce32cee8549ad5068b92e0edb04ef19ce5a1b1ed8275bc88b278), uint256(0x2f12c2243e09c24ebd9d8f8e5ecb7b871d4268c35f499691510b3a8b83c1f8c5));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x053db423f304ea5cb1c924c2815b5aba6701e7000acd6b76ae0def38efebc576), uint256(0x06df7529ebb7a24b85773819a4b187c45103db7fb28a638f4e96bec5db91f4a2));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x2130ed744e067d56e37177e8ca1a40ee86ed218c006799cfd439427dd775f264), uint256(0x246c953f78f9c5ce29c59dcd08ffb0d1e3af6e908b0aeddb364d4544ebb1948e));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x0ec65e1a937d007d6eeccbd39b5cedc39baf587bb1c427e0a742aeebe9a1701e), uint256(0x07a45b8074fb23e3972e2e8ac6bbb9d1d2ebb93c0b4ee86e7ca99bc5281a6b8f));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x1c19b362ae2ef1dec43a5597da9a268066ac79a0bb15784e730a94dbd59e4bec), uint256(0x19cdf0af299f9183e1710e7a6e39e1bfc83d8251b34bc95953f185f0e8e4f478));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x03927506090ec9f2336a434fe2494470eb08f0744178c44aaed856886e14d5e9), uint256(0x17f0b8c9df09072c8c2cd2b9242673cb0e2b841001262c978f557b13e1939189));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x07e1a1146fb08983c84ab7c43d2954fc9a553619d72670eb8ded600ead569b76), uint256(0x2ad5d4a68c27e88fee25c2827102904c4ad5d1fba91c7c8be3379a9a265e80d2));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x0d4cfc085158d9088b6304fbd292bf62024d0c9721ec658032843df5a6f8fcbb), uint256(0x10aabac6f430e9f33def483619a99a609456f8443a9d95a24d24d570220ca760));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x201138e456cdeeffa791aebbe55bfc3bbc86171f10bdfdc967bd2c85096f4f30), uint256(0x2bfae8bccf32345eabfe2188c5edbd0995e5c8907cb7bca79e1a1029676d9953));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x05fee21372476328cf10b01b192bfdb81190a4e6cdf50a202761cde072224867), uint256(0x18ad96abb1d50034282aae2ff54357ec06b0cede74179248a214ba01d64098a7));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x2ea60b88f530f61e3b5bea0ce433344b36817647d27f1aafbf2f5af4f3e46388), uint256(0x1e58ad25197ba132324859678659902b1bde16addf28ccd0a008a66056aa656d));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x20c1e7cb0656a4db5878d3ca1cdcbec33cf8f962abac40f1d56ec6c59eeb3888), uint256(0x0db94ba5b75d46c28d3e2431052b097e2453da6dbc6ac0c6ca16813dd5656bc0));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x20084e5a79d09699e5d7f3e53d6d8be3e213db7bd459d0a890efbe369858096f), uint256(0x14352e51e5c5c36d7d5b7edab819696bfe937c7819cf9c37ebd8581292e7519b));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x0dae28319e9c75f8cd3055343d261853ab058f2f66b7e7afb1f2dd2b2ad065a2), uint256(0x282fc3374d062d31e3ef42a9061dddf11e818795a847bdf9e6fd3e968392288f));
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
            Proof memory proof, uint[88] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](88);
        
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
