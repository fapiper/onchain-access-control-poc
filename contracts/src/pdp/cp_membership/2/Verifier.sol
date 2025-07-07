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
        vk.alpha = Pairing.G1Point(uint256(0x2a745a79ce1289666f6cbaef6077e101e2c4d1b0cbbb44ccc48d160b3b71ac2e), uint256(0x0591009879de99b757886f5f89e2da13e52b5ac64b06d81c6cc587cff9059857));
        vk.beta = Pairing.G2Point([uint256(0x051c7d1a3b3e4d798af047c097199bb0953363223267d48c010ef2fb852c24b1), uint256(0x0055497bd67a9090a87524d48440594960593d5ca402d96fd7eb0f6481a5e61c)], [uint256(0x0809855650d68bce3e222e69b9f786ef412ab2d47e14300221d084f0bc3ffde9), uint256(0x299582e1d0da1fffe5a3cb8282355df60564fb15d5c3b0488595c2698e9b7296)]);
        vk.gamma = Pairing.G2Point([uint256(0x04f75949f553d135c8362ec2594c238b2e6bfe5eedcafe446bac78d7df5c9541), uint256(0x0c5c3cf7da7d73caf7a5b2151dd9baacada8a775b5280d8f3aaeb9d0171164d8)], [uint256(0x187ad56b75ee2fe001200479fae40ba8d11aeb0a9a92b38be8ef7b64aaa97e34), uint256(0x060173c0610e32634fb791f6aaa6a706d8164b25fc387bda356dc96e78120309)]);
        vk.delta = Pairing.G2Point([uint256(0x1f6d15b2276918db24fa1a856bb98cedb6e60352373bbf4275e0e1b21fee5e1a), uint256(0x0a5054fb2b6620c3f167cbafb66f9c12204ed6a2371075fffe105ed149e8f618)], [uint256(0x19f2a646c621a17cfe8c4b3cce3cbf5e935885e0da7a7ddd38fb6f3c1a34e53b), uint256(0x2016832e58d40d6cd927e1b178fb25e99acd30c3352fafdb8954839ae59b844f)]);
        vk.gamma_abc = new Pairing.G1Point[](119);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x01c312be118b861ea00aa26f877a36e6020a37c7fde58406813eaf063496e96f), uint256(0x200a826a823837dff6effb68830c2dd8a2c2fc49678a17a330aaa8baeb61de0e));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1cc54e13a22f2f6bb5acca7cb5de4b9e4455c94888b553703c14fb6a6e0c0512), uint256(0x1541035d383471650b8de22bd3dd294bc7cd125bcac8e21a68a4017a060c7792));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2afee15617246fadbf52190daac19e585005b7b309ebcf7ddc72cf44a96ec5ac), uint256(0x2f71b0e0392720f304550417cf33cf3769a0fbc2ac672da80fc9fdae0b2e862d));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1309c0a77ed5bd848e616f3882ad2c16082169346bb1b77329d6864d5be20ced), uint256(0x26de66f52caac2bbb8ba07ea085232d1af6abddaa3531120f54b325fc17b5a36));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x12f4873889888198d981decdbdf2f0ecb300266c8483b226d548e2f4fa882015), uint256(0x240125d352879bc98945288969065c59efeef31aae6466ad1556ca5d2e13ac12));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x19312253c6caf65eb27b5c8448dec762982b0aaf8583269dba1b91990d91a577), uint256(0x1a0e02d1f57339e4442c6250ba84957b1e29293bc6f2af3e881b63250b04b8f2));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1431ca9ff44ffb8a046f4d7167ecadc7c3dd78da5d2f39df62f11fea959700a2), uint256(0x05fb882951a2c73a06482d6aa52f02006f27622d1e7b0782826a4dac2237b0a4));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x17a807990309e088b9c71abe2451f73767779b8b089df8a9038d43c3027c6d1f), uint256(0x3031e381993bb546910c3412dd93a9cb1b4ebd737231b4217705013603de60ef));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x28fcd19aecbc4cfa71c867b8dda4487a4d22ac760180a0ed125a3fbf5e684a23), uint256(0x1b655c82e96314bc041b5adf8a74453dddb1a077bafdac54e4c0a7c3e6701d5e));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2fd1bf5811f01b0c393b8ce82754ff62860db41fcc070f49ad185a94b985c918), uint256(0x26095b6f270290e0890b3cfaac960e2eca1d76f42cfe9b0cf5c4706f5ff2dad9));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x191ea62e7382c78fab79b0c717d3109dff19b0043e3a6430bdb5a097b636ad91), uint256(0x06993a06e5994975d884b3cb0919ee719202a32552c17141ceae0caac09463da));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2b1bfd3156e3ca47472f295a09866447ebc39a0d8e414145aded0c53f0d71848), uint256(0x2e698c3f0c65746627a45e8e8b526ef136bbf05b8e14f80b95f28153de04e87a));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x07ed6c6e344a93449e34e3e13166b88023e8220b483d45679efbcc49d3da65fd), uint256(0x0dbb4fb4660b739dda13533b77ab919ec44ee21edf8ce487d255e4d60c9bf0a0));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x19418ef7afb597369de1620b0cedb028d073755cd7ded788987bfc06c2674821), uint256(0x0395691844d784f5a8482ba9477c02bd39b2c2ce9846a244fc164ec46522969e));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2c94a0ef40f4dc0e17a320de3ce8c146041d93461c429d02a2acce5fbac7a885), uint256(0x244792ba143301dcc0bd2793ba45ae65cb33b2fc52c3092e9e58476a083e59a5));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0580dfca5424647c04a90edb417e7cbe622e413a5765761a9a9abdb32ae96353), uint256(0x0a13d4cb93ea1ebb3a70543368fc886e5dd1f1b60d60fd12d802a03e7b067406));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x0e5571331b9a19c4e23fa2adb072624bb111b16356197bb36b7b779fe4c8f9d9), uint256(0x2608a0081d1544994cbf59abfda0e121e7521b66f2d3d60a6d65a6c1648280ea));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x25f5e0d18f77f621f41a95ddf1f07cc1a2234c045cb567e525f6901797fa55f8), uint256(0x04400582e9278e1afa7c553772bcca67e1b4d23af86fa5172a16095ded074cd1));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1af9bff322831ab499897dea57f4b73030c3e2c12e25052ab12643d76b378164), uint256(0x2e248603d09e45802ae215927696cff392c4be504e459ef5ab5b101ebf7079ef));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2caa494f036b54a9c721b915383df1fc5828d607d9024cc0eed4fc644059bb04), uint256(0x275f449a0fbc4bee659b2b64905e48443b473555afe5952f31dd20683b3bbb58));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x09b92b11ff89c846496ccfdc4d7bc5e8ca86c358798909bb1f43fbf2388390d2), uint256(0x11d95ba8639dc1416ba9cd83c22d91ce13a8fb1f595c62dc5cffed6ce3d16516));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x23d612e88f299768fecea294d28dffa1869a15840e93883a884a460b6ed4f590), uint256(0x1173e1211f6e668ffc4d0ba704d31cc43a2cd6dace305b6959f6049f14268c2f));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x13f37b0ced72df28c393810b5896cf535c04aefbaa978959e1e5746963200330), uint256(0x191eb031fffd599a3ccae34f2ba0eb6fe680a38a95a05c11ffde703b007bde07));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2409f9aa2f5b38df9b666ef4136da05e88ddeb01075df39853c29b2d157e090b), uint256(0x0d6d6f6af8959275b598e43ad484224ddebc53e87fe64ebd14328947cd4050b7));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x0e17ccff8d050985031983b1da6ffed22568e48740082c1e652f6778b24888bf), uint256(0x020e9fbd3f9b49507e4adab71e24a6a2f05d311f71834a2eea90d791cb863ea1));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x2d163696479ef2bf614edaf9029e58827d854f179965f73a9b52fc944eecbb42), uint256(0x18d627a0401f3dff62042aaf5238cd53dec876ca5a1c1964ab35e317bd3b459f));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x17bc554e133ecc6d40beff366a968881c3351b09ec9aaba5483911f4f0f4d6f6), uint256(0x126e7e1387faaad6b93ef4a2ecaead068b9def243347b5da7d066e0d334e9854));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x083dee5959e29ad180f045f13a328a16de14fd22cefd568b2e3989281e4e4f99), uint256(0x1d8b657111dabf71ef58934e11bdd50fb653cd56efb9a1208eaf95d24532c9a1));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x05a9c485e2a906571b9433bb55e3c19e24d0fc7bbeda50a2c2d35831a079d284), uint256(0x16664d92de93fa1e3242cccf79f797a2d3d12fdf3d7c140a22e771e1715d0bf6));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x0334cf63b2cd8646aef08199562f18aaabd8c0222b407bc45c6f7c6bde77a85c), uint256(0x1873b63820a486b0e6902ff6de0b49f789f03b09a7f0347cd025caeff5409af6));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1a0ea69046c42419371a3b7289cc301671c1680faa55de529d449505b65239af), uint256(0x15ec4d786e82a470abd03a58127e0bb6b9520d9cfe401c44abcca73acf3e4ac2));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x27c825d1b362fb6ab3d906ca050b87d5c9b4543fd2c4d81d28e839435d480f02), uint256(0x03ff2561cbb71a3bd17938c5ab40ee4799d68c184a0f1b8c1e5eb09e76d87615));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x0c1be18c031e3c529dbbb95c5f3d9e9cae7a30e0bddbab60c7e80866f806253d), uint256(0x22d7d1f3a212b0529fd92764b28f19b0e18ec478d195d7bafd190895a764ced5));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x23629f1cf3f027e17b8a63398c916b0e55121971f2d71fe48d767923db82380e), uint256(0x0932f1c422f222e369397970bdabc5427d3f0c854ff244e0756b5624260244f5));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x1fcb78b5c6d3c33defcde62a58052261b799ffaa6f6ac3dfb7ab4008060f7631), uint256(0x02f35a3a6a35928f4b694ab4d1ddcb0101d59fe846cf17203dffd46806faba65));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x22d5eba3d2162c0a373446179fd5d9a0228b2e018d2b547e21fb25f9a8b35e1c), uint256(0x1966d1f2cccb661db672b9af2b9043d3ec13ac0c2d9b8d8ec17885e5876fcbb2));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x2233c403ccc89cc2ddb42500c965a5009752f18db6ed2bdf50026baf1bf38ab4), uint256(0x28663b92875696bc46985f8593b69314fc4e4613a6e21ec62c44a5cc9419102f));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x280181626712fc850faefffe065c4db9949a865650c54040d43d7be6ab5c6ae3), uint256(0x302185164c3b0d55019cc708d933888f9d3ae8b324fa200fcaeba4c108636920));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x052a567abd90faf75a4abb3cdd95b44aef3979ee773cd8caddbdb80cf07437ef), uint256(0x2309818e0e7e5aaf7c4fe95612b3edc538ec0eae65f9796b8dd22a23466b8e47));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x05bd77e824f2d078718624bacb8880a1caf9addcd14d7fef0a52fbd757ebc439), uint256(0x138776a4d05ca7f26dfb2dfd1347f485b3861094f3435c80f960117cfbed14dd));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x26039fa543f21d33d52fa4e75755ceb930ea731cff0ba90f96c4a84a50c9c551), uint256(0x09a9f32005c784478d62ebfc25e91adf08051412cfba75a6c3b4e9938d525095));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x0fe8cc64f9c0db94fbf732cb02bac996df442d63cbe93daf19060ae5c6ec087e), uint256(0x07f9a4fe59f0b496f84d6d86f671a303440dc8f0ff5905135ef4df445c2260b5));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x0d395d276824ad7586d2b69a01ea4e4afc94590a7c508bfcb3d6828b05c055dc), uint256(0x261698da6da73a179c7058fc83aa754b5242b97d8461b959d120105d15e79365));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x0071f262ec87ef3c0f5d2c36c79f82bcd29ac8d59ce3dbb750fe8a0536ff4f24), uint256(0x1c1d4eb0e833f057351e989c45b1f661807acc5608fbe91982147884f962dead));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x2fa1384ec2178d0bb8ef4a1d1cdff6f38aa9a17e02f496dfe3ca25340917dd9c), uint256(0x2d262257b1d38741dd581d033fa2155c37d1b79bd1bb0acb5e9aa28fb2ffab31));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x0f5887c4a03a816deba7ae55a697a8a0846d36f3c3331884e7ee4518667b326d), uint256(0x1df4f5f0659cc8d2c843c5067b994f86498b563fcf248f45ec5ffaa49c7edf1d));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x0bd119a78a4e0b465fb39cb0510126da5222498ebaafca38332f42034c002a22), uint256(0x179c7ed472e78e894b3affd37d0e68db0b2767a89a53a76ef4b47998ec7bae79));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x172aace190f39b5c95dd07b49f0d2759dc289b573d67990efef3007b907f7302), uint256(0x0054a151cfbfbb9238d99d9d9c9f321785d88827b05c0ce96007e26cbd4cf829));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x043340bb7b2d05d8021ea0cf5bc6b6ca469041edbb650ae23e8d3a3292811b1a), uint256(0x157450372a9a0fb809f4d9bf0e51a447c25f1a73e87a8bd579c29581fd9caacb));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x304e1391d2fa1b0062bad5c17d7bfc1958dbb052d731c6af17b1190023099284), uint256(0x1bb82529e6ab482abbff1eecdfc4ea259a7d8e0d9208e929de245dfe04d41e68));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x12fe906e296511366f2538f7ecff77cb57a4b45eaf6935a8e5fbe1c38e5fa8b2), uint256(0x002cb3d13e6159560b3a23d20ddfac6a3515f918f98cd393e89e11f6f9d09cf2));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x18e9bc102f9db2af6e34452ded231c9cc7cfc2a40afd46ec046e5d4c10300507), uint256(0x1f84dd2d1e4774775d8ab2c46ee6dba8e49e05ef47553676d76d88609090845d));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x241e44fd104b21a846ccdcca7887e4621fbdc0e2571a74eee794fbc3ad6f4530), uint256(0x1b9a3251474bbe9b3794c59be0056e5e7558ef3d1608548b7944d6c777c76186));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x2043bcf71113babce4936ba6e79fde5f46fc8c13c60532661d11f06df3a589ce), uint256(0x15cafc0a3f4448f50570ef18fca3fd207f69b6483ffc7e80d293a8fbc68317d6));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x1d24fcd968d87130fe07c7d0eb9e1578bc750ae88cbed244d15d17c5612b5fed), uint256(0x0e04902a865a3a1cac1b151002d07ddccec3cedd376ab431aa881941e2ad72b2));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x2877abfb9c9e755364b8bfa88e02eb82701da030f944fdd137393ac210c4ed76), uint256(0x1dcb0aefb8ecbba40745dc4c84b0e9beaf72012004820a14013b64cc6318016d));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x22488f7568868823beaa7b927f06706e984b6518ce45f19513c147d56a90b4d5), uint256(0x152c614340c6971d71c7be0de4a18ef677b5ecda4939a1feb91030bc90faf919));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x2bfdaf9185505459af2ffb1414f775ff5ccc50e5aacd967a60a451ea12dc9591), uint256(0x2db6444f304082db0cc16a8f844844a0845bbc91dceb3c7ac4c3de3a8d7167f1));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x0c1a38f1458a0c55361b2c87cc9c8684ee382a54e601493969effcc6816804e5), uint256(0x1aa00b20d22881fea92d189ad1b5e419b7f6664427b2f06ffcde1d7a834462c1));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x218904d1a3d5bf48fda1061b27763ac31bcc41d8a0a3593fd9aad072714ac82d), uint256(0x1dea0a77b04e2a9c16ddc9ef26b00e50298c5ef2ae49cdc031dbef3c5a5d0285));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x1fc3232c95a81f5bea89d65803a6a8006e921506ed9d44232a84193995ba55b0), uint256(0x182d02165472cee1211081c2864627d167611fd81f171bc7e61990607cfdb97b));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x0dc7a7ad3376aa4a356b3ba03299d828786461759523cab685b6d6dd168e0e6e), uint256(0x003c3b51629b46725b0eb4d23d1cb2c5f46328e8ce66409d599b88f69febdbd5));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x1c9151fdb7a7d6c5989b5a8fa3753ea868b0b11520fede47e70bfde0430f15cb), uint256(0x0b137ad6b2c1bbf7a2f8f638a644f64faa882eb35f65cb52a0a1e8eb49368cf8));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x17b1e02243ebccb287515d5bae5c87d75bba5cc574f819d5af6199405ce1e1a1), uint256(0x25d50b86df82699a3787be59762470d5346de755839b056d7d5080a9080ac008));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x0e79495190ba43498229fecd1390060dfadff0641f4f3f3592fab1f95dd786df), uint256(0x0761a36b27765053b4473267a575fe82e02c1e64836cc05e8a63927b3f18c864));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x0031208ee2a9ed9330ce86b701378f290547c1333cd7b8349d59044da02d7ad7), uint256(0x12a37824b50946f972378d87d72cade4736c3d7b944d91ebc532050f9fefb88c));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x3024bb04e7a5895288e77c85e87fea30c1365601e9b1593b95c8eea5df351cf3), uint256(0x0e2a7f5ea9ccc45003afbb6ef86b6dd71ff933585c3f1992e0d56514e1c30335));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x259df3e1835a494852f3cd7e6a9a4e0ecc623d087433bb653764cfde68652934), uint256(0x13d0f1fb034e3c9f034ad535085dd431a64f8e6dc32e7babac35818d096d8387));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x0c36b92d669ba6552e2263cabe63ecb9c347b12c58abae29e41f7f756011df56), uint256(0x1aab3ee31d7bfe8c464d8a55bc691b93b02a7a68bf6594ac7e16a4cfeaf5e99d));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x1d9749c65f163bacfdf34b97c555c6cd9de036da30c3b930709a6247e1f6b03f), uint256(0x16b9412774ada0e9c651de670da6d6163d997e22ed9695d9ff1355ae58af0af4));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x0aee3f4a7d99d754460088fa24d742199fe7fa4e1d2ee82dc56e72e6e6f404d5), uint256(0x16d03bf73d1ce2fc6c16d5818ae56cd5ac04f8b78ab8b6019565e940853972bc));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x19bd618a05607f53282d9275bcd32c1b65f5bb8eaee146ef3709e048e11ff280), uint256(0x2f57a509b9c47aa07d5187c5cc2b0c40286358a2e3cd912b49c5e3ddf70a3eec));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x26e8211ab6f5f95bdbe9dacb62d5cd123953338f015f6c4b4dcd572d35d891e3), uint256(0x062b4df868fc4bac80a600310ffc52d360e3461b3271432ed340b97a4a078684));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x1d2301a755f9a2d49d031436e1ac65c333facff0bb305e5e56d9739e46d93a14), uint256(0x06b47ee241e76de05d38b2792ba401a38e37c3f2c44246a3b58db4a56ba5fcab));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x2d88ad85ad1405c3346c515e9b590a9b0825635d85869ce73a9a6f192a2bb6d3), uint256(0x12bef9698d876cfed93002ecdd562715b56fe994624ce368138cb9548859093a));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x1ff47ebbf021a40eef9fbc8c3c090917f55901ba5b02ec97f7c2b9d46f072875), uint256(0x21fa1b748398d4a0bd8afbf0612b460ab528797c9135b51e011dc53236ace966));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x1b60ec0d579e6cac784f7ce317de41d620ba56c44abb163937329a357d147cd8), uint256(0x157dacb0b33613dee9e39031ac418b77445d521d5947a941a8390b9fb8f91710));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x29970e0eafa7424294726fe7cbbfe8155676ee47048d9049f78020d7acbda187), uint256(0x1c211c000ea326599efdb91516c9f7f5d35da099f84d9afe5bd29024f251ffa7));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x1eefc448341ae4c0c0b1fdbb781b6d8007fa0b05e7a4f7020cc96d39835c5901), uint256(0x2281f0d66f60bfeae9a052397743be0197a147d43c2393ae3ae255804ef811b4));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x1180fca7aa081796cb54791bdf149c69bf1ee7478f1ded185ab6bd983ef0e966), uint256(0x0f10e9aa6e520196796001028fccf6c852a771f1afce4fd42dfc4414419a3680));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x2338257a60f21b4628f2b263e0d1b141c732d2d2324dd07cf487bb057aadbf27), uint256(0x007d9710078e6e9d0dfadaeecdb6d024411898bbc11ba2e7acab344bcda28441));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x251b28fc1be9e06acbc5fb60ee12cc6b192829c2b2899358bba3f4644d4190b0), uint256(0x11bf0803f098c80aecdb30f64238e3dd924148cc3b4210e5f1d230335c1e6e2f));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x098def6169c7420dc31275bb8d18f9b6e7b55102c31f8cd3285bc5e9fac703dd), uint256(0x130f19f0bdb8fd3d18c2e77369ca4a0b40dcd22f29fb9c7a1a451b9ade74f1c6));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x0b355349d8295def1a8139b24c5218e1ba60041cc93e02a0b7363d92827f0f2e), uint256(0x0fdb370bac6ad2dc1df019c8a0fe57245760f4ce9ea4f2ee48bdffe5cd21109d));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x2c8d236f858eda08d6dab134cf8791b3f0a647c606dc2c74f192486dbfb05739), uint256(0x076c60f242e18c0bb7bc39adb6f67f85c71ebae557807f6b10cc9be0c55c050a));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x29b7108524d810c5b2ee5059f2b485cea1349979ce3691437896c33df649c823), uint256(0x25129a034d1829a2ad8404ed5b3249d224eaf778e4d7ac0c5e46716683ce89c2));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x0ae40c268a6fe0c5a83b8225b35099d108205f8a12b63ce7468a5736fb40d266), uint256(0x036dc59215187a4e4e9e7b8657f53ab309c79d991c2134ccaf903d0415884361));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x14ecab9ab5ac40c673f01c59ab942325e6c6eb9185efee7193c34fd1ab170e39), uint256(0x2db3ff9ae3cf822ef12b16e99ff25aac23bd6c1e8af6833fa463f1deaf95d975));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x2a283710f23532eb7434f7af9356b87a03600a490a13d87f86dc9781964b50b3), uint256(0x29a7538a55e4b3adeda5b3d632dbe3db40a9b0fe263d86736addbcb50c1d705c));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x24c0cc3d3f0d9d4fa0ce65ab246eb979ddb323b2f679ede729355fc7d276f0cd), uint256(0x209cd07f714b9844f16c15653b35773e803772dcba9f8c6a031b8dfe4686003b));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x213ac17b40e63e8997a295f949db1d6bc880caa7c33dee6bdb7349080b1cb625), uint256(0x13e7dceea3a2654207e5f390e9882b53b444c2d286f56c7eef35499f337b2afd));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x24b4c157a83f590581e5b8450c3ba5cd64f886a958ac6da8c05855bde46bee4d), uint256(0x10b22ed0327fd32cdb014ca97864ec81132fc202df878491641245bb8c7ad42e));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x28ff27138a761b3a7a68d5bb4601263d729c3a78e5f7d8f0bc9d1805bd72bcd2), uint256(0x235923fc429833d1c3cc10c2294f07af224cbf04058486de5ba38d2e3767c39e));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x0af36af677bc6e52f19dc582f4de4f345e55e1465f0d60523994a2c8fa7a08cf), uint256(0x214878564082831a810aedf15948ff56f8532c24b7095266f6759956ed04f980));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x2f9e057c521f953dc49eb630ef6af8d38ef75931995005a57b78ab5dda604a0a), uint256(0x1209b19ea61d49d1921af3ccd65f45e28b4f5f59a432b29b00a65cd2d677a106));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x0af903a1eb167e97351a48ef8ab9948fb03921be594ea0a160a644f2ab9e85ae), uint256(0x03ab029def01a231d79bde846aaa02cadcb6d3d93b28a23daefcdd52ca83e200));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x16169d8b49a10b77f8a7f5d51b7769516f1566a65689a4badc3a865831f084af), uint256(0x04f38423b9e7ea387dd20cd70bcd10d0ec44d97a7af76e1ac48d3d6a6ba05077));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x146f355c53cb475aa1d4c9029a1b959fe23d56a473a8410095b04adaae467474), uint256(0x197addb2dfe52b30a373360c59f6f7a32de1e4215641cd4be2e8dd62f166e5da));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x0c84d4356df472d909b17e5ff754c17729897e1df0ee369ca743a8b461822511), uint256(0x24381d272798950777af5e8fc4ee4034c1f1747f793662f793b7685ac97cff4a));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x2ac2f5df0e1fed62626a5b6aef02216dcb0c2b6f79ba1330c99852a48e93f7da), uint256(0x14c01389d85f84f0087529b7b376b5f4207513d64d7fc40c6b7da2c062bc03db));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x074c010fea3f8295d796516623a14227ff1a28b11f0b9d3ee6990b0c870a865d), uint256(0x1963740136e131460bfc5c963dd02cc764519e5b0dba0873f5b404d4078e2804));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x2b9c10d4af1fff5d3e87b4a0a74b9750eb7567fd25d68d82ddca639d021f38bc), uint256(0x221da92c78d08b88593fb5f76e858d2cb09961f16333a13455c0184a0964698a));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x2c5381947c50f5c612790108517b9182220d2ce693e5d7877dd014f4d4e0be14), uint256(0x16bd4616df0b14ab99633b4c90d6bf33a2a731f021d7fd818f67d995d634ec16));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x15b5bbff13447b7199090dded7b341c4e61e6539fc801c1740b6bbc688d725d6), uint256(0x27da7e4a4d9548d7f6315804f384f380d87de6c0ae8a499c0e8ec7d45467e888));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x110b317ed67d1254c5bea5a2eb06a8fae66918fbd53f36a5cd976a38ebf33dc7), uint256(0x1acb9083c087203550962fb0418537a88542fa4e04687cbe051f6e522c7981fa));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x1a54b83185e173e6346f66f7c2101d39fc14217de3a438d7cbd9d356344d93c4), uint256(0x01540afd97a9368270b2331775b93cfdec84023f9da1a5b3c6551507f088489b));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x0f4db1e7a9fc5d101e1b5def4882ea85caaaee67424b880981a0cb9ab40891ab), uint256(0x236176e194a5384ef081e95af707b20457d6e2162f7c2873168b4cc9e247d237));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x1b8a2b749091d592d5c2c3443adca08126c94510f8bbe0692b8f6c3a519bfcdf), uint256(0x00f1524e809ed19eb4b9eece6135721b3663b7bb6b63bfff952896c6b1ff8516));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x13076a382ec12996bc7d8eb5ce018c385db3e9c7f526653319586a4d9b3f7a4e), uint256(0x022c3e4c2be0c40faebe451d63748233ae4969147fc4b0069fcf10a0bab88a68));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x0ede10bf96bdb484d12f340ff22ce8de36a9e3cb3cfe174e8c550a1d84f66ff2), uint256(0x06bbef8ee3a59b08808e932b8a4dd3b62ce100db79d29fbe9e79f67db4861ab1));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x04376b8c9341e334f23977a4ac4c93cfadfc10e138ae4702953838c921768640), uint256(0x1e6cc5c71ebb9d5bb1710fd387eb833f854b25a60e9fc74a756dc2ec563c97ef));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x1c98d29d3e000785bcd4c6fc4fd90cbd314eba1c05380d2905181d48586ae9d2), uint256(0x292c43fef1ad0dc282a84d1cd90c735177e219afc7612886736ea7c6e47ea681));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x0eed8c75c0040e17ca433cd1038d0e8d0e1b29fe32d1263d359094127f6d86d6), uint256(0x2b134c2e853515b692bd2ca3bdb2210f3e0c348129a701947eca2ce573635364));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x1976beb6454ec7ca608b9beafbf64565727432ea70baf0a63cee3afd5e7d6c23), uint256(0x2918b8cd2d2475fb5ec875250ff224114d351245723b7062846476477bbde4b3));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x1387d4fdd80ef9b2154a084576d60667bdb613a1abba065499072854142edf7d), uint256(0x1596a02e0065f3164fb812e50ba86d1b178c3e6e446d04409cafcdbd0ea85af0));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x09a18631730edb9b22a5b6328e561a30e85ecaa0748bde25b24365ae65e04d19), uint256(0x05379a8f105b87c2f99925e21d996b350ec178b72c1077efea0ad56708e678ae));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x24fe10c661fb4fc6f7efbb4d1269302717733379563b651739d662cc219b5969), uint256(0x23aa0ceb8b8058b2903dc80217001864fda5ae0d52e6eaa570104c69a9ea6685));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x1e5d4c2bcc5dcf7df17dedc4afbeaf7ef4e01355d2aab56c4577a9daec3fbff2), uint256(0x26260ec65f8b0efe25f89342bbe69b3c81d64112734b60c89c69ec33ff393a95));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x244d606865f6d11db6e868f479d872ec41ce575395340f7002beef9db8f91e40), uint256(0x22b3533ab63f91a2eb0189cceaa33134d3438693e53d759fe635d944e25758d5));
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
            Proof memory proof, uint[118] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](118);
        
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
