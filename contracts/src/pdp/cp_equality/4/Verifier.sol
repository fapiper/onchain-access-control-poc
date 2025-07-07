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
        vk.alpha = Pairing.G1Point(uint256(0x1b6970b71c2bb11aaadb798e7756eed2538516d5deb223070532f61cfb7dcf6e), uint256(0x01c6ecb1631a11a1f94e5a296f69d7992e481a9c0310c78f78e80211be4debdd));
        vk.beta = Pairing.G2Point([uint256(0x25950192a03b37efd3d69f9c4795f2414b2133725cd49607f47dabd3ebae186a), uint256(0x2c81d2743ce63a4a81846c80b22216e0d70d1d0dd05a202c2c322b3c8b078196)], [uint256(0x17a34fc503a0bd6363aacdad46a46b59a06c88f5c04cec4c7f7a4353e5414769), uint256(0x0b041e0eac17f2f4cd23df4894ce47398fa0b583f9aa541a4928cc20388deb20)]);
        vk.gamma = Pairing.G2Point([uint256(0x188edd0a57ca944cce3448c58c3a91d4f1cf6dbbfc32b41e0963cd490760293c), uint256(0x033d56875589cf14b7dc23dc54372702921b10a25d4a27ad92b70aef99931ab3)], [uint256(0x152ab04333e9ded08d4724ccc5773166c499eaf70a42930431587bd9f32906a3), uint256(0x04b86bc025da063105e5c6c449603c4cba5f4f607a5be23a4eb939f989f82c8f)]);
        vk.delta = Pairing.G2Point([uint256(0x2b5414ec75512299dc460b168d58442eafb9fa602585d2d6bda897bc00791aac), uint256(0x160ad3fde4c4e172164463e2e256556c5709c8e614397003dd1dde8ffee4f0cd)], [uint256(0x135e50f287b6d5f568782fa3a29d296ea9baa046e4e8f456a32330fa5f3de124), uint256(0x107e436cc83d69121a89cdb8166c5434a84cc182364437e79b8109ca952cd54e)]);
        vk.gamma_abc = new Pairing.G1Point[](81);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0a94f47ee1db5e2bf0b7e83b469f2ef0b8a465e35d2efdffa7cb31adf95ce2fc), uint256(0x1144513b8f22bdcc1490624fba865e450718bb5ce1debdb34595d2ea3eb0a4df));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x03748f93989b3a6f8a091e312c1982762e139ab090487f24ed4788de3ccc2ab1), uint256(0x18bf635b9bfb6ca6620e4b1364b0bad8017aa1c65ea7aac212c6839e7791b758));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x054362515099adf28dadd623c39c2df41296038f8487ed9b805bb206cf6626aa), uint256(0x214012799ccf6482f2f7ae36507bb0cd4631dcb2c00500716ebae50369cf81ce));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x282c6312069c1bff7dd794676261d868ffdc017f0c3637be26d18fcfa677fea2), uint256(0x0913e977ba4c98a8905d2d51183d57144bb7f7c7e715745543b34cd52a3e54ea));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x262e105e8c47a4baebda960d4b6d0611761cc59b1ee63f8c0872529617d23c6a), uint256(0x2c1d811bc4e49938aae051a8892123d47e0f6a553da0483bc4e4ca16c523b737));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x13fb47b9f34d952816841d93852a01bc4d2222c666a81e61b6d358ba0e4e133a), uint256(0x0063d0b49fd1183bf55c06878f8649ff046f2e3c1abd5138863586b7e6df01b0));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1d6b15d8b6982458db40eb1a420c5b82e02759e32d7573564a217c00543bfd33), uint256(0x251ce4d07ba7ef4a79b87546aa97c9b3b9be7b964216b920393a4e98fe0a154b));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2e97384b1e54a82f70af680512020c2091f77496df0adeedca019fcad025256a), uint256(0x1e91771fac36906977aff8753f1e8e5dc4b607f3f79c9a88719ed7df2321e14e));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x09c442326b388afd26b1630e744418e496be19c688e115496546df778b49bb6f), uint256(0x1bc8455ef827afe5f0f7c8c2805439187151278ce041e00c2656a4571918d07a));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x044caf829aee96625a084de3bf68c5c0dd4f84d6cf334832cdcbd65402e02772), uint256(0x271c74863b0daa55949800de3639e64117b81084edbe2e4e23afb978cd233f98));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x18f0fef1032487afaa8e6d49ffecb06aff562d75fc46746a4adb70c153b5ef1b), uint256(0x16d20611bf0e6fd91cc618e771df51972215046a09339668103a7abde07016f0));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x19285ae60e670dd6215617879ba21a0d91791f2eea6a1d9b87b5d8ae93b7615b), uint256(0x1e0b216e0c74a9be953ed9ba14acd78df78a65ab3b936646847a0f0567e7f63a));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x193c7448f809383cf8e3e59fd3e1bdeb73c91675d1b3a8e1a184afd599e8e6ee), uint256(0x216fb8d84c9ede8ba7f9e998267b5d8e51e343d7b898c78cbc9880501b1ba2d9));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0f3533965c8801f0c8aab81b9d0e282dc59701e6bbfdea562f7776e733a91e6b), uint256(0x0c4c88cb56d028e7dd893ca4ad87d1e98a36a54c875416b3c3601c8f4c17320d));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1bf020aedf551d850476a542595e65c15b6d5beec70291c825ae68e3be099839), uint256(0x0468d56e22407409ec61b762439781552c6f43cf74fb2d7905a2b8599139e28c));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x00ba18505b5ac95098f4dabcd02d990f4f54546cfe3e2efb255da949e589902b), uint256(0x03048d5d42ba8af460d4131f9a404aaf37a5e190e074c2cd0c874d712ab627de));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x19070e6b94af8a23c18e30d65caf19a1a5f427f5b1d8f385a445ac2374474043), uint256(0x0ca5de7b5cc1b6e5e3164ea14b83a4f2b4ae4b14b01ea3ff7309867fe1f81d01));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2f6685b400497aefa399a69c3d64e09010c9d9f2f6140f8ea68eda31a11113a5), uint256(0x124913510598862c5b80f7a5c4ad46bf44a396114b06f6b37e9c86d38254c8f1));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x0787966978bb4afb10ef3cec6ad65fcadd29a61717ee51efc949951b81f10886), uint256(0x26740ea5f6faaecdcd47b94e8cfbdc0d8226ce2d1f35b4056d228caed3cb7569));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x0d42916f8aadfdd0b1a3c55276781e4f6fcf500930ab87a18d10ebbf01f877d0), uint256(0x2b0aa77e1f7fd1a7ebf45d1ebdc412ef036ed6ab2d16d82c4c0e4899dc8aa787));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x10b423ebddb9c03182190ac4cbb6d977fcde5a4c9eb215bc8cfc96811efde2eb), uint256(0x179004d8c25d499cd1129e3742bf123c77d7dca60b5646695d2ceeb1d4dd53a1));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x088f6d98cd608c7c5653df172677e3b78ea810f9fddf2e7c343c369d770e7745), uint256(0x14156b48186f4b6f8f8706d5e00139467466ef4a025634dc816fb31f399bdf41));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x028045b55a72c267eba2cce1dff77e12f23365487cb67af5f042819c7645989e), uint256(0x1c07613b39d7bbc826cf2bc29623b2eac48d1318c17a896a1035ddd1c482365b));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1b12fa2337c647821ba63c3c73b6cca08841b28c13d9e1c97675edfbb64b6907), uint256(0x02065e4891bae278a9fe31047dfbcfd64d4355ebe754e61efeb52ae41b5ef574));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x2d6fe07e13e66245d6a56635dbf056f5a968a1acb61748247e7aa6946f950dca), uint256(0x1ffcd984a19148fdead60dd0110373552009f9e4ad6c1f6f86f3170cd5b5685f));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x0164decaafd8f848523105ad9f5ed61f68bc323191d108f62a0c4884aa49b076), uint256(0x166af2b56265647b5680d399f398245f439e1796de2928f21954a8bb53ec8553));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x2802baa59d3536a6751dbdcc5f626c6917c085c9b480059f44e2f96c2c800ca6), uint256(0x0a3195751ca5a4477f84e02e31dbf7f828a6986f953eb034e4e69815d4b8a6ba));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x05103a8a16a0039776bb2e16ac5ecfe57e8f43b67c4c7fff5ab565a62b1630e0), uint256(0x244a111064248d921902c7a1a7a0997a72ebf9e2b64f59a748cacf136e66f6e4));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x2cc8b1234539f61d515d86fa8add10bd57a0223ad6795e6ef81afae66303633d), uint256(0x2f904091427d72c13de5e871ab1784509709bfa4ce9496d39c1246b0a695878f));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x2f727d191d503526ff9c55d720e31d988a2f581357240a02b943878b269495de), uint256(0x100f9e2f5760e02d8df329f983170383d6ed39d88b73988d6a83f203692d573a));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x0f5d1859285c3963cd3955bfe368afdc9d3049331bd0606d36e72851adb30ac9), uint256(0x091e38709d950eae9c040aeceb00c9fa3d36626ef954f008b2c566551b994a81));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x2b682ce7e61e3fdebaa43cf5779efe89d3a00802eef2f4f7e94a06c46db4ca2b), uint256(0x0713e1c5cccc25aa6dc039e253a15d5be37e7aeef806a59013a69191bec5dcd4));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x0320f491f7a984ce84d0f0e807633745a21f78f54ebac36f3fcf88371ca923f6), uint256(0x25ac563a91c233852d89c5a4713a04fc8ccabd710941a819e8b2c42163ec4a20));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x2bbbac0442887102a135fc7f13375eb68dafd5409e37601fe764006f5ccca2ee), uint256(0x2fae889a86085bb0cd2fb7b090a5226bdf58c3b7e26c45463c1aad7d44cd3ad2));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x2178adc510fd893facf5acd04d8fadfd5626471b9474f5511fb574ae4a73dddb), uint256(0x159bc57965360b4d8cdb81cb25a56896209eff2eecf1382797e5a16e56660b92));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x02287f7f9b8074235796cedc0e633376f08e6b601cf4ecfd865e0229bcefe6f1), uint256(0x20ac638c10073bc4525713a0644572d012d85ad4a1f95adce1a608878c5fd59f));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x2eac3fe7049691ba44806b60d565a8ae740b7c6c533333d2f06247113e7362fe), uint256(0x288ee8ff8aa98325885be66e1862e80e1f0abe14d2bcf5d0b1eba035dd40e207));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x27ad6dca4820fcd8651985c0a0f88cc8044878b853909b73730c5f226dee1048), uint256(0x0e1475bd11c795d5a23621f3c2b3cc94d0fd350a0572505ec4b9ec750f675814));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x095222d013714de0c1a116a1de69d2c8f475a693fd6a7324d19b77331d9d26a8), uint256(0x20314f604adc5482021c97b7800573854e1cae22eab22ccb4e7dc11a3ae682b8));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x2fa3c6ff24ec7087140b69084f9d8db42b3eb40054e1cafd893efc05a684fa38), uint256(0x0d69416937116d6e797955920a968a09b1d231202521513fd6295eac29cee6a8));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x1b54e37926e0ffd6d9baa43d0fc34aba66a2f20251d802d00963eb090d303ff2), uint256(0x29bbe2abdfb7936c03aae55809fe28f4dcc7a745a93f23c7238ac86dd799acfd));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x2fcbb1687360b3aa7a992354db7875f10730e6c7db0b576b26a5fec5a9dde5ea), uint256(0x061d3fd93090c9d50d583eeeb317bdf6a635d73350ab3a0621cee43804d51457));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x1ec12f75c19d987ef752d29a4676d2c096aacbb5a0882840425cbcb1384fd30d), uint256(0x03f6999dd508f66297892cb943076519c040bad8ac8a5d5db95b57f80f58690d));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x2031a921c29f7ee87c51955ce7cecfa1f4106753bb8278c4a4b8b257d68f8e31), uint256(0x12fced5556cb70309bf5893661061026852cb440959beb9cca6104d5064deaab));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x14e2e6a3b3457aeb0c4fcd2ffc7ef6dfc25c7927283dc9d6311168725354755e), uint256(0x28c924d7789193cc6b30185b4c6acba4fdbb7bd5be07a14a1f60275efc01dc76));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x0150c03cfb3964a25b9fc2be850ee72d3c59633dc03b07181f74d2d49f6fff8a), uint256(0x1d8e22362d4bac06bd7db755e5ebe3db3e34ab9f7d3cbae9d54a5780110c1a08));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x1ad83e5c631f5a223ac62008b36f27d766e12f46712c0a12452432fd1d172faa), uint256(0x1c0f1d69c5673398a6df9d3cbbc05ab150f08bc5eca643089d17be07c4040c8f));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x0e4a422daca2fd14a560e731145d41cee1400109cc46b76433a53fc08a51f1ae), uint256(0x225fed642dab8f77aca94304720c3d88297d321c4474575ea47a6045b2dd101f));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x12e014e298e406607ea55a1599cf25da6aa4e3881222703c9a401a1316b1ccd9), uint256(0x025c3d3974290407e273893c8a6497c8b39965fbcc5b822cd9aafc4544b7c31d));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x1714ce440c7173ba399db87aff25e4f4123d472c72a0d1be64c70e704a0c8823), uint256(0x0fb45b50c5dbb5018de86c1b01d28a850061376a1f6fcc1d966078793b553a7a));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x119b76e13b45ca9bd94280a78ba369d4f844b12d7cac30d1236975699576bf99), uint256(0x13a94243a8d18150844036768ca071d56ed97880dd6ec14733fdf1bc2590f0ae));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x21f09f28055b62f7e5a5e3e17299b6d5eecbb2e8d259f0288621ba928cc219de), uint256(0x1b71359204afce04c6bf1887811e127425c592fe6e55fa735405a601c34d2f2c));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x15ea2c63deecf050c04bcde4cb0e3bf308b9722e0bfe917bffba67f5421cf0d2), uint256(0x100059d1b73acb61a95d942f95175b0276b430ef5b2a7b14f7b3e8bf122ad0b0));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x2707d31da0f4a610983e92f5b2746a66a33a32ae443fd6dbc4103d10b8988af8), uint256(0x2f3b841d3b8374ef9e691669206c76af95d37908a8bf62c072282c02d8c7ab3e));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x15423594df9e7902a9dea948ab5180cb30ee692b61c1963998dce6fe203bebab), uint256(0x139ea58dc97f5518144ed3dd64c8296aa68fcc39c3b21f138604b81f9f9491a9));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x13eeeb35b3dc3e680e9c4f2f781adc2227976f3b943472fa62db047a2f8916f4), uint256(0x10cd7c2d6fd3cea5fee04a43999c861177952412ed5454f0b13f77f825466c6b));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x19adfd716e0c6c6a46d5425df328d40082dbefc4dbfbc2536ed2228810005fc0), uint256(0x010538486bbb8593f5b4f7fa29ae9b50aacc5a405867156da6be0157a077a2c8));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x17135922e79de63abb5990f39333cddd828859ffe40f4af55e3d81c0145924f9), uint256(0x07be9c225a23dce78d611d1906b45d50829f26b056918ddfcfcbb7f00bf53439));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x2120917585b5c3d379afafd5b834a777820142efea484c3990b5a5f46684ff9f), uint256(0x2da2d3214080426cb36b3c9e655d23f3f8577aed811c3fe4d44d1dc148301c2f));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x07244be5234e4461ed1131e2d1a52ecb2e40fb813805cc700a4d2f8237ddfda7), uint256(0x0ca86a9bd1b11f34d897c93c53100e0fe449ce450cbfebb30b426bc3c1790402));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x0e26bba85a8b19620b02129feecd37f0b06174668af8f0ef27fab316aaff807f), uint256(0x20118ae06184263d32639fc499a58d7a998fbae1a8e7d8ab30c7c72b7d493b71));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x088d836c98d8afcfb90c802e51750bfebc71d1150596146e205e5f3f84352b42), uint256(0x06d97fbd28cd272c72f0028d920ae9442e3b3872df6e8bbb1ce4dfcc7e143655));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x0d8714e8925c99b2779372ae859714f51df605f4824b6be398d2c9c415950aa6), uint256(0x140ad75eac7b7e70317fd6605534145046ec9b0d4979a55dd76464c17c34f0ad));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x05bbd5066500ebc9ae9d439d0ae043c21228c2eb7a72f1bd9e6af2baf00c4325), uint256(0x17ec8586e4efe9a5ce26fa0b9b1868dc70ac72fc8404fd077f278857e1921ebb));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x046805fe3c02a61bebd97f265bd1a8a98ac1906a8dfc3d83b975d38da1a54128), uint256(0x2b6cccc40784de010410f06e01c0fa9ba3856a202e3302f83ba58d04b8919d26));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x2d099efcde5e9d3be00491d3b5e6d58cf7da9c07e848911f3108e22c00c5b634), uint256(0x2f6c468262a1fd6b39bc7cf5eebb5602b2fb3012c19379b15a6e8d26060178ff));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x053b725416bcc2ae1bb619eef931ed7bae5db02d7bc6d0e7b062d04ad468ca04), uint256(0x2eb29ed2df8232cdcf5243e4b4a3ee3f34166661553390b269ae32c7e9e8d996));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x1db9bb39fe5efbcfac6ba5f6e709d547f4e83932e407816429f55702c2d9c96f), uint256(0x194c1003e119d2437c1c54b4185cf8b3d3b75a09c578414437eda9c2a3e483e0));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x2352f0df9b6b5402c6aeb5498141a0df068081010bffca8b2f4ba7584f683522), uint256(0x07b42404d94279b5cd1f0cc86e8914c2fbec1e04efabea989e33c9b9464c2f96));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x183ff87a2ee45c08c4ad99e08ab79da0262e5139bbbc863929cd1698f99323a1), uint256(0x17f4111519135407cbd956ecd658d72584f9318797447d81b3d906525c972231));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x2b1f92d48243cc851c43b2f0c576361be1c8362484b5085b43791ad2183a5263), uint256(0x0ea42c50268d50d4870027baa3aa06efb089e94d6e546d406c8d40cc6e38c262));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x2b98cf4d150896822c6712cb449f5f19ee388f754eeb6c37e9542cd7802a7873), uint256(0x0feb3888e19cfe2647dcc0a29630bea8bd708dfc3877af38d4b1a51d4e3fb194));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x0950ac6f548f3601c947d653f350a3a1fc56a80377e1e0277e8f7c77ff92ec9f), uint256(0x1e2f32ae903f9970e052fe626499715db7d74b7cad15f28e1e0528b387690d4f));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x2b93978eeaadca3fbe48cfb307ac3ac60c41096933ce27c7b83aff5b994afd26), uint256(0x0f97d0b83926826be948cd269b54d0ff1253347691d551cdf76d663413c265f8));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x28818bec3a9caed36e5f1eb38c635843c4249820c9b2371a7531142dc53e4d39), uint256(0x2b738b2b5ae2275de9b6cbed673cc1de1b49349a8095c6fddc1827048f619eec));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x1da69eb25238d595deef1781478c7b521b5020fc665b489d46099f1d5d1a3c1e), uint256(0x0df452a143c9f68a4480f9d4faf918d93baacf74eecaef43a747816a739294b8));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x2cb82b6c5547e420a13043928175a1a109dabd8ff2d8c6b45622ae7383b8dd26), uint256(0x13b53476a43569aa3e676d3930cca81ffe7049bbf8c9602bc15bd0d00eeb54cc));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x18627c8252b5804be2a6db4e1a39040b19d9f5848b7a858066d74fd4d8be8a2f), uint256(0x15a1e08258220e3c6acab9040c0943aa9fe9256592d41ceaa1a062453c5a1512));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x26e308764eac473c8a2e5d9a859bd5140ec2b12cef56dfc64e00e2c696de7fc9), uint256(0x2a138e5da02661802b5e8523bb66d3ffd1359b995bef3a5c125f8fc373f269cf));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x1ad0d8a7a7d2a85e7d858fbe858113c060d5dca08cf0bd46cfb64fa80e2dad3f), uint256(0x0086709757f6b6bf20254ac6fe4e7ca6828c05e14e1c945bcd3a1c7f80fda831));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x191b84591d82beeb6398501931e15aac68f7953fc7aa1165d04a46fae1d8fee0), uint256(0x03e2c3963b4402365f7e7e1047105b872a7a4b5117f48295dca971dd92fd3f08));
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
            Proof memory proof, uint[80] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](80);
        
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
