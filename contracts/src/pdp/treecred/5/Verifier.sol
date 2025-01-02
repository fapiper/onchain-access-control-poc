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
        vk.alpha = Pairing.G1Point(uint256(0x2448e6423056f6b4fda6571d3a7887e23ee98a7dd13895b057981dbaa82bb44e), uint256(0x0f943cd1453af778c67915d22efbb2463601cb203458514b676d1d571c5b5b9f));
        vk.beta = Pairing.G2Point([uint256(0x2c4a8ee88cf9189c68c4076332d5d7dc8b3adc3865f76e2a3c220f27e4dfdc83), uint256(0x03bf22dfce648a70411c001fcff844e66d17ea7eedca1a95383988f73d257437)], [uint256(0x15f3a4f480e8052a52f72a63f73202c932c86e254cf2e622f085b726e6fc9e65), uint256(0x1e1568ced059b46df482d01194d4a161726a3c58f884ba50183cce5b801f13eb)]);
        vk.gamma = Pairing.G2Point([uint256(0x26470e98bc8de86d52c57f7edd3700e90bfaa1faf79f7f7d8b04ef129a36332d), uint256(0x145b74f77b08827ced661db7bac72cbc097e4905cd21a7250de046c187d766cc)], [uint256(0x0d8d482a79eb99d7dd4fa29bd604cad1da8dbbadcf9181b14af70214c0af24a6), uint256(0x230637864f9423f593fdccad0b8cbbe59f42d5a30fb8a87194cbfa80542a6a97)]);
        vk.delta = Pairing.G2Point([uint256(0x0cc80f125f1ba7e179cd920bb90c2dec2ffded64c85e5fd62ff9765ac9935eff), uint256(0x03aa5957a5f35712f638bdbf19e7892e04eea473cecfaf836c45a7d122394ddf)], [uint256(0x2dc2ca01de102c243590c48c08cc9e0a4c468b2517db76b38748f8b684d03393), uint256(0x093a502637a55a5dadd306aa4afb03f303a0e899eea0812b8f79ecaf13c4a8d1)]);
        vk.gamma_abc = new Pairing.G1Point[](38);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x03d8f6f2a3186d3b23c45269a3bb100c75f39551a5191b1697cc50b585519879), uint256(0x289c074f0d30b23bf7ce99f29e18e0099320077455fb84b41b4f8b32283b8f07));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1f03786526124162390989e462eca2fddc698f67c337809e7821ddc8568a5b11), uint256(0x06da7c3306eb2f477c91231e1016c9585ba2784e7ad18d4225b25b53bde5dc94));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x091a2fbce323c7058508f8df4a8d2ae04da6974d9e136ccd4c6f5fbc5f5ab93e), uint256(0x134a110f4a1991518848773b9402d2bc9e55ae47d6061e80bd97d802cbde2125));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x142026b614ec31592f52a115979d744129578f62f0624dd1068d4c26c08beeb2), uint256(0x09551e2432c21dcf545e9298fbc9c7637e3926037c52731ef45271e178bade1f));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x15539bd9d36f28ad421e53ba80cfbc351918aa2446223c88b5accace8ac99784), uint256(0x112a763a1f61477f1d43b285a1a6772a015759a2089f0744f274315bca642615));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x037d878f01bbf0d5dd736325763cf13c32226f5369297d0c26b1e12ac713e2d8), uint256(0x0cca715bd610d9ac8d858345d320e8bfd356a15caab35d9b890913b3012c3cc9));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1b5def5476106c37d541debbdd7186aceaa465b878b73cf106b4c3ffea41d86c), uint256(0x016759427973dba562b86e51fe482cddba1f14686d8a6fbcc8cff6e87794829b));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x292bd1701a5549b6fa4f45408d6284d3f77711ad1b45e7778f9d8eb2ca85bd4c), uint256(0x2efaf4e21f8e63502177974ac116a9759ba4733da34b0b2435bab275bd310974));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2787b0937ba441c550172058ee88d0563429c86911419c9f5a27d17f5c5cdadc), uint256(0x150906453b2f13665e3af610859b1c218ca226b6f11aa63a26165d37bb9e5ab6));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x06368ae8a782f41114ded9d7a291f68b46275172fc35b891a58b93a6df848372), uint256(0x245b361000e5ca82a9798d53f34e1110a4e512703b1428e453279c671cf343dd));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1b5459847a184dd9b7a450be8876a1e6329a8921393baf0f35373c514df7f4e5), uint256(0x11fd28a2e741e004d4d0eb4847af3b8963751f2f7e2a5545d17e8d0d758a72d1));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x190e0cd594effd48191b422d3f826d507d18e772a4fc8aa4af9710e5cd3a763f), uint256(0x0eb1dc4001096c1cf88f39b62d84cf217e43deab1669303eda5d79784a866c59));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x21d2595b8db32e932e788646f8160344e2b0cd524e59a5b075eb7a4c07efd669), uint256(0x03cd979fe3ca09e9f3e66005d08d7396dd02c89a5e2e410a3edafaeab63b9a29));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2f3d21079a6d80a2266c5a5643a280753ef67c8ff8fab899a6d9eb0e29b9d6a5), uint256(0x08952774e2fc891ff64331675e13afd97d5a02d40c4df7023aecd946bc0c7101));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x23dd90dde19fb17f6299f866a46e0acd6d6d32cfda615484f203ff76b25eb850), uint256(0x11c0b169cf7d60a518eb405c3813c11e0580e198b44852ef178fd056a6421d5d));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x00dfcc7cf6f8afe2083a6dcc0f71e6e5bfb38b6bb0dcc3dd56823f69a1a1ab56), uint256(0x193c155c558f519eb57f8203c51d6021096ed6da9691a0eba386524d9ee911a3));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x10dd7899ddb6d6fa3840f082fc3dd2bb77087158d8cfb76514827e0519ff4c44), uint256(0x15fd8323ec2ac73cd1d72c49c222535b93e0f77cf9ba0a9d4988be9d60c119f2));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x028ac1aeab4ac5f3057f2da756f2bad66f822b68b553cc15df25806c618fe712), uint256(0x26784e8efe62822d84f8bfe718f132ee5d9b3f88388ca19cf3e135b9d3df6168));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x259318815fd69e5be59b9f839e62bff0dfff7dd2b9eaf4b767ba5373ff9ba643), uint256(0x041c719bf74f835bd2eafd3bfb7a8d0db2d3c97c1ea5608ef69bf6b7c04ff365));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x254452797e6bb474a50e06aaa20b8cbfe8bf5f0805b90a8da0681eb1c0b5aa49), uint256(0x073b5f8c41258de1723237d9010df70577256f14a00d9bd39362495b8c94986d));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x07657a60185d556e1853ace4fae66c4a59812f200613bfb18d85323ac277efeb), uint256(0x0de84e8fccd3dc0e959f7dec24d8a5ba804cc138e212d62a46d5297b40849751));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x0cd521ecbdd83ea4cc4f01abdd8897e7f9b653d8f19cf009fe3c37521ea9a9fe), uint256(0x1c0722c1210247101141d136a3838b851a0185119634dc8b47cb1070ee4493e3));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x0e789776f55780511c078fe311e676832385f26310ae16fbf5a17c09621e1173), uint256(0x0e88a17d9f90901186f0c4b8d14cb43cdfed899ed6e84f38983763c5f3a9947e));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1bbd5fda679d407f625da9f570701e36ffe2edaf4150e6526e12c501d210d0cb), uint256(0x2cc0a8f32c82dc90608102242ec4b36f1897b25f100e2a621d105ece250ac4dc));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x19e75110358af3479c5acefd0aee5cb4315b1d343742b784bc362484e7a70012), uint256(0x1c60280ba1660f0acd2226e298e9be5144a795ee5a74fd7e69b4c53f2098dfce));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x2b4b615887afbcddd72370ebc3cca58b32edc2f2df1f9000202069c63020c340), uint256(0x0d432d7bb79f1582646369eb1e8228788aedd63b2074725910ecf151a793804b));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x161adc51f36e293a42d7a846509a3d4dbd4ef02adbe81c18f1ce4d6a59a46383), uint256(0x16dc9ff0563a8ec92077d08929091240eb28a3d0f044cc686baf505fff4a6344));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x13703645eb3eaebb38fde8e53708b405918b09779af67356070824edb0d97b38), uint256(0x1126adeccffb97943defa13b43ba509ec577d1171f960c2539c64b46dabb259b));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x24615be41adb6e13dc054d29041b699d872cc8ee3d4b29489d381b0c9f65cddc), uint256(0x2cf68ac517809d9e02449fbe059aed71214e14348844c51db44bf59a864dc4c6));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x2cfc578e02b72af01d642024a4ef910796d1a68f1eabf30547719a023a4b82f1), uint256(0x019acd597a0e24e652fa527afad61a909832c9094acb32babf3b09cf310c26a9));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x026444cc546e82cf11b19951b1d67f10c7202d82fcbacfc8987328233e6d84bd), uint256(0x0068f6f08cf1d00e8d5551f7b65a08769472b85ac1eea80db6008ede12d32fed));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x062496a082b493f7c7292d8144a4e82261f0b053f1ffc9fc9978f824fdcacb0f), uint256(0x0f98e2042f418112f68912f78e2bb40bfde912cbc7bc94d8d9822149ffc99404));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x0ace316f74dcace3b4facc2be0e06fa3cd683b0c44c5cf79b43fbf20578df3c9), uint256(0x205335759124e8cf9bbfbc2b81c7ad7bee1b519149e098d1372e665f2da07624));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x0329fc43dcaed0c83d52c49807cfcded453869c2a5fd1acdcea396414ec861d1), uint256(0x29b281f9fd5ef165e23e09a5d7bd4022b067c5055150a83e93145c8bc1751acd));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x12e8d1f2b725630d74af48d45bb9bcb524f71fde60990407aad42a888fd48156), uint256(0x10b07314a1de9823a7905ad48317276b0580f6711b73ab3f3618a128e98ba9fc));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x1c46865728c443a23fbf14ad338c476301f09deea3ca8eb7e039ce5a390d3cba), uint256(0x0fa8ca16e2d834b811564cdb2a745d6ed5bb9e75128beffd8d8c563fc85bb59e));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x0320d8690c7f95672adfc369a22204574b7f1548192d3941d1f17a58f013ac47), uint256(0x1c34c3d1d35bc9a178a5a9d9bc525ff2b76685d235bab5b9490509c51d1bcc9f));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x1451a01969f19945f80fd408bd31b63a9666317620fd002d4996a2c40e215808), uint256(0x1710678455915f96048e751fc34fd9c8367fb0b878074f8e3808d4a7ed5b78ef));
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
