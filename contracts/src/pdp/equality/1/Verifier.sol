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
        vk.alpha = Pairing.G1Point(uint256(0x1801fc7623e8b2750da132fc45c8d1cc6faa0e8d407836d8253247aa683bd934), uint256(0x2d6672da9f1ca750cc06f6b5976ba83001e28988d8cfcab993dd2fc5aa815060));
        vk.beta = Pairing.G2Point([uint256(0x2b37deec12d758f80d1de0ab89a108dc0ffba0087af66c3e533478f6ee43936e), uint256(0x21a7ff3deadb01203edca5ffc094040b9561f01b079b4ac089932c5b8817d534)], [uint256(0x16762867bbd8dc0c6d08eed727c4837db91712a9d16fabaa04458010e676d567), uint256(0x000c667e398549626323568b60c1e313274b4872a0c2fa4df0170e2ed35f076e)]);
        vk.gamma = Pairing.G2Point([uint256(0x01d601db8e0027352a85ff76aefb2ca3d514a520612d649c691efdb89faf546e), uint256(0x0e96ee0c259947de27b4142d039273413a52434d3ceee063fcfd0bae6f18971f)], [uint256(0x0c427f01e9fd9650ca329dce390e66748aab0bfea04cd19699add07058494d79), uint256(0x2a37b15b985ae95d8adce10f90605658af747c0a41fe996815fce06abc07962a)]);
        vk.delta = Pairing.G2Point([uint256(0x246a47ba949fc78d8932ab02a86b282822b0e5449f244b4faa376a9679703581), uint256(0x0ceb02f2e4646da400706acf916f4558653343bf02d6459cb669bc79d403d846)], [uint256(0x2b10024d4c29c17475f8b5340d4adfe56e5e68b805c24460833539c6de6acf4b), uint256(0x089722a311982f9c948b05f5c9c7245d22abc6dd7b9456fcebedb2a13198cdb1)]);
        vk.gamma_abc = new Pairing.G1Point[](20);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0afbb236f2873663f6a3cdd6659ba095ab44108ab4651d4adb090cc19b83396b), uint256(0x29a69eff630df61d7461e1bdc3f687069ed7bc20fdff3c8c31da11398ade8173));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x13bad5c36c361baf2c4770dd230172ab6638b219fa4a73509219b8ee19d3dc1c), uint256(0x0097c58ae58ac73e709b4c96f082f8ca0d9b64081a3653fe7a1c665e795e9fff));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2bbe6fff1d5cd6bb1db8b183e7c710648781fb44a0b8bf2af995a4088d5ddf3d), uint256(0x0a770e9ca2c87aab71e39ad24b565763322266125951c9226eb4a59878c7c152));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x04e118fffa266235b9463407460c5e09e5e6a71b945b598493728f26cc333fd6), uint256(0x2652058456c813bcc9b96d7bd52e85a18b2e52dc74aa13b16a67491a100aac91));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x101f302a74e6c5274d8b9b719a4a3b5bedd287114ad73072959ee9fff295212a), uint256(0x24b5a2a6b2877024bda59e520b692e7a4c661281a323942c5ac43bd8a685f979));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0ccc8fa298bec45f7ba8e1c7e729b065a031e6af2c3d0fd2589f42136126308f), uint256(0x115b2f4518a68a7706186f830dbfd29e61d1cebcc02a1e959826036031839cee));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x30030dee37282c7871462831e13324cdded5b155201e1324c92c4d1a53d371b1), uint256(0x2739095f98a17d9f91a1c37fdea40b7d346410b6160e2fc68d57b17e1bb10684));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x083bd6dba9cc04a4950cb1b50f4f3800133333639bb176c70c3b51896396ed06), uint256(0x0db6785393c8a4376383a685073b6d322aadeb653c04e4ddcd8bfbc6b221e156));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x09e03ade70804f30fa82b92ee9eda71bd7ab723fab6288921cffcae2b4ac1d49), uint256(0x28c239a4703c477ff0d88cb662088df5d8978fde57aefa9a20a2c7c3c890dd97));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x09352ea31b4575839e210c63d430eb2c45a357ffb2ee4c5a3ae8fe337bfbd6be), uint256(0x08323d6ad32d78f21584d14c6826457575ed3664a8f6e8023a5b294719dee37d));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x291307606525fe679dd88fe1f8d20abeeaf7d8a42d1589745ed0aeff63dde6c9), uint256(0x116312c10f2ad42225661cd061f3f90bce0aeff9da4a67fc15f02e426535b193));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0fd0cc14f8d6ea532c1f994e808642ecefd61d3ab28b0265efe564770bcb701c), uint256(0x0df3709d0c78a0e104aa2ab4490e76d1efeb25db7fbfdaefe0c82d0d2fa8d73f));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x30549163d657402dff1e946027cf6ca2fb36a0be740f335ab57e73e6e8fdd3d6), uint256(0x026121a1ca5094eec02be81a7f70d5562676d7571124b06ac7f0a820c1020fc1));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x073913d6c7cc4e1fab47b98f156483dacd84128297046b8deb3d4a7459fe81c9), uint256(0x1a2349f5a8aba77027ca72f90ef2716d1526f77c2f05b6c122f145c7a1b015bc));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x27fb4b152be32278828021185c9f70f356423502834b88aab136666625a76912), uint256(0x20a23d3f2fa2bfefdac3394aca91f4b3cef45e8c17e3bd4ed36e969931d09b06));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x184fc1a22513ea76a622adb44b269d56f929acfe49c3672bdea07d3491819b5b), uint256(0x2ea7daf5f0f040caaa79da20737d686294c126a9a96137ff3e583d273cc0252a));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x17387093f68bff0d163d24722688ed4f4fe7a4aaac1d2def50441cb23a4adc91), uint256(0x2164730fb4614aec1e8bc5031fac2337d57ac4cee27d79d89161e0031868e7eb));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0d42039a4e8cf0e4f846c65c41ff7a2aa0ad4451fe5b287fc0d393d4d4e56fbb), uint256(0x19de13b2468c9cab15b5ec53cdaa88dbe6b7f68492b37ae762deae89f4a901f5));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x26af9c0e24accc75354e7e38b6775ee5f2017207532f531407c9843d1a852c74), uint256(0x22019cd165f95b17614d463dff733460d1cf2a83119296d88c1746fe706490e3));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2e1dcc2a5552d09df8d5a48ae54b9fb89b69c0f018cade4c56714188966cc6ca), uint256(0x2d36d3c5a432a8c45d750cb6a42c9a7b537b84bb6daacaac83658e60595e664e));
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
            Proof memory proof, uint[19] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](19);
        
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
