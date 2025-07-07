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
        vk.alpha = Pairing.G1Point(uint256(0x2409cc237a19531b7393654cee9882d9e7bf401916bd084265f82a01f67b22ab), uint256(0x2a28df3c869da29d42d9d685e27f4b205503652364536cf60ce87541c4b0f61f));
        vk.beta = Pairing.G2Point([uint256(0x012e43fdc9bfa52e3fc66b94ee3648c4eea957b2d7a425091025c2c3f01902b8), uint256(0x048ee3f5b2e20460815d2ed520450d6b5dac630ccd3cba277929f45c2c8b32f4)], [uint256(0x2e88d8c24687eb18dce7bff68757c4d1f2849e0c3d8c75f81c9ba1aba9737ab9), uint256(0x2a424cd56b8c40c7800c47fffd3c1be6da20b6c2002bead10ec1e88b567e7477)]);
        vk.gamma = Pairing.G2Point([uint256(0x2157fa933a398d5cbdc456d736da8ece91f5b901913a53a5f2783fbd4849ab23), uint256(0x1fd2883dc6523d1fce7bd9edb855404dd4745b0613626031073e72d60437eede)], [uint256(0x08b2748a066207f7cef2f056e21fdc69689984c2a358efffc1b80502805224a5), uint256(0x2054d7ec32dbf059d441f93337bfa329194cff018df792351bffea33b281f483)]);
        vk.delta = Pairing.G2Point([uint256(0x072030b661f0d7eb4c8c4dd52d2585420d8f5b9c2901d0c5a237947ba6b52f3f), uint256(0x0573ff0673a464bbc1282251f498d218fe1288b53356335c184bb4fa3037fbf0)], [uint256(0x070789be8f81a1f5be4441b6e144b41d7790d6c5ddbb37418f45844e184ee483), uint256(0x03344f5c403d8b2d677425f4ae1df86be62678a3cd94836c507d800bbf6c978f)]);
        vk.gamma_abc = new Pairing.G1Point[](32);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x27d8f9fb60f620544227b3480bcb0f0eaa695030345e78185fdd6036eb0da1c7), uint256(0x13bea643e460901f74d22814d2f43f72115cf87617fd6c89a6a3fab47981ccfd));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2157bb6788b0ce70095acea68312b075ca3e5bd2bed24b9603118ba5c86b5614), uint256(0x1ac20e600cd35bf4ce5a43ee001f041ddca5caad8ccbf0f5bb05a4429e3c3209));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2703b742d3a6d4292f7c01c9cb74771dea7caa9adfed53ded9b9ef22b41a7dbe), uint256(0x246986522cedf9dbccafefc8a2831f872ea15c810011685f94f9abd2c4109cb8));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x18d86c8c5221d4f4a7e49e2ad94fa6957095bd4d2fe3c09a6e4b2b0da6c78b9a), uint256(0x0138650be7601ea5ca9f2ea452946018466322d8479688ea47b3d33503e4ff43));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x074315985334ee5290ad7917b44d113f1dbce8edce10cea50ddbc9c6366a38e5), uint256(0x25df53aa4582c3fac32a3c2a7b7961e2cb6ec8af527d6ef15b9b44cffaf8d4b7));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0728406ab9145b011add620c3652e739b01182c472a3e3803c1ef5bbfec4c62b), uint256(0x0b03427037fc1e7a4b04d07e30323abf102e71e5fff794883730344398a43162));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x06e9ec748fac36cfc05ddb8f591c3a63aa4073c398529a3ef69978358a6e1fe3), uint256(0x2a05a1758cc243a8521b200b6763d28cc73cec9453433418c930386668615a80));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x300af0e874906782fa6e0e08a612d7d376d5283028dc630d15fad9f371607521), uint256(0x148652c204b8d95f4ea72fcb3b61b9436b021c90c5e680c22c3d839ad528b8e2));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0fb396dd89eff886a5ed9dd41428e4b4bc73d30eff412472e712a03f7299685c), uint256(0x0adc7b70890d6f9976e198621393f65f05b6c5564f7b0f51308525de1597aa85));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2d798feb6c4fa403706327e270eee5b2b0d4abe26dd912fc11a9f4eb6deef0b8), uint256(0x2ac5ed2d7d94f2400318fc2bbe773be2b391c6d62cd3069c45fce26c00168385));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0fb740be1152cfff7606478d27d7257d5dbd848e57e410a811bee359e60c3863), uint256(0x2a53bab4c5f04c84311da555846cb393dc00ec36116a0825f375d368bae62dbe));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0e151d1007c483109af6cb51acac62cb6006ce4e10d7fcd565b6cb62850ecd67), uint256(0x0a101df12685ba950fb6f4afc0b4717d10eabe214d3aea95af241ef8560c4768));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x125ec611258fbb6b689e316bdc8bf856dac19c0325edcabd7ca31cc65bd2ceda), uint256(0x26510b59fce1cecd67579061bd15d669480241237ef3957b80f8ee86b026f212));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x078dd192756f7269dfd4984d2407dbf153f0efa4e969c95fb0183eeba511c1c0), uint256(0x19663dc21ed2d12498b078d1307546ab3846dbd580b20c0ac4ba3400f343825c));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2a3364f704b3204781dd08c59e1d905117536e10eb5cba441984ca7e879daa3c), uint256(0x1c746cc10345ca09737de6cdb801268eaf5fee173e58519c226cbf7b0e37f59f));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x20fea009bee5618ed90b1443af910eef016898502c19de6e2ef4ae43d1fadf29), uint256(0x2166d8f77f85e65259783a5ec72eac521affece7c55f91cd2cc58b1af326f3b6));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x060735d9e50d28d3273256669fada03c601c3ba75f84a4ee3c2e152258d406a8), uint256(0x16e30e0f3b33dd0656e76ef268dda937c036199691bfe4b1955ed91362d7851b));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x15c508890614de4c9449166f2d25ea9ad1a8e432cc15920c77f058d5f1e49097), uint256(0x16a94789781c87d4adc08ed72aa11a9f1937e84866d2e08dbdf34716066559b1));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1936bc07948f81ab905357d26555e3d6a50eb0fa36ababa0bc6a9f27c5f6be62), uint256(0x21b75d0cdd514a9823df2f5d701cde94c37f5c6865aa28f22b797ed186d7af94));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2cfda8d49648f28c802d5acbd4972949afa06ab1d9a476452bcde9884baa7f30), uint256(0x1224ea9d877a8e8708c1fb4a22df91c3d4e10369a6e7a986979e549663ff052a));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x155cb29329c7ee0c21582d85c0e82fbf538b36ad5c84f9a5611191d6c8506614), uint256(0x19dd6383caf59d877ae58348b41e7024cb6d382182ec2fb87d2eb55610b15933));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1cbe1e305d8e88b739afcb3cb599ebde02d9f200d7ab41fa057c89a6e01d1523), uint256(0x25c301490f2480d27791db9c95699b68a5a58bd9bda52d909fe4abbd7eda9a0e));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x025416cf7ed53fb566319ad9e4cc1aa2107c9103dfb4942c4fa41fa4dd614e28), uint256(0x0fbc18c99c7c63d1d6184d98f823e8564a990cbcd9326383af73e6216c673a16));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2b3f48a8660fe36be7768eac5314407b835f8e1b6731614d8789de8ab3f8fe62), uint256(0x1d4062bfab069b52db1fb11bc47b396bf505602c5ccf95613de36795e69f8dfc));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x083710b509bfc23451e5b67e14085a90d50bd8c9d15b2cef884f467e6763e1c6), uint256(0x29122d1f302ef86b85acd439522d815d81afc94d871a0aa3ecbadec416181e00));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x0176f9866c8ce1e814808a67e5a885accddfb27c7e3c7e459328a78765067470), uint256(0x23427493474ec938e06fe6b1160b79d8851ebdc40626f5d3b2ac0e9e06d02a80));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x0c93cd41f6f73cc14a256140b46b573721a60365aca63e2dbc88de19ddf878e4), uint256(0x23b2887b342a154bf3f23003733972bac74d6eef9d4bb3fd3a767ac1bf189314));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x210ef9e1d275e9e9e0994921ffd275b604a378ee86f06272c98c6a7198fa79bd), uint256(0x0bee6e9dfcd0bca4243a83cb547d777087a70f17f6acc86510f3be964fcbf0ac));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x02749c250b48da11a386608849680abccf0c1e8edff70a82dc7a43b13099b11c), uint256(0x128777bb8ab8c760d52d2c0eb80e969b22fd479519489f61336dc98b5cb4d2b9));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x05c7a0d2f518d8a96de71fa9bdb44b52d8508b2e1ebd836acb759e4260fdaf2c), uint256(0x1e42d90ffde44c0028efeda45d5f50c578ddeac06d314da78fca07a1db80d9b1));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x0790fd6f5d090b80291e68f308265df529892695f8ac6354a34b3d4de782680c), uint256(0x2e6c162a1fd594db4f0dda6337ae7d3fab2a2111a87079c5eb2b555176894248));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x1a82640c09732fa36b7a5ee8aae5e8fd6dd8531622834a529325be8df9c8e136), uint256(0x2359dffbcd7b93e68a33f44c4383a97d2f92cf896c4ace19e87b2d6bec9e15e9));
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
            Proof memory proof, uint[31] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](31);
        
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
