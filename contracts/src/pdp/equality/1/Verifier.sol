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
        vk.alpha = Pairing.G1Point(uint256(0x0b6ac99be896849a42190ecc2668edf6de24db1b1a723ae44f958000b2fe6458), uint256(0x203362fc8378958b2c00d19744d1e67c0625b3e4d5674daba2fb38a8c370211d));
        vk.beta = Pairing.G2Point([uint256(0x04a895aa9acb7cae4b62d461f562dc3fb238210a40f5f6771de13e94db9d991e), uint256(0x2fbbe12040f12ae3328749069919305974349929febd947d24afe294445d104c)], [uint256(0x27025178c72ea58ce39937cebcec74b09edafb1e2cfb738db9c0846558a400d9), uint256(0x180fb8b49f26c0d07bc1a25025be86b3ebd765dec893cdd0b20b9accfb8f318d)]);
        vk.gamma = Pairing.G2Point([uint256(0x194e09458a2af9bd3a1d6f325a66a88296b727e41aed4d3bff072efb8ad8384e), uint256(0x1ab5b13b38831957aa77ffc2cfc12dba16d2006d5218d6d316568f9c79049a96)], [uint256(0x2a33567e6ab58daac17539248872ad26465e5070746d077a12c3653589e7c4cd), uint256(0x2b9aa8ca18b18102b5c42f4726955e1674fbae84923b0e55bc02e1870d4e2c8d)]);
        vk.delta = Pairing.G2Point([uint256(0x1163e5e0e58eba892cd6d6a5a57b87c9b98f39ccf29167b25800e5fc4861f3ac), uint256(0x15dd5f2c5dae326bdd04172ea8d0e15dc4f607fcee000ceb49d44bd7a7e05720)], [uint256(0x20801db0954a98c4fc7acda112504597385aa1663bf9d152a352f5dbe6079287), uint256(0x1a81a5387e272b0f55656b4938fbcac826a1f47a35efc050603d3f320abde6c5)]);
        vk.gamma_abc = new Pairing.G1Point[](33);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1565e9eef9deadad7a1c177737dfbd437dbec7954e74b51550e26dbce9765f1f), uint256(0x2cd7231296a51a3b70444a2e71b7ef4b083e723df7bf58eca93e47936e057581));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x02056a6cd4ecb803faa5390bbfec6f494594b10d48d54993ad494377324eca1c), uint256(0x19b3a9a427e8f47b8cb2f2adb8f2f54ecae35868bece7845998f145db84f38c2));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x16a0fe1ea76cded70e19e8d24ab7e0ce5e717db1b53d0bca8a7dbe8314885885), uint256(0x29f3082545a27ca9a3be4173ff30681f5e32f83e118d0e57a6fbb444063c9b13));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0a87978bfccf2b2afeeaed0c82034641288fdddadecb23b71a5d2a167c57df2a), uint256(0x1bc56b21576ff988786d3fb76796ad28f41ced2d2163e1622d91c6041d56da29));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2aaebb5f9cb4b9d2a8d5a57eb854832fa15c635fbbf48ea1f33e00ec58c30b12), uint256(0x2a763d6067a89934b30882eaf84c6c2797c153b6851ab7188e06cbc33898ce33));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x27e7cea47f2734a65bb104b54cdeefa30674a7b1766c19bf826b9e48ec1a207c), uint256(0x1f3398d7d941550ccf0c0c73c7c1c9fb1c28c88c72384754d7a43b6532d4d954));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1ff78d5915caae888cd89fd5f5eaf677f0884fe3820a90ad15e3dd31a4159aac), uint256(0x06ecc12e58b0dccf8aaef4d65ce2454a0da636ef592deaeb2b15a6bf68023133));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x265d7ef377efba1c89d613dad3aec431681fcab5cced611faa9e761760c14833), uint256(0x15fd6d8409640dbf2d550868fb55169a4244a503c38e47c36d7d315edae9bcb3));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0f7077350f73f4511b54d779ecd70a9e20dc2a740890f40773f862aafeaff644), uint256(0x15089cf71d6b8bfba0516e6edd91baa44fbdb12c42f919d5af7b61761c7593e4));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x16280950a3bdfbda60fb543a387b421e66ced69abafa97623254d22c30b1930c), uint256(0x1837275e82c8612d9f1b0fccbf65f94f1f44a584b2f03737a3b91662959d3eee));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1c25497e2f697e7df99ea492ac3465da842f7e01f6ba74244818f4831abe081e), uint256(0x14b464d41d091c3ed9ec9e481668d4ddedbd6d9fd80621f038b4add2daffbce2));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x164f4ec4ac4946bbd4cf479a667129b078ec5f68db5eafeaddb18783d9d5a99f), uint256(0x03cc466441ea3df9347a55b756be9f01011673676a1cb0a4f1094c46ae30cef7));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x22032db2d3d45438e76e00c5f4671d149d496f660e7630ca2baeea41bad69469), uint256(0x087f5d84aee2fddf063417cd261be876b4de3f89f4b744c3dc3bbf44192b86dd));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1e83819fdf175ad6c3379827d1c3f9356f87f7f7f266387fb70cc98aa8a7658e), uint256(0x286b5f03c2e1af7497871026dc7b9458f3c15fe4066d5a3e0e1db4502c68ae9b));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x28b1175e4f9ecb1e0b02db4fd2943069bd8acc7582e414645f3bf30c28e72ccf), uint256(0x0ee1b2fc6099b481043c39ac68cd5a199d944d783ec132b7a1c300ea33b5db26));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x246126c7a068c028670559debe868aa52b3364f740a7a4ad1b68e007d55207e9), uint256(0x1d747d8b072985efdb692fb6fafa66320ac5bc4afb65d9cdd328c7589cef4ca7));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x00b2e743ba0f75b11318b01c6fb5ac82fde5744caa8b788a29fe2a0f73685b74), uint256(0x17b4308cb2ad7941273aae54f49a2b5c18928c67ef4e3d153e837a523db664d9));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x28caebb0d6db0d209d015f61d29646dcb412691579b35c91b40d441df9278c7d), uint256(0x19fb391233024cbf38f6d27feae2bf7c6c3bea6b724a0246e1be5e35689009d8));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1437d733a8c05590ed440971e081a0209da4697c29d254af383314cc205607ed), uint256(0x0ea4ee59fcfe685551c11ef187d8b8da587a715ff4acdc9e9ed9214668c10907));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1cf145ed112e5953bdc7e14a0e3c0048a5c4f02586455af1a6f5596c1d8f919b), uint256(0x0d3719825f3c62a80b6e4ae0cd894ddffa54139fd0841c5413afbf945f4bf27d));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x26db0d684ab3e8ac53bd76a8fac1d10e157f8f638f5dfa5427b5abd1b9964ba5), uint256(0x05c05f245a5710ba803e8479191fc44a91ebcc5bb4e2538ef001452670c19dea));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x2513cc7bdab83aae84ba18d97c1a1b582a3fb95baf9a833d88b3ca93937f45ae), uint256(0x2108132e14c12cc88f347b05ca0ef358b0d0d3f1931325eaf6b0235d83a5ccd1));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2ce36424e17959a3c29f323886577a71924695c3086f76d8bbc1af4eccab5fed), uint256(0x0bccb58f313305eb6d5e570434a6fcc89e0f34683876d285467cbb79ed75c5f8));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2545a3470c89c259657a6cccc8b63d1ff8815b12d05de8233b41ba5cacddc3fc), uint256(0x06a5c3d50b46d61ece5814ac0e5ed77f8ce4ea1e3326fb3011e20ec8b31b8894));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x056ac15e5ffd876de108d7af7783c3300b35e0b43aea506f62c07839a345747d), uint256(0x030c5199393567101c519c86d9378eb003db2c75b275611d3b2236352f3fbea1));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x157be3f2c5151b8d6fc016913cbe762ece6849626f596bb8b443259ee8bfe8b7), uint256(0x08ecf736acaa9ad631f3a54da491ca88ceffbb4f0488f0d8f60f70c2822c8b21));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x0826b7e187adeee6f98f98a8135a09c7621e80a0933d66d2a8faec82738027c8), uint256(0x13bd1eaf4db075967843a9cdd9e0cfc69d543a2f6273cb33d945de03d89bef59));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x1f4fe1624048c95e9b899fda57f7f65fc5a2bd392d2e83da0503e362a6938005), uint256(0x21964041f27c5b9af51b1bc3066a3e5f68d621fae399ba6cd46b6af5c3ef75e9));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x1a679a109c67f6ae5bde4e48c2a0747c9071cbcce8302af6b715532d859d51bc), uint256(0x19a1417fd5379b44b282188293f6402509206a7c123851370b605e24538ce55c));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x1b6ed73d52b5022adc1a6993fc59e5036c0831f6ae76551ad373c17928b19dee), uint256(0x2ac594e6ed5d28c140415260ea8039ff7dc0054dea1c4bf795002685242f9e33));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x02d4f786ff347ef7c21477758a825f67fc0bb4cf2eced2e55cb266d703a95a20), uint256(0x05589f0efedfbc1acaf6e99065c0cb73abe58e5a572ac36b85eb04b6a89a58c5));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x26c0caa33f42a6ffc9e177e753b26a35230281706bcb0de7c474cdf61db698c2), uint256(0x05469ed04a6ff544932e9257756f8014f155e74ea998f0228e9c4518eb991eeb));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x01d314cc1a25a8ec0dc7c77d37b95cc75acea8259c25ef5df8e9787f975a778b), uint256(0x1d3f698414247de5c04a04de66e483dce85fc17b2d1d59acf7b18aaf84509cc7));
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
            Proof memory proof, uint[32] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](32);
        
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
