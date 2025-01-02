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
        vk.alpha = Pairing.G1Point(uint256(0x07e86a8c39e0aa6a59ad147c64bde66cc06d2244eaaec15a7f040a419e4a739b), uint256(0x0c38428897abd866b7fbd41f903aa1b7aa2b040d241ff3743fdd7f9c0d2d223c));
        vk.beta = Pairing.G2Point([uint256(0x0cb40234f5941b20e66cfc56e0864113ce00c73f5bebad808fe6d8cc79068374), uint256(0x0cea1f347df9fe00c5e1fd2d007e11f3b8c876419d13511e0209f5ff94a595f3)], [uint256(0x07eaa34b5d2d486c599f9aa0e09623bc5e70e069071a6cb70ebf6fc5c4e93cba), uint256(0x100ca53464debef0486eb7a69e9e796a9fc58da12766633b62780461deedfbf0)]);
        vk.gamma = Pairing.G2Point([uint256(0x1c4e4dd582eb5d1e28de057c0f22722996f41cb5fe135c967bbe78ac391bb5bb), uint256(0x01ab2144878b9a5ed71d36b00ce435c86592b13e3cf402833d16b3a8fea15195)], [uint256(0x155edd2c1ecb8f3b17caa385051e5a428f3afd80398475ce8469873b4fd486aa), uint256(0x14fb72813e2048f9cfeba266684f4a2131fad8c783d07d3cb81f2d8e795e79eb)]);
        vk.delta = Pairing.G2Point([uint256(0x2e10edb65a9fe7c4d5e91b8c405fb30348142307548c797e86d79c72dae2134a), uint256(0x070b00dc9499521b5325dbf6ad239edb2f3aa73bab7d824e1f87e8dfd4e5d5c0)], [uint256(0x06434abe0365253a6d1e006e2a0f21dc7191b0bd74bb723482f27392b473c2eb), uint256(0x21aeb788b5d617a6a4c9a041c583e701739750ab4408540e04cf371836b36431)]);
        vk.gamma_abc = new Pairing.G1Point[](32);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0c0b166acaf57937eea7d25c55adbf0a50688b3ed9331c1dfebe477c8c4103c5), uint256(0x1f73a34d3f15455836bd2330d82164321b24f38b31bba5b16f54eafd0efc60d3));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2cc3f3715fb3627a85c08f6387bf4addbda6568f26775faa894028ce2e36bf48), uint256(0x09750a2c02be1ae51cf9121ac84ad385747f9949a2cc58b8390f9a0cba2159a5));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0ac226b2b7c6e633eff875c2e7d53098e5af73fd8e2da42636f36d844cb3b3f7), uint256(0x271ed6dad13d6c0702fc98690563b8844a7464836da09fd4ff6db080df937a02));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1c449206f6f1721447754d646c7ecad326f949a578875fc856129c58e5549292), uint256(0x10cd8fc61ecf713b5dd8f30692b1b7e2be5049428170b96163ed755a71e1b432));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x269da37a3593d0824838cc85872d17a746c77c7aa6fa419d36dc2e2bd540131a), uint256(0x2a0056bf81bc28a7a954e21bc986335858dc1784ea2b255eb57f7ef3c8fc39c1));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2b7e57df3a05c6c44e077bb7dd9561e807377835cc0d959885dc7dca126d6edf), uint256(0x1997e3bec87ec0aa0b78d60de244208a5e1d2e72cf3eddee3601f0bdd10927aa));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1c6cd1097a566f65b42c047d2f2addf212347e682532f2e711cce4a9487defb7), uint256(0x0a70f33a66c71be3828b58f8d2bf8fcb85036b5e360bcfd2ff1208ab58871495));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1e690f3719c7492da112f99e8806271afd8dc9ab599fefb5f8c0bf54081dada9), uint256(0x1e2f38dce4ef34da2dcbdc03d5f1ab91fbbbed0f14c54cc1c95e3c5db9433efb));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0907247a9fc47a9baddbf19d366f833cda06bceeeeeabd1a4011f836f5adb778), uint256(0x0f35edc231a091a0304168f1b99e156486beded0514eca4d3792f8d752ae36fc));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0ad4c293ce0c358913e5c5e2d6773e369ea0fc2a19d0986a69b4913f20c03fe4), uint256(0x256272e59a7cc95e22609f1f560201ca41e07d830902df48625bdee5ddbaa64e));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x27a965a6f2fd308621b4adac12ad0f511b6f85957e7bf5d13f4b0b7452d3e088), uint256(0x08eb7748393407b86cf66a3f488a858c971206ab6189346abd08ae4d50724d6e));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x12d6e14393d08e0f2153f6700ecc6f8c45cd6b7d63a4087f95c41f2cc20763ee), uint256(0x14a19e1eadb50e1cec2ee9f87d213dde05beb441b0776aadfae4e881a2888b5e));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2c477994677fe923678b29e8f38c2af361656115f41ff2c215f352d86b3e6e3b), uint256(0x03061042ce0e0b58634d931cd38c184be1f06c1d6ec8bc3265ef88e938f1712f));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x06f419d8c83bbb537a6e61b53511d70b840ccb179460523bc90aeaefa1f8ed1d), uint256(0x03bd727d63a87bac0c27955f7b6da3c462685547a04fff469cc840f59dbc8c03));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1adc00421158a6f3a09cd9f45be878954b932ff9db9a6e46feed5021222dbc74), uint256(0x10b1f73a6ddc80a62e7f9126afcf062be1f1076156acccc532936a4423881b30));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x17209b2d4a24c723aa7aecd2003d5ff5a55a6080297145eb493efa496e3194ed), uint256(0x000de3c049391e49c72ec246a1f8c637908684ee2879c4948b1764882e1062db));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x089d4676ed4c8e1b8825b88ab5d14353bbf59437e34374bb6feb82c15b43c560), uint256(0x19ad8444c71a9dc4059c1759114e5fbd135ecb6d899ac580a978da77bae8d00c));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2ab53138d1f5248413ecc336feba5b9a3135f687f6768aa3f37f1a577e579b5b), uint256(0x1eca9bfdf0f9f24c6aed56e661cdf176d773d6a7046578f1001e651d4e67842b));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x14e86fe72f46803a70ab30007a31f60c46956aba18d5700027e91c9861ccf4fb), uint256(0x2c576dd5b55118b0705fa57e69a024e4018fa4f0554484ec08c94a5f00e3d2be));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2c11f732ad0717093ea41de17bd6edb5c3d4512665d08a193b7d31ff0d540b62), uint256(0x2a6a7462a4fedfd1d8391eae18763de19504d9bbac83b365dc27918f78cb42e8));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x12064060ab4f6e4828eba68599da390c7987d823462514ea28bfccd9e89516be), uint256(0x057ab58e4ac7df658efb6c35cbe443a092e969586be8f87fe05485576dd50ad1));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x04b3ee36d46ecf31e4b38a878748a4957aff5048399178f1ad9f9d0c56face9a), uint256(0x1b670d926cb3826ff3c0940c0119d6aabddc18e5fa4fc15446ee976b3dd5d36a));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x1b98fd8b0335fa7f5e0c32ed10aa1cbc385bd68957394ca3b73b654e2be6d66c), uint256(0x1395186f538d20d92177535260e553c51f01ea78fcb395ee2a67df3fcbffc785));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1a01aaa3b89041c81b93fa128f5292f7d03eb758dcef505494ee009fa6271725), uint256(0x16a94d866ee2eda62dda97a50bb496884e4e66c3f7c7476c63ae351929b2eb53));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x2af54c18b1e8c7706f87f22a287c3b64de9d0d8b64096f39c73d694db7f31fe0), uint256(0x0ef387a1c53d39ccb3f26456b93564f1d3f2d52b0373e1f7440264860ef88691));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x196c1eebec14ff6cdad2baac05f367ce90f9587f64123863ed1a887eefced0ac), uint256(0x10acf345db622b33ab91a1da9437fa4e09c0f6aa91e7798d74d2fd01ca376bb1));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x0e18abd5bd617bea931d6685d30233ee594ace89c5a54a4aa96a8a6590494806), uint256(0x1e0c98ee949f1c66e02a2d324e7f606750fa2f36de1b2a4b4193edb8642572f4));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x0092673df4edb505747d389c23b006bb1bad602c456e81b0d73b9a1619289268), uint256(0x2970a0422c30639c4551b5ced0ce0cf4b5750b0feddc1038a827a61b6408feb7));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x190c1f68f64f162617855b40c43e8ca341bff4cf66742eb0049601425a2049d5), uint256(0x048f540ab4d177151378f5a8095bf387037e0b600712d55cb81e7917884a9f57));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x2080cdb633bec9abfb9a186cf6e76018469e55170a1f3f9181e69d2ec8caa84d), uint256(0x1dc251afda392254c6e2f77842681002ebc594ab4e7a29ab064eb152e1bcd3cc));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x164832163f3de01b5cc038db9df906cb463faf4c46edd017dea74f14d3c334e1), uint256(0x2008ed9b95b075713f350228af9dc793a10415ceea9032379f153afe2b5aa4ad));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x0645c9ec9a9eddbc0193f48b0aa3929f5581526c7f4dae5f0f9399c6b2afd543), uint256(0x2a4871ae3dd15e14949449b66dfc7f6bf67b7f549dad7aa73723f93c00b9afbc));
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
