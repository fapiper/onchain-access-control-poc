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
        vk.alpha = Pairing.G1Point(uint256(0x1bf025308dd887750ee73005303918973306720d672d744363aa07e3b76c36e0), uint256(0x20db10f6691b7944a1f9ae4d5706bdcbf0d84bfc85af0c15f11341ccae7553ff));
        vk.beta = Pairing.G2Point([uint256(0x1e40303b44053a44a839300ac48b6b930a3ba66d7c3f20847ee362a51797cdcc), uint256(0x002c6f138413ebb527362a0b52cad9cec7ee05700966547b6b214dc9dff5ed8b)], [uint256(0x0a3afee5202fd3c27a4586b26289aade12fd94225e31f8c6f8e216481ffaaecc), uint256(0x075615ce891a2d155ce781a28795123a72ef2b5b45b8d73f4f37da80f24b0532)]);
        vk.gamma = Pairing.G2Point([uint256(0x2b600ce9538b94fa4dccb4eefd8b434f8389da9c94697cd9ee40223e39ef307d), uint256(0x053e0c2a1dcf986d111edee6f4aa9f8d0263aca59ef6f35937154712300728f9)], [uint256(0x2c6956dddb533a80100388cf35e9650083a6615826883b10dc441ccb00b7824a), uint256(0x0c630c1f18be2c0070ef4e4cdc2fb7e09267f6de49a4231b991f07f09660419e)]);
        vk.delta = Pairing.G2Point([uint256(0x2ce60deec21564717c6681502ae99b82b3f9ea9fbe3ccba9c82e1b1db1233d03), uint256(0x11f4c2b2f8d3a8d9d7111b1127c9d53659fba80cee1e11e766ba1b83a662c090)], [uint256(0x20d29fa0c699bb1206dd4da1035a42236c23e822ac8cda67d1938c03412745c9), uint256(0x1ae97d938b2cafe9f6c15dfb8d6d955d705bfc9f6d3b537640cdf2b2331aea1f)]);
        vk.gamma_abc = new Pairing.G1Point[](32);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1ea6bdf33957da76538fe59713a0abcaec2232e0319c00f9662025b3425d14e2), uint256(0x2ac594a20d63e432a51d21e4bf81fc2f04813bc34047f62cb9ecda3b31733f40));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x17b28a548bb45f6fb7cc26f0abd55cf732bdbed8c5dd09782e031aabb552e6b4), uint256(0x1f911a359fd54096e25145cc4f066512c853bf6ce71a640682b3c542b17b8ca0));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x12d91f846a60f4b5a4b5a3823d54360b738b3ed0bb4da4e6e384c1f503b1278b), uint256(0x2b405ffe538323f432c6fc2b99b6d19aac808a0edac901a0cad5f98e4c8a8113));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x237097bd79df951b4da0ea401b3785da97297178601f41285bf827fd109cc2da), uint256(0x0734dd2187988fe996fb3aa2b783934da0723cfb887bcc684f128b4b4a98ccd5));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0ea17f68fdb215d7e4d82389295c44a409d246b91008d8e7903c2f41f0f44f15), uint256(0x1f97676d5b81faa9c817784fc22875fa0ddb8a48f6147fc3efa69e0f69239e6c));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x09124662ee8f7f9a1b945ec6ca4695ebac4d6de7639aaaa97829fd077ee346ee), uint256(0x0a6fc4a0d5b2caf57cde69bdd4d806b69911768bcc8e95fce76d106717f915f7));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x22c6de340c0e17ffc8bdf541037991e99f34e5d9aa6865638fb6207d2b874efd), uint256(0x252191a1d6fa520a0d1d4bb9a2b35803d4425690a73adf8570c2f4018da0e478));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1d899066cb53b74d18f16c5924136ca0213f9545c3ef41722083b41bca3ed1e1), uint256(0x07fc7ca30b3f20a64621f01f5755a9d1668c165eabe7a3977a37c71d82fb50b0));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x018db912aa85e332edb95279a3e634a55d00f2779e17db5f168ac9b4dd6c40ce), uint256(0x11564d01e5eff64416a8a571a7d2ddc59a1a6dbce81f0c810abdfe5f62cea61f));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x240289c4aa5fd9fa05917090344a2252c8376bcbbac7beffda237efafb589593), uint256(0x2c925fad261db0f4fdd79678bf80f091b384979fa40e53c8ccd5fa222f9f2e6c));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x23fd0c48f288338ad939cf729812dfbcfd279a51c13b1ff22d5e974fcc4f7896), uint256(0x128e0c813c6234080c2218baff5f2a8ae3f5921ef711ff87c51dc18b16fdf566));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0efdf8441a04406e9b8056c17d603ac63a4f33c74b6ef0622a4e01f787f1d996), uint256(0x29ca200d347a9095f162467fc231b8739db7a079aa1ad0bcec3b060382241921));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1e5b36a58afface46b7862ef77ba00f3e9c356257d3e41396ff15dbd8ef4e7c9), uint256(0x21d7be612a5c1b08938c83d5cf5080a9265a5d18025fc7d905cea67662bdf9c1));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1f0e9ae62767a65fa04e36381978df496f86fed1a4ed8237721c7c4c828fdc94), uint256(0x235f88521ef1f5417c8339ce2823c455f83831ee308acf422573e946a0def167));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0f90fc5fbc9d248da5a28ed7214f7f328e7d18d01e202df362480404d048dd58), uint256(0x23f5f47776f7996914bc1e16e48ab8b3b25dc60bc5da356e59e80b51aa9a4a37));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0aaa0738655df2744598a4508fc627636145e4f4930ee90ce8971b40eef6b63e), uint256(0x0aa4efbfdf5b409870ebee2d7f24e03813cf197c801f8e21f97b63b0d122b860));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x17a00c8ea985a96aa95d771530dfeed9863782053f246db7b36a8f387d4277f2), uint256(0x14188e2dc61f9cabb15ef391ee07bdb6f5c89804dc61c9c2b1bba6c74b5db5a1));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x18754cb968fdd4233190ab20f038de02fc9f3bb567682132c991a06c02a50d6e), uint256(0x0f31d61a85ec3cc329c2689844f1ca99b691bd5669c196887d81e5c7b8968158));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x04b7df67136efdc3a4fb025bf038ab14e6bd24ff421b7047e3bcbba7e706cf22), uint256(0x1a9b04ef94f8137903f9891d5de9cdf2433c1a9ff677ee3ed630c7354823fc86));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1e31a9792c028af65a92dd937c6ea29f7889e2751ca6c74ec6e0e873c4af8b10), uint256(0x1fff49a54fd015c317177c010c8d303d7bbfe32f004eff6274029c25f179c26f));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x24f57dc17983e4669cd1adccec043c9d564d5891022b4c53d207f1a931172a5e), uint256(0x0bcdd395dd9303d17d9512ae41eb655d00c7699bd0423b5203ced0970614704d));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x27945aa491a1dcfd3334923b1b3a220d2d396e6761610a94e4a301b467beec7d), uint256(0x20d7ba2b1818fb2c5470fbcf3c56bfd1b446885908a880d1cc483f6d40497731));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x199d31b7bf1665c0bc0ef29c3d861a1307a40300ae293ae14f27ae53fa160cfb), uint256(0x2017346a1da0e610002fce38dfa40b0989b4a103649fc7665d06f93f875e8951));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x0a440b584d7c3ab39d3084b45bf605c2f6e10a62ad3f9e3effc01a602390c1a5), uint256(0x19c45f89cb88b223d777c85a3c951eb37b23e0e92717f188604e8af853fd603d));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x13d037f7e4e27e6b86bbaff6c4d5fa0c4929cec27ed8e39955104bcf1673d356), uint256(0x1124077de40375101b59d11195a8f5669ef8ba12777e9cb8a3754a91b2049c07));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x2932dc753aaf5f562b74029709731c2eeda3f2d5ed1dd8ccdfa8981f2cbae7f2), uint256(0x1339c50da4b413ffbeaec060dae03397201c19ba7b794cd545fdd9bcd5cc66f0));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x22fed6f6c3c570e8bf72c8688c162b6350e08e1e8270bda57681ab599a36a030), uint256(0x06eae10eb31a60132270512e53f52946e11a06730b1999960fc63e8add466711));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x0992a4845d5d6019de1f04c4e80d390598975ac467bb427e8c07d58c0c495e13), uint256(0x18c7718389071ebc19991eb568f13dd25d3d157d67ab5e8e9968bc0e377fee17));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x2a293bde4591454cf6b714d4f80213e35d4f6533f3a0cb37d0dc0aaabd6d9b54), uint256(0x24255845261d38d1d7ddf69525ab1cd16fdff1ab113981f1efdad599d9b088f3));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x0475c0b45b2e52890503fc00081f55e49828114910354dcf3eb0302b8a2e75c3), uint256(0x0490467d620502333d973f161d99920d1f8b54bc2b2c723d93f8363d6d26bd30));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x03ae256c3f8f06518bd825022dd01e66a126aa0c6089ef03e9329954f4aa7092), uint256(0x2e035ea26f30a0ee394f5f624e5ed1f6757a02e266425430458e3d2cdb29062b));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x266ac690ed843bb3d238b37718d1145e621729bbdb3c53e624fb4d90074be1cf), uint256(0x2226f15b7c2b74f68f1049d8f0db0326a6029ef5b0b010c438450e6a66b0a3d0));
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
