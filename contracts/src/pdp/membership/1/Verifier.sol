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
        vk.alpha = Pairing.G1Point(uint256(0x2598605fc5bd33fd79e27b50e0a4820d22984655462127805cf87c71d2c3c103), uint256(0x166b2162befee48d1ae982498000ee0f3f86064c325c2129b0076a10ff2aad6a));
        vk.beta = Pairing.G2Point([uint256(0x10a4e7d8db3fe9003f1b2ee165abe1cad51f045dae876b9b10083f768c51ebb6), uint256(0x1c9f63398311402dfcd441015330ce6a134d29dda7ed8188b58aeff4b874558a)], [uint256(0x18c8f7058d820d1711e2e00785b6ec65fabc74182a21171f53413613930a66b7), uint256(0x1677e434c5c329a0b6e7f9fbb7ad75cbeef4bbf8cd88f2224877c4ceb9c99708)]);
        vk.gamma = Pairing.G2Point([uint256(0x07fd70b2c1f710901bd3fd4e733c1ec8b5d271911a0ce2890d4a03be1dddf7ef), uint256(0x0f2d11094d84e9091de760276160312cdf730a34652a02f66598b8ef96ecebe2)], [uint256(0x2d98bb7b80957a6972dc295489f091368fff6d79c09dbc2c0bf6ca906640fcbe), uint256(0x241107ba90e63fe256aa54f7cac42e477d443f7d690953f7afbc1313a5731ad3)]);
        vk.delta = Pairing.G2Point([uint256(0x1dc0b976fc0674552e58ee23153082b6c97ba263e4c89d290931d40a20fcc817), uint256(0x1c2c3137348b88322743e473f4efae0a36330a0bda5f58eef6c70afe0f2c2b18)], [uint256(0x22212724317003887756d5b15d6eec0515f0b4adefa1620fe013abccfb6a0585), uint256(0x1a41e04317095c3feae76d2606d2650da23aa380da2318d2683f5e3e029485bc)]);
        vk.gamma_abc = new Pairing.G1Point[](52);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1e385c1b82b998ef710e8e52ef1acfb49623efbcbe6f6413dabea3f470f7d489), uint256(0x1bcdeae4679cc5b27ba2258325fb66512709959e15800999149f4913071bd5eb));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1835d459064a5bc69fa0b7d52c7429c562a39a118794ed065c9f61bb4e680b5c), uint256(0x06d2db1b4017eea83fbe340e80fd401175eb330eafc3b9770a227f5de6f96891));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1040b09b4a665740a43cbde6f9457c3b1fd26c48f4d6d83ff8e2e66b98aa1e24), uint256(0x2c57fe6365efa118d6b957f96df20cd8d903578a91316be89eb2ac879a7bd1c0));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2e8c86828c1b62a3db5c63fa718515a0a106509a9451b3368723f864f8ac9953), uint256(0x10e46dfb918efc907cab3f3349c5451646d4db0fc68a70e5da4f931fd14f580d));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x160c6a7a445ba3ed3279617c0cd35bfefc92b1a1dd255cf62854c16d21a4e7c1), uint256(0x206c35e5edc2de9154b29e73d42b8ce3648bf2453fb0aa0d03ab2536dd9c6692));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2390d9b2ca6e090aa16553cca0489edd1c2051f582f2dd3919c01350413fed8e), uint256(0x08eb7596f8cd43c89441a1d5fc22d087c0b7d46e12d39caf66120c4d907a25fc));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x28174a1ccc21d192aa25703d6acaf75c6ab38a84c78527392b927e465e05751d), uint256(0x1d0243fe35d0019d1d523b13a93b5d81d7ab2f79158fe1a84609d28928777a0f));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x06c1037dfbefdc5d963d39b99cb338654f716bca2f85817731eb2b0f26fb6a65), uint256(0x09dcd105dc6c4140c499911509f7b96342e920e463b352d3ed41feaaf0cd67fe));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0a6f9a65ef58423992be595c5bc4b59de0b3f3f24487fe833099fc6b1124f605), uint256(0x027bbd0a8f17519b03d0ae4bf50ea980b1752b630229d879daac38b95ff42869));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x11b41ad7b443a0407d32d7eedf79e6f91f92448465164ac4131b21cd9dc0f718), uint256(0x030617309ea42968c92923e39a09e98f9146d7ab309979909f8e0c24b16726c9));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2ebead1fe84522c6d927dd9b783b51dc66fdae909dac7a65326c9f4dc9f10509), uint256(0x093fef8b922f728c02386451f9eaf5c4121ee1d2b270bc14ab475d6bbdb7d2a0));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x097b12fe574180d533ec3e954988a5da06b969b8af117f2f7350f4c4eeaba8df), uint256(0x1539b654ea805522ea1dc2779e10c4a3b97614a3d9d6d05030df63baa292afc2));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x114a0a5a3cc3f9bd08ea53078d6819623f891837f8f4ed733b8b0d4d5320af8f), uint256(0x1f69beccc5da9849b2c755d6acfd93b8af7b4b5010c142b1355e9d3a80d6eb87));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1e09d6a3e1b3f243281ddfa505c025c828bce5730f4e64d69ec8ad3ca9871c73), uint256(0x03c97dd8f4561f8f78d84facb463340f309f8153435aed318dd5ff2658c8211b));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0988f9419466de9a87b950a33bea9da0e317731253fffffc6decdcf455c27986), uint256(0x08661455d91b20415a4fac910e02ff86844102c5f60fbcfdab41a8ef94bba45e));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x008bf4f3729e6385ece765474d12545e04aacbeda5821c90bdf9a3fb41af52e0), uint256(0x1ded09994a31e662d7ee1456398841de5c96f8f723ef463074cbec9e9f5a259f));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2246b617043cf0e13e957ee31a7379ba632236c70fb25aefb56944550feb0290), uint256(0x0c1278b51e2d219c918840ec409fca30eff08b784e2c599c2cafb6fab366688d));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x296aa26046c38892030fde96e0b450b2020a09cc02b15378b1c8793bfdb3d334), uint256(0x0909eabc7e8c008d30517f638a1ee6fe0bba241c33d91d1709739509d6342464));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2c0c09906461d68de2385f520b2a34c378d6e0da1811891c6de653bb2a4bedde), uint256(0x2706e422a9d7f163af8d381ec53258909669fc2b4efd17cd3697fe5fcf91d6f2));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x261cd9bd78141c2a40eb4858b90b1e9c9f8929de0d439ee8da54de4934c77382), uint256(0x1a3cad3c59da45096373996c0289a2747fce1bb2208bf33e5e15112678e14c8c));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x249a8087d42b180e171fea36470115919c59a74b9c63be378c3614617e2b84a9), uint256(0x2538703d5076337c1d81bd9c9a4820da36f304204da945f433228ee593489578));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1bf91fdf790bed95f054da11a8901463e61fcaf97543de8b2af30613096d931d), uint256(0x0f01b43f13072f779258cbb6c6518a4a99f51d669d27305088827064e3307893));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x01a5ea0137df6c21386330842d95f9260ac209d1142f21430b31af179bab5373), uint256(0x1d2a6363392c068e20974f2b719f9ca234d7959ced5f8074b28e6c8dc76802fa));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x094d88e176d098bf62108bd0a32bdd272d3c5471dd777c4727dee199ce376aed), uint256(0x1336768d1e8bf93e49f061591913e1781f2bf0454f434e57c5c8db9b1bbc6316));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x22601213f342c9789573ce7a791a10435aa5aa5ce4e50de70a13469297ad226d), uint256(0x2fcf68a2cd5217a282e62e28da16d3bdc672b5db1e319240a3a696af4f7e84b8));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x0722d086184446c0a7139564d4c9e2c3e52f63fa2f8df5c8e67f5fdf864ae33d), uint256(0x12f9799cf37aa3931b949504a13f70c1b3808bdf43806083ea456968afe7af2d));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x147886ae414383ce2999f3281e50bd78001f3049615b619687ea7e84fe39e91d), uint256(0x0684367dc83368242d69956b5833e6ab0584acc5e7853aac6b62755907d374d1));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x0998f0c3b9d584b50470595d6c810574c4576d00a77ff4d64770173e3d364e3c), uint256(0x058aff68d469ba582612b930c21a9f1b0d8db362333f92b8e902ca45457777dc));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x046cde6fbf56d75a0ff44a20b7613cc0e3494ec7ed9b7a0012d0d2162805ce28), uint256(0x12e64a28d5bb977546f862540b7426baafc88d0a1278e5fc943862f09236aab3));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x2c92128b0f88b72ea85996c7ed35f055c416040a017b96bb6d20c1b11cc2f0a0), uint256(0x1499f144f8ccb6331e66e19b42e0a57ddafba3b895b63baaf431c40740a1f3ae));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x302b93b78eb40c92505c4acf37ae6ac3f3d73a6f766fc77492e04d0b7167816a), uint256(0x2950a6dc40d6586f55768464f23c5569847ff468b8a8568e7058cbb8ec8aa589));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x0adaa22fd618cee82bf170f090c06fa0c3677c5dc152dac60debad14f7f371a3), uint256(0x191a18debbf970c9b83c9bb30478e91c112362697e301e93a1d1bc11220e9cf5));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x270915cfc2e24c12264923432b55a7283c92f96c6a83ebcca46ba685e382695d), uint256(0x01ba5e52d666548b9f973ad3c56e6eb8db53d908875153c07fb3c054cc7267c3));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x26b7fc194fde5871e2f550a93c5720dc105d881365cb9831ad3ced4a5a7c67be), uint256(0x1e0c65598f287f6a9b962cd254faa793d359a7214d2d123ea368687f36b48255));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x2c0fe9d4cf9e2118e97381218ebcbdbad65ffd28e5aa357a5f6cabb12032551d), uint256(0x18c744e40cb15890d1c1d3117b33a847b09fdff029710a1a0b67d576d4874581));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x1aa924580d5f387a41a884c89f924514071f77685cf063e35705cc474870b0c5), uint256(0x1d29cafd8bcc5992ad35d536e2a5b94c8862cfc3d6f80ca9ffdf8b46e162c093));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x0fcdacf884ede4ff726052aef098f3a12b654b75e6d262dcb0538700ad6ae146), uint256(0x181fea0a677666fc8a31c5956bc5fc6bee3c51f63182b33bae7e8926ffccddec));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x0d8b97794e2da3c480258d51e77ceb10b5721cbe7cd0f43cfa162d63242a8db5), uint256(0x293f18fa482aaed37207244c87527ad9a0c05194d87ccd49c0e55c589c4df71c));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x187bb6570cae282d6e634a6693d3d30ad21c28d5dd0f055087375a506473aa08), uint256(0x2ee157b1a88b28be5c419ab740f5c36f5077ebde0ff7253e573cd6f8b2b7926d));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x20dcfdf186032f87a2439dfd54025a8997bcbc2292e7f3b7d2ce8c871a31bdd9), uint256(0x0ad387dd0c62ba4ad6f241cb227ff92f4462bd04ac92193c6dbe40e56f37a210));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x02e3660f0fb883fa866bff333bf6f00b4105dce60dbf824641fc76dd125a0b24), uint256(0x1ed9bff1ec9c7932abcdd222dacb57eb188a34423d88e7df179d4d9e786f689a));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x21951edaf9e02a101402b8b9ae4d9bd5feb0b78fcb0f9c266c5ab98a2559fc63), uint256(0x10148e05a3c03ef22b9ccfee13488b303b57a527fbdd65040d2d6e126840d0d4));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x068bd6e132576a66b1ea7c115fa357bbd4f28f02b4f41bc87bb4e72bcb9f4b74), uint256(0x163f09ede926bd826aba55e81d8c020b45aadb96db4f3991ee789dd5e7cbbd37));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x0b8a214bbdfd25cbb00d1859a84cfe1f25a7d354a6328b64dbf506f8d610d5ef), uint256(0x2a545fea2fb49ff8a878ff020891ce06a2c4128d3361a67e10cb8e704e9137f8));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x07ee6d9d7f442c364e23519f99720b140d27acd9405a421a99bc0fc4367bb61e), uint256(0x25ce20cdd64f344cd1f8c6b115ced4a4878a4c383957ba9631ff3aeaa789677d));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x2b64afb0fa1a8810a9391cefe3f852013927b5bad0ddaacf4a712e1be658c268), uint256(0x1ed31c9988234176550995932059ec045857e53f49da3336a932c7d88395b4e4));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x2cdb328bb42f04024234b471f2c8f11dacd7255999bb1f4d6d034661bb19c22c), uint256(0x13fbad9dd1329f97050b45e039d953e930348e0747ef6ba769a07b65ed18eacb));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x167db6430348299885a177fe1e4afe1653828c3fa4d4bce67a57ce29274fec11), uint256(0x1510fb3900425b203eb1a66b634901c00cb0cedab415723e36401a88f3bf3403));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x1d22d47e0f1f2f04bd18ea4ef8fb70efeeea5241c833ffc8704191bfe2358489), uint256(0x11a6474599eae6169910be28a9b7f8e13079adeb1f32332d549d3f7a71dad145));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x1c506467909fb9b5a52a1f31766fe891bb0fa704498c42e67416cdfffb2f146c), uint256(0x0e96a583ff19e741b6f11d8686041d14773056df53f8499c38f0d8d90a9e7085));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x2ee7ab05dd6fb30212c4caad06bfb245f388bfea5e5cadd8d7258a7f6976ab1c), uint256(0x0731f2539c94a93e4c35281c0c10e9485c5af99d8e563152268a3a7db9fb83b3));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x1b113e314951a87f66040b58bd4fb41bb1a3686f28ee05576f438f931c6f9f18), uint256(0x0de38eab019409b1cb1fd997ded6a518c7703edf9f7638598bb8b280f7364fa9));
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
            Proof memory proof, uint[51] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](51);
        
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
