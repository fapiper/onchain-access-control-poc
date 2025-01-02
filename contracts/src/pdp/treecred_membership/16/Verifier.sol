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
        vk.alpha = Pairing.G1Point(uint256(0x0006bc342c1d17cae54781b3003ebcffbe8809ff6388d43d8285f324811e9d0a), uint256(0x012c35ed11a22e02ba2279e491cd7b5661e3b089d1f67e5ca63a796e697815dd));
        vk.beta = Pairing.G2Point([uint256(0x264c8d7345e0a0b18aae3ea950b2305578d9c084766a14b97e27389e68779c32), uint256(0x03678d80a3171636f01fb900052d3b9ed408c026c5aead64348bb211de65b293)], [uint256(0x16b03eec974521cb4e1e0b3dfba072ba737ae0d159f44270c1b2c881e206599f), uint256(0x0b25f6c8bc5a5958ee0da7abf227abde7739e78a1c9ff3570bd99caf9066e731)]);
        vk.gamma = Pairing.G2Point([uint256(0x09620f94579dd8ac40d9b91a8ed116c031d69a5904e6e92407f04827ea2f4f92), uint256(0x1be11dfe64b141db798b3593824a458814d90cf33576a4bcfe80d7236aeeb6e5)], [uint256(0x2c3aec33b4fc8a33e069b248784670c3fce885e60909248393b35db6f6677ea9), uint256(0x13247dca0a363a320a57f3b3d57a8db5ef10d8443ff63c1e907f24061246542e)]);
        vk.delta = Pairing.G2Point([uint256(0x28a8b825ed2c6471ead1a97f00ce6b58d090c64fe1bff4e319dbbe488b302e57), uint256(0x1c570df39ce6f2f0f1095b77b9eedfbfb77428681abf7339229e7acdf8a78a19)], [uint256(0x2c0e903ed7e6ffe6539d5ea3a5d1546993260c6fc026cb51e40bc9c7b155b4e4), uint256(0x07d07137b5bf2fd4c8af36c5340fc0a1f4810125d61e2060a4150084f2083384)]);
        vk.gamma_abc = new Pairing.G1Point[](156);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x25eb5a59b4187dd5f0f68c11392596eb79be1d85b3103905bdca48c8a2dbdc0c), uint256(0x1cdf66e453a448e0b9fb99b73742439dde55bc71b2d28aab0eb29c8830c6bc2c));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x15f6705ff0e163fe26b8e850791464b6953de0b8449987117a886b0ffcce306f), uint256(0x209c649f4620c206564ee6a7c583a887e4bb9943bbcf40b9fb3f71eb851d5f79));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2578d308b875b930e95eb53dc790bd8e2a2fc0a567ce99c995a9f7fa47ecaf2c), uint256(0x0879ca27d5ea9883cb97388fa01bafd134e8d0ab7da56c7ca10aefde92699544));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1a8b75898af21ec6295ac6e6b69994f016e7ffdd6a34e6857415e054e865a72e), uint256(0x2c7477ce62eaeaef7a208ab5f71826ff005bc8c3602032779b99faa473a4e002));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x24a28af9d025aa5e27067424a0b8fe6353022e40ff61b639584bde66e5e7d777), uint256(0x1ce5236290b461020ed4c08bedf12979822cbe728f2a4f4fa957af1de2ab3828));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x18a2b0dff4c871802ef5f2530021336ac1200113d2bc3930e6a481e4f54c142b), uint256(0x039bec33e26bda44156fa9dc392a7b38589d4536d05b6bb1b2c1a087e1c9b320));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x08de902811ed496e390e8841b906128ad8dda352aba917ced84cfba084b63a7f), uint256(0x2c14191e32c1af16713ba4dcf3eca5b20af174a4c762520ff67660793fb54b58));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2272ac61c75adc779b169f26b540a365e8436e98b1ed0cf82ffd7cd59e62c2af), uint256(0x1cf2847ed7b563d268e88d50af9796ccad654e46d29e1b380bbeb5500c26cd22));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2901720c97002c03d29a691624532f85f563c7b70bf30e3dca7858fccbbdbaac), uint256(0x1dc4d45a06ed1e32b90a25629ba8361e0cd332df93b72adc0ad5cac74df91978));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x13d44aba1d78df1cf2fdd83b293f4b59574fb0878257c5e12514b3a083b621dd), uint256(0x16338acbc7f623a6d9ea9356ae9bc32059b1b3d179403697a634cf7073ca5f63));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x27af603b63a6d4c39d82ad552ed242fe18d0813ccc9ef09a0c5fb9cb37d05cd7), uint256(0x1cdb2e938685d5a46c7b65dec48a0be60d46f54653c874e707b431d7e00bc33b));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1e80d5cbe5044e972358203723a06da2b84f48d56b5afd78d41ccacf4fe162bd), uint256(0x2c0bd6416ac2126ca7965e879a43b514f33bff9fae7acdc2306290e0871ec728));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0316a87b0b9bd3d795f20c43acd5e6ed1632e0cbb2ae7281a735dd27d403f62e), uint256(0x2f8f7f317bbf49eb4064948ac7b4abef230dbd9a1b23e2a2b5fc7bbe20451698));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1f5d79dd587feae6f5d36b4a6afc3bf8e7f2d3b36c60ecf3203d25b38de551a1), uint256(0x14dccf4e68e7a32b43217b32123d56898ac633102fdb3843ffab3c065c0df483));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x11358d2220398d5cd04bf0d53563ca64309b187052abfbfab5d9df2c0f4d8731), uint256(0x0270b8e7713df3708ba84b109cf44c6107b95ce140da8045a6caea6235048d01));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1ea86199459c1425cfaf2031a90a95675a72fd77e5e737518593fd3ece3f4976), uint256(0x06c538519382f3dd212414bd459bb1a4f11e20767cba20ac2943bf6e263c4f79));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x08da732767951b76495eef62f42ecf5a9762d4d29f4a406311a36ab6e3b5a44c), uint256(0x0fb28f11b0e14d650e5f54f6a5f46dc301360e6e9a0efa548f2ec41005421ced));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x056c9c6735f4b1bf07e6a1a50b76e4347b293d46de628cac947a6f2274864df1), uint256(0x048cf2e44818b46d7c3501eb4933fe1962651b44229814b4c1d64b188800f943));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1df2ddfa8099834c6d8d12acd0eca01e8d0d38b2f9872f04c45db5bdc7c18ed5), uint256(0x1899bd1ffcc70ab5f3eb4e2b38f032b92935443dfccdc375c15467945a46643a));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x05d22756e30229c00d2e24f7fe6caa62b439ae1df8617c035e4aae871c394e7a), uint256(0x1a2e69970df5a5bc3415f6daded8179b5e138aab1b40a4588f17a22856e287f7));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2da629ced084bf07404d2304422141bc1708f8065a1c351043701ae44256734a), uint256(0x156ebe3f55f6b19ee88e7cb9e821c79c099776b1144a3d4ec87331ff0616e529));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1682f5dd51894690852eaeaf2834974d3bdeb8d4e1f9c7128007c8be03cef79a), uint256(0x150134bea2fe8c2114d238d2dea35fd333f5965a040452d8d3318f36729b7a61));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x102b54d1e4725d66e2c9402b6334c99cfc4651763749a503d55efcde8b23d3bd), uint256(0x1bbe2b41acccae265749c20e14eb6ec492e197116f5d4b8afbf21d031e96c0bf));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2e83c5424eeb41ed70e38508cdfd8bc5e8c1732fb201a79643c32c2aa88d7b99), uint256(0x15a7181e5cb4ef67c531755dfe7beeb2b7835d500d36f57088ad68413259e1b8));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x23da8232bcb16f31205211dbc4190d0f62d70661f525309a765844c5d18ff733), uint256(0x16d4cb219e4729c6d88ea99861446a04a31f79e6aef408c8dd30510c2e5f59d5));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x1b6ebced90e2f83694cc327e8f9a30223fc30789eb6d97167e614d566ab6889e), uint256(0x191a15b9a9daac15d0aaf9d7d819b522abf576b083a2dd073728fb0316df914b));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x0b40dd265701c3bdd782af99bfaf8ba85bab943c0ffce26d2a8834264cadea6c), uint256(0x1da2e00e9639c2547f6744ca7bb5f83e0f54cf8b61abc19cab0b217b2cf02e06));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x1fb1e15e7c703f7af51a920f9e6e48e109b14f93c56e5986424ac430eaff44c5), uint256(0x2fde7afb311f65ab5d68c7214b5de977739fec4c86771c23a999a84a4d868f2b));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x20b933561f8aaffd892a63e304d75deea4de01aac3f8d16b7fac019a951272d0), uint256(0x2f153aeea9dc170ee3477f955d0e819fb17cba66df5820aa22b1f3b7df977bc5));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x1192eb5e096e82856baf3035f1c59754fe61f7ee62579a7f203ff3ced7b1c098), uint256(0x2c27ea6f1fd0e4cf0921bf04cf7810e676fb7ed995b38bfba99a2fed35f68a26));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x300c37382175eaf389563b5c5d5a6247937593e32f3787a7e5e3e4a1c0dafeb9), uint256(0x2711ee9b019e77c8bb794117a2df9c8e44bf308264fabd48b30c4406c897567b));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x0fd36901f334f851d2c50263371ca03718d55bbe08b96808a1cbd28f37aa506d), uint256(0x019baf55a2f6e868aacdafc9603887b1adfbf6d109176d9f096e2b97f40dc4c8));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x2b4d4207df86a7c8e93f2ff59025e1233b437c6be14f1fb3a9ba8d6e00d573bd), uint256(0x109596578130a9ccc89ab842dec228d7fc7f1be8a1e0fd4c5d2a0e256d462709));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x08a27aec3e440ced9c7f223d164201dc24a5609ce25b7a5fc937c4b3f96f9233), uint256(0x2a23aa6adb7513ad3fd534d9880f497dcd86139fb44e7e03e85002422a0b0542));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x26b0d82bb303b153138f346c49de586297fe7fd3acbc70c56d140fcc6182345a), uint256(0x1f778d68c20b196fdce5680706ebd80b1e8eb1c20fdf5dc530acbe0e1f32293e));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x2b049c91b23fa4e4f4ff206ac591203dd5819cf60df3077efd4fc9a03691611a), uint256(0x2937d726e9e76c750796d4bd8865646f5c9e9c2f4e3fb2535d96e4ceb3a3c6c0));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x02330ca6becb3ced50dd42e1e911cb905a64672cf548d812372d3577a7be815f), uint256(0x252b0c1ca929d7a89f7feb2edef4b6eca130dcf9cade37b957d29bdf15992a3e));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x1260ad86ed9364527812e78ce91be510e5e52259751ba1951a432c6fbf01a20b), uint256(0x18e46a0edb0867a9c367aed108f9d38709464cd428b7a42aea19f497488cb119));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x2426657e5821fb1392d39b56166ea7952e1e430cd0fca9f64bc4271927d65bbb), uint256(0x09547f1c75e0508a607f3d75860ca230886a3a19ad81efefed098808886f2b65));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x017166b000217ae4b4f53cbdc6d9aec94d3b759d4608d479ff15c5a5045a5d8a), uint256(0x030cc4fa37364273f668fd7e4298ab4434b457b0c842c6b138e6c787853b205f));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x1580be19848c5f62226d8ac5ee5a18e00575352a79bf7d7507a493f8b2394f17), uint256(0x2166c5f660c64af2037607f46536a830c679b2447f77191f5d88777d6804780b));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x0f466fd77072c5b17211c6bf15e1251b765be495f83d5f609a109f03ebbefec0), uint256(0x1174756a9673d03e83e6e83f909b9dcad2ff6f27312355c661c860177472ec0b));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x22e8cf19a9f650882c21d5f09c41b07488850f63b05fee15c464af354f67631e), uint256(0x2752405da01b3a5713ea0e45f6295ee9361f319e3830a0b65b8b3bbcbf305279));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x1567ccaca3091a486a4de28be303a06a32bc32eb520d1699fefc9b8a1a25c48c), uint256(0x23573ca019870ef24836bbf9904f820bad1f0e82089e9a165a03619e898c01cb));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x0ad6c13b86449890486751126a9b622b8d318ba596359565dabfe536d6067d24), uint256(0x1d744821d90a167713aaeda159b641abd602b4913368ccd91561a411b6e6dab4));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x04a4742ccfbd0a1619cad5a51f6255ea86d8c95ea285e023d3050e50709d3abd), uint256(0x07fef8b270ac994779660d2a0b2351fc0b73a07bbf34ee8c3514cdba777667ae));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x0d98810039fba9151885502cf1ece835802b60bb3aa4d0db73d51272322d080b), uint256(0x1240c911cd623724aada79e52e349e07de268332af6e9a052c37cb5984f739bf));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x1936b66b44d926875d3f5c11415ae69eb69b4a3ff1f6bc220073c975aeb2c9e3), uint256(0x26a5838af990da342bc7e1fa6e564b620d4cac1aaf726abf657fbd45f6c6a55f));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x0afea46dcdf38bd0d9acb94ba94dbd95b9e1e89781b9011071743fb8e60f8293), uint256(0x162fe27a24b4357bf4e2b177536d9ef14a5219fc252b7dc80d8d4fa8f98b43fe));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x01828df2a53746a23d978270a7e571f3a59af0f48be1854fc1756127caa6e6c1), uint256(0x152874b9c1967744a7cf379483b13d7a1df07943b83e7384d928729a297b6a44));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x294c1e8dba08b30ad93bbdee99f9da1610b6ac90d67815973f5a00e7e639cb06), uint256(0x1d7eb02815232c511ec7c0b3ca13969804c4230483632e77b4bc7a052d7cb82e));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x0d448f6635d5744824a7d7873402925ec8f39e98d31fecbf926ebf022a57131f), uint256(0x2d50298f32d2840572f1d9a07a4c44ddd0fcc8bc094716872ac9b6f65ce429bb));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x15ac17030a96b6cece0b48913484dd723a36e12837c3767829334ffe40dc7b86), uint256(0x26f42f5073c0037e4b2e6de04097121ff70e24b6781e5a2708af666175796b3d));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x0e01820ae1456a181dddfed8e84eed66549c64d16c3eb68aaa1ea81eeb95d10f), uint256(0x269eac7420913216d8ca131cbb8bee6aa2142fe48aa09e1e30ad9bef646c6678));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x2d126e81e0fa4a7e4bbd4d01f081d858da1e0bf93fa6d3ccc1d7d6d35deb6c74), uint256(0x279eeb11f84cc50ce960fe4ae656fa5411572be4e7ebf4e50a4687416f39c3d5));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x0213944e0e9dd3567807680dedd57ded85658c8edbdd0af5cde490d68ddaae35), uint256(0x14cc9ff59458607297957c1d1451cb09c2c8832bf1d2e23ca1b38c572faa5ba0));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x13de74d91d7be172764814d56f41264108e41a85f87fea7f7fc2b6038e40778b), uint256(0x2430914529cda30913e90abb249c275c0e6d001bf747b5eb1ad7301cd3a00079));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x0927d3edb2d3b9bbf8f5fb2ac5b95bbbdb79e417a562b9d6b0bb848bb122621d), uint256(0x1835780c7cc5d8a09eb4e39442b11935fba829246fd442b2fb5f6498b2afd0e7));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x20d38fa67c9f56ac838cad739382a706146f66ab15613a78d06f3b118ab52a4e), uint256(0x279899f2ef151af0ae54173e9ec1f118605c22e630b605ac8fee94a7ab27503f));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x1b88109fee331eae99dc4e58f8d2b9e2331d9cf907cc229e81cfdd0638d901b7), uint256(0x2ebf3752135a7fd8754d3565520b9f325ec3236e68ecd713800f55750d8ffec9));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x245d81b74c1fe397f022d26bcccf9a0210e5233a975720f754bc4dedb69d145b), uint256(0x1e39768c8ac5a5a70f3c909f639b3e9866a1db8dd6e21a0458f5f52175741217));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x12a124d912f25c5933a5e19ee17930e8bac7ffe8dbf4dc34b96a59759cbae07d), uint256(0x288ea0c592141b5c34d245e72f28dbe03e7b6bf33f52e1d848eba9707484dda9));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x1bc61bbd112057174952b98cd64f0a9a84d3a36cdf7a4ae02f0c29fa68f824eb), uint256(0x19b04a62704e36e631131b4407ffffe26d3208c54190d1f8645f122004de131d));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x18cb90b9c02af91f5f25ba0c4d4cf925aca42f7a66879a044cd9d4f8f8deae44), uint256(0x1fdfa2f20edd4273282c482a6d490188b87802170d3790ec5046598d5df1d8a7));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x12bf88a45627b16617cdaa1a1db04f8ec7c7c2bb6fb63e605845f476395beb7f), uint256(0x09ab9597e461c8d63f7cae7bedfb7b254765f2f06fafc6fc5539aa31bd9fe78d));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x0ce507563ec8c246017e8da76deb85ead4d1538c67dff241ccc7f6002b05ccb4), uint256(0x2ed5f819cc11bf329a4df8113209022d2bd72e353c1780ea495892d72de485f3));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x07202d4ae7e4b03d3dbb0af12a08923ef61a33794b0d8005970cc983babcbf53), uint256(0x2db0ed0d4c30f4da92c97652d5b23f21e135b1efa98a6e379915f4c18bea2368));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x0567b36613e966e60ae9c38102d3b443a53245791acfeb507b2a209f3642ee74), uint256(0x27465de2126718e15606ef4f3470c03ef16dfddc2a5c68a61b20ae6366261883));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x2eaf24c4c780c23a72c226423c02f8cac12c88dd6bcf09dc23579b9d6c41a088), uint256(0x001247a3fe66b89eb00ce8c024ef8dd1b3f0436199be49fad97936d210f74a21));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x1e9857cbb55a585104d825d8b0c55b849673c419bc1a4bbec8abb3306e89edd5), uint256(0x1bef9098fcfefdb30e3218813f520c2393931d0599942eab5a55e57d318319a2));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x1836cd410237cee3aa01ebe0733cc827826d76818cfb5b176f60740e94f81798), uint256(0x204673f9826f16c1adab94bdad6c00b8013f8f20afc20d9de6dc39edf9d144e2));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x10004dcb8a16edbcb181cdd2807d5c0f60ea484f0474e4aedc73883684cb62ba), uint256(0x17fe7aaeafa7248ab0c96d9351e3a34adc2bacccb74324234ec9a2d733cb013d));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x146dbfbdcc706a372abd5b417fa327a10be567c96c4f47b0bcb45a561f1d178c), uint256(0x0d7f11dfc78b67b3f6db8089f6388d93070268366ae13553c06f453ded9a34d0));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x1ec25053a5fc289b82d21229b6df2b4e221ddeed0964db03accf07a544221476), uint256(0x120c4782adb63eeb57f462bda9e2987f76c1d70bf0bb55c5bfb89dd8e639e357));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x1cc9d6c0215c515085be1e33ba460b0cca0e3cfe1c5a45d3b4fb065a385f192c), uint256(0x184fc8dca11a1688ff6e6323d5e0e71a46212d588c5cb7defc1d4a6167fe9a21));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x246329571284955be3f0bc62cd29e0440899ce7256178d10cfa460b72dd2ead1), uint256(0x232582483b29d8b6c5a30b342df254265aa0c1cc2ed964baec700b98bcf0b284));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x1ad8fd63ea7476f2b523f12c97c748c22f4e7809543d8b2a081743a9dddc6ad5), uint256(0x190d385809565b3e4e93f019cf356263388a49d20b1b0aadc2bb05a2f1c25038));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x2a72bf76cd038aebc6917eff9f3c4fb49beb3ff1549ab13d48907f76fdd5ad94), uint256(0x252e95dd6065d10920bc8999dc4fcec7c97e57b12af44b2ec26576169f4ba93a));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x02e823ec4900c583370be123cb5845a567d12797dafe34756bac65feeebcaa2a), uint256(0x18ce0d48f0fe7df358cbd2e4786244eb0bad001e7be394c022a4776684fa2213));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x23b65033b4856e558dd75a30dd97f38a4fdd648aa6a6d21625f3011d905317a5), uint256(0x023e1888d09846baf77de607ee2b5a2827897d4d9a77db20b46c871e4ea21641));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x11cfa7862124d2f939d3a1cf3567c209c05a6b7795224b8867443b34bc5a0dff), uint256(0x0d50cda6f9960820db9658856c12a288a71c572a21b76a14c9956fe7eca8b988));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x215e73ed61b9b2c6ed81c14faf89f46e9de934d75760052af2b3a827b59fee96), uint256(0x0e4ac306c1558818804ea6752064cfc20f4106f027bb7aae213a2d4a5876c00d));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x2c96e017a48206b214e3c2f9f873d204279c81ad61317a401f5b88019451e1a4), uint256(0x1b25639a204b5c2cefe018d4cef8c3d2014c0eb17c610667161b4cefe613d144));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x0ce6f2b2c222291068dd88c2fe99822f50c142ed2cd633941dbdefd5dcca5c28), uint256(0x1fee8d5fa6c47a5f68220d113471212b2be3ddac1c02ec7af7f7c08e8b9c86c9));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x116372235f06ea4ba180c61c3fce7bcf8e85cfe0a0d7295049033734028717cb), uint256(0x1fdd9e268dad9e6fcb214f6d096bd6dc284f79a8ae2a42bd81d2f2c7579ca523));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x1bad2bb7e4bb7b5a68c7df10e23374bde1d73d66d5a8bf3d00cd668dd7e083fa), uint256(0x2ca7e772c7fede042be3430e7b3c5b7eeaba30a5335c6d931da720a51b8c274d));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x2a85e7ac908d4f1fdfdada044358284d0f004edb34aa4853de6fd031054f2fb4), uint256(0x17537c965b8156adf6580de411ac5b7bd7a33c50cc1f61dca8f59538dcd894f6));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x2558386a621fb4d6de7c3d752d390cf9ccecc1e8b413e7087febc8c596528b59), uint256(0x11b19dc3f3f85ce295a69d3442fe903084e2242e4654df95c56226937b400b23));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x12c37274032369ec94d378972f779eb32a77bd04b3e590ef91a451260557e697), uint256(0x06848d678a09130bdadb24150b57dacacc221e43454b456ddfb40e54fe49ce57));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x08ffee99bdd1383646dd2226cc3b05b1fbc72f57859f344a98b8d95864a6462b), uint256(0x0d6bde1ecdd2776abc927941b7cf511152f4ef8f4c50d3984c332bf1d2b3eb99));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x1fa5731d640ae7b63ebe957d334411d71ca9da77d530e17ef3255a935c7eb0c9), uint256(0x025e2ca6b9de34ef4a1f886232489bf53a606959aa0324290712a58d1d5016a0));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x15391b0c384c7c2fe4bbba680ca4d83127e69092efafe358a30c0fd7d08aed61), uint256(0x0f8e0781dbbdba6431a5c3bd302a8f4f57aebe0d0912a551430cbd7e17cb3e73));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x07531d2b99adc0550314c0c7ac010f103630e09b4019fb2534c1743df5702bc5), uint256(0x0b2e9e00b5bc6ef9adee859453b8403b84eef4e536d2903390f168eb1476d0a9));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x28fe6e860372e0de69abf76a51c7de712c85b626179c143069f62e99d055a722), uint256(0x2ad1936409ffbb41809fde5927fa3ca7bd97e8fbff6b1e1cc87170bc39600663));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x03087fa0422e7747bee39d9105fcf7d00df16e82e345d38ef7e18b5787366663), uint256(0x0d32fb4b3cc081e8c61650b5b80ee40fabb9a0c7af11a94d3bc75ebdbc2e68da));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x205db3a5210ab782ca514d1e0f3e6f39f050c700a0b0314b0296f588e0d79a45), uint256(0x0e3c705b9db8371fc99928e4e09d0a926cf514e81aa887c9ebf784900989c730));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x270e660268e6780aef2458bd714216dd33b4a4f15d17c891699c2cf37980d9c1), uint256(0x0406cd1931a8b027df16f42fe9b9c6bf473fda4d1f065e6268075b27d1d48f96));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x1fa1aee25a8cd4fa707b976d0396774ae718df39c6b5c056ef9f8ec1652be1e5), uint256(0x1a18857f924c6366ddd829e2d2138070b50297ce7cc4e56b328a2be7e477b9c5));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x13b48245887f969baea687e7f750c496d62b2e209d6d85c14bf83a529be7b1f0), uint256(0x149c41f8ac96990109666939d6f846e61c9f23f2f13d3a4239e5bc1e2196a72c));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x22e08da76b0301000e5d793261723ac019002e2ee87477c17bfb082f4d4e4763), uint256(0x034f7b19effab302f0b350b6476c062b9a5f0344aa842e20f45c174862878a7c));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x2957cc189a5987501ab38830cd0865166400cf74b6aa354d042698decc31f6fe), uint256(0x2c3cc174ac4267f058b22c3eac70189860f0cd8c1bd693254d07d45cd1d8305b));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x2afa16952a87bc0594521d7101d8be9f100946ee70a868b3c220951a1122c8b5), uint256(0x2874dabd74f637161d6ede71b507d071266e54064bd56121af0655f875bfa52d));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x1ce803532862ba6fed6240146c840189672d8dba64e86bf678305558d23b54c5), uint256(0x1a47e941ec65943340a0861a79f8b0e9ce7ce0fa74715359e2c0670dcb213c8a));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x05979e81926fc788d6a5ab27a5caba2eecad85abd2f89c811a6847286e78b92c), uint256(0x03e16090923ba3a367b6266ca1bae336e91c74445383182d6bb1c9b33e6ca615));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x00631d2605923b73083196a1512e4d69a46ed6d5089ee75d075a9d05781809c6), uint256(0x1372dbf30637d22f5aafb48f2b54823fd0a8a432cba209b99b3d822ac44cafa7));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x14751afe410dea2242fa3792af3f4a8b89448d7edfb47326c7e02514087b623f), uint256(0x170e418129373f11b0a00582939ec09621a2c7a1066fe940ff31afded6656166));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x2cb9e45f693b0be84a44ce53fdd7488bc4dbbf8d310b40d249bc9c1f083745c1), uint256(0x249e4faa3e101e18296755fe946f727830ee4f5a9f230f0c7696814b4828c8f1));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x1f38f610f868be2e4a5c1518cf5a62ebcb030b86db3575ec67c2120a9ffe957e), uint256(0x1757881754820ed4a4c58a6e3b2e9c8aed1b4656051b8ea780b11159f62ca36c));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x18adb8cc86fefb9e7d9e022e76d063693a7766a3b4ef2701dee2f91bb612039f), uint256(0x17543dfedadaad40f904ba9fba9d61298da2d06ef0c05ec06b70068063402408));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x1fe48202b8282a77466cf7afca923325cd426d5ed2db8fb3cef9033a65cf5ab9), uint256(0x1a73120c296ab94d71d3a87d6a5fc969c3c0c2f8054a2abe68b493508472d5f4));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x10718d06255fce1a5c837fe202e9f63b844f6aacd6ea34d15e646b855dd95b58), uint256(0x128ddc94ccda462e2789cf402d51f0218907124320c4fe45f73b8af93100e68b));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x298588c519c4b1c569fb8d1ed785d48c406b23e173da36dc23b781e34b168bc3), uint256(0x1de51008e58da1e0b304940aa438e7ea9f9c5725cf73496a4f6e0a188acd1cf8));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x06e2b4dcf6724873a33c4421f54e57e9498c7049e7e0fc7b1896023e0eea01a2), uint256(0x11ca504426a7aa7733e82729b762171d3e22dd6de85d7d83cccb2df993d80406));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x1adabbd1685bb97deccc1fad7a26b25f337e3e5b49d2e20fd570c5780e6b5969), uint256(0x149f09965a097dc276f1cbeab7abce629a41dd62e08ee9fe73ea7fb331e41396));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x1f0fe188392d57e0cb8e49df37da78a3e8e6cc4be873591609ad9406d8d844c1), uint256(0x27c49b4229638cd9634739b8a69f9598394fbab1f081524af245bfdb1d597a61));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x224c7f6988742bd4c38a846e2c454fe850d6e51ed75f0bc4151c3929bb711931), uint256(0x189467e5df4b447a1f22b6d98dc0c6c61c95b55d5ef83ac0c3a9e7412ea13dd8));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x2ac4ccbd07fc61f74344763767a2b85962cef02148c1e4ccaa29135871fdcdea), uint256(0x0acda8293d02cb5ef293229db46b595b5425460eefdc34fccb79e0e2df212b71));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x16beb672f34f3c18d3d92124a0fd0675b5af24bea876c360ef4b61f9e9786cda), uint256(0x2c664b9db0a68eefa18e7236a5d1b24610664c8481a93b189cf85b1cb7c27a39));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x112eba73e3315074cc5bc925871697e8042b87f9a5cefc3eb1729339a9ebaacd), uint256(0x033ad40d651d4c518f5306fe06c818c36051e18c73f0d1d483db6f39d119034a));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x1d3cb674b124f0f485013d864c71ce9bf071dfd049d63838f368848fc8cc3487), uint256(0x25f7292a9313abdcbf08a58238c55e208e36b29d50e744433fd7c3be8afde778));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x15f1f2afd2dac97a4c16258e47514620d169ccf707c2a31e61fc9b31321c412c), uint256(0x1b6494b747d984050ba2e235ceaa9e6b8e6acbfdedd000b7a5337ba4ed111447));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x09f663f02bed758c0e9d6a3c10e0ef23d1ebc8ad74105e54b7e71888b70581ec), uint256(0x076ae89d71d5ab2fc0b9f5ec1c4c1e6bee8115c794fa08ea7852f0e5bd5af15f));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x2c07aaa28d9984f3fa71ca157b77f8e211d883cba9cebe185b264e1c6fc0990f), uint256(0x260f228a1b94067a7d355987a6179838c38845a91558ca61c9bf718589247821));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x06bac1025f4711f710ac2a4d67eca529868faa74067be5e019e94b818f9a081b), uint256(0x10891691169d3f84cb561443b3371f743d05770ffa87b1b93cbb1c6c7f565412));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x167cf89c92d144ca3adcab57f6da0ce3be8d8d9841ee77e0c044fad974ff93af), uint256(0x08d77b3a22786b50702d6a02b1f441b92af89eda88b5d291b780850b6821b750));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x0b175c7b6939c3853c6b51d820efb0c169af6b4b238aaaffc52a7c94df73c884), uint256(0x2bb71938a98248f3d543ba23fc049792f9d71bf1d57d14e431f665e21e5dc55c));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x21aa2a77f73a257e040d6033802ce85b78565300b8074d3c3e54cae22e3a1ffd), uint256(0x1316e2da2c2345f0d50c65a13389365bde5593adff221c8ebfa3feefa39dd198));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x0b90d751c81d18e0ee4145c42004c05466f0434c59b2b35533aae520cd9a1417), uint256(0x224ed70f32389484371042e0cbb70d167dc71ddcf7b2699dcabc023562124d45));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x2bcd4527ebd0d0e34b2ce7516e277550a4435384b27f93a59d8ec223a2dcad4d), uint256(0x13f360181be703214aa27c556732f1f75bd6592b6eb91f614a3e0b2153a1ce0b));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x1b281b93424f4a0ce109ee5441246dfb4baa6123c249bb4a722e9f027ac9bbac), uint256(0x2f38c131ee532da71f96a4034111eec5d976defa58b644c7c546e755d48d707f));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x032a609c11d38dd6ae9ed828f21eb5e24889015ef577aa3c241c0d67058d2d0d), uint256(0x1f6d05cc387bd88b2f7977a3bacbebf67b615069f5af5a245044feae5378e541));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x2a6d2042169bd5eaed5c9a1656e198de022523c6b91aa9cb727f23b9246fe69f), uint256(0x24dcfdb8726638b592585262c3b86a8be71efc52e29f797f4bb091236ac4684e));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x10010ac712fb703f875e943205687d7e7c7c0bb44c53bb1f2312b9b350ec338a), uint256(0x1f9d4db1a14ecf52413ff464c5cba56d579fa4646417ddb5f17b1699cf7a461b));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x2f8ecf6f385d1e04831ac55cc107b4b11baa162c458d48268ed6a36b00e9b954), uint256(0x02385e618fd588aa82fb6b0c50d0b3d6b597fd260af91fcc0967e98adc3b8a39));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x18df617694d4dfd20cb042d99038b3e7e5eea44cf7311c07636504788dc868d8), uint256(0x22c262fd7c9b4d08d35b79d4d9dfb274d5891b66378e99a9fe18ee54a1ee16d1));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x085c9b606cb02d7fcf477214b7dd1e66ea1682e550b65b7c1b69ea8dd125d0e6), uint256(0x1ef416a86038acfc9b9b438a964ca01afdd9e7a990d585c5d08b5b0833c99adf));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x2c38cb424192686f96534ad3765a9a34ede12497f0b050a4c416f9b79ebe9fe7), uint256(0x1a1558dfb0ff372256c3bc819af5097992cfac01074ed445e241ecb738c44e3d));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x2ff68e6b32b7a8c5663bc3de62f045915222b383fb2283b0d2835973ae184f0f), uint256(0x2cc1b0edf46038ebe8b62676494734f56faaf718e43717dfa4f5af66b67424ff));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x08e8d685ad6f96dbc294a8341f7c454e1e469efcb0378ce5e10fc378e3dd35d5), uint256(0x0ee2add9e2471cc8f1df1858af7c0c610a3b7b46ac4c20f216e3d0269e2e7d8a));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x02959c837b93854abc238c2f3e4ecfa790657915b92a44d46f6d90b5377af4e7), uint256(0x02302b3d7091a92c9b1f7ce87dc0773d2801bef9ce8449d83d6cc28fb001a1fb));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x0c3eb82198e68f4308f69f25cb6538e901891485cb9b3b9266bf800d935808a5), uint256(0x045931a3b68643459bbc25147834d24714dcfa8e749418314ca17e14a7d0a362));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x09dd95e8f9e942101d0072555e48651187ea2a7dbc0e3890d42c07550be8934b), uint256(0x1d1a1fca9b5f2160b17a29be4209ad0978426cdaf73675c21558d033541a797f));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x2288a4eff80cca07df3098f932daf6d19bda1bb09005bf34902b6e96535e4589), uint256(0x2fcec96c062c3a4bac0c2cf5677b5181e1344d80017bfd37f288d5ec8bbb45a6));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x01d3373af0de1e12342ad43d3fcbec6f7d3b462ee41d17d5037319f8ac141640), uint256(0x22685d502bdd9d9ca2b62ebe90cd271c4ab1f30f466297546164298747a31e5a));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x2d2f0485663bd34e0548c1356518e2d2adb3b94d846f5a7f4f0bbdf93abb4e04), uint256(0x25303d4ae06c9c5895351dcc5609c2d14b5c883c74300366252c7881e44f0d5a));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x109e9922411388223d1d268006c89227e0151a313b6c6716ab1336ec89286f84), uint256(0x1ee672dd829ed6f892af1860ee6a82a3f3f5b7b18734b45758c4397af22b5f3c));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x187555ffbf71f44a4f665c81e64087f7f1d6130dfd98caad1e03dc532c1462b3), uint256(0x01a2c498845fe2af5b0080db66f2c4698f0609ac8b94ae076fa760888692a24c));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x056e1007539c8b2b0b8ff8970700dbbbdff989d5b5f249ff1085b33bfcd27e24), uint256(0x16ee4e97d9dd8a52cfca29092069e7896fe1759494fe8c69064cb1dcd3ef9ebf));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x0e723e6b48d5b467b8cc546110619d9f8ef9d4c6db20a07a682c2ebff680e199), uint256(0x005d81697cb7dfba66d956933f8e77b158bf479bb317774146fb0b783746d468));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x10812b539bf5ae279189c8553add07236f0894d93fdf89545434c49267c007f6), uint256(0x2c6f7a19f42487ab304fc9864d1fc3963e6c7c1a0336ba22aeb3f8c16474c48b));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x0afa18fbac0509c29b4ba49a8bc4af6729bfd3a9e1bf1dccca256752244ac54e), uint256(0x0e79af02ca73196a2981bf9b9a59f24eec6a29571c37129855972bdbaa7b6114));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x11d9c8c2582f1af416a43749f2f94f046483290f3269ed7f7249a82c01c2fcff), uint256(0x22271afa7a1b6234a6c36d60b5ee55a16ca98543926adc8f187242ebd7228ac4));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x0bb7f903dbcb87f1140b1cb969c293e1d81777fedecf85a1cdbfd18481447c84), uint256(0x1429fd8b60b5b89a1fcd03325d27e80a50e2460410bd108f765bce6988675ca1));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x0f9ac0a613f8b88c8664d8157e8feec834f0beb2c834bb22a1906e3a715a2f90), uint256(0x232810808e964404aa1cac9828819960085d470acf01277b59c73f35811dd1e7));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x063a916bb2865b5ae29fd2533ca50dcbd4a1b5398ee1ec8ed9b5a0e453c72155), uint256(0x218e1d74fda3aecf7c668f26e0746612d3c0ebc04227fa2a8cd0039f0b99420d));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x21f4d37389497325fb3cae42a9d6f17de5b4fca3327da0caefa243e199e7e116), uint256(0x10635ce1cb2353ee666b8c5f7cff4d6933486534edd660b85af2127fd8eb69c2));
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
            Proof memory proof, uint[155] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](155);
        
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
