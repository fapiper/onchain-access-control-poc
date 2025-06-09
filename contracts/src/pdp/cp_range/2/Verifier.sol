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
        vk.alpha = Pairing.G1Point(uint256(0x066f01255c160eefc848616f3f858d1237369f0963c363cb7e2ac0328762f6a4), uint256(0x037a408f1cd9220c2a36e32558ff89cf499529bc1965fbb06fd61f82586f1b07));
        vk.beta = Pairing.G2Point([uint256(0x2be104a4fd4ea9ae97d471366f3a2665bba6b6a9e8590ca8f0a30cfbc4006533), uint256(0x031730fae108d685bff79e876a2dc1624f46dbf39ce58f150348c4209026b05d)], [uint256(0x1278f24dc0dd0d411d76abcec1c0d75e8261795db9a053f479688e15746800cf), uint256(0x117cb191db5968aea73569fec7b15869b5506fdff8430f9f08b906ba9fef7995)]);
        vk.gamma = Pairing.G2Point([uint256(0x2f4b0df3b4156ecbc4a339f32f729f8766efcc5b7cd283378f6b2b8408a37ef1), uint256(0x09e8c2021981f86e8aa2f96d4ffb59e8d1f29bb49baf591a9e8c78534feefa65)], [uint256(0x04718e2639fb8326123bc78673461ca886e00b11c51bf623e3d167fcb2d958d4), uint256(0x1e9f947e46b7cd3a5aea568f38ef066f9881037016345a038ccd6dbaf557c528)]);
        vk.delta = Pairing.G2Point([uint256(0x102785763ef7db6b0c7c5a306a9e32ddf299b674b8577843e9d47ad16ee51241), uint256(0x15fe7a92ef71348568cd7496cc1ea6452465c2aef8115222c39df5719c1f6207)], [uint256(0x2e4ca5b80e9139d02e248cbefb955e868478c7e19aa1344ca36fdf6ead3d9134), uint256(0x1a54b67f0590f9dd199633c6c1401eb907867d17f760c9861aee97be7233b32d)]);
        vk.gamma_abc = new Pairing.G1Point[](53);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x175454cd1ecb8737269bae86ac0a220a8443cc6d4c3548c66789bdfbf6262dc0), uint256(0x0b137e4d9cb496487aa1642e3eb292957589a3b98cf0144e0af2055ff5ca400e));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x094e0893f74b099e39b8e6a0e278df8561cd0c3a654c7a425e4756bfe538bde2), uint256(0x05fcd32fab55a52ad406a2b87523429a95ae1e9f424ce6e83a7cb2b189ad1708));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2950b80299af3f67bdea34e87c75ac1204c1e89b1b8d7995e69645ed09cbd23c), uint256(0x02f2779a4d6a22f67d9e58531ee7fb3e7d02c4847e48153e250e7c0cc80dfe7c));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2a004216847ae213b4f8d830bbb7b397f1f089a621a7cf08d48456b99ec2fd92), uint256(0x019710a3f87bfb92f7cb5b870f72bcf4d9e63bef0f6a9cdc10541c81a10df169));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2b189469c6f5b9348acd26acb47d0aae98bcb3ca3c62ecc4a8b2f942259ae26f), uint256(0x0ebb8416069b6bc8b04adbd8e6abc2008d6bceb51e3345e10a61c70a9eb04fcc));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2e6ff9cae8d61a6353faeb0dff244add0ddf544fd0615f99541b10781065565f), uint256(0x12c15fc3382fceafaa9af17e0ba679294c01bf3bdc22d8e7367c06098e2ef83d));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x26bfdb6faa743055c09328cdd4e0802ef538c11e9fdc09f1b4620e302c7bbe30), uint256(0x18e2a3cc7123424ab384262b33f38c759d0eb00d6e1ceb5f1b0e104d40b63d8d));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x106bb3f889ae47769a489ffad695ef1c4b0015f25da4876408aedca7ae36b919), uint256(0x28f1f2d00a7546005adf9c93236243eb5f063a97bf5beb165327c12bec01e24b));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x293181b5a531433d21c39f3602135bbd5052ccc73caa5f14479849627063a8e2), uint256(0x0a6399e749048c2e75e7a0146333550b41ff8b0a6172fe63dfedcfe7958d1384));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x14031e7fe9d7a808c3a74cca32b5fe39839633a7edf143ce0038ef8668957061), uint256(0x224b9d948943ae337ede7ebfb8f7a95b90f4515a67ae6f70ea3a8c20516fc384));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0ff717bc5a74c4f3d24fdf1db20e35985d3bed69c1b5a8c49bffded075d54f80), uint256(0x23907218e215e249ae68c40727e485d21c703c942176675ae7c2c1c69956fa34));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x165d697f615e83ea1f6c81a92aafe1ad6389a9f44c6827fb1aa9fd229df7fa1c), uint256(0x220c0737b5a24acb1451e4c7e67264ad73ee6b66eaeddf2ecec0339e6845dbe0));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x28f9bb7310cab7df39eaca3047e724acd78ec9cb48750c978395ef1e1bd7a710), uint256(0x1510a05c04c6e973b79a86e744123e9fe51511b751bab611f1968138f445b774));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2002c6098a6266b08aaac49493ff4934efdbb3eb91caef9249a1ac324cca74e9), uint256(0x2211cc0ca3a4710910fb985f9b3d614c21cd9ea07a9dfd6c178507cc53215fb2));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2383a355b84c75bc5ab9985e739dc8e0864ba2c4bfa3e6b01705a362054056ca), uint256(0x19050a904168d68daceac817ec2fd3ca3b14a0a0a2f61e33d5c5f3204fdb3f96));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1a0a3b44e7f914e8bf60f39dd87f22d1ad9acb03c4a1a6dea4cf1678fb91652d), uint256(0x2736942aeb24ad8272a0f2a8ba5e930ff885b0f5997667bb15a61dc3f3254de4));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1efdf3532d2bac8450de8c0088e627159cfc466dcae7c327ad32f71651465aff), uint256(0x0507d8905e0d1a42743842025c9e430c45f76e74ee5a8c7a891ad43668b66617));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x00a38b9e1d568519d151b67d7aa80dbaa87e643bbc52e304f40e6354e2723b66), uint256(0x1b9863c4ab7eb88c693e30a17bbfbd896bdd6698f943966cf55f21b98a164def));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2892766bbd2c3cb2b3a356801da8804e02510b5ca75ed389d5b21a48355588f4), uint256(0x08cb38e21347e5fa61c054110c9af58b98972c60652507c79ac727be0644b25f));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2887064c504ec1fe922b11063807582e7f380f048340d8ba4cf958cb7cb8a044), uint256(0x1d6e2ed403ec208f4c60b58210dec07bc305bc71de8f10025df768406f7e41fe));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x06954130bafb97d44be04e09c7cf4ed2d30dd57271ee0cff5e705828d20abded), uint256(0x02d6dbcee7ddfd8e877240bfe3cd228999f326abb6386ff6e1c548e724d8078f));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x06833f9edb9a69e6a040ddbdc72d22b6845d1858896dcefd413c1a872bfd1e2c), uint256(0x244c6d1a047529bdf9a139c0354930c1647a9c9783d15e8ea9b5dfdf09ed07e6));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x1360795c91066a97b6f5e86491f3817698cde7f2744ac8974b8d01336c0b0d07), uint256(0x10d70158d86e2c556b502ffa3f0712e726b5850fe32df284c6dd03e0a834c602));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x01adb1dee2ca3cb75a0668b3bc90d38a1d59400c2286cc5918278a84cbd0f5f2), uint256(0x0548f48e132f47c5445f6fab4c39367cd90929dd39a7984dd43a13ebcf6d2ca7));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x1fe4606fbcb761679f84e012c1c8beb17df9be0d6438515b08831d2fb543d6b8), uint256(0x11eb8a7c7c0d0125bd5e77dac5c6808d092462917ba911b9a05ae220216f5e08));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x132e4e10371c00020b179fc14883a5d910387ff789667adb176b03f4d9c33cb4), uint256(0x0e9e8cd9949c961c0ddcf3dfc204d9fa2968e5f5ad822fe56ab74e0346335ff9));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1490f6ce5541c5a7d82f70c76cfa2c0a9194650348b6781f68ac551466692c2b), uint256(0x298d08d4fa8e58f8fe6dcee2045615165d1470ddfb118fcb6ca44252b8be7300));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x1f0d46d279b53a0b5120f1ec70e37f19aad0bf1841608d377b0351f379e2a9cc), uint256(0x01d4cf9c43a4346f6ae70d97b305dbef4ce0fa8c9614032ac22c3cd84c42db91));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x2a28a3a86660008584e35602bd2e66c77e49541baf09eb5a09dfb2c1f265efed), uint256(0x1cbdcce07affa75e4ad8d6b250292738e8928e4a6f164874052553808cff10c0));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x1180fe43ca22c7f7fd15866b1fb134260b53fbbd7f14e26f1d62c3b64a919817), uint256(0x0b842d95563421e1db3054c75c4ad2700dd05bb5eaf6b3bd0f2e56983289eb84));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1b6e4dedd053e778cc3271a02731e39c3dc4f5e83a1badf5c9a5b604adc33211), uint256(0x108f2bfbf62bd18f33cd22bf1973feb3ed9e289ab2bd4527b45e7a1460182466));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x27b80ef1fa1dbd87f20f8c4939eef15059500f588c27b94719b598a285c8a3e7), uint256(0x2b7bc3abaa17e508e16f7a638137ebed386d5a0cfda4c4c3b2372a07dd77ec67));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x146ec0219fdf393201629f1a475717c7e02ddb09562aabef7373c18e7cfbe644), uint256(0x2e176b33247ff64a2572b7a1b7722676f4a2cee9a6e8e0f02abb95ada8222bc5));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x159b0ffcf6abf6b45186a8b920654c1214251c75a77001347d89fbba8e2f0138), uint256(0x08deca9d95083df84fc9c5d731e30b0cfa65ae00df3773c7b07254be1c5f06cb));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0ecaa864cc1d1a22891b94972db9353847ac2fd0d6fb9f748890e03fed139c11), uint256(0x093b92525137cacb19720293cd25fd6d8500be1b2392bffe4116812a1a392534));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x1505df6568d369366b1c9b12428e0c39a5f8f05a1270b5851fd5fa18a53966ba), uint256(0x247fef8c128fdf840c01e0f1b6f20d0d70e133570a935b275ad89bf88327503a));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x16c40536b23e16e46a468982314c493d4b850940877e4721a9f66e79c8fd4913), uint256(0x21962bcaac9220a2a4bf2113df0bd96a37fc97dc29d29034e6d9c282b7d089c5));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x209da1d2a62854020371d288b31cd19054ab1a4816e554d775fb5c0681e60235), uint256(0x2df5193fa311c7608b407f369db866468c82eaa31b6967b9f23200803d98f3cb));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x1775ac1715e99e320d770a6940998c87dfef19836c35c0e7bf2db375827a2e4e), uint256(0x0cd8a379f8da7f7d947e87caf3a4dc0147ada6d9db5a8e18f4bc3bc3c3b3ba0c));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x2e0affc51164a2641c567191b64d9329e812258f73c7734ab65a928ee90f096f), uint256(0x227fc2ed365154b75b8a455c4658b8896d38d782ed196c62e0876d95322c32c2));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x02fc862f79fa78b392e91e4533bd525f9f6790699895a4cb6d4a14d9a91e9721), uint256(0x07ef9ff95dffd59405f9c41d67eef698808fd839bb9ba94c6bea586b1d32544d));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x29c32ed4ad916b59e2eca2f2ea6a73455eeed03d5a3b211278b7996ee3d542d1), uint256(0x0629e0be28d1c195c1d8c141be39c9f619edde8272c30dd64f1a44f4fc8fb596));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x035013a160022c267cdd0187ccfd5fa32df71f365f794979ea44c451d7924ec7), uint256(0x2c16283beeadf11453f4d821b43c3cb945833524ee9b17cfa48ae8c0a84c5a1f));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x147e7caaf5b4de3dc5d661880c0c3170603db06beb3c3a993fd1c7e645496320), uint256(0x13c6d17a425c6c29986debf8930bbdc19f093b67b8bc2c3657a86e2b385661d7));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x071fcfced13fec4eb6ebb4f9fe2076756f36388d4f604bedc2af587170ea5d41), uint256(0x2d7c5d6f9837bfe112143c559c605685ee1f227c0ba025c2b70bb83bddfe5581));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x104bbd8ded2fe4d495cdbe36ff192fff7b0e9a39643aee47b8d23a96154284d7), uint256(0x2dfeef37fb11d8e800eda3b6d6f8a8833c5ceea271f19db2617daaadd15d7f82));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x0801b11e05226cb83de6b99830dd052e8cf846ebd44d7aa49cf867221d2f6e0e), uint256(0x03e90a817818ee070579065a6e5684a0d34bd8c58b734fb1e15432279cab5af8));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x11a191dc3ec58c9714629b0d1b498a0a06cff075f367c78f7b83fc45de708c69), uint256(0x0c41659ad3e1c89ae0b35856f6ef1188ffd13ac440c287197fff3713d99af420));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x263b18dcce95d538d363065efa3932a3dbcb04f27489fa5d6bf165a4f618b9f6), uint256(0x2c471bfbe5724652031213b2a6ed3d31ab19fe36d3cced3b234507791d8efbe1));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x0f71dd740eccae5c79faa16cdd9d40ee4ec229e9693a137879d161dfe3fbc27b), uint256(0x2211977c5778af791ffe580999ccda7e2a4eb1bec7a58b51bf0173213d191f97));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x1bd00f3835d83171c10af8599c1b490dbb7d3047ac91800d6f0adcf2d3e244d3), uint256(0x1478dab5b6f542cb9f97e2b51102394bb762bf8d10cf0341ecde97e515b7cfd7));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x1df0759f6b8c071e7a275c68d8c63f3b56c1805892742d812af519c732095ae9), uint256(0x1cde63f0fc9b573a9f2182014495c8dd2e103ba69e4337f9b1b8f0a44a09d467));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x182816537fc180dfd71d4406ebf11ef3cc448b70cb0a79ea8f186fccf9cf7371), uint256(0x027a2e60314e2ceaa868913f973611ee544e550c9bfcde36f287c7164214fd4d));
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
            Proof memory proof, uint[52] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](52);
        
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
