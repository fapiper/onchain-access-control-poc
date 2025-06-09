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
        vk.alpha = Pairing.G1Point(uint256(0x1c6ec18b67e116f618d3e9e8671ada38c6ff0120acb73da610c0a0079424d7c1), uint256(0x26d72899715f3dda681b8b71b3a70aac16f970b8caac5e0b6be6e4e00ea1c3db));
        vk.beta = Pairing.G2Point([uint256(0x014388433779344f126b32b3abcb65cf565c3fa0cd150dc625d12e72cbec89f7), uint256(0x0e6725d3eaca611dabcee5ae75775f027cfd221b7bd9bc16a7e552906273194d)], [uint256(0x0c2c5574c27446ed26ed39a58ce1bc85e314dc38bbb3b525be43e8a22a4e2f2c), uint256(0x1312dce7893ca9f8c1d0ccd6ce1eb74e4dc7e81ecd75bfa1c4b6a8e31d85af3a)]);
        vk.gamma = Pairing.G2Point([uint256(0x2dc0ebaf423305963cb242175969079d5c88dfb9654fe1740a08b361404c7ff6), uint256(0x1d60652fd9a48b3ea898eda4e2684173ef04bfcc8591b295725b5731d2d11029)], [uint256(0x240afa7844573a22df6f962da58a5f60a6365679a5351e6197a51f0aae86f7d6), uint256(0x192e84f1a8945b5c6a5feb5f43e1b9c1d361604d7b32b189ea1c6f86beaee890)]);
        vk.delta = Pairing.G2Point([uint256(0x2eef9881c09f4b7a67491ff9ea294a34695e543ffecd16fa6ddd8fe9f8e3ffa6), uint256(0x2a9002e69a58a83f728c5db2c4aecd0046012d41f152c46aa612b0ddfa888022)], [uint256(0x2589177a417c09c59577e5cd8030e7677030d48d10e558479a96cad09902d4c1), uint256(0x08a39b66ed6d7d748509da34a3947cd9737b5bfa2422002266e64508c87bb22f)]);
        vk.gamma_abc = new Pairing.G1Point[](68);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x230beba5835bf172adb0528a5f256d77fc99f65315e8ca45c7f814abb7325aef), uint256(0x2111a22781984df894f5e5aab3084f6c84bd5663d38cd9a9436b31d031b68668));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1ad7a63355d1bcafb40a7739ae9b4abd21a8bc43f8bb47bfe16115f3d582da10), uint256(0x00aee3c479f95198ac2407e547dd32386e98ce3ce80d582ff945e0dabc0ec23b));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x27109e3bc08a19ba511500ec40fcf068eddcbe68e7d141412005ce8d10a1061f), uint256(0x25af8c16844555bbb09e4e004416bc12068eb9912a422317e4cc7ed00899edf6));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x09a71902199dde06d2a737d699669ffa288f8f80d3e22c79d734d6ed29b22dc8), uint256(0x18cc4ca1fcc32def7f25c33f98a985f2c0634e8152d0fc09e4c43a772a058c70));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x15054b77fef3a2e841ef98509c212503bd5158d05d1ca22317af2dab4ecfe9ae), uint256(0x2064b5ea60827219f2c0027acecc7dd61109a4f60b91f218dd087084490d9837));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2b3d9ea42dcecd1825d4cd381163ef0e60c2bf21690d9d9d3ad5a07b14575e93), uint256(0x245f813d6c0d21cc8a48568bcf3ea5ffac4b67e58388cb3a9337b28c69e4dcc3));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0b61b08575d6aa8ebb0ca358335ec01c6baf520709453d181624992677554ce3), uint256(0x13b6668816a68b9415a9937c363a12ef17eb9d7d5613bf63254e3cee6155f889));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x221e8e2a601b0a1ba338790f0c9ff1dac05dd9e40471152bbccb0953bb620e54), uint256(0x24a338620796051649af4e748a98af77fc2b2052ea0ba1fea65607276a020c5c));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0138e5133be6de4b3669c0e19ea7517eb5c06aa59d789821dbdcefdc10021747), uint256(0x0c933573a041681dde98b1b5ad6ebd996cd9621a34011afca74e0709991dc75e));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x299947effb6a6fecfc6c93c80794f3a8de6430eed5417c18152a5aef303c4767), uint256(0x131cec96494d8657b206dfcf89a9da8dca698e75d0929fa8ee0a2dac88bc0f28));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1d3e88c39509f08a91230752e9091f3f62a9064e7d0365648dccd87a16dc557a), uint256(0x2998418c339d10adc84811fcde892fea8c5bfeac4dad00612105d5c2d47da91d));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x25e39b41e6cef30d94371e26b286dfd49ea293a91b4bbae3f7e6fa4055f99095), uint256(0x28db69c862458e1ac6c9208fe36f6d797b1a12087047c791bb1040f3c8f2945d));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1dedbeb90a0f3f978fe3153bf33234263c2cbd6d5fdb516648b3ca34d75a38d3), uint256(0x240cdeb99c14deb28c0981dd882bd1228babfe30a9c3f1dbac960fbf36562fe5));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0b8964d3b98c5397014506858ea2028feac76b2789a8887e2f9e0a7256bf744a), uint256(0x16c016e8ed819bcb94f9b82f49fdb16b97e3eca21a1f9f800b2c6641de3de701));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1fbadad4c0a4ba9817ce144b02b913feddd1454ecdfb2fd6fd86bad25f459e24), uint256(0x0bcf651620ff450fa25ae6585c8e45ed5c9b50229eee5276390d2a1fa4e37e8e));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x25527256a901d013c14b70ad2652f72266fad6c0c7ede971c6fe2d33f226d569), uint256(0x1df1fc8689f6afdbee7ce5c5de3c3fd3fd4fa891f5734224406e265550e7bfce));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x0e9259c7511e4d3fb45733dc86408c95c1f4711d13cfa63cd48e497c834c872f), uint256(0x0bc064df2557863e481794f313ac3d581a57860c9ac38702176414e7af02eee8));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x22a2313bf1bd95597473a2590a899ea4078b9bd1186f7ac6a8b425175e156ee4), uint256(0x08fd39d23c42bec1af8e2d7f986e41136dda6707d9edbe25ea4c37f6431b8fa3));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2116361c2ac3130d4de6de9f52ada9499a9f5f508301a7aa63ce9356d770e9d9), uint256(0x2725f62cf53cfbff0410d61a4bcc2a7521f9381f4b7b7c8130977d50e0bcaa86));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x233b1a809e9e400f41ab6eee7a7900e90951ed6db761ad87812818cc2f7d640c), uint256(0x236d977c2ddac60bca4a13b8e4a3179a9d6965a24a42e3bb713d9e1da7cacbac));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x0fe73da830a4b8b80a0e56954c04203c990e64e505addf84c0478e262d44c6f9), uint256(0x1bbcc172e079f75859596aae5a1f50b0fdceb7c43737fac60088d4bcc8bb5b91));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x2e859e40a8c25d70f14ce90347fb21e1409e532f405648d026705dfd4c6e81fe), uint256(0x06a19bf242fadd358aa0865d6f2e242442e581ccef842938b4d5148a0f6c3b73));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2852c7cea7db191a1b9ce4ff996d85802df109d8ca3c14724c3119a330aa020c), uint256(0x24edab4a28eb8eedf024ec315728c5f1c6a44a0ad5bf6017c83239ccbcfe2520));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x06c264131c42d79a2fab2725bd3ff0f48f4b6bc6783230c1e4746e93d1aca885), uint256(0x19c601ed6c071e290aa45aa641eac20edb213ad61820a52ce63b8bc055f13c92));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x0ab6e3eb0edb54463930f48168a037ed97df9e1598d84d33ec282e66e8d0f219), uint256(0x1ceb4d3391f9441297aaa93447b39b5165debc0d8c6ad865bca2c9d92401bbfa));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x148f56bcd1af57084c5b7f0b23ee13417136f8cd51963b9961e4c751d713f46c), uint256(0x2ee5b30c472abcc6b21bdce1f175716a2cc85076ff3680de89830922ba87ef34));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x028aafc9b0bbe003ac178a48c1dae0a019e1b1df65bdaffa027bc11fd9bba08e), uint256(0x0833be4f92714ca10f2f613e2dc12e34e748c9df1359a5609c03e1596ea7161b));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2ee3900a46f766b32403ab98e76c98341a2517e0e7fa21f1bd899f8aa42095fb), uint256(0x1b843512a9758750d9e01391252c6f5c118ea653f5f7634eb560ea1b928dafac));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x15d60894e16c6b01b2887be16e8a213dd49cf47bade3ce66540dc032b35f16b7), uint256(0x06e87b0e6a65555f85071e6d64360bd35a3e01eccdc933df348d3ffb4a1ea4f1));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x2638d49f35302618fa1914d7a227591a13f3f962eb8dfdc425ee342c892a094b), uint256(0x1d60a3f129fd6dc401d28f05c312ff9aafa0a73707c41987c5d0cec59c37f565));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x0946b79f885402ae706faaee77ec7df8eecab5ac3937228d8d7c3b4a6744b4c4), uint256(0x0a6630764bbf66ae928f1a1ac31997125a4f0880ba1b07e643d25da4837dc25a));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x22093e991fc9ee9b8e3aab40462482be78379597bc2c57e335310633e9cce88b), uint256(0x151625086bc3936c0930e47a4d30cb051c339b5526a447f54f259b8da408588f));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x0f6f32711cdcd2bf08d1dbfbd5bcf2da43bd2fd7a999ea890f98ed4566aff3e8), uint256(0x2d6bf80bb79b7b63cab5136802b8f4c38d9f0b28e9993dc95890a6436cd31e4d));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x092a5147fa5b95b013e7ccff2b01a981797a8556daadaf1ff005902761fd8464), uint256(0x0b4189c341f82b96f2ce7d992149bce01e9bd60be729dbb44a9c885cd6b08146));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0fed87ff34762c72a9eaf02396fd52f06f6b8f353d19283ce38b9713d46b021c), uint256(0x27590fc27251d6f2ae8be1363a488a84af1aebe41e705d20e048bf9141f6d465));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x07759813717ed89564c35e4d0e8a0c90845f70e900fc16da8378d5b460ccea40), uint256(0x2c35e6da88029d9f0fff43fbe0c6c7c4ddc8f959976a9053d634af0a37479edb));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x223d407979fd55d3e87f5490fdefefefd053595f41fddb56cdcdb014de4cf903), uint256(0x103313cccb07c7a9b214343c394aa71ea42ccb2d98e7a8ed5851143ef42f5033));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x28204b549d426f46e5c9025474a70a74facedf1a04f81b86b597cfc23de84fe6), uint256(0x03f6be6a58980ea12825641f7cb0438ad299a8ee85a62312b55439b60d3709a4));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x0887dfdc32c5522250513da394094818881cd9f89752b9adc20b924d657fb9b3), uint256(0x0ac47d3fa92ecda709ffe295fc65cdd1f452170fc3bce73ec711efdb6d13e2de));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x1bbc830a0b53965f9ccce808f9971e50e5e7a508a73b987c02c95a71eaaf6e5c), uint256(0x010375f9f33b918743160a207214e2ac4128b7db0e548dfbb08ebb281ffae9f8));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x0c3a66feea1926f8ad6e6b2e46c073a32b817fac1842921bb62b42f873f9aaf8), uint256(0x1bfd2406e6940cc4ae736a6593c243f7a5b5339981ab09dcc99327eae4648ea1));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x2670c9b1e535fbea0b40b1a9c2e699d374fe7ba6848199cab072bfecaeb03137), uint256(0x265c31b2c4dd0ac0a6098ea3e73c316a5a31c8e03b8914999090f4950edfff29));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x1a0b4ec022892fbca54d07312c6da4001eff06f7f81bc680f23d2dda665f9671), uint256(0x0b6228fe8b1f21595e83e4d2f6a8872a614b9716fe1b1f61cc31bc6e952bd60a));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x2cca96a072af37fb62f71979850779a5619bdeecb4502148d3bb6dffb70c0e59), uint256(0x29eeb84854d79a084093ca636ba341eb6a24ce530e431af715f8c5da1dd0bfd3));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x1b588a8105308a813c01fd1f42bb6bf76efb7942070a56119be66eb67e8da6a3), uint256(0x0ca7486791f78cf97f1d770014e5fb045d44daecb26665c71f5478e18a5ac37f));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x29425367a728291d500e9f02c19277d18246bed841f14a3de805fd92c2bd0f0e), uint256(0x2608951528979755b1246eb260a96c35512f1e13e7bc0c5bfd1d89193f421414));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x0117c8c504943c24e4588a82e0866f1063fde91fca9f720a6a560913b6fcf5f0), uint256(0x2123818b6a4ec62f9e5e8d6345cedbe45522e4499450a3286499e7fa3dada09c));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x0d5dfd15ccf20ae4bcc47996431b955a6ed94c24ca332ac2d8d97ec2ad6fed84), uint256(0x18cf04ee292a8bbab5db70739d2e4d89d2cb72c7f8d7b6a0c4769c60bdf6d310));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x1732dacac57ea4da907e2a60076b65f06efa6cf696e399922fddb251a0f9bd1d), uint256(0x0312adffb0667ef142accca32f2112e8545fd0c616ad7c8a230b160d570d7b1e));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x0ba1e8326de4c5cb5f36a0f36ef88ad504b811abfbef8ab947452a2fcc926e02), uint256(0x139ff6382e5742898079aff79f123bd416a6aa513596dda6a99e9bdd8d5320e9));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x11f8699004d91177e67c7a07087a5b5bd2a68f5cc863dd2ae81ffd474d6e99fd), uint256(0x054b139d9af55ae4c403a483dc1f41b224c53b289ac342827be88b42dfde59c9));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x25612d63eaf821131da8f597fe11d6ed688c1540e0293f08a147f217fc0fde14), uint256(0x24635ec174f7cb271fd333ce8939ec9b2cb437551d8eca4c6730785af42f8254));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x114da3e7738caff12a94ad767e9d296c155cec943ddf692c2371fe0b94c467ff), uint256(0x24c0965caaea4f6b98583543c71575ef584dbd7fdaed0269226fe2c7ff198516));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x0bc96031716845bf575228e2ae8dd19c9be4a25dd0524687e4aea7e432ab59c4), uint256(0x218943689d0e77541e76708de4768fe31520a624a8a347551cb3480dea20c04e));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x2e91ab2d81d03d4d7ebc9312e919ccb622e4ef4766306f69cb3a07290dcb1c2d), uint256(0x29ceb2e9c0a11c4bdeddf48f9c4cf5924bfdebf9d351b8babe6ca047b2886da5));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x2e5af56ce20969f994d68e08fb2688409b6f99350900a6b370652fa0541e962f), uint256(0x2297ea5ad14d6e88b2cb4eada05310b84a8e61393dcfb30e1abc50c78741dbe4));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x045971a1064733fd5525091e64f334f162d2db15b90d1a77e3fde03569b98f90), uint256(0x17c9e5d8be20508c35fcdadcf567bc377647bda126949d339db58cb913d5367f));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x0547a65facfbfc7a2d379e291bcf5fec8118b81d7177516116f1568773c8044d), uint256(0x0a11122c428d32eafd4222a203b632b455be462bf65b48d90c14790e0646165c));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x09feee833191a641528f7aae6d6dfe950b652eb6ab0413ed3c37ef581c135058), uint256(0x1cc4d3276718f90899ec8ea4bcb769dfc7d24416c6c00730e6f30ce029916afc));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x207b744334eb01155ba810e3ba3ac5dd5d482651912fab5fb44b2140530a684c), uint256(0x2bd314deb94d5707954f2cdd70d4d9473103864d7c2cf7cf8c8395cff3d29de5));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x04bddecfd1a014eac8ff350b5dd7b221dc6fc6335ef5db7934fd3158beabeb50), uint256(0x0d2bd198637552fe2ff74a0781a3e32745a947e102c8848cf5414265d1b480ce));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x272e2b8a56ebcf96c5dd02cbf8d8c16c120a981d4fb507795ad2e39dcbbee21c), uint256(0x165144e317f07d6986656704ef7b03b04c955152f88c8bf6bc8a8436908468fa));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x047d1899fd9e2640c66528238201a435273c3ef09774821b19f2ff1da02a721e), uint256(0x1d4c2ca67db8852934cdf7c95881cec98684053ff73ebd3578cd541d49b7726d));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x191d6a583c874406ac808cd32d711bf0e047b4a6c4f364a359ff344db69c58f5), uint256(0x208036d5ca6542f431d3f3bb1e947497a7d1e6ccaa84747000eeab8cc9f993bc));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x04f672290e07eeb498f84faf0b135c8e30ebbc741d431327583342868b76c363), uint256(0x0edf0168a1b2e61c5fa8ea987633fa78e93e99c1c8dceb8fb4127a27cdfaf387));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x1484ff467c758186e5e09dadc469612891b571d9e697f92710480fcad462ec40), uint256(0x0d4cdfd94966aa2cd26b50ced0af1659d77571e7eb0bd7c33f2c905283d197e4));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x24e11e46ee7dac28722851196134446347a30d9b227252e205a5182b9e2a4839), uint256(0x097353d0dcf0b7e44a7168022726b0bf1305592c38425577570ed7edfc61b30f));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x0fb9782832b339352583739f3122d0faa6ce977148d77f5a1fcd9f1f9fe25afb), uint256(0x0b561367bfc2e8c21e4f8922a1bf5d5b7fae2b2b8f71819a7cec1aca181e2e41));
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
            Proof memory proof, uint[67] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](67);
        
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
