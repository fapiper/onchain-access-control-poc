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
        vk.alpha = Pairing.G1Point(uint256(0x0f07b756aaccf1b58a10cde223dbfe6b1c8ab6d882e0d772ea7ec6c6a76b9f10), uint256(0x0e86325c2293cc26c5131dd794a186b88a908afa0ac3a27616dacb4bc338d0ff));
        vk.beta = Pairing.G2Point([uint256(0x2946525424e35d35af37997e8b1eb6dc7e2103fbece67d0611c4f66d7647af57), uint256(0x12f532a0d2660d1648bec826d801b1075c44747d87c11efcef4b0d33030a19a2)], [uint256(0x0750933072f10c930a9a78d720582d6221f4c78d3738733ca9f551ed37817758), uint256(0x1cad161743e362e15b56de44b4100a8982ea75676dd4ed9de11ffe23b21d1adc)]);
        vk.gamma = Pairing.G2Point([uint256(0x0c19f28e3f28a88cee0311228f71cbfc2246b7c9c54dbb555c962b9d4d7edff9), uint256(0x225566c8672d33f5c3707a0f5e708ca807822b6d51e09ee5485a4af52db9dc6d)], [uint256(0x0e1e7eadc18822070f0870c1fdb85ae65525e0c8c824cf35b8899ee3c5c1d9df), uint256(0x2537bbb3701e5d1bbd78a5f9a41a933f46b193b1f8e9a605985287f4b7d78f4c)]);
        vk.delta = Pairing.G2Point([uint256(0x29e5282a4c7307ca9e703602fa57791d33cc601e6b9db65d9ce9e359ae7b8448), uint256(0x19e1f44e61dc0786bb5fb444ba0ac70b638fde8e824a16733fbdee4fe628901e)], [uint256(0x0889d4e48917d36204dc0b72e550770c0bcc6be364a7ecd2667260ffab77f308), uint256(0x266c8862a5d494655e0ae2659e77ccef66d1660148248baa74a846c1d65e81c6)]);
        vk.gamma_abc = new Pairing.G1Point[](68);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0113e02ae210c3faf67526606c9e88ce9e8962a9ceca08d503f74baf9fe364c6), uint256(0x2f9e8aa9ac02499d8f3b5e551812015f7b973100d896d23058a5fb01a9f8fbe3));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x09c5a48e1780629219acfc15b24cf4c1696a0026c10a79a8c872c74f79c658f4), uint256(0x11882ed48767475bf34ef17734538fcfdab86447e1f4a43f0ed232435f9e1983));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x06df2044a81af4680b9cdb6bfbd0996334fae09209d497f667b6959215b501f8), uint256(0x18823a22a8348e84c872413b4ab88f8e417b7617fba8cbcbc69ebd40191768d3));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1488e5d7405aac4d0efb5cca0c5dd4970da5c700a025bdb8ad8b9d5b6d39f00e), uint256(0x125576fc6ea4bec3bb5f75bc91183d94a38d0fbc1e0d6a866091dba29aac7c3f));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x29805b66577d7af4a3bd8a41cdfafad4f398c71d0567cfaf33a2e5a623998d37), uint256(0x1cc882bccba7fc0dbc19459f9f16eb8cce6ee1e505f1514963dbc2bebe0e2ec2));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x255fcbac79e4888d1ac1f1d3cbf5fb3bec416ced55f19380c231f4f5f476c0ea), uint256(0x05938288e561e7069810ac71dba1093f094e8045cc6f94a85069dfeb513eba4c));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x168aa08a1a45f9f82a1b322461f1dc7f72d1e5cad7183cffe21a6604790d957e), uint256(0x19a80bbd993eb4139f289543efa6881258ad6e7ca76cf431c13a2241cd2806c4));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x09d2ef1ccfa2429cd0412b30b2fa170d9b04dced3abf006a24e739f6330601d6), uint256(0x015e72b4fb7a9ddea7d79a74daa229e36df26727354603612062bdac5248e1fd));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x14fa8d68ab95dcdfb7cf245ad5cbf98652e766377707b3f73b11c395d39d8b50), uint256(0x1d1800ca926b759d1da9e2c79502cf1090fa66d5c643bc225744f69e87b80fae));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1c2aeeff238b1c90c113588b7849f98882013f6d4066f04a539092e3cb283752), uint256(0x0a72817b9732b9e37db6fec63f43f360caa99ef2440579fac3c600d84af8f752));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2df10278507ca6939ecf05c9108bba2f6b3ec22a01e9592caea8bc842bfca54f), uint256(0x2017afabbf6356ce43d11f45f0abbb9a5f7da2614659b9f4c69d962a4383cb4d));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2fed15680bbed80d8cc90ec0a57432ccc103903185599a49ab902d34c5cc5220), uint256(0x2a660660be5bf73771a7a1acd4646965f9eaefb052e5a364b3e4de25c52d2d8c));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x169240a21f7e5a613151bf02e127f0414bf75f49bf7311ea2236026f5b29755b), uint256(0x2de1b80d1c5f111cde37b1672f43eeb78b4ad4e5c052cbac2966d4ff099825e4));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1cf14a49a421fb41fad5c6abda689aabd0d1c34ad4fd0c567db4ba25057ef534), uint256(0x2767293206f0f6b83cd5eb1677905dc9c6104e1f8066e4c97874eede9dd39462));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x236c570bd4d9592323250b5d7cd8ef550912cbbb2648467544da4f9c91d44b59), uint256(0x1f09725242e2eec83ce4f8942954b2ce3a5b341e74f38a171a672aee01a43132));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0f9966ec49f1bbc7374aea5d7e08fa910b93238a6c97f0b8bb0d694c811369fb), uint256(0x0b4a8c053687c6b2c4953fc5ce0c532fb29d47c751e51bc670ba8de8f2cf31fa));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x289a8bebd61a9084c9dff5bd7fe43955d9e4f05d24ab670579b9037de13df46a), uint256(0x274808258aac755c3ab4da0bf8a7498c82191b4e0cfc8ad3aa1a4f8e7dad95ab));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0e1529239c4019df25ddbbb0de5c0911e6cec24e4fe3afd3bd21995f227cd7bb), uint256(0x1a77243e8fb1a166ac4b73a57dd734b3452ef7ff94b6692f40dce51054a43fd7));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x0fe05c901a2bce62fd7a43cb30401fb1eae6acee42d811cb9bab89d87da70ae3), uint256(0x228ebc198c8c418374d3de78b32dd380f9ffa6a733e8b71f6083d751f3353277));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x163f843caf14eaefe8dac2d3d2d61173b8940fe918b86d4fab447bbc7872e044), uint256(0x1ca79a23c5de3d5df03bb6585c2fea63caf4fa1689ffb94becfc9c344e22dfea));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2c9ff815a7f09855c1d9a5a3cf03ed6c47ed9e7cd9f4cb2e5fac3a3159cf6ac8), uint256(0x0998bbadf6b4be288127202d25fd99c09d6423796f57a8945093d160db2f384b));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x20f6240459e1abcfbf5a403dea5ae2c364c29c0fd88a80120d4c3ffddb41c726), uint256(0x1eeff671777dacfd6414fbcde829629f780e2cc4825c0f215bc12ddb67713b01));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2423a06b25ec6c6d84e84fda8cc16dd84bc2c162802f2a262405e1beeaf6786a), uint256(0x135e15f6436679ff25af4e00f1c3ba66ffa9fc0afb24495c70865fb4ae67051d));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x17a46198903a86fe399eb92d199cb40e246de05bc726434fa2e5c36c88fa65e7), uint256(0x00bfd0cf8f5a35778f3c72d75fadfffdc6f9cc55db2670bda3026616e973ae14));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x22cbb2e87011405f7e70b487a56f34bca208a54265b2a97697dc5b38284b98c9), uint256(0x252356b9d1dd89147e4e54cd58a579746fb03e0a3d5afb3d03a1599c653de233));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x0ffb70c3dae4a6416e9c8c167eddfb2759ec17c5027bb8b44ea1047d23ce0c90), uint256(0x3058aebc0dc462e9d40c014fb82de90427e79652e8adb2a2a275edf4301397b2));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x07bdb8e0b3e02c871f7f49adef08fc65eb95f3184d866c473816b2ecdd311c1f), uint256(0x0840daa56968982e38e8369d9fb974e6203c179bbe6af2aa8b8dbe50aa2e9ea7));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x1010682f96a4fe56ec6112ec5a5b1b94a07dffcb62283d67d68ac2c2e33b9baf), uint256(0x16fce025388a215c0b2c492090c295ce06807294d9c6028122756b68378a6c8e));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x2328d84b9e1730dc9f2a28947b8b64a506d1e011b874722b236f15ff3b14cd73), uint256(0x03b8dd7594ab71e46f4f048a636eafcb34a301de95fe562b6ee2721bdab531a8));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x264714bfedee775eed625ef070377f5ce24015dd557e9a8e0e43c40ee8dc618d), uint256(0x2fd4b290e1de6aa8c70ec46153739ea85e6eda30e05b48a76638a240bcf012ed));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x02fb3a81733be41113c035fcddd154573206a44633ad9b3801f93e50fc4d5140), uint256(0x1c97908dc3e54c103692ca4f2c71c3d21bed24a5969a0ce18f2095902032b601));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x1534b037c664d67a2a3010852914ff8eeec65155faf25c63f215b91c76b9f9b3), uint256(0x2c8bd68bce8538ece0ece86493a7df1c6857eb48b2e946d9d39f79a994f6c8d5));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x005553831acc1eb2b856028a8e471f03af2f44c1d9470171b0971c872b15c193), uint256(0x28c0cd08542b5d1c79b4fedbccce7d9a11a7a10e2c2d6c3a2cbd202198cc5de0));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x156d8ec39dd37916d715d7bc98c419745bd9e98c4ef28dba47b76ee54d5d2d51), uint256(0x1390471e109a3bc0dc3ef9317efd14a8a53716ae44bfa1938ba568d8564d6b75));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x2796a3b991bd63f6a5cf75eb7369a1209b3a5fc00e7f5e2be8263bd451b3938c), uint256(0x2a2435f031caa824e13002ac984fbcde165eeb6c31e1f7af374108dce1ee827f));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x2dc14e9111d203bdf7f8cc1be9c2462aa7158beba25f4efa65b7cd448e123bda), uint256(0x2108eda488d6f3b6eb9d80e8f2071b34f9301324dbd7f9bf8a8c8e325e02fd29));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x0d8d7de8c96a7d68ca0b09907c0fc2070b65dc07b7a29a300f51f8290521b436), uint256(0x0906038600c044e9fce8bda213f9f757a1332789fd4c792e0d15b6c34407f461));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x29e34eeafb0eee364783a1ab458e97f7f9eb66269f186364ddde435025f758ce), uint256(0x0850aec1296166bfcd2964964834fbc9b55989f1a601b58eb19c4cd259630e06));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x1ed31807d6ae75eb30d3d8f51f4b6b900614343e8f0622b953f97e23296b9c88), uint256(0x24d80ea150e4b90c91457c554961d996090bebf12a4f00c39b84cbea9df7dc97));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x1298bf85b24e0d313f34efba4e76c0883fe87f5e80657e4dc5125aacae96e25c), uint256(0x112a576a006d92bc1cd122b33d5f8beefee87f24c135c23ed2ceceb7ddf6a8e7));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x12a5445b26f6d6e1de794daea6f3d97af8c20e9116413de28d1ce682982342e5), uint256(0x048514538ba0518f92886b9cb2d9f8738d9e078c8facee5f864e392778275dc5));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x2061beda9b4e99a580d6a6801ab95e62af581e9164c9464c604fd113be309396), uint256(0x1b57df6f0a167d46cb807fcc85f80373ac9d07f00419a99b60643cfbdd491e2a));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x23fa477ada5f8155bbc89c7714a710b490e8f748afb8d0dacaaf4a8f50fe8391), uint256(0x0e99fe8287534f767cc3bcddfea5befa87281e354a68f377d6827b007a3730ad));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x2e57c6e938aac39c53d1eff3b28cd328dc598b24a2acc781d5852d66caa90498), uint256(0x2a88ecb3013c5f94f2c4a3b4fc2ab9ac56d974fa10ed11802f46cd2cfba9fa6e));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x1a80143164fd08f5a407974d8efe738c460bf1f0a79b658867ee02b9799733c6), uint256(0x27e316b1fffa125cba5f8faf0135a12eda035d3407b461d66414fae0c80fef5e));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x16f4cc0af5f2652880627531b0a17bb05b1b2ad5d994b4b0b4ea3065024b46b2), uint256(0x15678717bc3be13ee0d8405c54fbdbc5211a6c50531495b4845d7c91817d261b));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x23cafb64c35d76f776fabdd63a21f5d3d5ce649b99e6c856226c8cfd8d53b811), uint256(0x0b22096683c44ba3625469a946715c7dc9be8eb1117647b3a9fd940143be5df8));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x14bd2369805b2a9dbd5745dd19e7305a1eed014f9890e185c9b8fdc3dacede5e), uint256(0x2e24bd15ffff52e92bc750b1f6c92c7d54a7bac58dc1cae0b5e220e0d08fdeb9));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x08ec9a23357ef7307aee3693942259138041b13a95931819b0f0e87534e8fb52), uint256(0x0a64fbff40d0b8eeb510d987e2d98c7cfc415d0926a54e6149a15e7508e87013));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x0990f4be547763e2326a9cf08dfb4545d0c6075773ef82575681eed58cbe537b), uint256(0x1729f6e5ef2f10da3ae62f2bab99725620d05791abc09e6fb5a6fc0ba24e99cb));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x2cfcfb4b4fcd2ede3ee926562e79c3d3490a00b9680e8c87936d3d2c96a99807), uint256(0x2946cefd1ecfc98ee088dd0f621ed600ad3483fb7b500df7807daa40fc81de77));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x075a65b6a429243f4a0d38d86d995e233a4a2cc9c795114cbb46e177a2c47457), uint256(0x217d26c17b06dc7f9f62d2d9aff1d3cf5a1fffcc3c79752bd6298fd62aaeba6b));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x2faa56d3c12189512981619871de0f0bc8ec96532ce09da75ad1cf055d87708c), uint256(0x005317ff5cd625c1f546cfe3518c22e1320cc548b38a63213cb5efa7d5ec4002));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x0ee85135aa6007a24bb1acf0dabdd24eef4f404f12eed6ef7848880f44dac285), uint256(0x1db1e8b2a98aa10ad34ebe1d95e91b837f2d7ec9512260dd4d2785c6b4ec796c));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x2ac653c025d34539e1c3d3b5ffbcf65f2171ceda456764b64c73d927a7ffdba4), uint256(0x039a3c36d228c636b9d7d192005863353402e7a7844530ab8a9a78116077a5ff));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x2b394d8e04022b362ad6cd7d01ec3912465d484c1b498e39e6b885171059eec8), uint256(0x02f497269de8476013419351c6cdbc0b20c6fb4fde4ee671dc83fbe98e815f97));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x02922bab8ec5d114332cee0b7dbfcf8779339e942de01d4d5025b5a102e36d6f), uint256(0x1bdd097f83be79c2625b8337969b08c12fd2f1f661c74b75c7271564c88c39d7));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x058cc3f0fb8b2e7a1e722134a4ef5b781399fdd8338e6c2843d315e0d649480a), uint256(0x1dbf7dbe79302d86f880c9f7348e187ee6765b5779d08d251b1013d2fb126d2d));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x2a7c90a557c5031d9bea54b6a952d782f2487722b151f0d69ec751f29f4678df), uint256(0x0d43bc6d5509de5c7778909faf532e521fa1db6aa2ec1c56ac32c79f5d8b5631));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x30323d5db013cd7957906194cd8f3233a7cdf2afed9f94e142e18b2ff1203d30), uint256(0x00111182ce964e2254210160549bd1f4d4ff1fe2c49828a46430d1df1ca4c672));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x12ae7531fc2e429ff50528f8c7105ca1394193ac8f01ac33941ccd693b3589d3), uint256(0x2182962fc085e905427e0bb48049c9401847d71bfb6631aa0d970cc6ebec174d));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x1aefd7e6cb65c5c97771db86b819db83d7188d13787bf8044bcef69e5b1360a5), uint256(0x27f4b918a81743adeb61fee34ac5d6058a96bca5ab6eede216d72264bf1a5598));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x0a21b999a58907dc07891312727300b9c124e95ae48961e416a6a73bb77bdcda), uint256(0x1483b2b1955671f20c4093579fed8516a34f708e4afa86dd601e9806e10bba07));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x0a8c120ca7c241ed6865be4dc65590662324028099dcf1ada1c25d1538ac7fe4), uint256(0x2004570bc4821507f1a85f277523da8b040824c72c7ff162731e6f28943b0ba2));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x0b9ad3e736ad31d838de4479b0d754520f71d5e1221c04c943086f55e7cd5e03), uint256(0x24cb491c74fb8f853c1d5fcd5a90bffb6cce79de51a0ff2dc1a51b7c21646e2e));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x1230081c33b8c1d09f66db96320922291f6f1554556a7d8202463486336aaa5b), uint256(0x18d627fcc8af5a92491ae463475b133a7b2f5613748c31f94bb0123414fd3a31));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x2a08856e38c83c2773344e50aaacb9e7e49fa424235c042d70c4a27b440b70af), uint256(0x2eac9eeb66742fca12b8aaafb96f12187f2daf1112439483c379babd0658e408));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x0d65d6f004dbbcc6557fa2952f003cd71d2e6871ab76008d6715ac3a0f7e2bb0), uint256(0x060cdeaefc004a2e9a62320fd4da254be185904cac99a1816ff867b9a9917cbd));
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
