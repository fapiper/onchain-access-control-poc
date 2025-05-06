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
        vk.alpha = Pairing.G1Point(uint256(0x064c9e83cd50f26a268e0f139d79475ad882f593c38f90a558199ca948d3673d), uint256(0x1dd39def9e404422e97f10870363cfd47bb0adcd37f2b52e4eea106b6142d6d3));
        vk.beta = Pairing.G2Point([uint256(0x184e72eac2a70f47df2fc5ed93017845391e2d145973ca9fee9165134d077bfe), uint256(0x1246133cd428ec5feac640a847943a86a2a6a280f8ef3e7aeefca6017db934ae)], [uint256(0x0adfc25e73c23e339fb47e57c1b44115940eeb46849f42ee9225f038bf1376a0), uint256(0x1896d8aa27b69e753b3d1a1c032ac2981f1b0af6cb9b9c2dc8279ec2b604b750)]);
        vk.gamma = Pairing.G2Point([uint256(0x1f13f739ef6b64c82d3fdc7bb6a3fa365cbca447d33a729a7adb05b8cb5190ef), uint256(0x24b4c8d7ce252efbdc55e1f39aa0d1c9c65d18c1170f2c68579abb6b0d0d6239)], [uint256(0x0917a845fe72bc899c89fccbba79950d2b1fbc2f0b199f03292bcf9b7eff0a11), uint256(0x29d7ce0747c25fb3be53e4ea3ba0fe63db08d1615b518c3d1588b9a3fe9475b9)]);
        vk.delta = Pairing.G2Point([uint256(0x07010beb034fbfa8e350eec9f7c2a21e466622777c7a4e27f733582beeb161f6), uint256(0x0480dd27f44a7dba07262df005e112f6555cd502ab3ce8be42fba3c4f8e3a7ce)], [uint256(0x0690c2d267d76cb0585bcea5fd5f4ec283405641b3ade31d2a561043f94613c9), uint256(0x039b9be939874394b5e7764130b2772c0c0a0a844d0a32b6213e8c49f5a3bebd)]);
        vk.gamma_abc = new Pairing.G1Point[](36);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2eadc23f6af81233feb633653f7814995e7a7857c244d1f5b7fa0196c29a1479), uint256(0x247237fccf7157e539d5db40b1fa2dd4658f7542d7c617cbd4d2cebb4295c386));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0f4a6bc1e34f67b3771491b84f84fac0a1be56456e8d1f700c75cea296347dba), uint256(0x107cd8186e4a3e5d2627a5dfcb03b717b3afdcd2894a905d848eba375821e02b));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1ac9f78a6e67a13ac390edd5ab6804bc8fb2247ef01fe386439a4cf047f4df2d), uint256(0x06491964199a0d6f0829cf74f7e410b4f16f1843446b48fa87b0c5cb02643793));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x066f44e88936d1d63c5f2f95180625abd3a0cb08b5172c468ea9c3795c6646ba), uint256(0x0d413d2300f32a808e01622dec60ce3a4b90398d3531f2c91d1855ed427f2632));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2f781eb57715ba0537f4822f8edd07149098c891050f58de178e9d09da913dd2), uint256(0x135c54cf27acda5f83e101414968084b665f96de6da76639fbe98a99dabf11d7));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x22ad358ea2c6fd46d5f96929ea37cf6f29ef1d5126aa53e85a931aae4ed74501), uint256(0x0fef6c8a26e844d9ed9c9d82ce0eebeb24b86cdd76d33f6fedc5f53378ea4a02));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x230a437551d42160ea154a0676f3fb2ac100fba21b6edd58cc9df71ba2c129b5), uint256(0x0fd6a917623a489b19e12a54bbe9e7ebaec26ca2fd4084f11de8e5215d46f191));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x20006230c342b82e99837d7413874d5f9132a56ca780f3fa984cd0358ac9b724), uint256(0x17461ae4950cd81f5a0af3838ccfe63067b74976b54fca7572c7ff617f7f94c8));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x07e572fa76c3a8a5747ff91ce1ea8c5c3cc1a35cdbc7f36c962615e4596e98df), uint256(0x229b12c56acd9b8b16d8f268f8ba4564f61d8c4169e6e1d6d508b7d1db08d66c));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0ee2b336eb6e768b0190de9bd4bb373efa00810a85a4c352902906764bbe3a4a), uint256(0x1eccd8e3f04697c0f72e9ee506eb37058aca53de939f0c001ec6d7472893163a));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2aa7a6d8094a4066b8a84ade1852d4738b786cb0a9adf4ebc3fac75df22626c5), uint256(0x2ce23b226967fb1a58a72a9985a3b72431d9e37abe5a85865c5559d702e374de));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1711effdc53450de6fbefe6077b64c39c354eb5cb32778f03536450113d15f13), uint256(0x25170034abd9538369cc29b74d672e39b63bba08c988c6a2a09783ca34ec5273));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2f65b9ea521177bbe54ac5f893ae8f41c181e73fc96952c5738f0b048831f44b), uint256(0x26bf9f1c1e710dee0b3535eadbd71c4417555749688d490189451a5b7cf297e8));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x00273bbd92ddf8a56cd3ccff850d95631b64614504cc160ccaceb46e275b350e), uint256(0x0d8230104cce40ee609a3de68c1bbc0bb9f809eb519164fcc93fa7a23c7f5893));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x17d2f414aa15d8ecc042e78f38d61a4c858f9a29fffb6c9c4e24e859ae20d9b1), uint256(0x3012544a6a898bbc47ac004d615ebea7b56bdc8fb4c0cb5321f59cd8eb200e66));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x07694b35c34c8c04a0ee0c41d0f66ef13cf2bff603f91eab9c9ba77a4c0aff7c), uint256(0x30522ef62253e29bcab0e26ea4be0da1f13304d030b7b87e00b5e1e196c11b55));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1d8bc7463931dab65cd085ae8ec094463d9fe4a34ad15b7338d1a42c48d22402), uint256(0x077f7d7aba7b9171459fd7e9247827ce60c4fc6943ad2703c34f4e764ccc77d8));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x18ccd7ffadd4e2e88548003476666dc7cd158aaad645605d7ad054a0c889ac26), uint256(0x0479a7073e43dc042c87a769f55690b578f5987245e98c2f0fbd65dba1ab6462));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x109c9dba870125986c6e89735ba3cfa46692dab9d3a36faa1e43fea1f47c366b), uint256(0x111ad469816193f74d498bd72d0351e0828534109f1a64c8c285f3d6e026397c));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x296913de0ed20966e36511f8410a3b781e29ba35a6560e3f5600e7ac9f3b62dc), uint256(0x1a6e5b9eb7c1ed5d7e0386f4c77356386949ae0e621096ffd5ada35114eeeea4));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x13a4f9ff7879ed3d36c7b673ae9866ce8970ab1027e102e33608bdf9160ecbd6), uint256(0x10306b3244b23d284d04ae26021937f87c559776dbaf8869be48e3b20d092ad5));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x2fadb3ab7197f6fad73db2f6362d92778d791cc5221cbb55a6d2a906500490bd), uint256(0x1158a6b0b5fb467ce87b4dd7160d533c7a42deb07718ad42fd274477b35b7b23));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x21cbb235c9172b91688bd9c69978aa060608afadc83254959576de8ce68b6463), uint256(0x01cdf764c4ef6e8ee0e155d8fe2e77f60607bff425df164107dffe333f701b0d));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x16057a6fb8b825505514d734879d6ed1ab8d786a7830d435d8509b086aa653cf), uint256(0x2ba26d71c4010ce4f78727a78c4ea3c83ca85f8bd0c92b09bdf7001525c7a901));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x10a438d66a026e117fffa9d14320d467d1bd9a90219c3a7eafc1c7c83efa6432), uint256(0x2612944011d9d32681a58f4d1279dd9b0bfbb174a33173e03dc7975fea730072));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x174f1f8040eb101cdf385ec4c7b8a0587afc8a60fabc6ae44c11318a66c1c80b), uint256(0x101bb16fdc2a2a114d68f167aab987a5e298974860767adf354065a7cdcefa23));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x0385b40e144677675d77a5d703f3213ca9c2b9876fd0f97469a62e481aaf84fa), uint256(0x082fba648ab35bceba47517b49c44e6531e86c0fb21485c0dc7cdc3951e8a35d));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x145ad0fa7609e40ad129082b28d5eae5b236a60a1d1c088306c8dc60e29aacec), uint256(0x279d508af4643a6b4ed1d4bd7fbd078c1cce1e9f525208f6cdb1816164c3dc1a));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x0a90577a81f532e9832ed35765cda617f49ae01b3859d64a11090d472204b5f8), uint256(0x004c3b863cc609a6dbaaec1a630afb8853ae96fc413e600e7a36f5f72062407f));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x0fc2732f186470f4b8191f3a583bbd4928775c1bab54c247da5d8d3c8166d4c7), uint256(0x1c8482c6cea8d5eb9d631a7d8159a72b4198aa3d9a68042d2fd9905550ef683a));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1b08b9381294c1e00627757f41e5f3221f06359948a21e96608de4d15e995cda), uint256(0x18e66d005ca7f04197a9a52bf99c35ae20f2a564caf3afd13806ac6f50285a43));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x2d455e4726ee0bedd069d4cda549cd8d8a1898977b134c009a7bbc90eb658152), uint256(0x04e100ad254e348b52d227a94ed2ec90a2e260bc4c73d51af08efe30e426e790));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x0fb17199a6dcf6ab525db07de3279efd0852c459570395a54a80affa48cb4148), uint256(0x1e60f89474adefe76598eac494e2889ad6ed72a1a5072591e62513dc8feb7ad3));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x02877663675692a34a711fa938a2dc31486ba536eb2a3dfeb61e921412ccc023), uint256(0x19f8e6b16d5a13683b2752a551f05d4d18233b9da63de4519face129ed53852e));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x2b356c1392e35159501637e6b201685790fd65f78811dc025e3522bb98011ca0), uint256(0x2984cade2f22e9dd1d98571b5bd2d94f42e2c6af60bd2522f72703b29d938f5c));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x072ce4aee302f29ca14dd7c872b47b09e8d4729e36302e163dab82e5e8d798c0), uint256(0x301f0100b7534fd33aaf494ff0d61aa8cd8697867703f040f0dd302ab21a45f1));
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
            Proof memory proof, uint[35] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](35);
        
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
