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
        vk.alpha = Pairing.G1Point(uint256(0x190e3df0b07dc0cfa7432a26b0ae328308a8bcdef801e1ab0bf37a3488d87256), uint256(0x17ea781871d36ae9951380ca2566706d8b20dce2f8ee0f1e97073ee6194cca95));
        vk.beta = Pairing.G2Point([uint256(0x2d996aed9ac31c7ff0e00b50b3611c7ef398ebd054976cd7ac76916b967a7d82), uint256(0x0864d89717745b884865228c538277e6a1d4acc10fccbccaf6cca0d6efd06e9e)], [uint256(0x2f2ecbf45284ec331aab9c3bd2f9d9022f5b08838b16a6d0ac2e151813de31dd), uint256(0x1a4d11b31eff040178f7065e1da829c7c8a3cc9d5f884bb50acc3a3be8eb263c)]);
        vk.gamma = Pairing.G2Point([uint256(0x2f91be07e6e444044df70b56c67180773beacf2c855667cfba722bc94ef36027), uint256(0x1d01ef08d7c303dd50d3ddfa69eb848fdd5e3baa079b222e08afc8ef0dcd9cbe)], [uint256(0x0aa7ce4fd0db944dea8a64e7887ebb98eafd9edb19204e8d2c422acbdccf961b), uint256(0x2d6e6a80564ed3bcdd4dd0df53fabf775a81ad57c4f7c9dd6b9bed2da2d9c88a)]);
        vk.delta = Pairing.G2Point([uint256(0x200f0952dbab157a4bc686412f6d83fbfc07eff136fe6b13268776534509ecbb), uint256(0x14433fc69a9d0ad1ab03f57b50d8de9388fa0ff8a583a90de10c3c2b3ee103ac)], [uint256(0x197a83774de1c4b40a8ab51acc750883236036e4a7793a3c7d273ac4806de93e), uint256(0x139b6bd05baf9492e4fbf4c52c43455e58e799bafcdc989abd5e0cf3ef9d146d)]);
        vk.gamma_abc = new Pairing.G1Point[](30);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x214ce86e8f0e7c9a0e5c1a20053a40052cd4a3a56b7e86b099a736e7a0a61d61), uint256(0x057dd8a75fe6a215c8014b4486d92d663f0eed592c1a9c3c2cc3e44fb4b67e7b));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x09f26ab1a5a7a6046892aae0b000066d52a9a180a4eb1af061181dd134322748), uint256(0x035e09a8d6bff4c49bd9c33c8c0d9ee2fbbe67a0ef4363833109f943427af36c));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x24f05099cd70a698898a3957a3176b9fdff9c739ae4727e697ffa245a766afb3), uint256(0x1d5ba89faf6f8373cecc585dab33043c1b11fde306c12b337604332b72cecfb5));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0b79b65d812af27e1af0c40aded0e2aedfc66b7432ef8e5036c3664897bbe7e2), uint256(0x28ec9962c7aac931564c3c927f4ca8f70fb1cb553a1ab32a5bc28b95ddd13386));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x206438e01b55eb855f67ec44accf88ffbe0e7099da59123c7548134b4197ac7d), uint256(0x1557d7fafd16a34fa85aba13e112ef49681bc3dfb0ac0bc8e0cd7f3765cfc342));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x160f5b2419b9fe9dbb3f1ab1a2f931d88a53c98576f7c1d7e35c2bfd1ea42ec5), uint256(0x299be0765b371dc15f2de65db9b15c15f7e5d81cb32fb692a286882bc6d9ab1d));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x253515f6d737ceb60d79ca834d373ff683784a969ef9d4c21cae6fb34ae0dd8f), uint256(0x28a552a24b2daa1b835f9bb8923388626dc472ce2b75639546bfc1d2da2ce655));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2b7b0bac73a333572d457213ebf93de06f27d526bba6de588eaeaf930c3c550d), uint256(0x25f864e0cf52783dcb9866403a658ecaaf6d0ee8dd33cc9f733dc078508dedd1));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x173aa920f01905ce792794b93ad4ae5119b83192ea93fa788f692199a9181ec6), uint256(0x008fea997cc2c8b85a50ad746e74297b2672e1a66cc72bf11706f7353580ca1d));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x11c535b0735290dfd84158f36ed898ecc7d1d33e2d12c80f2bc78c27e2a4e8ca), uint256(0x24964e13b210bbfd88e043d71830b48d4e34d2ea19165c411f2c5d60e6a2d495));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0272cb0389f8cae7df07807a0b3cf4ba537060e01e04f6349e8f4cee5d3ba36e), uint256(0x0ac21df5212bbf4e5671659d884db71f5f529db3e73de524fa5f5da114d765f2));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2b6878b9b92742dc885384cadb931ef124814470b2ddf6fb3d59856f72461c66), uint256(0x2f3a192c40dcb2c9b73f6ca73950407108162952e7ebc04f90f2ae83064ab3a8));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0d00b946d02b1e2e514768b26f9da632a2c16303cb3a3a2dae4090c92cb622fe), uint256(0x0e06d4a50a8598d594c87ac15a2c57e7c8faf23341605ee13b52a4170250defc));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2e9c7d6036ad7fb15ce27d0165a6d163a80df6ea7967ee5630e9a33239ed75fb), uint256(0x222d61c9eeb2a1afb8ffdf50b7bd8902557856a65a5d96c16863a75af11dbbd2));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x19982311279507f9cbc7300dc575db7cfe167d4698f3af8e49e4b091e8e29b7c), uint256(0x0de42dc1d6f64797aa182a3b9734ab8e7b6303b132af3b1362519066d69fad3c));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x157660ae1ae83047d2908f21f4a40742916b7c82a91b37c293ca1c6083846553), uint256(0x22743b37697d98336b2cbd7703c4573427fe0e51734051301b49f56b8428d371));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x274309e31d46d94dbc12107bd2713756728afa484e05494923fe5ab776aec19e), uint256(0x1ab32b31a74becd8aba005709434d76b4a246eb683e2164790258cae629637a5));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0ece580e369852c81d1552748838bb0ee0a0345422634e2605e5bdd81cdf53cc), uint256(0x2ace64b4aabf58d08956b81285f4382df562789cd90bf6b5e2840525255e3390));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x24de2a0d8712f2b4a353f544471c86b16a44646f3d561bca67651183d484e35c), uint256(0x2f10e45e0f17d9706de637d469ab1f21f77faa0a091207e505e5446f1680f005));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x24efa3fb850121bdf49a48bda5abb8d5f4a5cd8d2370550c173d73eef7819883), uint256(0x0f6302bd56009324d47fab9049fab54c7d933b2747b98117c303f0d9621c1112));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x0592e1d5f3bc4657e6cd9a57f022176676657afbeef976caa2793a4f35a86916), uint256(0x2eaa38c810ea75b8b556dd74323ec24fd07d741a969867d19b8adbfac90668e2));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x27df08db2701f24fc68f87769abf3ad92ff63e4f6c183a0d2ce32b8533bab3e7), uint256(0x25b56128f2024e1211f9d1aa19c4fc8c3e425bf6b1ba35d456fd3a200487ec6f));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x12a49838b1664dc4672ac8e1b902695c7b02d8999e93c5d9731d641f5820273b), uint256(0x20f2bc414dd0f2b8cd59b6b4c63105cc95fe3a6efab9f7dd6573a2f35a423302));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1bbea69d3d0599c63e6dcb4a189f619c5483a7fedd82554be80a060c1fd6a05b), uint256(0x1c9acc8522bc545283f3fece37c3e01ed46744bea301f05d67ca82b1c107cad4));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x2e94faceb276ec07c1c513f4a307b6ddb817b92e98f02d377b641e9868599b02), uint256(0x0070cfd6a468ad6af3efa391f405ca2d584d1096e87a68a4f18a141946bcc9fd));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x11ada74a967699881721020f467cfdbe28dfa92dad4a41c08925029010d0ab15), uint256(0x12fe78bf32f83f212fe4e7d2edac224a9e8e3b572805f77be387ed78e5ee54e6));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x2a62b308a7a6ecf38d9229757eff4fd2d483f5c4f457b0d0accecf30e64e1335), uint256(0x0988486187991536d9ed53d2aa0f0e58ac9957608d3dadd67ba37f6a576d05dc));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2672168b23d9fd60060d1c16432be5092cbc8e014db77d444d3a1c451dd9ef35), uint256(0x15fcebfbe52276d6ea7421ec97b817efc624bfbe88c470ee7821fa8bcb1271ee));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x0f9f4e323ffba8851921eff664bd5e62f30bf062417e76e43e8e905bcd83da0c), uint256(0x1c34ebfddb96e6356c386ad5a442fcdc3dceefebeaae9b2b22642a2894ac3454));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x040d636784b6ee85294ee54241bca236e8dd0254937e7646e0e812455b7ce538), uint256(0x194c6e281edc42d4e9bf431d13f843480729a44c06dfed9afccde7fef57a402f));
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
            Proof memory proof, uint[29] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](29);
        
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
