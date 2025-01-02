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
        vk.alpha = Pairing.G1Point(uint256(0x00b65af6d57b057adbcccca3fcf3635651db71a2306038f35f9b737a7a92cfba), uint256(0x2dbe8f720741161b5795a32fe4e1d8e646e3ed7bc6fafdc20448319e0ef735e6));
        vk.beta = Pairing.G2Point([uint256(0x10e11a3aaa377b8e4e0f114c77b2d4dd10ba44c1b79528b79f0366fe98b89968), uint256(0x12e1fda285da4d39cceab20731c0a0f4c665881639754325fb525e1a963aa3b7)], [uint256(0x15d9414b5bedec1dae7d2e298bbe8fa9b302767fbb5e5ddacb1ab676ecb4290a), uint256(0x1a0c48f8f48f19588e40132e52feef7a52fc347563b87469a116c28d77d6308e)]);
        vk.gamma = Pairing.G2Point([uint256(0x0b495ae5af498337b8c5692c16081983982250e1f921cc135c109b2b29f4d7e2), uint256(0x0c82a12dfb3c25becaec748d400dc95857a8ca5044e47dde9398bd01b62d7d0e)], [uint256(0x05cb03d80364f363913ab47cda18653abe7d1a44a1c565190b5258667cea4799), uint256(0x1bf88bc9e1d8139f7975565c66afad6e874a4f12e8710e42404ea305235726b4)]);
        vk.delta = Pairing.G2Point([uint256(0x1878944b8566863203bcd21213eb0d6159c09c991c94c3fc4dd9cfd6791fbb93), uint256(0x061bd78c19385e59e03de7a1eebc56971d4ad30d9111054d47d0cf9f070718e4)], [uint256(0x2f96e6f9c7fdb40f7fb636a82ebf016b159adc2fbf0c64d2c3882d061df48522), uint256(0x1478821bde71d0fecd28f274c80b4b593f5072877b0854e5e9202f43179dcea5)]);
        vk.gamma_abc = new Pairing.G1Point[](36);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2643c3f37859778188cf89334b66be5fd0501bab207de4843105a1b12da94d42), uint256(0x0204678af9282312a082c41cf51624e01e31194e4e71d035ebafebcc851f90c1));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2f5b9c265c6937cfce584d9452e49ab261f2fdc7f7029463a79b14f0919cea57), uint256(0x2a8a02dc6dd15d2c583e3609a6d4c3701310e429c37502b85c674da06b1888b3));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x04c0c86ab515b0ab4b1d83517908a49472410fb992194cca7ea8e126c4dade36), uint256(0x2d148d7db586bec66b5d7919c4417fd1c965683a463e5c70b7b95ac76bfa6779));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2fc3a91bc97fe41edb75c0edf1ad9199d620d0857505761df3e3c3226ae4639f), uint256(0x2c2a5d2df8d0c3ca61c8bbd55f03129f582b7a186eaa5cddd47253911ad9e0b6));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x07faef3c30c168bd6cfc932ce3233ac39644995c749e17e4c322718e5a744e4c), uint256(0x1168a81775534ecb3adbc0f554cc4d6e62119816521f4565298d8c6bee4c0be4));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x10553a8cceabb1ff556ca880166920440e0889125b9f48a851a95997a87df8b8), uint256(0x0ece1e070dd888ef45a2ccf631815ea604f2d86f222fb0600612101baf156b42));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x04ba82fce500924af753ec4757229f6d13ccec2522d247b5c67e117f97bb4eca), uint256(0x2d6d35a1c90da183a06693846e93295426b85c4a556357e46a7c11b85059f8f4));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0fad4e73bf2dc678604f009a336015875dc133e45fcd0afe26c57ba5f59e961f), uint256(0x00ae72473964490a7cee3c984cf1169ea69af4d880d7dc5408b5556f931206a4));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x03d414ab9c59464b18143e8fd1b18e0630995bc48da2b06560625c0685f02d3e), uint256(0x2cf32afadaf2fa331494706157419f5681f47c83cdace39f6c840274569de094));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x28488c956702ac475fc3f26c249f9351203e8fd261dcc388781b0af7db2ddbd2), uint256(0x1f5fc51de7f7478df2731a15029986b2b4ef5d5678c5af837e45b74cfa10ad43));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x132a31b61ca030515c67fa14a72a3bd7c979503ccb58c80541824881dd5f7614), uint256(0x04097b2882bc06c83d9a2b0b2b8378d868340035ba48f75d9410ddb6d76a18cf));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x29619fd27ad26bf6d63328ae4b11393df9104a2fe23f4346a1c7a40f5212bff7), uint256(0x1a6c24759073fc9d56a1cd09d4ad3d9ee6fb49c4cd273eca4a54d4945332e575));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2bc316acadb7ae800c816c1bf7d52e2b5abd4b69fd9dad6296cbaf78b5a41d4b), uint256(0x186ada3c9514cf64355e327f76cf72da0c0d1b0a5330eb973fd6871c38ae14e8));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2b08b55cb9c89c19023ff01f62ab983fb513aa627cbeaf56d7a75ee549b2bc78), uint256(0x20e8adeaac0169d9328cad3ae8879151af846b974c25303564d760a5ce13efcb));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x15ed140b7e2bca82f46988ca5d8b0627106beb4b4f46ebd9418ad9fd3780fa17), uint256(0x2952b5dacf817a00e327e83cb6e95d705660a85fd1df783c17d3b5dd37487aaf));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x2f218b01780619fddfc12916a1b9ff74edb7cdabf0be4e07e67c510d1fe6c9ae), uint256(0x2b99b2b20f9d1169883c60e3873c5272d914452c6c26f8163a6723aae7945fe3));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1ac5dbc75ba2402c793e4747f405d56041fc69b8d850286c30be7d59543e569f), uint256(0x0767cb982b291225059ffe26741f4aa932b4b6e43ca50951dbcaa28c20757601));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0cb89ac3882e7b3191f8288d9f6b79700979fed757a698df23ea242e3edd2f41), uint256(0x097e1e12cfe98874a86ae6b34f6ebffa3205ffb7aea13ed9c13530a570c2fe17));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x0d530161599198b8682f755279a2aa7f2198b63e600c5c5495d0801f89ab0158), uint256(0x02f5127b4b85af1f035402daab520e50eb69afc63e47747cf804163e1a30ca97));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1ffd44fcde74a05032d2df61cd642e5538a4f4966027998ae62dff3754ac5b11), uint256(0x12907e39ff37fd87cf9ca1b57d6d01b0eae51f30dbc97d7a5ee4dbf8e0787c3e));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x16fe68de2f5f357fd306dfd26b4ecdd159a6251c9ee4f6afcb0fd98b5e3b6e74), uint256(0x23b610b60119a31f1aa7f6a3e89ec676cbd6f01538fe6a1754e28d2fa052d104));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x24857b87b351ab44097336be20a5557e53d24ccb8b28e5a7e82780fff2c3c962), uint256(0x080f49c5b244a02acd1f798104e2d252a333ee709ba41474c14297166f45bb46));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2ad3b062ed7c1a901998e3dba079545593533414647f165dc94680ae5c4285b6), uint256(0x11c336e67e48c556fd7c3a585fabd5f2add3e899d3d265b21391e29f390bdcde));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1c23b86e243b4de83183e56fdc2a7fff5628d0d5250c76defb21688055c74f3d), uint256(0x010f05bc7e0ff948ea250da392ad478dbdb0e392ee0264ade4e079ea08af85b3));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x22aa2b5acc94671bd24c82816a1c38a44e5c69dc785e2b33bf06d6f6367a143d), uint256(0x0683eb27c8d6330001873ddf73b7db6d4cd8bda88ca003875274fa6dd61318ad));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x21290c03a3c7c544d6a698056d623ad7d7da0df0c8c9f86087781b2fc76e2f38), uint256(0x05e27ed6b889117b4a2d772aa078a104779f9ac442e778d7ef0efa7ef2e45112));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x2dbea6e1d7d379644cbaa8932cbb755550adc835dcf940d60e8eba7d08b0699d), uint256(0x19c62c337838ad9f7b158f5aecb25221ba6c0fe914964cd46a2b644b00a8b0a9));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2f984cb09fc1126eb3de5b811fe49c2c68dd0fc48c8a727b3cf67f01053a0d59), uint256(0x16f402d37069ffd21b82d02a8bb27dcfbf8757f151a94045299f630000727b3e));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x1171b5c69bf54cb2ec8a6db4802f220b95013874fe2dc5241dcba316b1e8338e), uint256(0x0613805d1d47d52f724cc6b9176005c83ef93620ec2672eff177cad7fbca5425));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x0c1e241992e18528b7b5a08433040ebf529df229fa27e9d93d107ced46192093), uint256(0x15ccd57c31e79f8313476154c3fdce47fcd4022dec0c3e20951aa1e397975900));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x2345836944f5d3d7670964ea990afeac1cf505fa36c3d0ec800e2c76455db236), uint256(0x107ddf49c9fb81ff611e4293984fc719198acc74b062468ee8e1a96a36333c96));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x02cb31857e416457bf6f6bfb8c6abf303528858c52812e1f242426b03690c42f), uint256(0x1594c795cd25e7c7c5ef87a6aed71e508476d14c9e4602aead00cf5a09ecc253));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x1781ede2027c0f4626d2431fa5c7929f71eb1c4d4257ccbe8c3df3d23236329a), uint256(0x056ae9e2999c8dda657341b53a40dd3870418e4c92e3d0b6a5e44fe2be74509d));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x15bdc68dc852847510bf8f5e49d653651258ec55297408b5fb64782b9e5dc2e5), uint256(0x1e2159f4d6b8f56ea0deb172ac2fdf704f16442738b7fda1580d95ae303352aa));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x094dc52f109002d29f5349118e274f032181d2ed9d7783a51cd89d9453cb55df), uint256(0x295e067dc717de6783f03276096c9ec3151aeee87fc6b1ae5c3189d69866c52c));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x0240a864b77967f427d3d8e620ba9c623b65b7aeb04d309d7fcf0e242c348809), uint256(0x0a067b192de0ac38409e4791d280e783b87d123ea3a7e5dba9c90f8f93d00359));
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
