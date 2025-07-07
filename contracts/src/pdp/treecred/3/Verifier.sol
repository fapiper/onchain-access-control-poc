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
        vk.alpha = Pairing.G1Point(uint256(0x1282f6329a57f3bd1607c5dacaa566e0d94ba0fefe05ab08ca3f6993efe91bb8), uint256(0x1a52e7aaef3290c69e84c53b105f24c10412fc76798ea5c00e98c8963be85975));
        vk.beta = Pairing.G2Point([uint256(0x2297323135cc91c95c965d70d81484ea8780a24e4d27c25647def7d7ec15cff7), uint256(0x2d295ad4dc67bd2053bd59b23836befff599f6f7227425efafa800e3ae82e4fa)], [uint256(0x01bfa3bbdc084eb993e04586b829eac6c129e01ca54d2d792e7627ae43a3acba), uint256(0x22d095f72a09b208fd608b28909b47e7aa6dc45142c2bcca64557543b39c3ba0)]);
        vk.gamma = Pairing.G2Point([uint256(0x045a026d5731f3622ad3d38a2ddc95017c2c4351dbab8326a7834ec0c976d51f), uint256(0x21a249c2c66bc6c6cabb26a82071d4ac3484035ca6f27170fc18121d4fcb3bb2)], [uint256(0x034597739efddb09214b7979e80639ee41d922bf8e448b049209101dde8473ab), uint256(0x0dc1e4b38d4d173f4ca685033179be79926843d3172b6b40f8c3f608151c71d6)]);
        vk.delta = Pairing.G2Point([uint256(0x03f9117bdcf4804875abc0d29d6f9d73b9476c5f4b5d1ea8520407223c3bde49), uint256(0x24ac4d0c21b4fd31105f496e630934b8660cdc6035a39a7584cab49ebc69c1d7)], [uint256(0x1b5e22747c1adac256554e6d71bd44e0967d71d94a67920b14e5bccb046b0661), uint256(0x0231ec8c4465f55595b82b9313150610f18a88ca2f5473beac413e9ce329ebeb)]);
        vk.gamma_abc = new Pairing.G1Point[](34);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1774c6f282e0b696a1cdfd61beec57f3b9362e1e5abc8763fb8184cc5998f906), uint256(0x22e81bd21ba834a97ebee400e804c0c36998161721588a98f86769024c8e17bb));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2c37ad8a44544c0f154c0a2ceabf77c080a65327498143cbdde64f72af7222fe), uint256(0x0cfcf867732366d35e9424f2825066f4574937872bab5e580706f43b6175d50e));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x28e3bf236718ff99ad58227823094e5811fdaf210b74e8fdf1a85d0cdfe0bc7a), uint256(0x0a5c5f28a2bd58b5655edd8024ac71f654d24f0b4204ad3503f4cc4746f6d285));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0926b66c403281820148329b0a9cb89c7a6a12f99d85fe1b34d7747f7f525975), uint256(0x03c0d2e4bda7eb572ff18c171925702044061432f359f69a6845bbe14c745f44));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0e5fc23b2c7b0518246713b0adef34239cf9e878e4311d7fc0af213d2a32aec1), uint256(0x1310c9d751f34ff7bf53f40070576b443091909de2ff0fc086ebaf7e8d517b6f));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1b19203c10c98a47244ee3ba8724d505f8ac9145ec9c7f65a92108203564aa16), uint256(0x1b8d40f9bb3f619b1ec5eac80709a8485a3c594455595f50b467b927539c2de1));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x274a2c9ea336b40eee3f17136487210f0c2e6c6de4974da0ee80eef213b5aee4), uint256(0x06220d4a1414a7dcc67238350e2787eb1f9226a5a0fe75e05e54facea1a59826));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2a853a059b40576a1501e8f83e3430f849f7ee7487e895acbebeca4672e3682e), uint256(0x11e48b3dbd041da691ff1ea97749e67619bff89a9e25d353efe9449d5f692603));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x00a7bc0095043c39bf3dee2d766ac1811c3c692d9b9a8595285677b2657af2e0), uint256(0x15730936a6a7cfb0d50d5fdb81ff94f24496ab7b3838c87c7c4f87ba5d726be2));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0dd89de36596a98a213ae4ba3aab8ef02768cf2b0df4c78692df4ab86410de94), uint256(0x0c0412dea82b585cec53269e5d55e12f4fe49d3c056a7c34e8a6944f3e2787f4));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0b58a2db135da6cbd0b5eedd98f84afdb93738df55fa8696fbbf2ce72076ae33), uint256(0x10be7646222f34155f86ff5401dc9668cbd0e609326cd13b71ad17b569a2eda7));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x123a820982d9975ec2d6724c3d6220fcd7c8a67820f245ce0e3979ce275eeb9b), uint256(0x2cabc499d0db5966d09cb20a84a7969c8b013235a330b3fde668f45ca45a8e6f));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0f565a88e6671d04f835d61a5d723c93225510612006e239c6f5414e47a254f6), uint256(0x09d6d2b0f431af270d9c870152fabe07a1530f8fa9e26b35433ad242a0acd1df));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x05c9fe771ad2d2e537c106833217b7d1c3bce15f17b2999494cfd9a8698504a8), uint256(0x162a25879870b9df7c88c92bb608a32964e762374d4c0cf8cd2ae89c863ed8ef));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1cff9c515ff854fd0a0487d2b49a0bd98851ff7519f02bfbb9828d0a57b79859), uint256(0x001522c52a96f248e461cfa271f3506f90bbdea7ae336c32f8ad4d8a5c4e8991));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x16848459d9797c12b97869691b26926c07649d1c322da8dbddda7e302a547fba), uint256(0x23dca30b5ae4549a5d46f96f0e847f147c7d00ecb78fa9cc2533736ea3be1598));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x07a27885e762e2a99d11db86d0323ae3e67cadf72cc81f713b81ad497d22e6d9), uint256(0x081aa468a1ff5ea83d2b1505d6de761c62450f7198e80596be41dee786edc30f));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x259a0b58864b2636aed5487ef55953ee2417ef80bbc50fb11e9924aaed60ac16), uint256(0x1c6fe913d9845b99be3f5d33d6fe8086ed374e37a90ddb11bea8d0e36ba9c8dd));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x169c1ae4ee8f1bc5470ebc024629090b78e4cc7c0c7f523fedf54a10a55103e8), uint256(0x23a8d04db6f21376699e8465c985c6b8a7b95f92dd412e340d75e4abefe2470a));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x0d26e2c5142812f7d36c42e8fefbe3d5a32f29dc92c7836490a4f8860ba562a5), uint256(0x0fc800871b8fe7ae1071f00af9702b88ae01323969dc3046dda057bc55f418e4));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x129c0fbe3500e66d20043b38307e3573fbd4b0d48602ae9413ec09cd506ca138), uint256(0x10d43437ef905586b2cd22dbcebf46360b7043fc2b585df50f8d13a6823d0d1f));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x188487675ae06a06e23ce9a4513c785fa1b8d5c9f0e9546f12d86e010fb017e4), uint256(0x0295abcc50f99bae841523c868949a356ed108ac13cfc064d96f7db22d816bbc));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x15ea88cb3fe68fb082877c26b9093c1ef4cd2b0a064ba0cda4bb47efe61cc3df), uint256(0x19d986524f73308cccd254ca843e24bef8e05e417856411e424223f22b5e4886));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x257c89d5618997ee7d3f1cafebd89e5d8286ceb5828d87bc4417b9297e2608cb), uint256(0x06a49d8eb7d50daed6a5ab5a953a48da72d02964dc504c2f0e8c166b345fa964));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x1ef0fdf8cd82cbd53647a5d9dcee578c9e781f41f6fb54a23c6f146308e4efce), uint256(0x29aebbeb4fc9b8c21387d5ec22c269bf1a49ae0fc2935164f2b6a49701db5b51));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x1eb36ec7138d5eb4321c3cc613e595f389ce1388c7800af053bea512852c3f3f), uint256(0x191f8262ee5c257676767fe39d05cbb149341e0f3a9c3ca8636b87047438ab03));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1322aa14f2c8ff9d24451e37b2e73757bc54b029c7d0b6a21f5bfe341f4ef2fb), uint256(0x01e5be6e77b58158d0524e44873fa7e18d2c5a929091e6875310b776eedcdee6));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2fb18156c134c4780b896203b9aaceb8e0c5ff547a2719c5f09492061d802435), uint256(0x0131c8b49f0878047ec684f762ce5b51036cb7f89398517e013549b77b8a7aca));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x141fdf8f90055c28e09568a440d5af0f70ac3a1c3082eeb2482dbf20159a9b0c), uint256(0x1a61d6977d5de178c796450c456833af3cc35fa68912c3baf9e41eef0eb725e7));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x21f03474d9a0343d4d000cd7472cff81a28ceeb18fb90e5a80a2b95c16db25ed), uint256(0x1269783629af1a55c9fc1fa3d227e58f5b1af36f2674d5d3d3b4ffac08360e17));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x0b2657622c5fe0456b361c26acbdd4f37162aff8e9269aba4940ed4ccec8e840), uint256(0x082ed9acebbfa1db5ff49802024903db7fb4d9c340f5c2ec5fdf965742a82077));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x24e079bb9b552e944b0191959e591cd4c37489ef82e0a997e5fc9ad044aafd73), uint256(0x1317ed5d25bc6e06670590cdfb920d64b939b10efeb47f147d27a030a17db2be));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x2de357a4125eae5807f85880a4bf7b09af63347b97bdecd3aacb0ae2df9feeb6), uint256(0x07fb039574bc551c21094149d2cef0085b44848d2865aff832e936c04d64a7b0));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x2509204684021ca186aee9443602a73ef019f2ef5f58ddfc0cce3fa8a4cea91d), uint256(0x06f416d31db2bee9638e3c0307ab991027d0fa38cf6ea4107827b8a5b8d16ed2));
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
            Proof memory proof, uint[33] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](33);
        
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
