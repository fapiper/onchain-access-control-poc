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
        vk.alpha = Pairing.G1Point(uint256(0x122c0965638e3f3a1e82399de291e2709e4a8c97301b5694349235cafc5647f7), uint256(0x2e300760e3b1a192581bea8e3aee3b7134161bedab0d58285c06189083ec7b4b));
        vk.beta = Pairing.G2Point([uint256(0x1e984b05ada52dbaee9c20095d8cf6bb3d3d25b123a4fc7684e2c57d0b3ee509), uint256(0x03f7789f719f21a594b4a1116fe1d596a65181f41813490e58329edaf6086e4b)], [uint256(0x04beb68f07a6ef13dc52de28a9158ca0aefefe6a2f44a5444bff78e9b5197d91), uint256(0x2d75c919a1bb21b9645594adf7fb4133477e61583bd85625819e8e9bede4cf30)]);
        vk.gamma = Pairing.G2Point([uint256(0x1dfcfe4b3dc16abe15b96420d1660b924985cdfa3e7efebebae979e3e8cfcbba), uint256(0x1ea3323ca1a976d7d104f22227a7a041caeca7d77869a51175b13fbe336ba504)], [uint256(0x260e951081b164ace5b62231795645aed421d519eb554949a528c609e01afaa5), uint256(0x2d8405c0d5268dd94b2c9e3cf0f4d39df73df2ca1a7268371630393fde647859)]);
        vk.delta = Pairing.G2Point([uint256(0x1dca1e0ad4504a34e324abf4e2ba009ad742bf5220716f30a97c9544c3d43bb1), uint256(0x2dea9e80af2d63a24877cc5e0268fbcafc39a872b277a61e7e73d97868aa996d)], [uint256(0x057618217efdd9bfdeab85ad682864d6d6ace479a2db27eefe6d8d48f65d0896), uint256(0x0daa6de2b411297c14015005811addf8cf0bfe9ff526176a4b422df90b323c5d)]);
        vk.gamma_abc = new Pairing.G1Point[](36);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x29273429a5bf06c6f8fd8082a8400843da33d413696e097cd048756785939d9b), uint256(0x18883602a46cca1fca5655932cbe8be75c13d61797ce6c8f43fc31b92d793e42));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x18520a53d295bd0fd8cf7d1c9cdf30f572b8089752afa4f451dde44abd4e6260), uint256(0x27048dba1485b88ccd00727509fae7b41bdda4d9bda852d99a6523c740abfd77));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2c416c575488310fe7bfcd2ac53fd9e0154b781dd276608a6873c4986683b86a), uint256(0x1685d70a13af99a85cec86535732483c154ff2774ea0de91971ffcfd153af7da));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0420275cb692cc0ced76c7a7f481ec500c17b41d4939621872ee6f5852a2fefa), uint256(0x1e7b5dae45e88c215399799e9e7f7c7387754b9b26b6fbc5b2564ad155e6f8dd));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x169e683c684d1bb7d2a0c9b80c243a2b5b432e4d7c174b72ba08d3d94d241573), uint256(0x16fc690dbd8b6498f8a8de293941ae0659ef41e7956ef1f0b9d0556f70b59159));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x13cd4db7518687df0e5d338ed6ab2b0403739bd3e3249814985f161e76dd21ce), uint256(0x2c8239bd9520e76a142114bc7f52a9ebe74962ce90abcf20c1607f0706d45231));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0b23f6ba25f24975b846197ff4b8de51c1c433121e2a6bb70bf97ee75c2589a8), uint256(0x2bffe17ebe7299ece938f819de94165c0aa8ec037b829bac73e474f51e4a726f));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x215a1da987dccd38a38bb6854be00b8141740eaaf15451cf8b2cbd5027382286), uint256(0x28f35eab4c958c14a059f0bdc3dc629a9cb0da4b159803757cef58c7b6bce111));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0d7d373cec3c868ba52a1080a14a8221eb9bce5db28c75baf8f7aa7227bda258), uint256(0x1ad4b9b138071b40e7eb454a26e090c236640f6942e40ef85949a13f2577ce1d));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2280a9204388d1f1f3b30c1c1568c6ec31160d4e8f23414785ed4e4964b79c44), uint256(0x2a92468edb7f49f9de0d28852289b9d64182e19a4732aa52ab2cba60dc60e29e));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1c06d6eda4d20079a73b28cb7c08275ddbffc86fc17bc44300ba1c7ea6724557), uint256(0x16bac23f87c4d3177d0bb2dd5c4f048f14a01caa8cf0a070ad0f8cd4772c8b2a));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x15e1e855515e4f56acbfa4af88b581c014eae78223ead4b700014e8b410fe199), uint256(0x000a95f6c81958edad5ed5c167e832a84e1b5afc48c57c8db00d6c7d5a7fefd0));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x29942442922debae057e530b2bee05348b20bbb9ea917a17a0a92c43f297d86d), uint256(0x01e35dfacd5ed1406913bf3a4c1dd804e7515642674b88aca5b6ffc9c0348e56));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2a4c7a11b5c3c5c6aa4830c1f153772195202bfd8e2693fc9f4bbaa38600069c), uint256(0x17b274b0a9af7031165d19ed03aca08f426a2d1a1a3ce6d13644fe2fe9d01807));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0d6a26512d4cf7d43254c7a1f9dbb48a1022e34d0270a09325b353df81df825a), uint256(0x166aa90c5f0b0ef958dd5c10157e94d7f3329923aedbaae85724a37bb29f914f));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1ae0de911d57e14db67be4a7bb58f29dbd81db7458f37f78668a75ee500740e2), uint256(0x0d05a79c032d523750957f7b7eb86a58d9785b2afe993f626586f927fb63a822));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1add847650ac2313fb43d1c4ac4f08ed57c0412bb57d0e00dd364b2c34b33142), uint256(0x1c2eca3f1d2ac7123cedb204e745b6fd72bacfc5443c61433e5d4e07476e5e7e));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2a04dcd9d2330ec89f344b4f76a76ed04202f8f1cbca75a06586d49e9b4ed601), uint256(0x2973a764e8ce3572b0eb82270bee9380c1f1168000800b638253944ad25ff679));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x0839ea563f350e2fe51357262907385a4ecf5584f81068ef9b2159b62484eeb0), uint256(0x02a36a4c1e897ff574f0a37780bdc77054d66b236fe399b1cd4a01d32059073a));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x14e36d949ed5d3f31c322ae4ae3cf6690a054eca8372920251afd4fff883d5da), uint256(0x291e3f1d3193e1c228b9a6e8433bb14eb34732bd821dc320489d22214ca5d6aa));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2c168b001e025948a42f46189aeb246dd363c53feb09750bf73394ca27f135e5), uint256(0x27047e60870f754eb490f1042354bae85aafef9edbfce4d5cddcd8b3aa89907c));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1db87d840edfbe65e0e61574e5c8b6d8699aefd3262f817c3a1967b5012166f7), uint256(0x0d1ef0586065790a8983ef7bc310b8247f38ec331337528445283cc2c8fb61c0));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2e040a11455d2f4ece2dbbf47f3036781d39676e278e1be9729cf3f5893c2c1b), uint256(0x1e89402e7ec3b842e038313c9b05a4f1ae2e5f47f4790de9aafd2b13ddcecb10));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x19be688ea934fcb37b1741ac8aa6ec55ec76bf0719db69f713de3d7785236e90), uint256(0x15d00b5fcab502c4c79be5c7c7c54ccaac48e244ff2a5158f66103a166a8fd56));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x0d00d7c261cd0cc0df0e2cdb800fe282496f9f53dd83f346410f9b7d6e9764f4), uint256(0x0341032fe99998703361db66cfbb533a5e94a069b8f6fa268602fd156e7f5c0c));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x0e3acb0fe2b36944a2b2179966e34578324031c9edf4d1b45b4c7b714cedbce6), uint256(0x0868e72fba5098eb0a992b95396da51619ff1301e52facbe36ffb066ff9b120f));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1f5cb1f30cb797dacb1bbd24e5b207a060018cf8ecdb50a9aae66d6db2f54294), uint256(0x0198189d52644fb38b28032a613f796b375c1cae6d597cef32952423f08e664a));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2d77d5f6aed8dd500b5f524b8d3d3f6a964336cd4e701f90aa1dfda3d65206a5), uint256(0x1427e55b51e094b3501fd8f82d49e38671ae140ea5ba334a20ba8af276b551b0));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x1b72f8ac880be9ae3c7d3625513ca101bdf4195c10bbc7939e44de7bb5af4a06), uint256(0x2c8aec90041688cc03b63421fe0ddff8d7dcd48e5963a4db9117cdb48d3e2469));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x2226d29208816a12a497edbfe28fa7659bfecb8a2fc4c784b951d96679549471), uint256(0x1f52b91712ed374387f075d68dd759e4c846d6192d9fb5ccd7f204e299717b4f));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x270dc036a155a51ce4274d306c5874f18047489f9e4edd4948f65eb80abf0896), uint256(0x29c1a4edf9e3080a9be4ba4fc8ebde01f0b17597dce8c6425bbf9a2f1ed93197));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x18176a69afaae58c4aa5b2fa661b8c99a5fea0dca06a1348e4dc89bea683ee88), uint256(0x2965f97f9a66c6c08865b2526165f87c910ddd04ccc59da05cac0f1dbd1b4e55));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x0645bbb8bd059b3c80f6f982ae9dab009ea7c53843ea853a8b3a3d27c0ce6c2e), uint256(0x02c34d612140765759d8336cc157a6dbed78469c3704d6fb773f978ac72a3b90));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x2510530dd159e57d7cac01934075ccf1d426ef71492a679746b01404ddd6ffe1), uint256(0x2ffb817cde652dcca71fe7c04c303ed4c050534a517131b9cfe599f55ca0d265));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x2b5f4f9d0362b3d1f5699b2a6d487919670dc1fa698f65d59ca431ef7cbddef6), uint256(0x090280b433f2d79ecf72b768fc69aea4dcbababcc8bffefb6782484c99524361));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x24ad37c04351c215163c726b81f31961a8fb8b46311988813a1024044bd605b3), uint256(0x2bf862689b9e18b6be577d13778e57616fc5434c2da295a9e2698eb61e9c0429));
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
