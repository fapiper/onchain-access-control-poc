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
        vk.alpha = Pairing.G1Point(uint256(0x1a60efaed9f84ba8ccd42dad4fd948d6f641b5cd2bf0bb06d846654ab5961c0d), uint256(0x28ecca159059bebaaf5c54e8128f781688d0eb4ec74ada3f30dd1394b1804c4c));
        vk.beta = Pairing.G2Point([uint256(0x0229cf3ff14e7043d2d0d9734654bf15db040258d77b50c9e167577e037708f1), uint256(0x10ebf3e8a0845399b163bd562bf523f0cb1a9bbaa3e2db71073cc8d57020ce5e)], [uint256(0x0a67b68f45c3327e855e8e1fb7c8a64b7b1a81857ab459433755972175f28e99), uint256(0x1616dd48195c99a95e7d472cf6c9069b901caa1223e38ddfbcae91c4ed66e64d)]);
        vk.gamma = Pairing.G2Point([uint256(0x03df6668d4ede6551ddbef1d39ee0ba73ad98fd72d732728bd50e6f286ad4791), uint256(0x1cacd19dd86d9f6d16e9dc9db814cc19efd40876a9b9a698b092fbd010a680eb)], [uint256(0x004a9c61d4f09ff8c30f1df71e502fb54dc08722eacd8f2dc81132e2529b5f40), uint256(0x2177dc61f420c3caa89a5015e0719d1c9d788a5815a09e1712652fa649418d2b)]);
        vk.delta = Pairing.G2Point([uint256(0x002aaa5646392ec9bcee11e5e0006e627f9e41afd61750d9062b64983cdf2eb0), uint256(0x0e54ccab52698e7f9b4556c9193968253f07b82a51350daad552f04c88be9411)], [uint256(0x007312bd08ed1d1f93cc4d9bf649465b4b38b36543edb5f3e48ac5ab99f44e8a), uint256(0x1197c2bf4b44244c9502a94c9b4d70310a6bf8d195a1da43796473d1e0087013)]);
        vk.gamma_abc = new Pairing.G1Point[](68);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x14541d72c857de85178ba7f352e9d0a9144bf65100f62df9463c8489a0037196), uint256(0x2f001153192dba516ed709d648313b508838048764816ddd6e786e12f1379a95));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0abe9bd0a391e5a22ba4cb976619289fc6cad9139b1f31dfef2519d9acf73e26), uint256(0x29112acc0c8a341ab10524d0d218b4c85d960ef11131280a96458c907a539cf8));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2858c9a47e408c00f512b3ec087903ddb8739f777a5c55435d07568c7feceb19), uint256(0x151914ca8e4987eda90ae3159456fe2f28e04a2411b906f30be04983b4c991f6));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x02b1231644130907ac2a036b37ffd0fa9251bf49c24cd155fb8ae4a31624b359), uint256(0x24edcab7a22949fd01df58e73fecb3dbb5d7895d6c96c64baf541ffa286468bc));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1645796bac011b3da79a12d94fd14fae9c7c0ac0c1f3227eb7c287a360304338), uint256(0x143cdcc464d383d5d1d252a53c7c8bb6c31d3afbfad9e11f115124b37a883e8a));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1acbe2d24bfd2785a720fa703a9e98c8353036d2b854518d0409d62dcdedfc10), uint256(0x087d3b7d5ac3a43f0177dd1e7aa848249ade164d823441cc2ba4ee3e6708739b));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0295499565155ad22ba055b330a9086b7ca67a931c4480494a4b48f6a5f14d71), uint256(0x2986e444c2e88731e43f0ef6d740085716396d4993401f4188d255e4a489779d));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0c3fde89df81d42fda4ef8011960dd3e494a81d990c073dfb0ab73a195dcde17), uint256(0x1e7232451b45c9fb3baf8ff643002619d20de64cc20b45aa445ee53f96074fae));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0846c1c120e48c3eafb728c64cd3da64e3efe6a4e635a91bfad918a8825748c3), uint256(0x077c4863030eaeed7d0af4230be794442c5745be177f5a16092d597bbb38e884));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1fa5a03521e7aaf0778ba78bddb8681eccdcbfc4af2f21480dc1356ce608d7f5), uint256(0x2499b74a51a0f1ae9f33c5ccad4d1a9e88e3d6dc6268a639e39412c26ebd838f));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0bb78e0a13488b459f12143f8362606b7d827f05b2e4ddcfbe2160477a72e9d8), uint256(0x2710de26d0893865337dd55b1f3a2b05d5e3733e0083679c02c2a512d0104af4));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1f6a21d468edcaf672280f6661911f1d418013033b76122526b49e650be983db), uint256(0x25aa30ea2a7669c849b72fe0018a047fd286a3523e7d70d8e377deeac3865e42));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x009bd2b3adf647dfeb8d135b152d31937256fca931cff6a29f226f8185e02650), uint256(0x2a0edae02f1fed22ee6a8edb06fb0937993d5352076c51745ee5354b548a9176));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x00bd784fb71de5eac180ba9d144a5cf123378e7920add9850462414976799885), uint256(0x2869df04e72becafaa1520b7d8f42ba18a515a24c8da127eab89394ff79a1fde));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0359e6864811e860d35383d6f4afe1dac8eb24a4511ddd62e1c872623b7adc94), uint256(0x11035ed9fccd7502aa534449f5a1b8f0007fb518508375a288ddd82215f1e676));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x2d9d6be71714de127272fee0a0868ec256d18ddf3a584f908f001b8431340892), uint256(0x0414e609c2da5f6dd10bede7579d2509ab9a453b67b8a268fd3b8c101f2c4dc4));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1413ab1a9a1763e11874ffdc2d59844e716936c60109f13457edd7613865ec94), uint256(0x20184ab6ccbf34d99c84cf532ff9c123ec7fcda487ba8cc3170a8abd1689e4f7));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x23f3325db8db0b7f90010bcd374307172bc10bc215ed1c60c529c5f135ed94a4), uint256(0x06cfe9ba79844099d5d4898cc19d19396c56cd0a4d541a8873983eb4d1535827));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1d6eaed79761662777bcf143f6c4eedd132f24b1f92939904b262bb4d71de17f), uint256(0x2ab31cd0b176368d018b0551b068b96553ab747bfee01db83e659a67c9f2ec25));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x043cfd7542350477d35d0509436f24185748960631a149075a772128f78430a4), uint256(0x24afdf15864f9ae5756aa44b422ec5769ebb8172c0f2db63528cc86ae3590fb8));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x04c19f1ff2dc0ef3fd2874f1d55f84556fe6ce5f36358272a49169e0cd7869d1), uint256(0x1af25cda0f91a5596c026d5cd66bce9cefe8b20fe79ff3639bc875be3c2e98f8));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1960859be2a53ec71f73c46d6bfe8df68559f2afe4ac9114ee5220195e5878b9), uint256(0x22a8ab8246785f45a36f558abfc6918ec4187e7c21a790a93516bdc52a3e41e3));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x25850af79a62b8888c4ff0b1560137bfd2a5ee9120817f914acc01124c68ab1e), uint256(0x0d3fbbd2ac13b572f1eb2f9fbcdc9f4fe0f8b57c05c4b16c5345a201ae5f2b75));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x0ecf03523cd0f16d805d1289700cf87c30c7b0ac8cb510fd5d70928bd0a54cb0), uint256(0x0827a769d24a451854d7712ba71a9acfbd195768d3ce1c9e2955478270c89951));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x2904dcf108ad9401aaeff639bfc3f059fee8e4e56825c77024bde91177a9e989), uint256(0x2f8690c5a79e2bae1043a56d3e7ab885c1376eae83cb8a570beb253646186bf5));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x158b1a6a9b89c0065d7caeb153350b48f4f5a1aba214d37ce29c1d20c3c32d61), uint256(0x227016888dddfe3a7c496b21d1aba2bb8697ee4de65996d65a4c980ddb37f99a));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x28b69e11c44c6045880c26d00acffb68d781a1c86893952319a4a708e00dc65c), uint256(0x0f3d70042927e2481b616048dbb0732f93613262256836d72059533bd5e1487c));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x16d79aa18b56adef1b26e0195c3d8e8d462765fa8585759954bc956286d6d658), uint256(0x27efc8b32840ed31aa00f6a6a2b05932a3cbd425e0c1e025ecfd71c58bfe35b7));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x24127464d9c735d87ca3db7d38749bcd10df411c9fe4d02f6a148eeb6e3fd378), uint256(0x16d4116c5e2982a1440dcac46073e91750d7eb87c2b2a33aeb77d75b73a4b255));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x0d52880f2041e454ff824c0afce003fad36e5876ed3ee708ddee05492bb37487), uint256(0x09ced600cf1a0456e5f74071a3198dd67c1138b5902011d5955857bfad314746));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x2b1877dd04cc5a8d5901b31584944ea2f17906a44249b946748749c472288405), uint256(0x10b9911191aaf30be0683a0c241de1260ad8bfa901d97b0321de97470ffc1ff6));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x049744f637279754a8f0271fa39f8068d92b78523f38591d044b1219efd79593), uint256(0x1f8a8947c6ac5a2cfd697892841ae598e2ecdb12ac5b292532b2eea934376920));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x1e2b35306bcbf1884ee32419fa810bc95e6ea5de2e72df7b3b728a1995f2ba67), uint256(0x189afbfe515389831127e93afb5fe6498af85317acfa50bb826151cc62db8ccf));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x29fca9808de29a0784266d60c21b0798a5865f5742057f9a87dcde431f87f721), uint256(0x2ed20e2c5260fba46926e28c9ee4e6ba435aa1ee1f43f72d183983674e83de7f));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x1980f2ed6c08373affa3fdd51edf186a035010d3a1dc64a9b4d7d01ea2283c97), uint256(0x064dc2c35eef848b4be81b4e66e9cecd77de601fa73a382b89482273ef176cd9));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x00b885bbac9f7b475cc4a17c392eb628ee628c2b63d4ced8a4b0e8167f3548ef), uint256(0x1dc72749f58e2b6cad950822b6e8e278d13e1ff24ebf7b7f7b6b2f6a1c1dc899));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x2355acac9f09b27da526e2312557f232042eadf7523c2c0f15062248f90ee837), uint256(0x255327ad45af03abb23ab4514bfb2496fe2f68cd430f81b69583d05be72dfb0f));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x13555adbbc18e29be9df2f3704f9c313156bfdd13cf053ba63b7d0993c5ab25e), uint256(0x26f55cb895a14faa89ccb5acc7a2523b80181faaf1258878466a9e72ef3ba3c9));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x1ec05993c48089dae7161a5812030040fcfb57248305c194e19a364954a5b719), uint256(0x161afbfea5cf70d94cf81221da60ea5ec64c891d1eaef27a3f79af56bb8f319a));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x1105b7f726fa9bd9e9e93fe69a97758234a6ed4411ff4871475ca49a8c849de4), uint256(0x057c7af4bf541e7c4ec6480125a1ab4cc6f7a412cf53bd3244aa0342dcb6f685));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x01484f9a24ba1dc8ea52b00882a312633a8209e0c21d935985aa42920dd84ef5), uint256(0x263c3805ada8eac500a978c445f6e5cdf5ec025cd1d23ace9a4a39faba1ac252));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x2bbd8b4ab3e30b9bc7b10812f8837aeff952f231151b162614a829a42a6aff06), uint256(0x2efacecfd6aa4e311e5b9438ad7cbb21017bda0c9b35a72a661985741e542462));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x20098dbb7347582d5e5d5a0485bc61d400bc68e5fbb493970a9d1fdc5b6aca91), uint256(0x190df5227c52149e0f12a441f80073dc0ed7380243a6c84eb696863b95a503ff));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x302d1514ad1316f23ffd55b1ca7ff30962283cfb6dd1ed64589ca4042e76d43d), uint256(0x18ab61ae6df3bfb0ddf257f30885bfae44574ad8509399747bf540121f78b74b));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x0ad2dacc52bf7156fdba951e56e8dafcaadd430704f2b53b5d45c3396c53b45e), uint256(0x0214c078a4bcf789ffd41d22a33b86f3c3b0f04bbec7cef0b36bf595222c0c73));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x297f1882117536bba47aa3300bf6ef8b28a3061aa6efdb609f4b481a1d767728), uint256(0x2ca2153bd2de6b1a62ca898b40ab9d98f1bbd8cb5087bf283b37d334f91adc67));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x232708a7652507ac677987e5c566407cfc26e2c647866f22531c61002f3209cb), uint256(0x0bab191314c9f987abc0ca95a605c829fb8535f6c620e1de68ee9311166eb2d7));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x13db745d460383ff5ea83ee85b343d9b0e120f430df1f2586ccc6958dbf640a6), uint256(0x169b738780909f6c9b508ff540d12440d84c4bd4fe1d8b1adb5e478294ac7103));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x270a8491f1cfc515fc29ca9e414a9a8d43c79dfd9c53c149574e2ad7b93420bc), uint256(0x2f00bde100ce74ec13d9bbff7065cd7de03aeecc928ccad997c362cda2473344));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x02ab69b30718065e03ed9edc0baeff2dd956c26c430c9460c13ffce778e69cdc), uint256(0x191c8a0ee246ce6fab1764bb50cf4b944a93008a0121b74b9440ff6049e526fd));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x2fab632c42f9cb14a0a2dd2647319183b029635ad45ecc4db45a30e355c3f43c), uint256(0x181d76cfaadc8eb2066a329f4439bc33310b80e05830e1429236e9f32397a882));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x2d26f8c8b6cc4cd803aae4b30eab62a70e04425ec39a72ade5380ec500a97e93), uint256(0x16f30f96bc45b7cbf67a600a86dcc2e94ccd368d6e83e915f8e92cd9a50dac78));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x1e6c7d5f9c992d3648b6ac3d1ff4116fe02a637c7ba3e777885c779f81442d8d), uint256(0x2230f966e7bfec5041dcf21764f108ef976de566c595a7da0cd26350f9c9e3d4));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x1130655c38dc44cb7396b214f055a27b3b8f035a48fc9bbeb037471f39b5777e), uint256(0x2d0b3931f123dbc85a90351f0f6e219661013042474661f7a892485197e211b1));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x0a6529b00efae716617e9093c46afc5595706431ddb4c627495f7b5bb5f84613), uint256(0x163fac3cdacaaeb530d81f68727ecc050bead85acb6a00d4aef85d16f7fc33a4));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x10ce6c6e68c417e8d5dac8e1aa38e6e85d6cfd2b974395c85f3642a89c4902fc), uint256(0x0442a389dc2ac1520d0f9d743a289c608a2d269b96541a8a9bc1e7b44738f9b0));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x1fe1336eabf5af0be268484f6d5a2bbedaeb832147894d42b6f90a0e53d18672), uint256(0x29f243fe3367002240118f8e687c0d08f507ff2b2568a742b587f7cacc0006cf));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x0815db61ca9b17791ccd797cf194acc5be862d232e406f08a1154e655826786d), uint256(0x0f9b386f06d93bf006c67ed33263f0f30785ca1837f5f9c466e2cf593bb08c8c));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x241f4ada30a82ae15d15b06458c3300eb2567f3598c8165f9159f94045dd6358), uint256(0x1602835b19ab92b03fe16e9399ca515f3633bc7728c3eed8bade2dfd0517f403));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x238aad8e7f6f77304d4a600787661c1e567e01bb78508054a21a256947013962), uint256(0x2014e3a49728252a7793a742eab004ff9b56afdec9ca5e836929402975678352));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x22637bb37bf4cf1cc70068c93abfd29d355c8664cbfef4af02a62ac3b3edea3d), uint256(0x0abf99652ff1dc0d3d727fc3e893712c529c7a3f9a1c9c453f22e812598c0808));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x0daae2adf095432f4853aa759d48c53a196e906228a7057c54e67fcec161a678), uint256(0x0ddeb950e26c1755f1696374caff75573f544125f72d9aa947afaf60ad0fe718));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x061fae6a5600a78c57a57bc648acb16290c11aeea4c0b7e650febd5366c746d8), uint256(0x10f96cf7e17bb9dad7bba2d25f89df4ee8bfca52a1045a67e6fd18fd0075d169));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x17a33d9dc49918e6deeb0c980308f512ee07330d1cd1518ebf8e7beddf964938), uint256(0x0691583fddf1e04ad59a2b6e0d7f2c339923cbaf2c78247e8c27d5602d11f032));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x151738846fa7a977645fc512a2e418d820039a2c10222c3a163556110ff75878), uint256(0x125d1e29e84d7780a4502a665bd897ae03027cb4c84799843e81d0b855d57106));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x00c3458a4198ee94078f71047fb3a65d594802e11541703658d43888cabcfc97), uint256(0x11e8d6fe14805bb779bcd23538bf38a44d588864d58d589c78bded928491785e));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x1015fb156c0c859a9c16a42a64d25b40d33d3c307ea7dcd4d8ac9d83360b77d0), uint256(0x0f1da5b380bc1a04b2e5b3cf32052b46b5456ceabeafd20dad1ac6e0c719b90d));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x0e1b049509b435426b46157dde3887a484c518ff7efb027bb03fcc9a229dbff6), uint256(0x0a95306330fde4034a33597e61f2a505eb0ddf7cb086c2740d61ae2a2e19cb0d));
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
