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
        vk.alpha = Pairing.G1Point(uint256(0x22fd3ccd53ee32353514306c43512b1ecb745fb8356fae79c2268dd2a5485ef3), uint256(0x185f06aad67ba821ed56d69b1c390fccb89856a50064c257898d7d69095ad578));
        vk.beta = Pairing.G2Point([uint256(0x2a3b74d5a1a858ceddca9c61a03e5f25c663612dafb5296c7e6f867ee507c7d6), uint256(0x1109cf17fd4d5e483f402c72e82927a93cfeb3407fdb46d336ef98dafc1fd058)], [uint256(0x1d3fc0a1a270da5239ca66b4b6f46abf8c9da4650f85161778fe55b3f314cce9), uint256(0x102df9c9b614a70d2ee59294ae9295a822f84e551e9852a26cfbb6342958046a)]);
        vk.gamma = Pairing.G2Point([uint256(0x22142c585b61e41c69df6e7f6abdaceecb993f79e013a57485b6c3dbc950c4b5), uint256(0x0c1971e285eb3e3bab0c86970e5e67f7765ef460fde70b978025ba518255bcff)], [uint256(0x1896b059ca7fc9ebfb0c0158919ebbe33a78d06f053316f40ba890dab6565676), uint256(0x21d3b92c518b390fde89568a5a56e96ef4ca6641c22875e05d382dee4b05b6b9)]);
        vk.delta = Pairing.G2Point([uint256(0x15d93ef6cd22e305b5c9b1021db455260a71e51cd6c5b123d63687017fe9ac2e), uint256(0x07ec9e4bfa1384ed540aa9b0a49a19ec751fd3773e2b096c6e60be36fc6fe168)], [uint256(0x2e68bdc5bb4fb6e945cfdec64b7c55ce35da78e85068814649025f1ee1c9f042), uint256(0x24d6b0756d13e5eb06482b9f213c4517a705e2ea959f6f3f7b643a0a49f40ca9)]);
        vk.gamma_abc = new Pairing.G1Point[](49);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x18d4842ee6ce85cd061007be49e773b11ee02ded33a711d847454f1e87892efb), uint256(0x08d1b8d484ae06621bf2a112c05a41555af5697d46999e96daa32ec28d7fc0a1));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x006673746e7ba88adaebd76f320b75b2b4f6e08c303dec931eb103276998acc6), uint256(0x253d968bb2693f0da4b18276994c815371009e5afbedd5e51df5b5b96c75a588));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x050d3f70d692eb1cf82fcb7df81297857468c16d91081352b841c05329019773), uint256(0x2858969a70585a9c6a9f1d7be0af1d405135b8067581a51f758df454fa4601f4));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x002f7d5a77de09efda9b8f550e1bd0856a405d63449d7eb0908af3037214f91e), uint256(0x218bfaabb962c98b62943ebc9e7f64d64ae54adef30099192da44267528fde54));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1411abf2fbd52e7820e72a07595556bc949e41f47f237d94046f8b56e053c349), uint256(0x1385396c5e195a17d214f2dad01ddb84b5a032d51d679907e90e331ddcc1b484));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0eaa8a584f33d1b641ef57aab4e622c555e96d9dfb24fb9e570490cc59aa857d), uint256(0x291bbd0c8dceaa1a10934d040642d17f90372e8bf4ca3c82cd0347e3300f8d34));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1747ca57a3315d342db4f63c6bd9e054c45631e8a42b8341b459b8711f34c341), uint256(0x29763fc53d73b586cae79badeb06b857c7bbc04f526d9ef158ac68e33e8a7336));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1c884e5c7387387131f468e6e2a89c05f313e9489b72fb415761e1155ed44a26), uint256(0x03003181f634bc9bcec3f07d8e84e0a542712d1a8bfd9417e4c24b8d8d1f46f3));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0015b542f1d623a6c3521e7f35e674e7d903f86702cd623fff8a98198bb57eef), uint256(0x2c945facf927b1faf28644ab4041064b3ffe1f4f74b7ad4fbb593c7ab3af5991));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x040a13b57744dcfe3af198a3af26a4e3f387ce1a2d11ed89dbf15123222db0ac), uint256(0x00493fcadb926dfeee5b21a259264a62b75c6fa5583cf17a080fb2f5df367b2c));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0d85db743200ba29ef255caa0f3d8956221f9d35b145725c8ab39b5ad6e53b13), uint256(0x20df8d6af2d08de4b0eb5ab223bb9265b59a09541d8b59e832cada91b09c7e79));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1b7b4af1edf454b2d85966819d97262e06b8e6a669dbdd9ac7f34a695917d420), uint256(0x1d4945ce05849f24e4aa51995b79cb39bf7f21bcd7bc4ed7948ad8019e495429));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x262cb3e58bffa54fe839616faeeef138cc147ff87b1bbd680b3352f239f13127), uint256(0x185f469869c031714cfce72b1be670303dd802e47a298d5f9e8a6aab1904ab5e));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1af05d2b4e9bfb50246049a7b300eaa1e1fe3d8fd645d7e911bd9f089bb3c1cb), uint256(0x0d1409d3aae1a99c31f25fb55b086cbf43a25514ecdc8f2a95eb8fde122ddcfb));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0c3db7725c659c2281d12f232cfea2f01871cbb32d6f722946ce76ae56e03ae0), uint256(0x0740744c973b3183192086d99808c191e81b794c7a99277a82a156ed02739f37));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x06d4cea527ab77ece50fa9985079eab82121658485b6d74c0df8d6e452d3c254), uint256(0x25d43b206bcd1fd198e597678c15c5246655231fa61ee59440146e3df5def52e));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x032a0a77ee36ebb98469ffbacfed8a2214c351806a7b153507eee3cdb15b213b), uint256(0x111cf079a6ec64aeba3b88b3e16f9e4c742b42afcc228718670274cf3f295b14));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2130cb56703a9d38860a898b19dfbb5603f65c4d7e99fa933095607208397cef), uint256(0x198597c770bbe58867799d871e3abd671bc95e2e0d0f92daedd4a616fb77df19));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x0340c57a5c2eb49d6bf390d4ce2063983fcfa63b07603853437966ad1b054975), uint256(0x2badb21d2e04431ca26f9eec42578eb4f09dcc7bb1969f3bd966af48f1f16c2d));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x0402d78a7bbeab394f96d4ffc8050d58e81bb2fd89b1741d34f79eacd9143566), uint256(0x04d8ea8b907738d1fc6d7ad3ddb96870e0f148b94faad8be40e3d872a91d229c));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x23cc023d625342a309e4f6dab8d9dbde0c68e0e807373dc7eb5b05e1df71754c), uint256(0x295309dd35a2846ea61e92b730e6190d4daafeb2435ae110fae86f9cc60a4e44));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x2dd2b4e2fe18d28dbdf1d610279093f68ead16a487683d68f28aa376fc838241), uint256(0x276679d726a9161a55e8964b0702abba5c12f332d0ea206110e6991eb2e468c8));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x1f267d1ca927882c03cdf68f1b2d1b65283d2f1c9488eacd3d1d01e7ccf819ad), uint256(0x1d3208393657c924cab431c15a583239418f62bd3db1e06832883b984c0b5e75));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x20f1d2d47dfdf6b242b00a031e6c86a938f194f4a3e7162217ae49d155f33f53), uint256(0x0ba74fb9dc6c39bbc608c2e5715c5ea8da2b42744fe603ed4959757d613b1b86));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x288832e3da050ebd50df580c0cd11640cf3aa9744d0565cd2ed5a43102d3016f), uint256(0x0d7a3218c6be6c232d6ec007d81c2a996625e48f2bec893cbaff2a21a13c437c));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x139e7185b39662a24a7fd1741b30cd4986e4edc0f7e6f44169cde75015f07581), uint256(0x1dcc2290f7a930906862c62fe0afe1d0120a08d33443ab75a0c47d9b5136ab43));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x109e8dce733e92612bef463aadcd423a3d803951d0a2ce57933a57cdae959aa7), uint256(0x007076134a717d72a2c0fff8cdf39eeb2c46c5961918f0221ce7396991a96eb8));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x28b34bdf0cd814933115fbba2417e47a506455563aa713518264fe7db8f49ffb), uint256(0x1f67b1cacc74ba3c906badb4328e6cd4a773072208b23691c217c125c948c3af));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x1950ccff43e775a898769ddc30ff3e1b87a8aab35945ee4030d834a8e82cc687), uint256(0x2662b338867a951b6e3164dce5207db6c0dbb6d78bbb1a14e854af6a677c2870));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x1d6711f2d4c450e9aa570abf3c4704c687e58746d9733f41a1680f2bb4ba5a75), uint256(0x2ed542f7c07a54cb7a171a4702289f6750500407b41e21127f6d47d343ab9c3b));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x2ade5711c9fd65f6c10bae8ef7d9aee40fee3b3053a6da9129c7cd6b798c7558), uint256(0x293dfe6df7fae4afdcb42cc135a445ac928d24771528c321d7dfef105836da96));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x274b581fdeba2968fd9744dd8584fa8873adcad90ef1673c1b24fa2b8745b0fe), uint256(0x0db2eb84c0aeeddee88a48483269f4f4546900bb7301d3607a5c9a0367b30035));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x17ba2b317567a0605c2701180ca1e71c561c9d1e98d83a7c60b090623c91974b), uint256(0x198ba3ea3ada1326d120832c3fbd5dd2710f4f6d0fe4e30a1b87daa2f8faca46));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x2004365c5d251f89c42a280fa6f2ab04ceac5831083f85abe51f529ae9dd6d7c), uint256(0x17f5ebbeb0db0356f48855b3862da013641fb083090093a87509e0bc4ded5e45));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x073b70ba5c846e1b6f114e6b80af47997136cc58aa9f86fb6a23c015bcd7468c), uint256(0x1dd17c3cc0744069a0930b0c9df801fd75f82e929708b74cfe8cf4b15a532962));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x0696b97caefae769fa7a6018374e51786b1e6a0e6f15a6cbd9f97ddf6a2eacbb), uint256(0x11a689af4e9ea76ceddaa0b238080e876bc93684290d5f3347f6de517ba7909a));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x22125e6dde46f498c4ff619ba195ec5b81a3e72d9fc8eaada455a6c1df9ff8e8), uint256(0x2f0f1ee1d6b835e72aa88c26c9359a5d81aa3b8b762ce17a5f53614b70ee0b50));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x09d79289a12c1ebdcf7974e68677223c2f34feeeef48808d4ca8bf35eb8d207f), uint256(0x102c9466ac9edb406a19cd40eb6f5decb9ddb2247a70f3fbdc5dddaf3df71772));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x12bd556688315b1d2f9301afe4c653f8240eb22b1bade15dbd38d70bb83d1e7d), uint256(0x06eb4af7b678ab7d1f510293f3da7efb9b88c638ca39c7297c03238d0fcb68ce));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x001c9e4b52a8f8f00a7d69912f0637a64df14e3608f2b4ec391af2df1293efde), uint256(0x2f61349df274b01cdd27d2479b174052934ecd8ccee1c398b02a57e838db6edf));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x2108fa7e59315f383e0a59e055c33ba5b346fa77801f5f9d385d366868ba1f3a), uint256(0x11e994ce9bc59c272dd4cef6101550d400a8083a4372345512a16ad7fbd28316));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x2bf9029db1b045d66cb72f9ccaa53fdab6ccb0968e0db60af8c9b9061836e463), uint256(0x1e28dab093c7171d49cd0d52ce50bb34ccf37088602e5a6867286f186f3471cc));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x04aa7f6f65018b5d0c6e69056b633099304f3b1dd26b6c02c0347e08745a5a9c), uint256(0x1ee9afa9fb2f55a5881eab9dc52a6177f5e1c5c87ee5da2eb8e0039a6608cb9e));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x2693c7c903f5709bea2695f41ae80e0900febe2e78df50a6b819191fe261ebf3), uint256(0x2bfbeaf41716b5d87c028fea41e6e05af320fa37567c75c8b9d73eb31491e0d0));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x1bd3d67c7aeab904b67a696bcc40854170fd9f19a964791c4be0234feae00fb2), uint256(0x0f3b26b6fa5c9134d3d70d245c6def0ef3290b84c248f516c11e58a417f9ddb8));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x1aed01f896c51b4eb5a20b586c23f0eae6c0ee21e181278f31734f4eb7747bb7), uint256(0x00d46307d66de167827dd7b1a30bb9bffea3bc1e37be0da64a666117c951d9d2));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x27f84272cdd9025daf25577494bafc705a3d486ed37e5a7838d72384c43de496), uint256(0x1c576ae7afe3871c47a387d9b5da96a8f5a96a7e1eb816cd12390ceea79174b8));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x18ca33fa7979d5f473ae1528a1713294fcfe607070641861e60804e2f6676627), uint256(0x02484638308f46744946491f7151f4ea769d78248bbb98bbfcf9843bb1bbf47d));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x2003e55881eb9c73f04b243d419d4ac6051f79c3c2f59aaad604de7b446eac52), uint256(0x2c2015d59014f73cf563910b6598f66aa456fc1f2cda23f395c269df304de671));
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
            Proof memory proof, uint[48] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](48);
        
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
