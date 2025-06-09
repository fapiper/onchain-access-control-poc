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
        vk.alpha = Pairing.G1Point(uint256(0x10b8cff231535bf72393903d5222bf413a31b17cec79e2cd2639f342b01e53a1), uint256(0x10ed6107638b71847b6d075c08ed96f066e0e9df54864097ff09169466843c26));
        vk.beta = Pairing.G2Point([uint256(0x111a156cbbbb618b93a7d848817d3dfaf24040972bffa1e6f712432e73bcf414), uint256(0x1d9dda45177afb3b023559109fea34a27462ec223bb82a55cf6059360a228515)], [uint256(0x1bc1d917703b9f3f46ccbd7c1095f87a39963d4459b4d22d60516e9d3f897659), uint256(0x19dcfaeb68c75e0bbb261fb9e0fc0817bba71ba60b0407c06ec910c3317e7d4e)]);
        vk.gamma = Pairing.G2Point([uint256(0x1925a53c31dfd22a5e663a9b151de2d4c4a40e9da97a6fe52fde6441b70e5a01), uint256(0x1e6a72a09f22651819f203acc23b4d1525355076a8c273268747480ea528a1de)], [uint256(0x0b74dd033ad3bf102c680b763e5b8aa29c1726b7e2431e14e7aa3d9c85aa8515), uint256(0x25fdb916884a0c223f443441f49724a076451e648bdd35a6d4ee5bea8b5050af)]);
        vk.delta = Pairing.G2Point([uint256(0x2553565e06a19742e8b95afb3e90b81b3abc465b9221ed499acc0c5fa7e00980), uint256(0x107fe93cb5ce92dc6baeb9156b7298d208035e0d7235a898936a1afaa9012466)], [uint256(0x1963bd24f360eb69e38fd3d1b57da6ec0cffdf186400fc9b0c6ac6741173445f), uint256(0x26be63b0b0e652c56fba28d3e120513ec22b2819437fb8a7411c06b16e03f57e)]);
        vk.gamma_abc = new Pairing.G1Point[](89);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0579bf5fcbd3a0f553202f4b3c66981ea8895a3ef1257a6fbc89c4981f0526cf), uint256(0x0562baf3fc5966bfa7b3b5214f2508e41912cbce0bd4e11297dce23393bf9485));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x059038c9efcf35b9e138f079a1c6f5feafbee21762ee711634e0359d9922a9dc), uint256(0x03d8de09f323aadcc28bd0c0b5d09a0711efecd31d8f87b4b175c4dbe04f0e18));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1fd34106a3561033e80a217130cc072d4a022fea49ead3d2dff4e15461660144), uint256(0x26976e541b7a240d60cfade31143bf479425fedf4ac1bc3e8c8fbfce32a372bb));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x29a3963472cd5439d6cf37bb8ed335cb7c28e6f922e3ef6beda5447672c33f0e), uint256(0x1819f4d738c882eb1558f4104cba9fc77f3c7a7e5ff482bddfa40014c8c3bd0e));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2818fff760c366a8239d591cf3f121173d20cd73e625ae94c2d0b5e5d3807eec), uint256(0x108b2fc3a5c4324115b691ada2b40a4569121374e238e776fb725343722f6f77));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1fbf901479925f455fdace0752ac6b7d2b2ac94a4adf66cf495618d3156a23e2), uint256(0x016c141b9a351a120e8d0c9ca6b38ef4fa58d303cd40d4b40357dd1152dd9de5));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x287ba58826b35f2393143ee6294fdcc5db1b81afc35a2d875ae2b6b030c95946), uint256(0x11bb89532e6b26062cd8b67bf0c613aa9916e6676f4a9e6f1915b47a9cffd45b));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2c19fe519e29e336dcf84b9d982aea677d883f100d43e1d6f015fdd62446ab17), uint256(0x0a931669c62880eca6e6606611efcbeba35ee6e924b86f34cba4d4ffa46a1708));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2815dddf11782c5ce0a103b08970327959a529eea81cf716ddf0659c4fc26a08), uint256(0x02d66a91b55f8b48e62e1c999b5d4329ff0ce349d47e307b300d39b9eb7423eb));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x202d59c570051465a1af55076b75bea84157ea242bf4c641f22875dd89be459b), uint256(0x24f0a125400ad23c0a9a76a9f67cf8191739c4bf418cf3c864d60ca608d356c6));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x028ed02584b4b292f7a74843eaeab4721b911117f2ac329e7e86b503c3527b27), uint256(0x1e9c998234525360dd6aac01e52907300b192a7236590f74fe65723209c3ca07));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x11948df11206ea49b154e1deb0aeb15daea34731978b3ffc3fd59292ed0278ab), uint256(0x180bfbfb8633d47f8c76767771334d09a5845c74b44acff192c77ab786c6dd85));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x03adf8bdf89c7e8d023d0d10001306a29db41f7ea8f0710a2f8fb64673389f62), uint256(0x2eb9cdc8eea6473502f4b0c9dc2075023666a77f8631ea32439148b94989e5c9));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x24f3aa09e382857093f3ce514b2b61031eec978cfdd811b71ed43a73491a0fe5), uint256(0x16fcf98e4a28d16364f392034eadee9d91681c16dd073e96aa2d1075e4771dc8));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x02a9d696157b0efe4dcb2c4d954fe724a77b4451bdb14b0e79cf761e9af006b3), uint256(0x10b564772835adcda012a8f45c38aed32b901f6129883c22b55c7097f26af1f2));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0a4a7caffc06e16bbc5c09460f17e609c952d0fda81ad512248d0b0d42303702), uint256(0x0eade9a6b876782d6a6021ac993179699897ae999ccad343275b372728d7badf));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2d6354b5e3ac66f46f27d2348302c30d5ba5e681f37fa1996737b2994207ec7f), uint256(0x06b0e481de36804ccecfdcf74784895827c2736321f92ee567e2078b0efc17b7));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x12a92e3a3548cf5e27185bd1e51c945725b61ab8a7c1ceba08efaf3fc9905a85), uint256(0x2be2e13e6a0d38d9a19afad0b13d5b65318664aa4b1ebcd815f5566f6ab23c49));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x070ffa22f85bc980308ccc26dca731f2d87e354391969e108bdb963a8f251951), uint256(0x1c2b19c374a506d40772772f1ab03050d34f754f6b22641218248b76c0169cde));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x282646bf82043f198b74db3d32e29bc1a43e5fb6ef7f39e15100484696b5ad74), uint256(0x14c01bf7ea3314d6c879a8c69badac37be1e5fee1fc2d4837ddc13f3686cfc3a));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x13c0adfb47db379967a1a03953d7768f2c695d72722e824a8c825175549480f3), uint256(0x0139697e5d8afe8579b188c4598ad9b4e832d903b349c12b91ce482732b5c093));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x0979e039760dd67a18ae988d0501ca7b1f1baf14fd10fa35eb54ded4770a440c), uint256(0x169ea96611bcd3d30e2b3a2a96895d0dce93975ed7dc679dc48d6270616da4c2));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x022a6f4f29adaf5ef1aaf748a72b7f95748a10078340e6b0ab4472f327cf7d2c), uint256(0x05b30c883a98c7d6d0a2bf21bd5a338da4b507d1831c303d16685ef776963872));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x14b83cf8061947a19db7dc5be957623272784105ef1a2ce1707d00a9391010ad), uint256(0x225ba39d0fb50aa965bbac2f925288260144dfb16fa2a4132729e4b47d3cbcbe));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x170bf8d1c7dd07c6d34e95381de984fa9bb6bc552f77ba6e3833696323033be2), uint256(0x2ba71d3fe945c32feb749eb219b65192806f2e1204a102a5ca543ef57d0e8e79));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x1ee1d2eb1d556e00db715f84b7eb6c3ac0a8004275665b46b8339d25f54895fc), uint256(0x04288925d34c6a5a95187280f601db3bf1550578ec2a2cbc7a9f1e58867f6c37));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x18c2c249348d395bc9730b81ba03b12a81fa53ebc59177880e20e62ee29fa19e), uint256(0x2f346b8a777c9b38b155c3cc758c2e8c1b2552af48bf3ee434935f80dcdc5952));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x07ee3523cd40eef3fd7ba21bc41cbf82686458c77d27f7ae211f8316275f7bd8), uint256(0x2032bbacb4492d95104d6fee7d9a0d22c69404fc83a4e8cfff398a6e23c6136b));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x031c6f3a589b5381f406dd5cde3ead8a443c5e133147005e28ac0a150bfa9748), uint256(0x21659d9a1bbc8a5bb20b7168f8832f27cde87379697a0f8904aff66aad212f26));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x0b0150e93cf8fae43e591e75dd84cd5d238f06d2dc06d74e258bf7ed19c5a9ef), uint256(0x100237db390fce288bc46ea6ff1b3d522095cfdc30b636317f2677c1668fcd53));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x01b15c255e8822aa4ce37f613f54ab5888e89d9781cf09ea34311d69cf04155f), uint256(0x232d6264a41e95e9db443c72bc66c377a5ac579a057a1d81db7bcdcdb0843760));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x0f266a5015f815446c99d373b229d11b3343f81f5e9a278fe9ac7e72f0f08e02), uint256(0x2348046b559c74b489f074459efa891f0221d9766361ad8b56d04a9b35aff06e));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x1938b1be93a49eb8754a48029e72e7050eeec1ba6a8b1844f5243523e6eacdd5), uint256(0x2d2184e78406f68d801f026a56dac755a2f7b55f5c2c3610da4e47aac448d59c));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x228e2aac0ad4de4e2ada281bc91121ea0ffada77a9e2d096adc30841331dcf27), uint256(0x1263f59f1d4752ba42346a950171b18a84c7aa64edfd1cbee94e7398803f903e));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x01f3152753a8a853c162852b5f28fa9abc9a0474f0888a46db4e71ccb7aa0d01), uint256(0x2bdca881722e47cc184bcc03c4d1112f31a7377b6e08bbb93ce39646da2d15f2));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x187002971a943fef81f0c7f09fc925a32ce8a820146b0ebcb1ef6d61ee28daaf), uint256(0x13c77d36c47a778716fda0f3ad578a9cf85130476d7d28628ab2c299c9899634));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x20ff4c2c0173e03841aee65c9c6bfc800105e42fdac1c82545b08db1a4a8fa4c), uint256(0x211d221a3053e52d283f88f83a845bd473323dd89ff94361e18f536e05ce40e0));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x20d4d3e464f7958acfdf24a12afd12612c9e9b645186a3820c3809d42ff62f10), uint256(0x2e95600a1127ab691c5fd63d5d2094bb70fb412a24513fd6ee10f6e61bcb35f4));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x2a7e4129a58874d44d3e221813096814a650d1bccb65bbb6c2e0fedc8e619911), uint256(0x0932ab27e1ae11edb413908f8e5c975c241066c94e310da4bf8903f54f61fa8b));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x1eb9cf5a3c848ffc7434166da029d53082b7a225f0c704dcc88c12f8bbbbed58), uint256(0x290d10675f63ad2bf5ecdeac37f26fa4393a457b516493df619b1dbd7b4f8162));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x1758b8c91c1dfa9000162ff9cd6521b71508dad5498aa16b84fd31782f0d1c7f), uint256(0x25ae612c92b75ba1d10a2deda9d0a621042b60c5455c01cee055de0d18ab50d1));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x0559f896780706b77c70d3bc2f375e22ca914bd33a648ab90732e8d8a072e259), uint256(0x0a8e8eea4be0c1ad5606465c2e439e40dd86d88e02520052644bb50bb3d9e8d6));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x1c8026ebfa5914800ee4549055e686d24c82483c453f2f0a8585111800b0ac37), uint256(0x14a7ced1a8fca66a011ef5b425faaac004fb14b51b77f948bb71fdb5efcf4add));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x1c95295443b6d6972d7f3a4e69667ed58bf6f636881f64470ac7745464be644c), uint256(0x2da1500e593bc4d29d1fa116796a0506cece1500bda52fc3cec5120a2605d413));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x1b0f0900c27ce3d727b3ddb2999d475d004f9647e46412361e52911105a18528), uint256(0x216dd03a333fb5f0e52c5a089dcc395110c8d5d09715346e3efabb0795dcecfb));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x2dc332c843aa798029faec0f5bfd59cccbc6e04f0e9f10c9b71d8790a9a1711e), uint256(0x0a927185660c87efca3e0eb052d21c06144ee2e0a020aadfcd7865ea7cb7c61b));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x1755e39903f655c2e9c464ec92475f8a44b83c02956c37862843fd52d2e5b857), uint256(0x294337c369c279a9111b6c2aacdd16420046109000698c3bf4ffd5392f27895e));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x0ec48f4c8e46526455537352d4e68f796400d25275bbb7e3653122a4097f071e), uint256(0x1fd8b916066f3afb4787604dfa4f2a9cf4b1df58405ebfb51bca8627944e2e3d));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x0e0aaba83bffc36ab15158b1b0bb29e9eb64b6eb04d7ea01bb671d91d21c49c8), uint256(0x08766f6621cbfe68c995d5efb7b58c5ebf35431e36a0a0fd9808107dfc98d7a2));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x026219491d0e7e5a07bac7216af3dee485f5c1be9990746dc8fb4f5a5a1c7f2d), uint256(0x203813362711ea541d0377ebaf719f456dc5c67e0473412cb7d08be75bfc4073));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x043970472b566d711958f12a64683194786ee61b9059822eadf89237e200f547), uint256(0x26a3cec497afc5a768dcb669d8c848a1a2231f4cdfa56029c058ef900697e1fe));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x10a836af34f7aa7dd6692787efa634f6878c95af4ebd3f9b7073e16a799a14a5), uint256(0x1f7679e18f5eacfaf4e01361f080620c12093d236d3d3f7ce39722a6c9273972));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x093c1b787d69a464faeae9c99f974839724c5a0eada616aabdd9dd9431889359), uint256(0x0bd44ecdabf181a66bf5993b5ac119f1a39b1f73c0a2a7063252abc4a494e7b9));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x147876e9cb266d728b2b7743499e251a74d7f81a0c942a182185803fabe06f71), uint256(0x1c6befb0a8bffd7d12bdc678e215d71aa983ea6b57c146ea043e677153e28358));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x241591d5d9e25365446e6bbe01b58e437279d28f1657676f1f5e02dcf770ed07), uint256(0x0bf6f59eee0663567fb917c7a9308056c2e72793acd4b6cbc849137c1c0a800b));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x0844eee5300e53b19c9b45d46e86ab7f7760ad9aedd78fef0139fcda6aa224f8), uint256(0x026df51c175615e16aa8123f6ae87fa526859c437cb1817c56ccdf38032382da));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x19494bf9fa9db0baea64725199aabfcc2ba32c5dec3fcac068e2184d6a9ad8f1), uint256(0x0563a195140c654fa929d3162762359dcef2286db738d025b72b379b44199fc4));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x21db93ffd86855195afa428102d9dc1ea2d40d480026a77fb05e7cf7dacb4b15), uint256(0x18f94b63e014949017892e6ec18331e8ac2e4ba3e9e653487f72c99039e1724a));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x306316483e43c634a6494b4e7bee69f637905175f79a08457a40637cfe599b45), uint256(0x0f802fb13e3e5db23f214ddb0eadea604c31ef4e082aa30328231399da375ea0));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x1acfbfd2f16e3e82be251840c168d816482a809e09504ac3de02bd85470ea69a), uint256(0x096470dc2ec16787e2d959f654c994ce31056a7f523d5b13bcae4cbbee94d7a8));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x25ff824da835678daf5660719802afdb0c4e6bca10e852433453897553f1b1ce), uint256(0x1266b4af9a4b522290b7a23d0371b9185ea2b5139c6553ee2d79f5b84915c33d));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x203ba24c5c4124a6fad02b9eaa64fa5832f0643ff4decedd980aaac5a18784ee), uint256(0x27409cfb5d498b99e3761a67859c01cdacc269c48eb233b417c2c7bc31c0e184));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x190117afd3f9b5f8a9a0ffbc2e08d4915dd02e45f16e07a04a1c892331d93b20), uint256(0x09bf9a320a040276c659e5850a3df305d588bc1f20d1763e8bbbfc47e93c4fc1));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x13db47d324ee380b76c59db87d3598bb0100a9663676a7e0b82a117ff62e92a3), uint256(0x0f66b26009f628c75e61ab0dadb4a391f7aaf514fef8c2b0a10040dbd198a1a8));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x154e7abe0aa15c4b9304ab14d59b77239c1947c2f2f1bdbc9ebe55e0458d7f1f), uint256(0x24301dec19577d57d98aeabeab848bef332c62348912753330c0faab847446cb));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x15931275d9f3ffc9f6d375612dc67e69f919d82e25d2bcd9a5e43e988ba522ae), uint256(0x180cf2bf948b87bf619d769175b1edd6eb7d404229f9da37f918cdc11297643d));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x02947fc5b800b01c7aaf7ad51dc3c474716abb099b1c11a2039b7cc771dc6225), uint256(0x14d7fa993fa9645632a82d508865cd41d051923c1a0bfc3f181d32cca13b34e0));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x1b2703c5eb6a46b27cc7f87f87e875ef5e6c2aac86387c10f40d358fbfdcc7ec), uint256(0x238eb01530f2ed4a91dc577fbb0ebeaf5ec322f75a9325428462697e35720cb7));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x1cf6f0ce49250b0216611b34be0b218f4493bbc707bd35703cac1f915c9dfc95), uint256(0x2d4c468091e0f55c68d6391827ad08d1681f00205d27f3ee63430a420ea4b2df));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x1d248942bde147ecacf5fb4b6930c9bbf92c51eb7a2e2783675d480a65e5719a), uint256(0x2e4d9f203e280a0d087d8d639beac58b0990be59fe0a5ea96b66ace6f8602802));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x0d845d2c486add0002466f33a466b24cd4201168808093e27a0000373c77b6af), uint256(0x13fe12f8b689de5ce05a6cc848835f7f9a6283fb42732e1bdc791abeb0fb1e64));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x2175802e60e865d010496493c30fa214404c753fb45fbbbbb261e5f0baeea902), uint256(0x195de42b16a4018a3a4efdf412dedd420692a569a72b447533d2068dc43230d8));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x2787449c64701cc84a93c9602b9c97959c4347699b7b052b9c686d3e937b9d42), uint256(0x09a83be8315e05c87a414b483cb59c91bf3776524240a981a0e0f21526c73d98));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x285e37fd2541e664a27ac888fd7e5c674476edea9d1913d831e9a7e793476f23), uint256(0x0f14bcbf1b8fd193b1fd02a03159154e8391b12a4c461fa9299e11b344b2cddf));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x0e1a0c31ccdcb6c03b400ce18bd481ceb04a6a82501f108cb6afa51315b6af48), uint256(0x2d98a8010f8133708842ca814c4666ea2cc836a39dc4c09d219d46d6e9386d31));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x28afc4280db634cda5d406aa7cb0a77c01be00ea6e10a79930948072f9902ef7), uint256(0x2cd4b5c84141a434c15c1eb9e9b63f77164f9566babc34d15d8c3c711bd27923));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x1323308a54925e3134d838ecfc8fe76220690285fa698bc93de7ee6c95c5dc10), uint256(0x177e6a86987ce1849bd22b0c34a6e28ae3e4bb247a1c9c8684b56ca041aae42c));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x1338bcae9b7d3a37033111e051ffcdf63880629484a6c436b903158b4117b6c6), uint256(0x03ce6f3318cadfe3b8f81e217f451209bd06758f1ae9fae282ba64fb64ef0215));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x192b2b854222f1b07c61e2fec2ba7c52293a8864d64253aa05160e5d9a62ad0c), uint256(0x2ab88d79215bae44c6f7f01e263b1e78188234263439ee78a9c17e96f6e5476e));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x07c0f153cea3a12a8b949f9e88afbc40e3559ec7cedd860e1aeb0f7e41b017f7), uint256(0x1cd3f7dc2a609b29d8798f04066cb26a9656e3110c80301eb6a6fac4931cb515));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x04b35691e5949d91b6b209141dcc7d606d9dd7a16b04528e9c62e0a89888ce3b), uint256(0x10f6cada7318e00cfaa1b23234444a00afc880dd4e2e3470a51032075d0288d2));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x184052ec73c7b382752cb6604db4b5671915df32fad8d7f5af9bc33ef584dbca), uint256(0x05a32e2f33cdf91fd443e0ef91183677f82c54425f86d3c49a182b0c239037df));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x0b571b3c1a7a2753d70e685d4630922920f9848780f25889931b46ef9e85e936), uint256(0x094aa6873951482ef20c8c3b3f03528e6a390d64604651d215cbcc4a3eb24a41));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x0de4b2d47769a974ab30dda5811fad1f6b8224d11f0a13fc4f5c2fd54420f727), uint256(0x1445fda06e096656358acc3356bc4c81f47a638259d663d952aa8c11a85ae7aa));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x2cb06fa3885d18b6bcb11e425f2df853d21d5bc1fd0fa86afe642797b3804eea), uint256(0x165e90ea8e084b1153ff44220b96d06a65048970659309348462f30dc7f08ba6));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x088c22d0aa406f3a2f78a6efedd6e77dbe87db291e26c7f87c174f0fc075f16a), uint256(0x267c8a5c747213895de7f751339db21c07c15af722f390187efc22d875dfb76c));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x24e4d182c59e29d125b2459552c03bba62774b86445418757a85b02eb71d00d4), uint256(0x2089caa4b0ad9e1cd06542deb0ca198538b9d8d4a786a93b16e7f8ef8dbef365));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x03fd8a93515d88f270abcff08f05bcdda45ffc1865916ebdd0d600756e795e6d), uint256(0x26fe9c9bd216d548c9f4e6e5cb2844f0a50abf6db4b3e8970d1d94f7c557ac05));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x1ed188c2c782aadfbc9b3bae06de6ecaed3ea6b239cb6b1cb3aae876f0821e2a), uint256(0x24754d74255adc4669351709b4f9a7c1ea281c3e09528e46b04a625cedaf6874));
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
            Proof memory proof, uint[88] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](88);
        
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
