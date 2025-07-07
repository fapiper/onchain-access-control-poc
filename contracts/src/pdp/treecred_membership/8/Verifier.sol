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
        vk.alpha = Pairing.G1Point(uint256(0x1cdf978f5a13fc8f6671e783427bbd17f7dbb3947f314a0f62a56531914025a8), uint256(0x20677abfb0d6567743622775ccf63fedcaeb22b282fe67ae34cb4bb15c09ebf9));
        vk.beta = Pairing.G2Point([uint256(0x251eb288e3bb1579eb1f0121bc0fe6b328d0a2d82ed15dff30699d7e1360e1d8), uint256(0x2e272ccfeb3769a75596378aae5ddcb178d0a4636b9018a1c928314b15d4bbd6)], [uint256(0x1519afb98562ae82666ccc24c0d33c692227996c4e648f55a155bdb620ad6e72), uint256(0x1a7642871c336bd7371b1d6638f1e8aaa641b6974a2839d35238cd7b2a3410eb)]);
        vk.gamma = Pairing.G2Point([uint256(0x24f48c98982bf733df4564c67ef5cf83707c8219dc6b926fb8032c5df3a621ad), uint256(0x2d83eb8b89a17e2a6a4a2aa9a50332143d8ec6f0ba38df9c4094002d604a6796)], [uint256(0x138ec79633b9c674d6c1d8db7435757417676587fdbaa4e91531b4ccd8fd0766), uint256(0x14b53a85be2a7b5e93721a453e508bbdb32fa6e02093e5097cbe7fe6aa834d09)]);
        vk.delta = Pairing.G2Point([uint256(0x2e17ecab175cc3dd08572ae8efd31cb528f57b5fabd9b8b64fc50e9d2c283daf), uint256(0x220fe979188a3ec67d980a357be8302cf0914c0490042861be8f3e4fb5cad9f0)], [uint256(0x24a723da9a35cf580c50994aa08fd9a5c9f2d49f4aa3b1005c05307dc5495fa2), uint256(0x1b9a700439a505343c1e0fa89ff2d82a241654a2a0a3e1b87d57b694a77b54f7)]);
        vk.gamma_abc = new Pairing.G1Point[](92);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x28fe83fe34cc45ad765760547d375533007514d5ebf4bf69183a13f9bf8b8c0d), uint256(0x162873c8b48bd777279f6c27d17c13e7b9901973f4265b0728f3945b3aa5ba1a));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x23093a824dd04dbd4ecdbbeeb286dbecee05ff8e94f63ec5121f89d9e491564e), uint256(0x1a8c40f0d1d6e9e7a4a86baeaf02fc297eba6c230f9feedc19fa601886ddf943));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1307ea863dd07f6087d124f6ffae9f71f3ca4691d4ea732858ffdfc1f5c38c5c), uint256(0x1d3e383a9952c29eee8ceab8a5547f3901639b242f65ec68115518a21712c8f9));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2f25fd96737c2fe96ec0b42f91681f382116eebe153b9d0dfa55e65dcda6832a), uint256(0x089edde1f8280ab3a204fded69039cf274742337bc6398c841a0080e3775189c));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1b8a7dbd60511d8a837d5c0d43141fd1934224fa1a2c69d51dac3377434af314), uint256(0x04c30756081d30ef2212333d831859fc542828164c29e27ddbe632a8d120e5df));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2a589bde5af5e3bfd033b1de44355d1db2374adec7b69f32d071bf8cb039584e), uint256(0x08c26e44cc2987528665802119d916e9c331482e4093069c43c9679aa939afe7));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1c1198726e8b76b6a3f6f9e52c7923b1505f10d130b45c9732a1a7bb442a2c7b), uint256(0x08eb78b758dc24f940b920e19dde3de62a4f104a3d21fc8d0dabe33abb1550b1));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2cce3fb660ede956c737182924e064f0859eb116d1c60cb0d4b44d7db1c5d0d5), uint256(0x2c2594eed79ba239241f089d945e973c2d69c38ebabbae1315c771d2e655903a));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1c3ffe7c5e007e4692c5873b58eeacfe060d91507c2dee8bfebfc0b25e474961), uint256(0x118d8d538bc27945acd379afcc647d89bfd9cf1a2e4ca0347c04eee2c713157c));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1e9ec230772db398b34779c0232863103797d7d3e06e2b32aba857100ea9ad5d), uint256(0x1d2fc71af10ccf3a2bfd9b376e73678b403af08be805fb1b99d7b9bbe3a57bb7));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2125a9c4e6f4bbd2dc459d2451f0891a50fcb6766f0f6c77daca0051de3d661f), uint256(0x0c841017eb902e946b5a76521f2693e8dc3a55957c930ec9934751bdcda89cdc));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0e364eaec1c8938b82ce113a021a12d6e8e5669a50bc2bfb015b597ea2ff31b7), uint256(0x2bb7b7dea302b86a5292309f2c0e0c306d59fae22a12596518aa9f87a9933479));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x05ff0e1f24c9ec6f11583ffe727c907a46b807681dac86ef3832feea70d89186), uint256(0x170c5590d4776b50def7b9d96a5a4584ea0a0ae32b16d3bf5f80c7d97a026d89));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1fcc24041d4aa5e974e0336923e52f1a5e767d6685662085994c790c2cf28f83), uint256(0x301d326f6a18d3e1e8a5ac8722e0c1cc0dfc7f52d0928e3ba8d622a89d20de5b));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2b5ebffab88afe0ba4918809d6099be2c46710ba2117c3f1f077017c560f051a), uint256(0x184960889530d7df719a09c7138231012a0dfaee0e66608bacbb1d94fbc23a05));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0d4357e872f137408965e7f10ede0db5e81dc73686eb31d5bb81a63afcbd9a19), uint256(0x170f16093f8abc8b1d2bba6e07b55740281f14999e6cd2b8d24592f1a05acded));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x058137a09e3a9568348708b633781b1e2fce78ee82bcb1631728914c9de4f30c), uint256(0x1174278e493d99d24a454019971befc8800773ef9b80b78b187831702a1aa56a));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2bc2c14dc99caeb6e78708510026d3e1c7e59392b4239bed488b841f16f76618), uint256(0x0c597e624a3abbc4acd244d926e7fa044c442adda2b3764376f1db15b6548371));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x0b4ff1a872ceff8c803654d272fbdf77757009af62bd283c85b7a7d72b54e93e), uint256(0x05be31bcf9cb9ec250d25d017c507f086832540a7a1488861088f3bd760881f0));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x276753b8d86a2dd0841fd3c2734259f70eccb5669740312154057971fa6ba19d), uint256(0x040d4d73bdbb6c39e0d514247c73b55babb48b0feb63ae45d868c81e163cc47c));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2021cd89d65bbdc64bb3f2bca1475d1c0e23233b7ec2e3497fa62b836a57dd09), uint256(0x187d161719dbfdb9243cb4b4c0d04f3c2509e8ca98313dadca852995caefde93));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1aa888c773cb72b376075bdf63dfb06aea05e365619522216dd330e3a0cc74ab), uint256(0x01898f34061465a8d7f98b1e0356ad1cf6ae4ef5d985453afed8e8cdc979f91f));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x1ba55e268eb19008f92502cdc96f7a181de1e327a88521b3ece02d4416f3da74), uint256(0x10d260eaea1aef00e84f4b8eae22a80d943431b37548ad8c867a974bbd4d8db7));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x0f7d39b87d78428f11f43f622479495de31eda6aaf08d4ae4c5e21f12fd5b846), uint256(0x18cdb3f107b6816f98d06a86af733e654d1e9fa8a0acbfbbf801838432c76b86));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x0c1f26b190603b860acb338d29b06be101fb9da2629a51a6f0f0e862b9475e00), uint256(0x1574c28f702237d0ae4426105a9ae478e1f4514934b25e7923ef7516b3d94d6b));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x082c6fa907940e25f9d0c0905588eec91d1f3a9f2b38501c6098db5a43ea1a59), uint256(0x1d503592f60372e9447546f2544a74a3668d3561b7b6d852ee9abbf0a0501f2e));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1b725a2d1de5e7975d0888cf881e3603cfef07a24738a860fb276d1b6dbfc0a5), uint256(0x2addbec56e71853744ac26fa5ef03cf23e6891aa900991f9f4956568df0760b2));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x0ec0525ddfcc244ae501bca30079a9ef09a13309550727bfc988adf4be125297), uint256(0x26984a51effde1591dbaf8c22bd54366e81840e8bd792eff1c1bba6d570a283b));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x214f352b2e8ef8ef46e8886dbcd80e8cc8cae21cdb3db4109db3222f92e9877a), uint256(0x2a18777c7815f798ad86b4740c2ee359e8ee4eb1f4cd0f3c5bddf37f2ac03d2b));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x0e1b1bbe60600d11242f0116e7e2501610f735dde120fc35ba5e50a50a76730a), uint256(0x0fcc56dd54fde5650a2d10674ee9ce5f301d8a915f08ed8dade996afc1a755cd));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1eb661917afa88d3ca7ab430451bfbf490a40418a17677432449dc5127ff0ac5), uint256(0x0dfa79571642e152de89f9758d68ece1e4e8034cd68435e5b193605231d78cf6));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x2fe3b09393c74366bbc11faf0d97fda85d8d014c46aab6ef47e625dc7959140f), uint256(0x27a67f7bdc682cc249e292b4e6aff9a9efdc7032f6eacc9a8189e5367d09e504));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x1a34391b8d6900e29de9964be8951b163cc4c333f2b136099a45fdac03b8fe84), uint256(0x21b0a8c26becb2af4b0ddae2ac8315752930b4f65698951cfa601a102c9d0988));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x2d52b1eb6a705224df3dddc6a1f2aadea0cc957fc3bc73325f368acfcfecaed6), uint256(0x1edde075e24a95df5fab837a62ed50e0c76c93f348d2794f8a4aaf60198f4379));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0e82dab23ea785b150451d10463f36c8597fcb96829c4cda46e9443f9d5ef830), uint256(0x296accbe2c4509e26118cf009a14ae73ee9c1b749e5e1848315e6061fceb49a1));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x153ea3bc1f757f1c21664218189d088d4eb3729b8f0e5f39d51decd96d6abf2a), uint256(0x056f666f9352017bb619fbb186d3bf8057cf639db9a701b93d49389c6e6ee227));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x070132057057be12b5bf3cfda68e18fd93f3893cc6aeb9c508cbac30c342a674), uint256(0x09c6f0e7a600d4d2e389de66a58cb96f98410c5a60fbf1086e5bd5419ece65a3));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x28f52c2162b1db77a274f36dedbe04364a618dcf8b142963cc5a3bbd2ed0623c), uint256(0x1ad329de09e9f11772ba8e1a4f1c5dec952415306c64607c4afee8747a19c08e));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x22ff1298fe2d0daebc353e0e66a15e63539cf5a34f6bd99b045258ee1a40a8bb), uint256(0x07a3db70e3feefa8fa3b293e2930b3a5b65eb42741367e9e0dab54499a7f72b1));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x13b7049a7fc1de326c1fea78874fd8cb0b466eb7d006069d9726fa96d6cbc66d), uint256(0x139457db7b76b192685cc7d37e1c8df029f6bd4bfc3d5dcda035018fa8832fd2));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x124d86cc7a53d6690c855de81adef4c6264e6b0dff8e85d2ab193a8453479b19), uint256(0x0b7ac559b6966b49a797b7f8bff9072e13b7cae332c3d7e6edeebc307905b900));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x08c2a9620dc964d1bf6ce646df82b0bb813008e68a2899e74e4f7526b7fe1182), uint256(0x0fb7143aa3af1b2c6feed6b35af211628176f9d1f9e970e8b26080745820c14f));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x2ac7ec4387f1a325b4033b52464d65196f7bf0b98baadc6dd8122bd33afb7e27), uint256(0x133c732f3be8b1df1f61f15079c730389e41584add224c5ab06e24263d0716d3));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x1eda115d72c2a10634855d4ac9caf4b32c10d073ca12880776bdfa4b89b58790), uint256(0x139230e19f155e0256c5891fdfda210d8640d8ea7b33ba9dcfc30892a95b45d3));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x1ad7450fe0c48238b4d91a2ace54cbce668b727bb437a0765913474e8c419f92), uint256(0x0a96c7a48760e546bd0f82cadfbed6e7cad0e28afa9bff51e816a01cf5653a94));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x0020543cc29146b263f2a2437a191eba249f752b5c61d27cccf617a301fc6e8e), uint256(0x11db80616c2501d5f85e5ff675bca7f0b093c26241a3ecd6bddfed1395c037be));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x24308be49567be1da9d2e506553001c2a826e7cd92f21b99bf5eb9414176b05b), uint256(0x3034d18ddd0fb1ed78bcc72528c1785607519de9635fb148ba2bcaa6b9d36adc));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x29aa28736aaf0fe2ea3a57a7896fcec5c8dd1675fbfd15713b8dec03d90d8922), uint256(0x13124d6b6c5176d08cba7e58f3d7ef628a8f3df3e333ed228f08ca8324f98ded));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x1f126a1e42162ee52ee55ca1e7159e4e6547133ae2d92de8352c2eb98550e87f), uint256(0x06426110a2512976e58d246460bbf4e90feeb49c832d4bc8c17bc6db09b25a60));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x0e41c19c7c4d3d7846cadd60b538d1e775ce981943d9f2fa5f86094de9288fbe), uint256(0x224fc2f27bc011798e1a5603b3f56ef4b3fbe43a661b8851b587503cddc8d254));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x2c9f6126ccd77a2db37ae70612cf3440f2bd2f55850e773bd5252649ec784e40), uint256(0x25bedbd33c809f90d113fd5b1f2e5640e5b67fe93f979726570d0ae95413c396));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x02da2d9232ea3df3c763f7be63326e96509a0ddce76929e2d92eadbd927f9e34), uint256(0x23792f4f83b8cb113f6417c786373ee5674a8f9cbf73d85d66d3c9c35331a4f0));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x20448a5ea2c4896c6c2041ca72f43b86ee2ed06d6e738e0af71d21cf10ee4f22), uint256(0x073df776d93bf13f51410073da2e8f6513173938f1781484bc61e42184d30099));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x29837a78c7572695e1ba78d2996638542c1937ca2d6358ca723f0db1576ed268), uint256(0x2c0492f0865cf91443b09f0788af68f07697c776a06a944f0d8197849af00596));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x042df7b3e1585e274e46917bd3f343b8adff31fdffe071038f0729ef30efd4d4), uint256(0x295a94ed706024707011602cbeb54b63a4644469b6ebc9851cfdd49652aa704e));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x097e8c712ab895a0ce01dd6962de53b821026a5a55d4602cc31e54669d97f570), uint256(0x2accc9dd877289816fac0edb1437f2b26433195cfc84172a59a5ade1ca1b45a1));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x15380e604f6ce0ef38c8066da89cd6cdfbee4479382d38492a6609e62ef5c690), uint256(0x06a3108e3ebe0a0fbb4c379089ef14566ba120d53b34b1e447e93fc1aecd4347));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x2283bbfae53f8f91aa22341a9f117bac067bedf8d1b73034f23e81500a6d282f), uint256(0x015a0b5119777ee2d14d4dad06c2966753d683dae9d60241f9eca8640cd968f0));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x25abdc0f950199a8d9241ea59a04fd587c5750a00ae1d52287c0fdd088178049), uint256(0x24a6c3834045d543c6e19ed6d7bf070c64a3f569369290582a004b7f68a0ca77));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x0cd61ffb850b92f8e53d7a35f1bc15a6e1d9700edd637be6338e2ccbd255487e), uint256(0x048ffeca30b6361ed07220f6d217d8036eea38f8419d5a1b5f579ceb7211d15a));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x11df6ef2f41d781be3f97661a2dacb9eece039a40111ea74df23e330979f63da), uint256(0x2946ab8d4bf5e70c8ba5e75a9465e3646a5532fe53087823cb1363e005088d5d));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x018bebfde2458cd3b4453957b5d4846f4de74e3d68439c9032e1e47e5f196ca1), uint256(0x0a45f02b5a38fd464db4e8785a11b1f727ba269156a5f0d4bd87e304977e1253));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x2fb587129d6378a87406a1c14fe75381a539c2440c046e1d37dc7923838c32a0), uint256(0x00df1f1118e91af304374a578b1f09623374e411a44636e75d44c8c8674c22ed));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x06d54d409f1b9f755eaf138ec2a2733ab39bfc30bd0fea3adc6c7382caf4b63e), uint256(0x1e90426429d15247e2ef712ddea3829f3896b0bb53e433660b303f646de8167a));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x29c1ad33a1fa422eabf1f52ec5a531a049b9ef3319b96d541d5b2e78299c48e2), uint256(0x1fc1ee6af8f1dcb807dc8e05793ce563155e03dc4a7d2916df8e451ceee2c0dc));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x2858b12fb910a84eb6b558b721031bc6ebef7b05884c57c2a9c1586a2c7e3bcf), uint256(0x2f99daa79afc4eaa44c876021c09a7af97fc8f8ebdee28e3133b1ddeb4be6abc));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x03355e4ebd8e3791d88e7dbd80661d2dc21e3b394877ca71635838629b2dfc89), uint256(0x0dc26a7545bd2baa2f7f9ea9409fb5eb2886e2b3347f900550c43cea55398b12));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x3019c3fd3066be57f1201e306b1ea9d33cfe6de4257b4bee0e10c6ec6f4d35c0), uint256(0x188816ca12481708c08e5dabe45ce8f65f35ad0217e932b6263c7fb7c9274820));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x10b6c79fae71c6ded33e436975ddebda014e17e1bd197111a6a5e4d42c26c6ea), uint256(0x19fff5d8865b4485a59dc5f07fd39af6ece54683ba1cc6f0b950bc87cec65404));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x1897738d4e8358e1df6b38dde8c05ba9958654a08aaf1aa546e956e8a5ea6146), uint256(0x1377ab7b48aff8b0900917e32fd081ce1d4f43297b132e9cbe3acd09c1738ea0));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x2605b3a17bde65bde31c2179266cb76192a1872671b14d8b41128b6502e1e05b), uint256(0x11a00a8456c1c5c688a8cc94babd40d51953941e5929aa7a834eee8f04f478b8));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x2dea6406bf7a63d7a8f9f8e639231c6ab42d54a54bf157f74ffdf2cf576e0cb3), uint256(0x0caf537cd807024aeb7dc828d9886d4477ea0c0e681552aee6ba699fa4bc4f9c));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x08bd7a64115f3b69ce79d447bf56c424ba8dcccb15935b9e7f6888ec3995b367), uint256(0x0477d6e29b570b31d723329e0fa047b291a9fc26b189cb40b0379dac9d952c16));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x23559c4900500d6da83feb68817ea503068971679174f75e58bc4c615e5e16c2), uint256(0x044b3f74ec26b2bb957c55ed2910ea429996d169d87d11ae3cba7667a9f492f1));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x06520d43581ee6c79d2743f19f3e9bcebdc30dc71ce335789a529724222fb141), uint256(0x08b8dcc7bcaf5d7bac735750e5cc2e9d7c6bda62393fa81f6eab8421e8b76756));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x1c5c5b027a9236d7415002b27e4def17ec427f080101c34f3ccff6bdec423836), uint256(0x0b38e494b2e5f5c5875821ffeb728a6e44262a01b27d366a5b6324306ffaeebb));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x2286a74b9deab8f75ecc3fe61f319781258514f535ad8e505a85b41d18f7a9b7), uint256(0x247a57c417c1bf8376a495acbf83aa0f67aa556e35f884e944f7ec5ccffab6a8));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x280eb546d4948a94c2a7d1a116de04e0bc41b2eabd3706a5a610132e801e388e), uint256(0x135e396c132869a22525de9f64ae5e20125aa797cac201bbb30f290cdd5b546a));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x0c85bb4d5e7bd3f4fa53e26393deb8c84b729b88f4d82a95d4d7454583f2570e), uint256(0x20a65f4dc9c6db896c247fe37984addf4d1d4d8b2e51e92f76b0a508b0cdbbcb));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x264f6978764c3b3c2fead0c5eadda12bfde190e29785733da975e7985ad68fcc), uint256(0x0ef463790ba6ad4f3d3161e5b4a61468079f55ef0aee2e129e4287e9dd5978b4));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x1e2198ea43cc0174a29f87bf29d03f91e04972c28971ed571a576afa6666ceab), uint256(0x05dee975a9ea5030032aaeb1f01e98f77ffc67abf3f9c6fd17958a829fe54edf));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x06f8a4c9957ed0f18a823964b854b78de1e806d8f45fa6754d0dfd702447e61f), uint256(0x138d7f6dca99743b6cc47ac831a454554314696e44fd364a40a20e22967fc46f));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x28024c9eb355af1f610e5fdff8dd41a3b8a8ae1b05f38d244b73a1dc86438f13), uint256(0x078f2119350bd5674f5005671299b4236bb2ef011bf21c9e0fa79664b6f024f0));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x156e4e4226ee23b2a58989175f5c1d63de86d1a83423b8e2b23ad9042259fa24), uint256(0x2304cb2090e38518a928e1f29b7386a7515dd93a9e3400c3da8f5f9bd99d06d0));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x16451ecc1901777bfcb3e5f79b52e306f60fabae77279fcc151459a928686f53), uint256(0x11fbc853d353e6aea49b2cfd344170dc26086ad3a9fd4419bd98d8949390285f));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x14f542e66a10c01f236544f8176af38f0649eed827d2079e6f8b6b53920a99a0), uint256(0x28a548f44ae3c780b12a0e7d42018327ef8c3239ecf85f32e9ac1e35d3840c65));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x03fc1c84963d54656f19c5a917c9623076cc04f8cb2ed6d42280c294171be2da), uint256(0x15795c97c8b53960ef48e58c64d3fa9ae24007fcc53fa84efb0cc547ab25aaa7));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x1984676d1df922e0d12f7f180e9b4a7aa9e406ce577b760dbf4a5d8a214a8578), uint256(0x1e255c0d6b68ec172e9ecc94d330ae88853d6720642dee1441b83ec9b3eae9a2));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x0e6c4daeeb209529c253bef5f505e63eca79d0a0781eaaa9087a4d1a69559da5), uint256(0x01be2119e15808adefa28656b9e5e0bfa0f2d6502be6dac50041a23bf5a59e9b));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x054f8beae578fd95c9694f5435ebbd95cd8191445e0b24b91c0a7db2ef454482), uint256(0x0c3a80328526a7623dd9624727406b777b9b6388ea45efedc8566df5e3c4b631));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x1650a493b1dff35ecd57c6ca57786f1d51e616f3dfe9208a88ffadd5f764981a), uint256(0x0d04fe970d56745399db9f45a22d3549eaeda4c7cf680c53bb7c123146edc567));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x1930211deb182a7edf7f0e101b8701bf5795804f41b0229f742acfacd036ba70), uint256(0x148509fd9e0e9af194a952e8f4100593978cfd33a33f9cf037d5c4f4be53ec57));
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
            Proof memory proof, uint[91] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](91);
        
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
