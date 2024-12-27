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
        vk.alpha = Pairing.G1Point(uint256(0x107024fc28d0a0a18ec3ac657396543e6c34882b92ae6ec619614eb33f037fe6), uint256(0x05a2b3c2de975ab85a0483325d6ac2d688761fb0e1f8664e51776045c15d7792));
        vk.beta = Pairing.G2Point([uint256(0x0e32dd55b6013009a7d75b2bc0a84361a26acc1cd89fb70362ea4c960bfce1ea), uint256(0x09a7f857bf9a0420d164213c9d9ca21473ed47887a542d3affc1d6eab953b95d)], [uint256(0x02e963d325ce7f79e40f45a7435c035c3d741c237eb8b21b6ba43cddf1a92993), uint256(0x2088d456674a7648b07b37ea324e5a737462c0801942d6896e6874585b6ea911)]);
        vk.gamma = Pairing.G2Point([uint256(0x19ece4161b6c0c813e8791b9e321ba051e1436df863870f3747d089e94c7be20), uint256(0x27c0b331087fe14c20145e7fc4aa415730fab586bc77f916e18afabad4c652cf)], [uint256(0x2042952bcd9d0d0869b6ccb4c86bcc500fc97add7a1849eb5c85effe7fbf85ac), uint256(0x157b7adce57ca5a7562aab9d5a98dd1617465ebfc02569e573e87e2aa937c047)]);
        vk.delta = Pairing.G2Point([uint256(0x04141f9bf288c4709fdb16339a10f0f2d50d47c458170f530e516b133c01f73d), uint256(0x15c12413680ef01e674b487d72d715f65359215eef76f155592cbc243fc751d0)], [uint256(0x0b89015e0406b0c80f85a737d6267946cdf1e1e64de3da2a839fe0f07db5630f), uint256(0x1f93fe461173e94c4da1cc08f0d3ada29c411dae917c7ad27856c1dfac70be2b)]);
        vk.gamma_abc = new Pairing.G1Point[](54);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1151549088404efa466f08a2366d2b9868ddbaf53466ca975ad403503ee121c6), uint256(0x0efc50e2c68183e9f7e29673c4f935f62d38dc7bd501c6045bbf41410926d177));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x11d5f04243ce3aea644c1e26765af604d061debd408fa6ea1566a4f4f91e07ad), uint256(0x1ec366c25d3593bf11400fb60ef5d4b0c4cd99cded6948d78d0155f0eb2dcf21));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x25f7812d5d491b235f79c0c0b7cd4b799f0643dafb5584af6500605b0ada7a98), uint256(0x10d28e457f98f5d133ffe3ddbb6bf51210960c7242c485ccc7a690dd3582bab7));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1da8837ca087da01b3aebc1f5bc30a8a710c3babc38b93696acded5451774de0), uint256(0x1be6dbf47142cbd91ef07fcdde1b4adf7404dd0ff87e7c3e5fc4d9245c5c3679));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x220bb9ff0a513533aa38e43630d7b00683f85412319c3c036e73d4a35e171acd), uint256(0x0b06d9ef70c507b98ef88e25bf345cd02d9015163479a78c57d5a57a37c6a633));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2e827c67a9bec0546e5a13693aa1db388c55499c45f3db3beb26a951709ddcff), uint256(0x294e54b57a05763b90889e53821dabb349d54aea0607261fd4ddfac60c34cac2));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1e6a5be843a55f51d9d8513fc98a3af80c2a50f5a8b5ee8ccc590f9fa1ed4a32), uint256(0x2f25057850fd7a88fdd1b076728fbdfde82305079aaf9c85ce23860c5acd4de7));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x25a121ed5d99d566579f66f3de7348b1ea1a2cfe8ccdcdba1d86ec3c3a88a1f5), uint256(0x0fbfdbcc7d4de9f52f5162d126d002e2c5d902cedb312a35b50e369c7e802480));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x26a81eec29917abda337c2042c7b02a186f4bd8c31e240fdfd7febd84b113830), uint256(0x04b9205e84d92b918d85e4e07521165d0834ea27f64fee1d23af642ea2873e53));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0d88599a3f65d192f4b257e28ad2ef1a525f15e5489c604d1eec76fe6d7a201e), uint256(0x15374d2fb25c72b6b5cf9c7022003024e0d29af8f2e0ebb0e914c3c9a18f0e9b));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2204e80ed0fe974f2455b0c052151f8b2a182d8493a8a927e9dd7dad8768cd2f), uint256(0x0ca6196e93f13b079620d6ce2de8d97e72a6c1120cd9ca8527ea7bd78593153a));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x05748d7087b14c7b57028e5eb7201d71621e0e4c4ab9e9139946d1a49491713c), uint256(0x16cb5755e1b152cb8574c7ff7546002ee9d256235d8aebd69052880c892fe991));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1e3b35421a3aefd638e69bd05591eb5bd806534928869f3f7297ad5a8c575b76), uint256(0x03e1a0f366edcf8f520fece64847351df8746dea47b5b34d6cbc8b67559ff5a9));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2767c91a81e44de88912fb0b1686f890449df7f1839e43550578866f3e200d34), uint256(0x2ba77993709a51f309b1b7de8378d0cb2de12484f08368532dc0840c684d23d5));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1050c61cd5fc26a0cda06e1ff56a5ae6e1031ac1c74db72ee6d670c521984d67), uint256(0x2dcec072eab2e24e796472aa7e01392ee19a9fd46ccc3a08497ba2a1e98202f4));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x15e5e92346e46bed16a99b778308fb723b0a9980a8d29c7dd10caf491dcfb83f), uint256(0x1318e80f61547664ea3ba5faf1d71b61ba22fea9e9308b3d9be0787a86e13958));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x11bbaf722be23cd8d56136a753fb7e4e8c53fe78e435eb17897adff3ab0409fb), uint256(0x17b2a77a9f4575a9580717f0a1c60d2bc9dd4cb7f8cc7d11e42831bfb63141ce));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x14bfbf7fd1722776bf1fadd7d27693f50166cf378c32113fc609d0659dda834f), uint256(0x06739039101cbf276f627b8fa54c6bcdb7b6a294e3b7166acb9b0daa0359cd61));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x16ba1253911b745c3f8a36422ce78540378623ef8ef9f330f7305f0f07e4027f), uint256(0x24c8eb04614c0ba416e0a6c1036b41749cd3b8102827f3aa6254d6e3abeb6b7e));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1232b137da699e4431f82296d44f8137d6ae54339062efcdc6c131549ddcddb0), uint256(0x11bed2cabc9192189693d9ebcb49f2c524d3193fc2e074fdc05844c6e08f93d6));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x1fb5fb7dd58d0a8db4a523a92bd5b817e5d0374bd780bcd028bc196199cca557), uint256(0x215ace30ccb7697d2d4250048c38a66128dca515bf0a40ce92f0ce1b45f02d17));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x136c7cf804a56a0b1351edbf04919b39c8be7e83582b5c7ec2f9270e24f79184), uint256(0x05946d4b7753c85b1e746480604e56ad494560ceb4f2956d731e3f05e176ff59));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2c3ecefc696c860d4078e927877dd46fbfd727ef6df3eeffba6309346bee37b3), uint256(0x2355d422fab0ed9fc28b06f929990b5c7e5ecc81b84d9e39c057716bf7a54f26));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1a814c03eb65ba2aa33022fb4e03b77e71a1c975395fcd9ed35a8b87d57fff2d), uint256(0x262eb83205cee8c82b92e9009ad67753798b86d2a47a05e21c3695a4cc6536fc));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x1f19e9c9f3f38281d69f2c7da57a541c4eea4ce47f3ebddddc7a794d2eef1a76), uint256(0x29ef1840aab92088193c014684b2047d5a2abcd48e3967d1ea1d19552b3b036c));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x0251f72a791b74e487a7a5df70f9cf951e0d386898642efa2183e5cc83897068), uint256(0x15550b761abaa16fe9b490425cb2208149f2f17796c2a90296ff6dac479adaac));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x0e36a3cc09ba134766b5edba49637d4f83656037fee557d374add65a4929ddd0), uint256(0x19fa49e289a1c22c23935a4be22d4937a36521ede8edc125da05c3cf649e116c));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2f3eeb24fac79ad46b6aa587fa3da43e30ced5cae59634f18e5fb176cf8c5403), uint256(0x28b177d156de3305073a246b71cd091aee80c277f2bb79592db5825e95583402));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x2e9266120113d113ad7004e65b4409a667da4f63d14ee5c843d30b61bbfce13f), uint256(0x1467872529c8d11fa7e7340202666c11733d7200b609d1db0dd258b68636f7eb));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x20e81a73b06bd2de804e035aa884cf99afd647523e0e677019ea358e7e2273ff), uint256(0x2165efa722878d3a3e909171ae80b94bba19dbfc80d009dcf172540423989ce6));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x056f50305ff896ae431f128b2c998d4f6e84627f6ac07740dc5da8e8b754a53b), uint256(0x17d0504127e687af8d629e1357fe1ff82c28a79308446ee6a290c54e93e539ca));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x199ac9785af74d5ce3a8682399f135205cf597fb5488ada320a0a894a82cd513), uint256(0x191b294cc0d0f77b0493c4a5a6322c176bf3bb85752916b35a4d56e108dec483));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x06cc8a08c11e71c635891264c5b6e4ed3371fcfd1ca546f896cc2a3f8ee1d743), uint256(0x2b61e3dcf899c67b77844cc0154d7a14b7d22fdaca85e8020ac5de7f51b239bc));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x12ea6ddbcb9caa77766f3d7e1079d8570073b7a45e4cfe7060f47830a449d54e), uint256(0x054f8a8af3d688c1d107d370f141fed4f5c03b018ba97581f363ae7693f6df48));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x17248a99223b5e33a87204e6f47dbb10353bfbd9a33f300e84955b5e14df777e), uint256(0x0f77b5b08d3718c6c97f0f5167ee356217f4b612c52d0685d86dc05feb528406));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x15af2ae601c8755d62746657122f9cf9526f2aea117793d350e64c88af227bb5), uint256(0x081c8988552599462bcdd53ddc193b0082d324f4d6be65e2107cc379780beb3f));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x2c0c9f4b66a78542192d2513025046620682b908e4c6b50f289af17d56a60eb8), uint256(0x0a41fbc7ee7d3ffdb54f55de0149e8d0b1ca5f5b7d8ba9e1b62f830c10808a94));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x09bc4c7a53b93616de9050d0b889d5f812274cfbd8254a959ab3979d6e34c79a), uint256(0x1bb852ba25c2ed82e437261652e8a3af4bc6d597fb77d062f600d6ec15c34ca9));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x0220e472aa89d968aedc89f20eafa2a8d99351c57e35218fad00f805edb66de2), uint256(0x1688c393fc32a5e277e09172015d04809c404038911b44ceea217ed738fb4425));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x082fbc4f2b79d506c9e7126598aaae63c3a87fed3ca495abba40c9e07034c8e1), uint256(0x2946ec27c31b11c9dbeeb0ee3e2e0d0d2ac2076a18ad17209570c3c5af8f07dc));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x02ebb61992a2408b74d5064ca13df716f3d7283b2a86845fee9ecdfac5646514), uint256(0x027775fef610d83fb17d29cbf173ac66097a54737a529c21dc4b1aa2e1024781));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x1857cd7f6152b066d62aa520acb7514b4d582758e04c593bb0036ee6e0bead65), uint256(0x22baa8422a100722cd36af7fe16f5caee339eac2aab56f456a94716148229c55));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x19a3b09e3c2e54519be419af9cc46cc10017c68f6be10e5c174a7c1569d45d88), uint256(0x000739bcc1ed6f6bfcf9e83c46b8b3f443fdeec9b1d57a966808e6c7c8140630));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x15b02f9188b251882ebee8a11492363aff13584851e7b520923ff9879bdca532), uint256(0x0a63ea475a324e4f0d728ef4fc3ceb346891a9e2bbeded934c6016468a0a7f5b));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x078d4c28fb499bf06a5d75ccd61c2768501a2b51032df55eca640325e471750b), uint256(0x25dda5b30e6dfa40ca1a87eb183bfbd936fc4667055c8a48399d1f721b8dd3a6));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x1a2a094dd18b5301e0dccdafa66ff304b29c5b176e2aea8997eee399d54686ec), uint256(0x179e77bd31affb60a4771f4174ae6f64b8da3652f08ab7dbac43e15b954d42d9));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x0b9ea64b9973bc851396922a089be29a30cf368beec2cdfe8a86c9084cef81ac), uint256(0x248bac67e0b1d08e758f47b47ff9f063d38b90053e3dd649ee5824f8f1135e6e));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x2d5fb3b7f5db36458edffcffec9d7c79b3d40a80723355c9105ac26f2f309c06), uint256(0x29ca98674b9963219eae0d580ccf38579034d13aba5d4994c436f4da7c879e14));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x278323b050db6ebaf06d35a7431d427a5b7fbcb9f62ad75e16aa983b5690547d), uint256(0x2819586fb271ddb688fecc4eb35d2f34f3ad10791163dcdc4d173e7f58ded61e));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x226389f13e4fec1ab6cf83607eadc211cc0c427c9cde81560cab7f4fba4924cb), uint256(0x0c5ffcdf58f5604abb1616e105a94e7b045668a0f744fd9b34fedbc6c3ebd013));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x2893f508e67ef92256c36b9bfd20c94561a71181154d1535c10135d93c617a40), uint256(0x020ec0c2d9bcc225ddf46ae971747a196645a5bcead214664e5dd676bf8cf2a0));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x0c93a8883cd6c620280e64d29032684a96abb99ab517a09f95a653c5f9854e16), uint256(0x162380d23522c1826b4a419cd4b7ae3112e7f1df66195f65254f68d2a9ffa1e5));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x1aa0a7cd8dbc6a94836752d08f77b5ff507dad8f99547226bc2b7f740866df20), uint256(0x09150c1815748e76b5b86e0cd34ba7e51540219fb575fb5bb4a0c6aba2fdc485));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x0ce63882d25280cb02bda884c16dd08857c98f46b556c810d88d8a2f27ec64ac), uint256(0x0fc54f8ccb5945e5555d6284e72b7474a1a1d51100bedb3f932fc7258fbae885));
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
            Proof memory proof, uint[53] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](53);
        
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
