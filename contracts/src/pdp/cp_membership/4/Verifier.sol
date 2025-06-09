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
        vk.alpha = Pairing.G1Point(uint256(0x2e775ea81b8355875e477c18f8683217ef8f3040e071ecb18ac8ea618211ea80), uint256(0x200b0401951ddcb617feaa4fc1fe0186e589becbdf7f9118aefa2ae07c8340e2));
        vk.beta = Pairing.G2Point([uint256(0x2e648700d65580ad0446db495eae38b3617a6d06b522385d52a834618060d797), uint256(0x15a554fbd5bc7ebb59d784862567d808b3f10611327433f21ca1a4062bbbdf05)], [uint256(0x18480b41144d42e3298ce6879ab7e5a54b083da91edc59d82039481a53c28b08), uint256(0x2ab291ae1bb90dda24f99603d88572f058dffdcc662b3f840477d1ff61b966a6)]);
        vk.gamma = Pairing.G2Point([uint256(0x194b1e875fcea9edd6998ed9e9812799b75a412c4f056a44435905a65794b760), uint256(0x01f32f3b35b7510408d7245e96920b4bdcd4fb7867186e93cd96b7b18794c88a)], [uint256(0x243205f168df49b67617d70728e715c29d66006c1a3f1ae78946bd8b37df6cea), uint256(0x09bd2f781edd86341838499feb7751de98266613a36faffd6b0642652e0e661c)]);
        vk.delta = Pairing.G2Point([uint256(0x132e7af064c62927a190629ec48efc4f1b1187d9519fa57a039441b12e68f46b), uint256(0x0bb8ee69b0749a91f765a89a4b086609cfcc31f1ee344b9d8873e6bd1f43b671)], [uint256(0x06bc31eb6a29d2a89e7a809590265d3a39a298d5cb58b7fde671f7ee81e1a553), uint256(0x03a66d35c135f015169a07e6b880e74ddccf53b4edec5bf8959eb182415c9af3)]);
        vk.gamma_abc = new Pairing.G1Point[](221);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x20420ff7427deb5d3ea419d0730df0d143528ca145aaecd6d093eddcf944e664), uint256(0x22eb77de32332bf89caadde60eb532440eab0f257c7faa2fbba95003fbde6b91));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x12ca48e11815bb1f43017452ce3423ba7692546773b92f9d01c8bfcde66bd0a8), uint256(0x2414e881fe58dd8ae703c45a6544cfde491cc330b2a19ce1fa6e25ea4e5dd9d3));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x180f4fbb6eb174bebcddb880e8ee2b4248b90e25b0d800e989be4a4662ef887d), uint256(0x16ca9472f0a21233c5add007a21d4429133febe0817e060ddf1c5802d1e62aa3));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x107bdbaf6ce688a472c034dac98e78b75f59268b3f61b60d9434a0210c5e24da), uint256(0x1343d7ebb08d0cc2bb6e6d77214cd989faa77b868a2fbf2172c58068ee13df3c));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x18d7e80bf9cd962b7cc1185cd12933f02d4bdb7badefc4f43c042e7beeeff541), uint256(0x08655dfac176de770a387479b504af0e7c8b4ef25329890f5ce5c6660864b708));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x27d4f6c38108af889dbb2ccdd9a3f1193df0d1bc721592684c9779ac0f5ebf10), uint256(0x2b80db86c2fd7cb4bd3e261252430134c46f71f103af0e27bec44e55a1d6a1c0));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x07e57e4ecdf52914675b9ef35e5c925d9368ea59f8c796c78b27339f96369a94), uint256(0x0eddf1a96ef190f06a5f5196314b131b8e67734730c3fdc73ac60333d93f1462));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x052b8b77e27d2fe84e16d1e43e58f308a6dd67dd06e5d74236addffd2cedde8e), uint256(0x2d35917b0656c17beb25b41aa70ee954ae26bb0228402ad56b1ccafd779663a7));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0841bf5a5992eeac5a89f81b2cb98eb226099d1852a6c2979bd5563dde95ed82), uint256(0x291b48263fe89268d0f60a3c58c89094be54ad8cd65d098859c872f28df2f5fe));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x24538b6b57a8d2c42da2e344f09f81a18dd1acecfee8796eff1695ab4ee63084), uint256(0x00feeeebb480ca4d4badba3ceb9751832906fa817437ea782e0fe827ddbc359d));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2bada6e41d7301ed776ec072f23451b40821eba7d3227426dbb5d60f113f6a02), uint256(0x1b039c6e441a78b3c22b87e52f02caa6c6a027f35c31df774b04a7bb23a2c5f6));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x22947baa4214ad476d2d4e69b10ff376f5da830f2ab91d352de76ccbdd764564), uint256(0x0a10547ef0391a51d365b37060b79543b53e45f9c8173226a407342be81e215d));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1c6a3e0ff215a27294c017ff3ce3015458b342ebcb1838f8d60758f81ff9dfe0), uint256(0x15a05a2f4bddf996769f5ea59157fff220c0b9898ff00a336cdb6c667d1d42fc));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x10c51505533cd6a2a047565a095b5a44bb3ea3c4f0e73c36d7d3d54811e47296), uint256(0x242c9be178d3042247686583ddec9ab43f61f047fe2482e7a4d0c77a8c58e8ef));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x035aca13dc51bb496bbe90782f24cffa7787d68a56c3d952d36d85bc0bc604e5), uint256(0x02bce946da6bb525fd40c3fdd6a02d9a5854905352985e0d1c88b092c90201d9));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x08dbc813a64276ce09c5066c9ad9b28a0d9719c4e30b80fa3e2bae5e6e73909d), uint256(0x27915cd075ec003b7fde9db2dcfacfd94d0eecb99a2c7eb2b0e133bcac7e3e20));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2bef2c99d79f04596e533ee61c21144704768611d02dbeee2e986aa9ff25452f), uint256(0x2372ef0cbc65a1048dc3c1f9945cec4d0f913d3541875e6a99180b8e9173f149));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1b0fd8fac98befd3ae60a6e004154faed2c052f50daceea56981de119f560804), uint256(0x2036386986d4d182b736b16823b326dc32a8ded6b4202a4a54d7e40765320d49));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2a8b9f0537022dd24095ffb963a5ef802ab55a40266aebb93842c594219e477a), uint256(0x018abd058b0b2c69bc92f137b5daf0a552a06c18d9869ac72c787cbfc2a43a9f));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x0a1ea3a333a528cc49cea4192ef7e62d426ca3274e4ab245c32dda5f5554810c), uint256(0x1ce9c1c8f885d970f539150147d12455bb4b227b4d7072ee1028ed06eb8f5719));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x025b425a4ffc7f3c8f9898f7b31735ab6e725cab6c9092aee4d6c26583335096), uint256(0x13bae5b66157c9f39015423925e7f14d03e342f55665283760c57598c9f713b8));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x2d7f1e5880293ac3930a710ab867532520962b175266d167cfe058b7be955054), uint256(0x238785acd0c99ec8ec9bc340b526a3c672ababfa5e53b53ce4b55620099f27db));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x14337765901ba3cc9d85e83b76515cdad0a0572d5d42b55d3d6ee8e4746089cd), uint256(0x03e22de319604d60bd3ee6cad55574a168777b7df957557fdf181d18be23e0da));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x19cef3c4c25bbe48f5a74d69722d1051e48baf35a43e9fb8273f0ae3d143caf2), uint256(0x2bb47cfd24e529d191f864e27da7d8c8ef5159bbbc05c8e918696594d85bc3e0));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x2d915ae085a1a2e1eebb34c1033c64b35098866db813825754d70ab376d0fd45), uint256(0x2ae160acfefda3f9a9b437beb92d2654d673cd9bca32b3251811b458e57f5197));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x1d0f61a64ee856ea7d35f0f9b1a74e8d1bfd4f6b0dce164b3cbf4b876ac5d084), uint256(0x148c394d21be7455faf33a2a8a3847003e8c528c246c05639b1535341d9c9401));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x082cae07475a6567bfb3811fedcc060e6d833966ebe4fd6305f6f96bc12d331d), uint256(0x2b5ff260260992877043a542a8e549156468c97d815c5084a0a0920b894c99af));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x1a61fbeacc861d4d2610c886f76e0acd57fc958acf6bd1d9feec68cd9273f854), uint256(0x1cc9461073920224ee32359869b07ce8bd8d10baf1858571089d10c7c356dcc3));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x1742adc7d88d991533df1a385cb6c26348b0b485b9c81038eeab979ca4e4e4d2), uint256(0x222cf2603d001689d16280ceb934a735e5b6f5912e77feacf2a5662c76226b90));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x00805904b17d2816533439a2dcf2b6e52e930e5783035aa480c9d7e4ab14d31e), uint256(0x13bd7f443ca6466e2709a27480865f90d2b27317153f1abf2ddf17ba03cf6f39));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1ef67bd4d765c61ab1bb47c25c925683153db88a0b6c86fdc092d5595da09d0b), uint256(0x1ccec89e6e8af52f7e3ce4f6156fd2fed4c44597d1e7bb2f306d05fc450e3b4e));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x19f4f43d75bd583af81dbb4cda8929f4a9ebbc61deaef165c83b8f78f85e200b), uint256(0x21dc7d5fb9dddeb19016c7b2400c4b5ec6ad5cc483e2892fdf1d08d6468934a5));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x11fdfd824c5e08c10ca29597930e33922d3381620d5d758345aadc2ba554534b), uint256(0x11b65780b843f8395c409c4eca150b23080501c8af34bc3769e2ce62c1ede9e7));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x2848c085d143f01cbd140d2b65eef4cd50ce227c158823773b06eb767063325d), uint256(0x1f1e3276819d9f34b4a8fffc972600f2f93183da5f37f96bd90c822632df0c99));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x01c3f9a375f67b756ca6cc35f1d466d789cd48de202d1c283a7d5bbfe65cc07f), uint256(0x2cad6db3b1baa3a5722261f3e3aac398fffa44eefe4984c7ad5bb6d87239bf50));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x2dd752195817e878319d870d647a75728ef2d9f805917295a05cf08adaccca20), uint256(0x235178ccff4b740305af3dbd57f3627fd645d108ecd27a35120b2dee7d54aad6));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x005059b504244ea939906b66e4f081a94a6d551809f0d38af9ab0c83779549c5), uint256(0x197906cb4afd3693263431b527d12d7c4a37a1a6bf266bf8bc6f46572d25ef75));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x056e7feafb5ac796afc12ecad9e6b1c85d58e9b2e88789ef53caca99a4ec0b5c), uint256(0x03fd8e1517c4c99523dccd6abe56650d6219c8011272521b1db827be097c4869));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x1361c1673adc7abeeb0eba014c4119bf78b4404a1001c33e2e200067a0fa170e), uint256(0x205661181a5e7a220dd315eef9733f6c3f1f57aa3b2573fef33c086f11a6f0a1));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x23f6c51fd7601d3b630ce1dfe45e4ff9cf4a747000c802595eed7343aacb6219), uint256(0x002854c9a8c3bb6f22e3d7429a9296cce03f7ff856f13c462ed19e7e4244d410));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x17ee728eec0dca745930e7586b72c0afc58624ec5e7200c1a00acccb2b17a393), uint256(0x27d307df11352a95a45b09373766c4ca3703764c932c5a509bc745a33a05b8af));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x0748d06f43ae340c1a942c514e7dc46e358ea543507de2369f0f57f33b5dac80), uint256(0x1dfe744725ab6434cbeb4ca5f0fadead400d5b67a96f6ec21b6e483d1fe8b1d5));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x2de054db3d21916a4e3cf297c03006b7613a7531979a8decff024c88e8614f34), uint256(0x03ec3ba9c702b42f672e20e47c541d72aef18ccdad9c203177752bf98c1cf7e4));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x09362308a4efd4ad2d481ed50051bcd35200ef40226ff37deacc0cc22a5dca95), uint256(0x208b290c9037b98463dbb174e911a7d5d366339bdb84f5f14bf2e1f72516c43b));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x084e58840d9ce97c0b54534cd7cd7e68eea09a032b3d95a384822a2ee69ed2c5), uint256(0x218bff5a0fef06a53d86fc62cbc95aa239f7b38c95d21307c5e039ddc2b4aa8a));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x228d7aeaf71f32ea186be03b6fb95d0c7e52c1c8389087c5436c9f8bc67cd982), uint256(0x1a3614268bd8da248cd10035e7dde26c094bdaba26db13182309414c2cd3dcab));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x11587730df8e310b748490ac051e9db639cb380666aff486eea8362b4058fa89), uint256(0x20c1841bbd7845f32846bb8b45095e83fe27cc41214dd919bb2315adf460d26d));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x01cc48760425139358b82de96e1644834ba189956a3431f3e9331b943f057a08), uint256(0x0e8f61db6081fcb7496f11154f03af5a6bfc7b11767cd000ede05a686cc5913b));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x2d3079dcfcddc778d5af046c62e28b8edac8930c160168204486c655b5f36fda), uint256(0x15353f2077156521fdd3971aa12b5feaf7d9143b7c22a7ba4aaa6d5c63d29339));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x2f09edd86501b8184fca893a708b095c864f393a5ffecc346a6e211b8705ad3e), uint256(0x2f599393e017420eb0284f4a21eb7752ebcbb63d98913e7b4b99918f8fda7cc0));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x1ef73369d43349d17f36049f1698bdb4c06936bde82b2b281356039a9c6dde23), uint256(0x02ef73595bafb27648c55d8e079c1f9ae877a816d1ec0aef02d681864f11640e));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x1b08d64da18cb5fafc747828c3d95e40c7337e78b0bb01b232c2a47dbe5cf8e5), uint256(0x02a2d3461870afc3e3b839bd2c34959d2c08df688437c10210f8078021cc41e3));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x2e299d456c24b8f71bd654129fd7401961e0c39472632436acf30bbedeb41fa1), uint256(0x13f16fe351b8b6307997995d196c88e4641fc8b851b4eac72796bb693b9c42cc));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x01d6f773be971d36d877b7fa55a1c8489fe6e7230a838970705ab4e41219f86d), uint256(0x0fa218ec348f4d07178c305877fdcdaf79552fbeb8a733a246ce53d842d8a6be));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x02f3e2eef52f4649c06f43c2e4676de1c2b91cc7852e229a654fe873a4e968bd), uint256(0x246786689483239354bfc560ad7215be67be45f31d7896195ee282760481cac7));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x0a9982b227d6c990b4fc493b580b4a8b3d65a101d35e4db16202b1bafad9aa57), uint256(0x2fbea27b17701d7777590c15b195b4b3ba57344c0a7143003f4f29fee248f6e0));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x07f76f514199eb36223b94cd155415820667ecf15e90ecca9fe76ae6ae048169), uint256(0x14dc3fc650526ad312545bb6713367f2d7938e78cbc39adbf2f68982869159ac));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x1990c9098809e37c3f3299eca7860c0918effcb68ca634da006f789a3b58f1f2), uint256(0x18bc035973c3db26752b8b5201e337240c471dde87d7f338477d32b80b005a49));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x153db15178662846b10b3259276e0d916a9bfd9c64c8ca169689e6f9992b698c), uint256(0x12a4003557b90366cdd474995fe0e3e5920e58c8ae9de4edef3f18ff091518de));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x26aed7c93cc7426cc25db63710e5a41fcfd9fbfb51b88786a94ee13c915adae8), uint256(0x08e2e5a472ee32a7d5626d2a3a08b36192873b71d55ccc3c26b340e6fe60ac70));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x1f8e932563cc7f879e82919ab0d12fdf51b83a35860a3c3275d13cfc7aeb0fae), uint256(0x0c3ffb9405ff207d4e169884cfb109cd67d20daccf61d5033e04aa79f9081baf));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x042259d266ddc71ce131796e743e1854b6ffe3f3f7736710bc8131ddf0225c59), uint256(0x1c6534ea5d341d754427f9683d28ef90d0f0fe4c670e75c946ff1ce1b541268f));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x0ce2c71d6218866d02563b09f0990b11d21cecca801e46735090c9cb926e2959), uint256(0x1093c069e5f4a76c602cf80d8483d09eef01974bd53bee27a1ca4ee206534e87));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x141769a6751897cfbacfd4de9cbaae167cba4af0575f2388a4d1c00bbfedb349), uint256(0x08421b17cdafebed292e75af37e1277970a826d9d75f5f5097c19ff5fce4c4cc));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x28f936f6f5ade33a01a08929a705dbf425abdfb2efa2ed981c26480b7636e164), uint256(0x2117f4fdd3fe1f941fb58d62c785ac3f8f3c358deee7a0c7da12a66318ea6348));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x147af4baf493abd4a91e903a90de36fdf7d99b6add72c030c0631911056af661), uint256(0x143499505a888a0b32dce42aef7201d91373a696fc36f61dc7abd771942bd46f));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x2a876bab0337826c4b9570efb43fb239897a48465344dd6f7b7a909963bec508), uint256(0x003e0ca501385bfdbb4fd33a9db8fbec7b52e58ab03cddff5268be4c5437213d));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x27623b2065169e9db0cd388d73fc3fb6aff8db09b2e698b58202b99ee0e4cd71), uint256(0x259c8db5f97a81a93cd0c8fe9d4426270e3503f5da32c48dc9ed9eab7e6fd824));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x1eea7d92ed03c18e4e221da1c56fdbfcc10a5ba968a533e17dfcc5600c5591f8), uint256(0x013e356296a9b7de5657ceccc504ca87b60e9de28379e1d4492d44dab967cde4));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x0b3f2fc8a091c5ecf693956d25bbaef932a51cefcf0f0455825bd1e9ec5dfac6), uint256(0x0b412149b08cc2eecf0342b29978e735d82da6438ad1ce106beb7cb5234daadf));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x2ca4531066029d4dd389108fecf62063bfc56f8609a223c0b23f0be187578228), uint256(0x08d9ad492995390f93127c14d6a92f8019f76cd7855c9c948f614a800fe9e7bb));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x22b806a619b730c83ae52f86160381568fa0f0a5f93f04813d93d8a30fb11d1f), uint256(0x17ab2870630fa9b64e98ce05d8578ca3fef66a29a0d44547a442845816cc9bab));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x1c22cddc2f1e310ecf494a0a5936eec530fa69884452995d061c92d7895293f2), uint256(0x2eff107ebb4a8aa2133596ad039a514bf66f238d22fbce62210cae56555cda19));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x09fc77395d7a7ee8b536a2d6b9560ce2133b22ff6bc15dc0d79a3c2f00b80bfd), uint256(0x1ee73cf56185748ce1c64a2b6f73507c9feb6fad444234e95dd33cd6af84230a));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x247e6d80c520556a2f10a57b9314bed06f34eb02eb66a9348094eae8be5d4ba3), uint256(0x11483ac23fb568be6854fa2b423d3f798f0faffa3b58e2080c42f68449d336a1));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x10214f340b929aa0bb15a988de06719b4ce982644a9c30416abfc91480a7883e), uint256(0x043f150940d39aae3e2ae2490e58a74f6639e0d1cb7049bfbaebd4292db7c792));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x18f6d2a798cb7788757b0bc3ed2af868b17b0e2d9eedfd87cbe86b6c90796fc0), uint256(0x00c9b6bcb222531cc5812dbfa900c912bc31218be20f2e25c22fbccf0e13bc40));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x0b489db1631dcd87c4d409f846cc8b7b05e45070d462ae0b1f9d0768461f6861), uint256(0x16d82d1c4c04b8aeb66e36771c7a08cbe8b9092bd6a3544851339183bba5f7d1));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x2c6d2ddd47da39eac0b2d3092b83e25d9147b09261659e0f95e9c154dbf168ba), uint256(0x0bf4f475859418476bcb6a4fb5f8ad341dfad175ea3617966d63678e18f27fd3));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x2d6c697b59b5ffc73e07ceea8e0bbe1ef50fe78ddca9480d0c4d49654e128e1c), uint256(0x14c4182d06d5ca807f703de16b70964e0e19fc64582e0d9bcf4570812e186bba));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x1f458fb59f5d562ac733a6387118aff1d6ed9235d466325fd60c3e8fe238f7c3), uint256(0x12025a6631611cf0fc9b4689bb9336229e99ce42cd026b51e102f1c8fccd77b8));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x2927b9214aa67bc4e3d4e22a8dc8a1d7d2af6b41ec3c26b5991361b04a61c22d), uint256(0x242dc73ae65d275d175fe3e837b204ada96b6cbb19265c4a56aa24bcb3a8a08f));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x1679d5c628313daa44012aee36f3b961e46ebf20130d1bf9b07b6bcd39afb75f), uint256(0x27e7b232f89b19ffb396d3bdb49196c32031ab4aed685b485b14d5b8f60e5d00));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x2826d90e84e0fa4764b8559d60cee95410942af116f7531191b7c600498a224d), uint256(0x08807c17130357a23f71ebc93da189515cd00b43650bf42c9b84dfaf5bb94cfd));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x0d4d9413562221bda26734144fadaf289e0b9b3e3c1c2159eebdecef1d9b5b62), uint256(0x2e17fae5165f1b45f6d87c9180872dacaf6c1b43725c7874ff528af75ad9c9f7));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x0a29500ccbfdbe5bde2ab18929839be156c9d222b48993ee5d7307cb28b33c5f), uint256(0x11ee68b827154a12c81208c1b07bde1aa36c8fe18f9b9a6787fd224b9c2a3478));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x186c6022ea43913f66b884a8e9c2583212cda979cb08e65207a7b703dad67cf0), uint256(0x0d8a19e92920ba9efa72b8fdbf51bd755f5231be7b062c5b551e34a4363f75a2));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x0db384bef22f2d7dbab33a1a1de4e15fb2e038f0d45bad277de4d06127e8d3c1), uint256(0x157f4c0c4b0369f6848a882d4c1a00bdfe477fd7f271c0e9c088188163cf2120));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x216f119b5d49fd746dc16e71828cae2497c0b4b79372cfff6de9de6603376d3e), uint256(0x109949b7de467d0c35e4adda9b093eb3e42dbe2c2648ccf00088958ff34f6f4d));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x05a88dbc57cb84633222b4c34d08a92b929f43be9742ab362b512ab578cf5000), uint256(0x00e84e420f9353d265d19b964bfcba31cefa9221a93e8651b38b7747e6eaa703));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x1c48b11357db24ee7191e4396088680b803eca97368b03554ac44d4d08090c0b), uint256(0x0003e3a61afb027384cb3dfbea7971dedfb268f333ed128928c799444ef03ad3));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x21d4a4c3f557b861f6a6e1a09ada9a995ee0746679f2f2f05a67b8a190135430), uint256(0x1dbc49e24d64d20d2ee392dd7623b0c8ccb392234713322b4444cf9c2ccc89ce));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x113d25a3bbd71402d9607675851b27950a788f0ef2716cf592612d34f634283e), uint256(0x279b8ccb4f2a52dec66c6b131b69e2158026434c0e88c77bbc9ce9591dbc47b2));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x2a1de48ff391f7c20c9b4b23fb5fd6d790cc4c4e53778a891767191ed86e2ee8), uint256(0x2cc2ce2d55a8f81d746b773c36ba1d7247ad15ebe2fe6b8d356264782e31fcb5));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x0d3ec5daf4e066db3a76809d2e92e84151beb9a2a09eaa48bd2f80de42cafd10), uint256(0x0caf386407a458aa1dff8b66a179e20f0384dc1436cff9d5fcaa32934e4e5207));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x205ad6784040255a21edb895c77fbf17a16950ad3cbd78ed538cae41701c28eb), uint256(0x1ec5b30caa1b2098de6f42872e76a966a8a4fa1e4374fa2647e0005d51d4d4c1));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x26c4213df4ebe2ef43c7ff6d809c6fc5c9d6b6595069e975e07ca573b65b6f5e), uint256(0x2bbd6d577da06aa2e586ec4105dcc7dc822db83c8be693dd80179c9cd76f3e0a));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x0aff069f51bc371d8b0b9d7db2da6dd7b30aba3998d1de278312c919c9db6f35), uint256(0x29a481beeb18019b0c3b101e9bff40b7d41568ef91bee1715377ebbe6cf702f5));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x065c0656cb13deeeeb54d77acfecd3eacf9ba20b9353fc2dbd8fc87be5ec6533), uint256(0x0f95e95a690c97cfeeda54dc1fc8979a6e4e39066989b0b92a50e7ad95197217));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x089049304539a2b99b69dc6697b6d74d661b2155c8c8a58066ae76e67bac3dba), uint256(0x1cfe858abe2562a710ff2370a8e0cea70c57911135cbfff1fc62d8f618170b38));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x15c6d510f0fd5c8e6670907bf71eb79de9f390eff3be8d4b1fe74fd74e54e1db), uint256(0x1cdb8b19ab966acd94c545699bdc965142d879de1ce18f5e64ac26a2cd5b6a8a));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x0474b167aba54595c47845c5c6caeb338a05ff9a65ed7cfba85133004b5d60c3), uint256(0x006a19377443d54a1573b5ee8d9455c25cfcb447824d19ab147fb5395e7a1555));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x198cdd1d5fc301d57167b330e62c66b4280f580a16dfa7088b0c1de5cc9a0d7f), uint256(0x2c7286fb448a928ac5c07d8f23dff43bdaf573d006226b8f701b939449510317));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x12548c7763917ab8f44ea2eff8e99529aef4aaa16293be78e90b22d36e2681e8), uint256(0x1160bc7e18252fa80fbe3afa0e33050953945715d5adefc6f7c92d6cee76389d));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x1fe07add181510ffb413d7744d1ac6089d847362a5f5469d0477d8a6d1bf6464), uint256(0x1bf2cfc6b580755d36f5b13ba864f98174ed5ac2872e80706150b9c081370c83));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x076d04297fa5f691dce706cb14a6a3b7d19a8dc347a1007850b7769813a61d6c), uint256(0x0f7aa1692d1ccb35ee08bea5dfd558f60ecafb47441de613150380bd687a5b04));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x0faabd1a853cc8079d4047dcdf8ebc8f88945839c978c380bee83edfc782bd26), uint256(0x1a6ae3d05590136ffeef6d88dc75207cd57517f55268935453214d8ac60e6446));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x155df30a4e42483c06e868a9e5b7fd377323e5ca0d418e7f01d4981539cafbc7), uint256(0x1944fa38096ffccdc7ed104ee9bd84054d46a48c4839699d0e80a66f5598cbd2));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x073834bf4157e252b3036aa9860636a2299850ccff75d71af067422f67387284), uint256(0x29cacbdd1ad00e3c1298e5e0ce6201616c160f92454682e34dd07231375982d5));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x2ddafec3c0c0c22968d6c856806d8d25a67b050ba87f74a004a9a3073fa051eb), uint256(0x0ab899e1c5d43d060b48b2753f9f71ccf3bead027f84867f9cd7d044411d5cc5));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x1f5087f71740250bf4774564e0dfe32acb1274673f7a7cc9a70c91f0660895b8), uint256(0x21483858e99e607340d461244a4edb46f9ab731da6d04badfaa35858c119b12f));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x301946655966515fb1d31203db1b2dfbdaf9c355759beeab06cc8ebe429dafca), uint256(0x077c174c915fbccbfe7b30b595427e978160a190f92de150c11061f139db17ec));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x0041a57404e796a455e579a5b33c0a20d2aec5b7e2241c47f15b50261a084f6d), uint256(0x1dc164869603f2ec1de433eab3dfce7ac14f58aa496163583753ee1704bea62e));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x2780042ab08846178e86013d39dd01284edfc3e67c310f676807aea60ecee32b), uint256(0x2607afd84835186b5de489b9000341dde172181ebb4743ce308c49213ec5df9d));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x2175a3e3b08734263e4824baf7c1d04beb8b9a86f44a09fbc6c5f5c1265f5dfd), uint256(0x19ffc8492389db959f86a224872a47c611ab56fe9c21d9c7dbdc17924c89298e));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x06b1272794fc84b3ff334e2ba861ab9802b90b4e0b41098049098ce713f8eea1), uint256(0x2349daab586fae933fa19f89c9bfdc93b2d35dd582a855400763ab8cc11da576));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x204e2727d98fec022737396415d0f068139fccec6899182c7270ce2e64177a60), uint256(0x2f79acc03e06ba63297addcc19117e927dd4af45a0db5b6d65e7b69b08c90bff));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x2bf05f6f5c955e22e97aebe08f6819079ae2039b3f05b313654ae9813e8eb5f4), uint256(0x081657c1fc890448f2819b83066048ad9f2f1e0ecbb6956316c0e2bdc8c46ffc));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x0376d2ee2a78febdf208b25516841c14f06c47b34b66c82fca9f0325558a8768), uint256(0x0a711cd1bf8d6b2182b325f74cc8a69f0852b3f948892ff55a510f04d691f4fd));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x2402c95f534b4e113a5fd57076bc380490d90876da2ad5f01e29f861ee7cdeae), uint256(0x083ec8e6b4d9f106233251f36d47f527ba4b8e0af94177cac6975829de5c3b4e));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x1e3b613ed90c8a75db99f6f5b16e182153ad8d71d9dfeea80a9baf889b8c98ba), uint256(0x2d5da55fe8644cb135ae1662e2a019c3a32ff795b0e72dbaa30aeae53f319759));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x00e46ae8a7edf1b215209fd7879c5851b0c0ebbe8790f28a8899df612d5f1f79), uint256(0x0fe0d35ece00fe59e4d9ad19d52d1996b742f9bd59830639f5948487c8410914));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x2f04edfc61225236b66b8a2cd0a0daae223612fc85e795561a882fcc599c9ee1), uint256(0x1c12895a4eca554218712ba559a3b74525f97779334bff94dc26604b02423246));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x017967afe86a341f08e1fd27a7aea42d0098d1414df6fefe6352da4c052bf540), uint256(0x190510a8fac084e9a769c009b0374706a23babe9d489aa1fe2115ed7e6e15806));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x23b12386a11cc22e3defcae273394c7f5a4d7b9e4fe172bdd2951fd564bcfca4), uint256(0x1f51f33718ef01a98ee096c6a5ebbbe5ead19f1cb7bff05c5a5b2b44c2ab1630));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x19f16dab67ab94be5ecdde96370e1970d2e83db06fe546ee16127cc9757fbff3), uint256(0x0d9b6398ccb7d2fe2c4845da0f03e9ecef8ba5628de35ffe65d9ef510ba72b75));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x056e738cd5162c04ff4afce5204bcd3792c6b1a87de66359cea2fdda5b1cade5), uint256(0x2e4bfc368880aa0a4524be8f6c381d7d1b54f8821f4bef39febba95144f9136b));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x11eae8f5757bc9b759dad9b882b3c71ca91095ad61d8fbaa33eebbd3bf96658a), uint256(0x2f7498425b0452e958a823c26a49f6dad7f1c5f9b2d29f9439476f494cab7c83));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x1080086ea8bbd0db9d4bb3fdccac235f786e58a1d15ee527a14fcbd0d35ebfd3), uint256(0x1a5133ac24e959ab53fc62eabb7d26cb536b21d789c9e3b0acc822575b9cd029));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x09afe87116cbd544c66746de67412d14264fcc02da8f4c0d6c4289457804a121), uint256(0x15bf2b9d93d88c401397476f9a5ac56ad44f0903f1db44c4efd95b773fd4a239));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x170cdc2f05e026878d006e7a14020ba44c206cbb513d14ff205aba605fb99d8d), uint256(0x256f14cd34f9e9b3e3bea4472da8caf388c36ec44fdbcda66fd062b2ff8f4b7a));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x2333d4b513f4c8b4b9fbcc877d9742563368c936269903be687bdd09ad2eaf7f), uint256(0x265f07e1a8dcb3aea6a4b1679b67a48ab5f029f942f8f6e0e03c65acab79599a));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x015dca5c478b05b39483f97ca5dcb79effd5dbf6186946187e758d7eb9ce2551), uint256(0x1d070ea90f8fcf91e1c0aacc8cd8623e02473392bb71838f8f011c0e2010a0be));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x2ff582da3367aeca88d71ead4b749c8eaf52aa38d8347b28d038f98662fba3d8), uint256(0x088edd5e727e59813521c1dac753ebfe2ca965d5a93f00bdd2174660c73c731a));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x184c374f78ab110afbbd6d85cd985345f6e2845fdd83201afc2befe8b3e4d3a6), uint256(0x1ee2042a7c44b46525317dc50c4aa6563642555e466577cb89d68d57ef870cb3));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x22f995f7a26fa5fe5f9e35633c13b0a4f217094aefef909376225de755612265), uint256(0x227b0b14513578e58ce40476a857549abb1fa8bb83c05decdd78d2d3155ee110));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x009032a60055f548c7cba5a21e04a0b8b820362e9887293ed893537cf4a8b836), uint256(0x2943461e1ccbeedcc43f57327e571a2e84e3f29a42961f9e77154f77272f9bec));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x0d5366740051c87d40d9059383b389f502795875e6db3802448c3e7318dda07a), uint256(0x0feb568b385cdabfc79dc5dd10807fe15eb6dd43af4b4e518fde15abb81117fd));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x246b066568c27d6c8d613f6bcdef174db90e17d0422b9d975bec492b56196d3d), uint256(0x21e2360dec7020a2c05b3f372f79e63f1c9ead9f386a72212d69c43f58cc42c6));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x2e4c9b2ad82a215bfbb4220f854efb411fc4b3f1e411afb9511908a628a18d93), uint256(0x09049d92c92d1ce6b6892e67844903c478220d6edace96861192b06630c3b6f8));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x2f6b8b281dc2c2a5fb68637f04f38ea7ff211ad8cee9f561a09532b0c3bbec18), uint256(0x047498b670fc954cff803468930d3c6c88366881cae8ef9420c052f71e3cb7fb));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x13209dc600f8ba8f6d260bef5089bfc3ae8d5cf5fdf96e7cf5d910d4a3b8974b), uint256(0x03e1f5ecec39e6fd585f69b7e39239331edebbaacdae85632fc819343429adea));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x17017af3d321f406226cc2d794851448c325aa1c480817a991ae48cf7ed437ab), uint256(0x004ff1871fd9214b24ca76e425a7043386a2cb34eb3e67693b7d45a294e46a2d));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x2e53d435311aaeb941f94b9fd400cd038042c0effb981637f484da9ee6bf01d9), uint256(0x0a078353d3ff022da5fd240e8292826945bb9e651903e61342c0a5aebba3f4c3));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x0ec115f5859d5ce9ffd425111a133a1d1de0e3a7d38160540b29218c80db1a64), uint256(0x0319c93ad75d8e0640bf0f1f5d3a8582d42572db88cd77a556d29a947c56b644));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x1c72cffd1e30725c37fd89fe030ad2380275eb6c23c87bcafdb711bf66a809af), uint256(0x10645a250aea47a221b026cf9b4c4a13dab37d3ca5f10f7169da8e1765226935));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x24277a5569d7c27656b742a90d72482c0354ffafd25446b88ae1e2a32fe45e6a), uint256(0x2db89add6d65a90a69a9d033a93579228d0520f1363c8eabb4490ecbdac89ad6));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x0d61bd049565e434ad39f59eddcf25d7649a20836eba1067ccb03839f40ec23a), uint256(0x129e3088b410be927cedeaa599e8537ac4c582a39ba2e468162b5fa5fccbfe6e));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x09857d52ed3de84950be116abcd2379049fb1f86206b10bfacd6fa2b3fa6dc5b), uint256(0x1a7b3739b4c162fcc9aed8853f985e01268ad1e2217588a2cba42b14381d060c));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x27fd0bb93ee9cd691d7faeff9fee2ce15466b49526be141856db51fcefaf2d6c), uint256(0x046b458b949dd28b7ed06a13b870d6f8a8a2fa8132a74f1bd07bea98cc047c58));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x0d37ed8fe4536e2230bc1d3c2b4cefe3c90f1112b88b430747795be786eabc7c), uint256(0x1ccf698352c627837ff7438e696879643902e8cf76c78b5c15cbe324ba26fabf));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x11105c491100df704f66803384a5cc80f1779c7dca43becdc9a893a6c5435828), uint256(0x2d85e2773d09888e91dfc6e17860b404294dbf1e291af53f55d1cfd068b31646));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x175795c2b8b844c44668c1ef3ea2b84735202e53bd09522b173e19db7a849713), uint256(0x2414ec54f86c9e8ac1bdfb55c789ef1deb5ae2f43fe0a38401f970d015d4cc28));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x2d6c96e9f984a82008bbc3e7a2d4f753ba4eb4c7519743a65710376ecc8e1e56), uint256(0x238089b5dd4dac1189add894dcbe744466f75c30fdd3f42b91bce84098f06e14));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x2f69c53e10f19c86d00b59890ab1c6fdcccf4761f05b3713029b6ab21c6b4c84), uint256(0x1f639055a637554261fe33a30f677ab8a8620bc262e3f865711e95fa5cf9152b));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x025dfffe639d889bd56974b3638cc135a55ed3e72688a28d6b92b1bb2c2c692e), uint256(0x00783ed486be579142c8e6296e4d3029339ddf2ed52ae221fca5a92a9b3bc3f7));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x179d6ed45eedbe42e37208c5f988f24555d8edeb787ab5c91575563ce3cf9332), uint256(0x1a7f97d16ded5949896f1961549de7ffc1463403836f71e3f92aebbd952f56b7));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x259d015c597d2e72dd32b8fe7b259cb1ec34975461ffe8ab986bb6ecd89e21d8), uint256(0x2d457a57889e434f79942ef980d97c70231eed1d9b3c20fdce3267dc94078c1f));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x24b69e8160f39470868b4e7b5e5acb1f7bd15d070b53e38b4f8baf2d98bdda69), uint256(0x0ea780cd85f18bca48dc6a00eeeb1a3f0ad1e192cc0a45cfec1c2f5e65276ff5));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x28bae07630ea7e15837a96c2f4d80eea89980c480555025c4b2ee012e6c79e51), uint256(0x2b93243c5eae6ce90063affbd45f3ee96ff01a127b39e9daeaf1d9f906aaf1fb));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x29bb1e1d54c6f0b5cd72f1facd1f1138ea36217319bae16b8b085d47f3650f56), uint256(0x00df249419070fe26d73b6de707f7715af690674989fdb031f2e951ce6cd6787));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x0b00ef35549b11e0f79062bc4b6ea06c6ecb5c13cd1dd51cf46f2fa20c5dc41e), uint256(0x295d290e0bd06ddf4b221083417c1449f2a343bec9d327e77a403553768ebb9a));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x13ef21d37875fb5532fe868c13a6f875e626e7ef37ecab6b8278ee4fdc54a325), uint256(0x2f440b63107f9ec8accd813b31965d4f4709421cfac2dfe349a1128b772eb0d7));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x1c649bc1fb01202cb19571a929ec4bf1ee83beed9c6c40e8c1ee81f48b83dd63), uint256(0x22beee6e0c48915351e8f911f328e0dd984068539730a948d206a8df057bb32d));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x2d072d6ef9df7e4a646541b7e04e15b3b94e7abb83fd30e70f223fcc1293e04a), uint256(0x005ac8e231dfe743faed8575bf7a219cb3dec30ce8378d55054dd7dc120ce7b0));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x0feed83e850ac3ab30d9eb44461e2967396459e4b9654b367c374b27ac184698), uint256(0x1e40dfe1d8986b9f5493723d02f0b12f0b439eb70ecaef8cf1c202846512f020));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x2acf2493b23c42f0254f5f895a7f02cfff9fa971a908ca1b935e5235b6db2bf8), uint256(0x0cdc70ffff5241f992edaa452efdb3ed0dc7cb86277726c1e00ea092c31fb4b6));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x11065259283fe40093e75f17423793e5d1b851444a05fa8df6434eae4bc59070), uint256(0x02b75f1bf549f8372eba175129b68d5898585adc1c910c7be0f0f6225f8505fb));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x005da07520141047da707e1637de0efbd9ac5cfcb80b5291527bfb56c5203061), uint256(0x2af067c47a5c8b961c0fb7b7d8a072a5a2a14c0b2473604a1196edb41736fa50));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x2f9df7b445ca5a28f46440da0be684b6b01f17ca0ba2cbfdb820540b3b691b81), uint256(0x2bc7845cf9ac6f9e216f63f1c51c85f9a502639f62b28213cb94e6f5dfc70cf0));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x216180e1aa16567f0a2864f7d0fce432e10d357f228d0af1b6fca8ef9b98a052), uint256(0x1dd9fc4b1f101f5c7ce2574a051f50289933dbbcd7d85a9873d230f0aa19c1d4));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x0d37059d778d5e25aeb3123209d067336e56627086d30e7ccdc9be2f6a4d03a1), uint256(0x065fdf8f1d68a002a711ac4ce6ed0e5c53292b3daa8d776c3b93ae5224d3239d));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x102a48f45395e7f8d10e7583d1e4b503ac368e8e1535e2b3bc0a9a0245457090), uint256(0x067567644dd61527b3f938bff61dd50ce1471eade0cd7f3199fae9b59fe25cfa));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x24e512eb4069cf4a5533525060661a73a69166494b1d074f716850d16a4fe1f9), uint256(0x27800c57c6634e8561a92ee2c693fca1b9d244376cc69b5bd4bffb1590832c8f));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x212b7e85d64cdf142baff4b8ee5af513076d9d89611395146afd674b55ef79dd), uint256(0x1b068ae4e2e64d0760bff76d9aa18033a911a0c60fa411818d89174af6400b5e));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x0e5da17d7cfe95eabd6cc5d6e705fdf225a18f29be870dc96dba6dffde4325d5), uint256(0x1866cf1a4be1ba806c386e87cfe5729b4c825b8d63f7029beb6fb208096e046d));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x209175c01ad2c2a56b441d82f1fa02af0991cfae22308f59113b3452fcdd4479), uint256(0x04837565100a0e56ba4b4162c6e8ff8ce865b45154efd7f6962a81cb4aff025e));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x003de107a0f19274ece9050b2bd50f53d05713cda2dfc856a1431a683eefe251), uint256(0x0d4e11d9ed094273d6f0fb419b49a7695ac131a85ffabb7f187b8c2abe2b8f3e));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x2a4fd3960029f96c4af0fa627cb5022a27a7b0933382b676844bf6f0a9dcffc8), uint256(0x0d08575df3b516d898a269abcdd001d806a1fc23a90a24259cf3ea7003545bde));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x1b28baaeb741185c81110d8be2bdfb7f3519be0a8b0152db6100fdd33b75c069), uint256(0x2e4ee0b8a42be9195fd113dbe443dcb5fd0de5e014297cb9e2e7f07664b5a66c));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x11f2524ac7cb45fc12c49c2b493286fdd79a9aa9c55522149406586444f2d5d9), uint256(0x15186d987d0f1cef06960755e91f73922fccf33790c87d2e0b83b6d548f7f1fd));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x0574768d8874d13f0eecb58859d261ba33bfef7f12d7910b77a80d143ae84040), uint256(0x23d598bdba00bbcee48a81b92e4317d86c105e8874d6ca3eb941b04810fa5b0b));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x10b9b98759b72ac487bd2abec2525e11de5581561153194a69dbc660726e4860), uint256(0x0fda7cfdc04482f109c01369614bd576df363037e0b255169aa0233109b4d03f));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x105d2de1068195a1ac065f810d7b3ff02c1a86ea4dc8f21da13fbaa9b708e391), uint256(0x076ae182b04f7678f5ad91ef8bb8130530df7a2612ef1895912a04d58f56f7e6));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x13626d633c962770ffae6718b788c4089875e831e17a31a89623aec30edb192b), uint256(0x2921c9d44770b240d1e56e6d934a7223735d5bf293e387597791b2e52b59a073));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x0251206b5c8945be0f5cb6062456759a1aa1d1acf108ef0d20b1245fdac76f44), uint256(0x0acfed7856d5a1c721886e48cc0a2dbde00b344c3cc547a0efc7ecba691d1516));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x26a0bd435a558f71453f47ff8386821706f8229703a4411b1417ed98d4ecd2c8), uint256(0x066a2ff7dc87c088973e2c9b50db91ffe8386bfdcc3cd5d7d3b9b14fd7f75ac8));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x1c0618d0de85331ac26c43e2a31fddc6d43e1aef0ecb5dca56382379eb9d71d6), uint256(0x242774c1c4abb5af16b5b7546f2b248ff9bc405d25adc49786172eaf80c3a48c));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x12b0af4f373ebaca5d964ddd4c00180fb34edf1e98748b051c7c6974360e30fa), uint256(0x2568008a95114cf1354a52bf3b58fac3a1909d98418f0487125c2e03c76c45c7));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x15ab5bd750b676d4f5fc6e77b9f6189c53b282215eb1e8c7aaf0a54ee66aa122), uint256(0x09548d04231a18934e1d4f001e2c4986a629ee5f0b642e56d56e33b3a7a346b1));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x2b6d1bba2c3434eff94b8b3f9830aee125e97dc7984a2f41b5c88470cb10e9d5), uint256(0x169a66e4f2a266dd5ec38d404849622bfaceb1d295b59f50f5ebec7606e22399));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x0c01f3ce5866e52941c7b56ace66492c5d425530b529eacde960dc01ae67d6a9), uint256(0x2643838b5fb291696cd1a1e7d02c03e1e4581d90eb026a3a4306beed213254f4));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x04d634c39d2f7c88b5c108d9d63cc85b325744b12766a0e6fe1f1a8f4bedcc34), uint256(0x2c62edb08678ab7fdc60fdd825deaa9712050c4fedf1b065933a779ad292002d));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x26c084f57771802e348cbf90d70549c9a963197cf271cbd2aad0b4fdb4e4bacb), uint256(0x028f348e3242315cfa8a9c723df9affecf6df59810dd3880df67cc94b104c7bb));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x13ff21fbac95b77ccc6afc880cc01a93731232e9716cbb13ddbe84c93b9b086d), uint256(0x2d17e518e28a4f6a1b05e6dabba361e2b1974cd66c13905c9c41fd254171c6e4));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x246a9682bad77d4b3bdf6b70f5c9c43266a162f9589c2082ac79135374736e63), uint256(0x0154f65570b9a51b653417451d54c4f25e24f1ae55ed8c204f43b0a8905f4f4f));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x041a70d03cbfe24d36d9a9efb52455a4fccdc0a294d109b026c36b173c7c7e74), uint256(0x0d2683fc1123ffb67a644c33ebef5eabe9b8a564daa9cc779f20d142ba76f3cb));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x21f45006716fdfa1622f92474dcfbaa8fb3bd16c24171d8c13b51d9f02a8ab78), uint256(0x222959b2253f2e58832f7fc2e757b507307c09bc909bd8aea2f2a7ebd75a6cdb));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x28cc948ab031bcdc18527264a3e3f926b8f2ffe7860706abcb24f22e4a616184), uint256(0x03dc7ed48c622c83bcff5a351ef8c6cfd7900c29601adbc130f816bb6ec2d8b0));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x2d09ccae3f7e794217b9b2cf89f1e9047f7ba79af6ddbe7b0dabd310a088b246), uint256(0x293273d59b63ff27c2e2d6780304eb9afa8fbf99712b55dc179307898427de65));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x2e20018aa3cfdfd2abd76f712635a49cde1aff472148676e1855f043e025bfec), uint256(0x2fd0822efe664e8cd0d5a953008f5b4d40439c6bd5edd45daa2da20758800ae0));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x100c317125877e31abfefe2d99a23eaedda345a98f863d171c00c59bb3e54c79), uint256(0x13f753e39b47b76a5356e131472c3f30b8727e1241d4e06666af9bccf5edb3c5));
        vk.gamma_abc[202] = Pairing.G1Point(uint256(0x20fa6bc556146b613b35ca667337879c35e18e2e63355242af842a9b1f7c047c), uint256(0x26b44ff95e8cf6476a28526d10cb144f6947d4a61ea81fed4f2ec826d9957a4b));
        vk.gamma_abc[203] = Pairing.G1Point(uint256(0x211d50d5bf61c13069478cf5cbfb257fcee48c21abec9a56f0cfd0d9e8e64065), uint256(0x2945287bd296b0f0d9956500fd950eb594ae2cdc11d4193759e9a29be89a65b5));
        vk.gamma_abc[204] = Pairing.G1Point(uint256(0x113abd897ec1324badea395492e0eebbbdb7a9b8ebe75b3a2ba4b4efc13f57bf), uint256(0x058e6850b960fc02ef138e734b39ffa5dc82a4cc20db65ac93b4157b68040d9b));
        vk.gamma_abc[205] = Pairing.G1Point(uint256(0x1656adfe81e92ba5a5c2c44405c1aa03e8132bec0cd693360fddbd116a6f057d), uint256(0x2b2a4c700283e15a3ed1825b2d313b8e83895c252f29666c54801036a120da87));
        vk.gamma_abc[206] = Pairing.G1Point(uint256(0x19117d6f2cac1c0c068f281defe0d1d17bd5d5292edba42154a3df2bb685dcf8), uint256(0x24c8da031736d9b05560b4b6a2640ab2a4928e183138fcab81d6ba479fbce135));
        vk.gamma_abc[207] = Pairing.G1Point(uint256(0x0a4bbd0599bd5100ea65f1243df0bb06808e471e874e5cedd8115543b2a582e7), uint256(0x1f730276fe068791a20ab34ac352ee89efafa4ec0ed0eb59c6561f9c52c84d51));
        vk.gamma_abc[208] = Pairing.G1Point(uint256(0x0b85229d5d22056c02774454854088de96e91968f3daabb288b2f15009ade64d), uint256(0x200a6b6d3c369ce97114558a3cf742fee2ce4b77578728d8d8b2009e00f5147a));
        vk.gamma_abc[209] = Pairing.G1Point(uint256(0x2309f6ac9073fa74be46f8017a03f13fc5d784444a597c5a151c1a4bb0721368), uint256(0x1419c222663f735167e41ee763aa29927e743eff5ed390805e663f142f89ef12));
        vk.gamma_abc[210] = Pairing.G1Point(uint256(0x117a1f3ae9fe23607c16301b2da0abb66cedf458fa1d23cea3c4f825ae9bc8d9), uint256(0x2961aa1f208252c2a1c77f6b68f67966e24390437c248e6cc37305ee957a01dc));
        vk.gamma_abc[211] = Pairing.G1Point(uint256(0x23de27953cd385830c4534e6f7524f6d457f62228cfdf4be9d34ffc0a08a5fba), uint256(0x1ce7ee954e4c11e95c9535ddf4a4f6df7c407d3001b7d83da4dcd97b59991716));
        vk.gamma_abc[212] = Pairing.G1Point(uint256(0x14e4f38c63f689c2a3b81ada247d0f8a0a6c5f95c70aeb19c8c697c329d5ae6f), uint256(0x13a3bfb83cbea35cdf39bab7ed663b4f5eab08ddd0c45554f1eea057e7d9e767));
        vk.gamma_abc[213] = Pairing.G1Point(uint256(0x1be62e570dcd443d5022e2eb0f58ebec20aa17223b6cfeee7f4fa24234b3822d), uint256(0x2fbaa5e992957d56084503cc1b9eff1e6066cfe5b7cdf0744e9980a4495cb8c8));
        vk.gamma_abc[214] = Pairing.G1Point(uint256(0x258cdd55159a5c41b3bb83bad01de757d50249d99c493e5531bee1b107c619e0), uint256(0x13bbcb0f9461bbb34f540b3f9413c6ad65f6efd72420eda0f87ff1a7b8a8a122));
        vk.gamma_abc[215] = Pairing.G1Point(uint256(0x14dc512799ee03a262f0007b926759b9a46695832aeeb6ad9f6ccea726d203f0), uint256(0x16e35a2d1f693c63734c1809da8c7d61db3bc6d389a47e1e27acf5e1dc4ae6c1));
        vk.gamma_abc[216] = Pairing.G1Point(uint256(0x297b103e6daa66ab3358f093dc34e66003e2906dd3ba3c8707f4226ae289545e), uint256(0x08dcf4c57633fe2640ae2a1ad8889c127c68853d7af012b5a522b54fd0fa08fb));
        vk.gamma_abc[217] = Pairing.G1Point(uint256(0x2c6272c23ab9c9e5dd22cf1018629218c71b2b253c99f8e734dd706cf5784e0e), uint256(0x085b3d273da6540c953b5e9b1d1b8d36f858de56c4cfc99cc27b1426a9388581));
        vk.gamma_abc[218] = Pairing.G1Point(uint256(0x0416d9a06f109af6a7bba033f4d4c9ff7d086b1d878810b1405b9f4ba7ee1c10), uint256(0x0cec8a28525cd5b6344b986a530b2a337b7810545e4b385dd1a1908175907362));
        vk.gamma_abc[219] = Pairing.G1Point(uint256(0x0edcfb45c501e2cab3a7b1bac4b8b18923c339fb1c96abf2cc56a44e7af4560e), uint256(0x2c2f1bdf80364d0dddbaa7e01cfeeb11d23d7335bb958024805f5d205716b5e2));
        vk.gamma_abc[220] = Pairing.G1Point(uint256(0x24c7f2135929dfb3fe833a182dc34b413b847f2a92d7b40cb3f64676044fe005), uint256(0x175152d99eb6cd8169bcfbbadaa46a1df028983b835b0c40d6ba10e5036bd9fb));
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
            Proof memory proof, uint[220] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](220);
        
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
