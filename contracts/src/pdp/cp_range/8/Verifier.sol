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
        vk.alpha = Pairing.G1Point(uint256(0x0ba2ae9e1f601ceb04d900b4616f8dd18f7c9805b659df5a0c1ebacd4f31470a), uint256(0x0999d55e7946ae41d03064864503d5afe1cf1695fd41e423cfac9e4cbea8f7d5));
        vk.beta = Pairing.G2Point([uint256(0x245b2883083d86317444a37f419087ae08995980afb3d5d839ba02dd0fc05ad5), uint256(0x2860449ac7b9d4435e1c71688cd8075cf4accb4febbab6a2307cd3c9dad8b7d2)], [uint256(0x2292548c8cc1521bad8d9c7b37b802d24e46f7ea753a5baa2f487f807c51616c), uint256(0x11c551b1a4d6a30d9f6f6a4937c4a171a1b2330e17ae874cc371ab616cc0bf87)]);
        vk.gamma = Pairing.G2Point([uint256(0x0c1b57d9b0c50c5ec48db4b966f403354c0a1fee42ad6771042b8b13d4993198), uint256(0x018fb15d71c33111b923aa41a7b6920597b46a5c078e11a5e4bb4c452652ebe6)], [uint256(0x04aff4bae0644d0bc0aa0ba7dad1c3bcb500b03793080ca64abe25975a93a94f), uint256(0x072c7052e7a5f125e460549c2849e1809eebdb98168043b9019c6b6113e5e2bc)]);
        vk.delta = Pairing.G2Point([uint256(0x2ddfed218f96a214f4861efc14e8c387572a31b307d62257dc42c46b221ed93f), uint256(0x1ed7a6e5132a6392fdd13a0105886a6e15bea0d2d51707753778a1a305a7abc0)], [uint256(0x1ede741bdc7f19addcf57fd734635ce5395abb8352f310e3f19feaec5960f401), uint256(0x25fe207db855f2e020c6ee6259d8e0466a6311425f39526f6a17f7253e722a50)]);
        vk.gamma_abc = new Pairing.G1Point[](161);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1380e3690a29c6c3d0166226d466198724be6369a3e1c3a10add91e8b3f5aae8), uint256(0x126361224715aaa29817b59e5d4a21698f7e01ffe30b58fb1b57a24b15f1f80c));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x004777cbc7fa94d891433925ec80358d49a90ea221a3dc03da59429d5eb95cd3), uint256(0x211e957ddaf49865e960f7e13016a5544e78861c4e32c752bae735fa6349a430));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x20b9dc7f472e969c44202df4b1051a02b83c753886ffdff44da53faf815f7d06), uint256(0x08f52e8b34ab8b90e23ca198a60c40087dc6ebcf6eb865c25a72637011562765));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x222348922ce7eb2653a44456e13d37d3af229db274cd1810ae918c836f40d231), uint256(0x2d2b0a44505684b54cac7d8ccc657a2e2f1dca2ce8903f8f8a76af7c6dc2d291));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2ac4c9e0af35c7c7145156d9a4f78b2c0d9f155bf571e3da12ceff082e881942), uint256(0x00e62940bbf4c3711923716301ab07b04d6175f3e563601de9df3da2bf296899));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x16e1623853856cbc64ff34221ba58114be2c2961f8522b3639b6d5c5d4784e42), uint256(0x0c8d1c6a2ee558224be6090097c196b5005376c7b482702b3cab92b783b0aa9d));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x01feeb5d1de0813ef6184ee3f9051f5dd04346173c444490fd8e940f9903d13d), uint256(0x25633ef2dd0811626056a1285a740446d57617fd8214e2a6967868b297b7a1fa));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1492cde6d396234e8fd2f8b9b408d953b3a75ea40222d0c11cac6ea40e5bbdcf), uint256(0x25a8470b89c4f0dc2bef4ba2282f385769f7ef67cbf5ae90faace72c7c87b1a7));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x149de66c56c4174c2a100af4f02166a2dfcabc443560124685d5a6f5f2311ecd), uint256(0x2ecb923c86675824c36cf7837cc27c2741a3b28db48106c89da4e004214641ff));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1f677a5abae4eef37ba3e1a1d3b128781651f94765374a98c2697f148a5054e4), uint256(0x01322958fa4bf66b3e128a276f6b73256510aa5b2ae020eaaa330f5d99c423cb));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x01bd4a4d26c00905378ed8e080965ea263fb5a8eba2486832c101eea82b8129f), uint256(0x0552496a7d250e3a119776cc10e61c1c35b6bbce001597ba3e76914e7dfcc289));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2fd1fd2d767dffea96a185df12f1e00a0fa55a83b9d435c98117004b902f5745), uint256(0x2487c1d56d68ac268a1d918f7f59a681d273d93c46eafd53f643d70d216cfaf7));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x203d00d23e85c549c68bdd5de9cf0139742ab3235956757278c5835c119a1b9f), uint256(0x0e276a8d18debb9458b24eb69a83d52def0b945e689073878dc12516fe72e719));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x16315dec88a80ad4e4186176a2e3c674e2a8639d77f19976491865c052f31471), uint256(0x12e6b665099ac030b422c0186f04aa12743b809deac4507c3962cb5c3d826dec));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x23ed1929f2c41ad15d4ee09cdaf96013fbee5243fcc1dedeb4dd20928a3ed6e5), uint256(0x2a6d55ddd83195c38975fa030a23e05cad6269bbe156209c43c4cbf6f48cf090));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0b1cbaa99aaa887a27e147641802ef85921ab08170cefbdc5c88f6654c93d35c), uint256(0x0743a658ca55448413528ea57c3c01a53e498ebda94fa16ad6d1a05a7b6ba25e));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x03514282b266c99e0c647d70dbdb84144b08cc3ac6d188762f89122c919cab82), uint256(0x17a26b652267cf8617de57aef398ed9991cadb49de04b4cfe60cbe45f9eceb1c));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0250debbc62cb2418d11287a59edb24958a3a0cfa1cc74947915b4e06fb19e62), uint256(0x1eec6822985a2424bfccb00d4c914642403c550555f45f7a8213118c5aa7526a));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x161ea7ba3da8c9409952b328ca5b1de963ef3b2324aa53676b316c8f9afb8617), uint256(0x0587d70787f12f4848a2907845a4114a8740bc8478d20e716cceafdffe09610d));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x0d5b0d499e8e0bb50a222302927a876e0c9c1c09322156202f7cd164a005cd76), uint256(0x243f0f9a2041850613e67b9c67795c89306d1ce010b1ad135087b1abf4ee6d0e));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x0a52c37b216b8d5a99e69bf6294e1b56339c1b3e3a90318129cb48535966d5d5), uint256(0x0ce632ae0d10728066329405f6cbae90f8f4efb22ed4d696f0364b349287c319));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x244271caa13e1243d001b9146a68b15755966990ad68cd8129e504e6a20a782a), uint256(0x06fdc449c3cdb9fac6439fa5c3c84949bc974eda818363e269ad92f232d0f858));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x1c50508ef66e0fe1902f7e2b484374d42a2c75871db13f00e1533d33d36860ea), uint256(0x27fe95d00db4371c386af69cfa8ff2ad3e88997a2929ad630c8db6c3b94dfbe6));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x19aae294ebbf3811c04ca8feaff0ac1396df61a363bf88e9c9f0f9d801c2612e), uint256(0x25b68f8e2f056d6688a2d34e2be29dae14b1d6d1d603d3a633eae8264c390c11));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x24123e079b106f6967d21acf48ede4369d281024de1ab6ea5ee31baa54103f4d), uint256(0x004a40f3296e25f888e313ae84351d0ce625c23d86932e5628f99cadea41a248));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x1e4dc28c6931c49dfd3bfd8783d03759e9873f0d7a60fd4d0e0c44b1357bcdbf), uint256(0x295f9f88e23046bdbc33f6c30cf2cda17b38190d46906c6d21e600f490562330));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x2f484471813819ee925f4cd32a50e2dcdfeb12cb3928fc784d7c22660578458d), uint256(0x224cd5d39773e5e9f60411e02332a3fb24d910210ef77c29d46f8ce11fa5c5f0));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x0967b9645507e792d4d1a190b5dca1a96c9ddc2a0d694a5dd00943a375e2354e), uint256(0x1e21053e0496f52d986abd7f6c735f13bc49ea2b30a730973a5620270ebacb76));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x181d90c1cb72e5ac38809d229613281545364458b74cacf00b9ea2dc240f8c3d), uint256(0x2a924747b4b465e18434d8eea9ed03a8e607fdb9f54679e80ae5eb1be62317f2));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x008fc8770d6ea51fa2ae4fb7587c35e9fbbec6b540d31cbbe3ae11e33d3db5b2), uint256(0x254b9ea4bbe0b39b79a18300148732dff954b2112eedd28714604d6e35ec170a));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x0dc6ee823833e80ad0463490e850fd47b5f917a80d9268de0536ab306916eb24), uint256(0x26ae4170353b02a69c15b3f5418bddceef2c398f49593d5163a9c46d08308ead));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x234f5f0ef4448ccee3f80dd3367086d0c3a67c79cc86db79d2424663994e6243), uint256(0x0fdaaa2b17b7eb4dbc8d388e04b418ffea22a804d8b813527941fe394a04c03e));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x29c45b0a25a80def30fa1bc24df517ebe0d16d66224cf32a3a88dded11530360), uint256(0x1b2547a736c24e2648cfb0f7bb0f0e3bf234f4a7b3d8cc6850806f72154d98c0));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x1032f3046f46e3572667f11a49de763c8ec78d535b784d19038b2a2174e1918c), uint256(0x0e5991af4fb394de9bbc3c111f10b2815818c3a08d19b3ad082de027981e4743));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x217942aa9e74a7b706afc44a7b13459509e582c067a9aa72090acd1af069b4e2), uint256(0x00c40e5e681ff7e825616e7ea880ad7d00ba57002235e87c393f76392388543a));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x1962e606777c4f212808fc6b2bedfbced85d801c1cdaae70e3add3ef9345ee4d), uint256(0x118d14755c6c19d9c51646fe846e50c4c8c278682728980400a9d0d50c9b34dc));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x21fa8b8aa0c8d75e5366681ec02810200543ecb52565ed0e057d790e659182f8), uint256(0x028809ee6396c73cb371f25a9e82e3f21b407bede045e03ce2e203d3bbda3e6b));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x2e6350d83237476242b3f7dae9aa5b39543325b89b8db7bd17a00300b4a09dd1), uint256(0x0a851aa5571e7a87599ea4f52a7fb11e3e7a9009711ce3f60da66873093cac8a));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x272b8bb0e293ac7fafa946cd4a561be4785f9bef4d91ba462dd94d14b9b5efc2), uint256(0x2ff9d040fb3828e20a5bbaf57e2850d280fb77c045f7669713c0536b75aba665));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x0496c6aa4a82a428eb5ba8ba6ae4b2827744740553aad91a6d60b77b30ddbadc), uint256(0x3033eaf7369bb917c20f40fee6ca0d43251b6c3a4b8b88a8063293bd44c98a3a));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x080aca0f2350f945274dd2463ca7a0a7a2a26b8d8b5cbd249b2489ec665f8b29), uint256(0x0bf09096b8d6aa0ca76d880983c0e0c1b24ba3dfb43d02969c22c454eb06d529));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x2771837dbd1d54ec6f7cc0f8513d64e77ed63f41625d11cd21ce47d16b6d24c4), uint256(0x191ec03689022acea62377b6e3587a16e1960a6798c2e889342302783812d054));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x2b8ac74c5db40280410cbd8d752ffdd7795e7f4d7f2d6399f2e90015114be878), uint256(0x1d73dc0a18bfcccf0cefdcf443e6867c88675819953efd00f5334caf70945f9f));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x1283051bc97c2031fbd8070d616ee1fe24e86c4b8ab6b905ea9411d3ecfeec8f), uint256(0x0171fddc2844ece9a2c46016faa932a34400762ca4e46f9750583b46acd04920));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x284a3837d0961ad8772e2beea36fd5a4838ae3fbc166eba82f32238dc30ea949), uint256(0x0e3fa8713d3569f851de5fa89e351bce57000a5021264dd3cc1e62d0e0131a64));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x1c4c14d8228945efb4659a933358dbe523a308144a4da41e6a8b873df9c80015), uint256(0x0a5d3d21038d8d1fe17684f17d4e6a6d7c740c647cf649c452202a20ad4a7c87));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x0b581815c321684d18944b162864effe63b106d542375a78d5ea0db696e6d957), uint256(0x2e420590208a7fbaf95a3dcb0e59f0241b4eec72c98a4f40787d7882f8f392b1));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x240cfca73be07c4fe4d0d9d6e1652d8d0b3c3ee1637cffdf0128e1048af9866c), uint256(0x0662f955843041d67130675a84ec0bb7b35fa30f707f4e67b64d90062be14a31));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x057975b389f69612255026fb9b8746f9e83a165e81cf79c1cd63274f6a7e8348), uint256(0x0a4d81abb587a81ccbe343971a16d7bddafd834ac6a17e43eb7d9100d2b7df1d));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x12a8938e1e42136cad36287bd013b62c1843850ad59a7decaf7dc2b29f949803), uint256(0x202264854a6796a64bf4739ad50824f48e661949a13946a6ce83824067ec181b));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x00106dee81c67cb95663bc8832f3ac8825a7059998cf93c42bcdc0879116b406), uint256(0x27b803d28a364ce562ed08b6f8caf611e5e32ab5dcd4f41205c04a7b18e9d082));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x2caa5710d2ec64f0fd4eca7cd1247fb24814aaa1babfda5cd5c6a8537e7987d6), uint256(0x2a445a0e51cf6234a4798fa7dda7637a05f72fda2d283230794860ac942dd181));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x1e7ba3f515aa287624e87d2ecbdff744540cde8e992b3ff62978f7ead556baae), uint256(0x16cad76b5f55a44cd417adecd821d1e5764dc506067b59b2f9a676a8a287429d));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x1631e37125e36083bf79fea4b96ef16e6126d397f290af79ea7e6dc0d5293ea5), uint256(0x274dbb1a1765bdbadd64d041870095d130c3fef343b9673295c4faa558c6bd55));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x0c53936c575d4cbe5b1145b78336edd7cc219f3db48037b3eb4f05a338dec905), uint256(0x016ec84c0974e6cad45562ac0da53d6b8bf44721a8e2999bf7b206d05b9f089a));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x18b8881c963222772836f7069673650554e303ed7f78f51f45fa43a6f0209555), uint256(0x17885d46c2f84529c0161190d7bc8146ef51bd76cbc64d1e7d6907cdde7d5e49));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x107520c42e593b88fb3895f585192174a09b033e0f1c256c5800828ca38b62c5), uint256(0x28c4d8c73787fae2250b2fe40c9a4e7bb9ac37b5e0c679e57e457fa936950277));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x2c9d0e6a05805d714c41ec6a7adb917fad8e8df75c6ecf4344e5421da050c8fc), uint256(0x033b7041a98d06c4f833d4270cc7f78f696661cef16591dc16ef3d3ee9542b41));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x0cd5899f682dc98299fb04eb9d68d932da9a499009f18fb4a05260afc172eb62), uint256(0x1a230415366826a2a94208f4ced1adddd43f2dad04664c85a73fadc733fb1e29));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x0764625d8035c7689b02313f05a6adecde989c064e94cfd92d5eee3fc654ccf4), uint256(0x2e53311168072047f9c31e6debfc910e65c1f2432162b0fe8f21c7b2db2a5560));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x20d49e4eb49c8daa9bfbfc56d733feeecfbb4b19ec53a795494fd757c61e3d43), uint256(0x0972e55c8c75915764d182a42c245af206d03524863a56f7576c5edbbb34f933));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x1cb4d0f692b6f4e5d1e4a6bf22178e20a2c2ac3b416f97372d325cbced1258a1), uint256(0x0ad16045572f44af2b75849a84efe98554e7a70a63cb17a5e376b59d407cc6f8));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x079612208aa9502e325192cf049dbc848a8f1fef5ecbc00a3e3d2c7f251093be), uint256(0x28deb99068ca9d3eec46ffd72036c93801f3b7770c4607fb896e5e4b87b86aa5));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x3060db1201009180250451aa8b15f71506844e59ed5c46c6389edc4908a9ddd0), uint256(0x0d99d998bf11a6f1fa56e0cdf37330db816ff2b07b6f06035869010227ebf7ca));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x3046566a999707f2217791aed8a7909dd2734d87e0dfc2b8973c6f899f4244f4), uint256(0x251f7bb22c8577dc212103ec089af3cdf29f3cfa1cdaa7f67656b5a4beb7fa88));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x160e34a30833642c0d5740dfe0322a361d72e7907be427cebe21e1414e173eaa), uint256(0x012d4624a37be89c76420467b82df06a62e5d88722b2b701c0d58d0f136749dd));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x1c20e24f1358256e1c936b45308a892a779906b14fde0d55223bd12c5f40434e), uint256(0x204597ee1461d792eade40780878e6616cff7affb482cd29417212e21c4d36fb));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x1f2011d459e2859b03fd7d607e1977d29d82905bb9f1e21362c6640d9aee265d), uint256(0x14d1338db2e1590220f4b74169547de7283a4967af5625eb454fc07c39b819d9));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x1cdd6c81374c2deb3b58e44402b4603932ea691d0d63b5250f8a915eeac29531), uint256(0x04d74c85032c430eef977a1768f193b53c8afb8a7db62d023b64af6883ea159f));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x1bdec082ea29000a8041ae45401543b5e9121bfe4d150d82dab589bb7f430740), uint256(0x0603f65700ba165e08532bdef2c19e3f67b0b2768d6c5f950c90cdfac3777d9d));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x16e428295ebf0ecad116a23f0de00a128b0c8dcbb2a58f2030af351398f87004), uint256(0x1951422d51f92a3d4646717ecf453fc984c09000733f9c54b311533a09bd63d2));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x24931d20c88c45770ce6ad2102b5857a92a10311caedd90b00557194b865371f), uint256(0x0f2bf16c99c26ef1798120f37be5b4fa53d11c85631e31e2b9367e69a222d056));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x1b73e74ae3d0105346ee9addd2f63163f0ac8dd79971d80c4930b347898b0e42), uint256(0x1788e971dba60673d6860368fcf729dc77f4282457f11068918bd8fbba172678));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x12fb4e96ac671bcaff9d78ce707ad7a4e267189cf2bea6168117b795c0e25017), uint256(0x1875463552fde37063cd8fd84d5ed36d5e003548a0757b54981ea137672f1212));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x0b6e10f067bb113d67aac58c1c4ce96870c8788beea95c6f64ad5c1ad46c238a), uint256(0x1f897682dfef30f60f00165230a302b11299f90f1b9bf7dc2f9ea838a9011f61));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x302f3249d8b19ed6b52472bdda0239670a48959bb892634ad970bcc58e237cf3), uint256(0x12c6cc50b41bb2f5ae7ce32db743c5bea60df53c3b79d8fadd93ae8558602b0a));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x2a33bc232ab9c71a6a087cb83e574498bf710f77d9d93d85d7eec6e0f7367c7e), uint256(0x07d88b535a0fbeb757103eb245429080ded76bd525006898340cbe01abbb4b1d));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x1dce0f5852a77698764f5f9723bfde9e6bee5feba6787acd828e782316553c39), uint256(0x039668ff6a14fb15d0fa8354a779e834526c6b36e927a514b0689b846137b7f7));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x069df3b13321acb2b446e38a2edc6f8c9d948f4017497f2b1a72e0404e3a6c07), uint256(0x0ffd5853cc335f1595b939083e94332ca226ee491298f692e487992c3da12515));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x065104d5569a08e82adb8750f7a78a3d0f9473d9f0aa16c94f12b6cd5413be91), uint256(0x2be8131a3e4e316de21d1b8726380e2f751786767b86de46b454c9a6b8d31c49));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x2bb94df62a2de92eb112a853e0bb7a995ece8ad5a65aaeacfad30165ddf092d5), uint256(0x1ebee008f9c93e78f9eaba18891c5a3e5c3a1f6fb4d1385afac38b19ba2e4967));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x07580d00248683d048c10be2b18f6482798e4ffc8df74119ecbbfd350a1f5293), uint256(0x05ecc7667bc3588cb499d79e5dee75dd6223608a73d01cd5e553ec3253b167c2));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x262d1984aada3938f5d8a45387e403687c920e5551742ee0a2aad9219c49dbc4), uint256(0x1d11ed2d78e681c78253cefc6277614201753b98f5cf7e930290460c3fa2e045));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x122b23ef1358ca1349d7d630c858c3f22fcc22fa7adb5493003fd89db83eec69), uint256(0x07def1e93ed895be0124856dc183655e7ed898760277c4d3318f9fd2f201f865));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x23126ec6cf9228264b5ae5565e89ef2e19d1fad00f31a39a7a0b2edbb7a317a2), uint256(0x2d3880adf7d0c7c913720c9d40c8b0987049597806980cbab1b5d4231c2c9a87));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x00e15d2f335cb7d1012fd74125a4aa129436b5f4dde537af8f9066ce4d9de850), uint256(0x1e717982f9139b64b7809c7bc9782a1b27ef2cb1206bff8154812d5d667ab261));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x1f0322d879ab5235d30ad48cf4f775f44c0a577de3982392dc013d192be438f2), uint256(0x08b0423fd99f10a0c0c0b99042aa79b68b391e817157b60ffc194508d0be7486));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x2ae32f5dbee55697e984ca0a829538527f463c20bbe2be8324c20728f2a06162), uint256(0x23d46f36e98e5e242013965a31e85495d20af257d8f09edc92dd02817775b184));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x2cb40446348b43ac617febebb289be504636999e01dd4261c3c81c2af4490d9f), uint256(0x0763b442bf0c03c4dc1c6312eca5c43b4110bf2b436fae9b6be1a9c05f4a6435));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x0ccf4e03d7196e1b6dacc795166915fa550b6c989785de533ce4e74b633185ab), uint256(0x1c2c14446d6b68f5eadf0afdf36709c8774f8af0c85587cb1116c52bd14b41f4));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x2b1119246489fd1784b1278ec838a7b1831c855070e41226e1e0cb7648b6de94), uint256(0x014aa1a326dee5dfcd76ab223011cdb775ac38681d981f1eea1682fb2790d520));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x0f16ab015c61a34001f3186f65d0c7f726df1a40dd8e9138cb822488f1ee8ff4), uint256(0x1682db2e46d33a46245e9327a4f2e604e779fe5164cb7855b368d965c96fc665));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x2f770fdac675d384bfa8eba2b9c768b6631123b0ba63f269200a492230383207), uint256(0x17355da24a8b83e90819b75400dd621edec207a250499d1de05d396a3efc8819));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x031ab19bd75a96bb0b7122c45dba5b7c072636f543884b38c1fa43af5572946f), uint256(0x2167248bd40c0f996add54ef44899401c9c58ca3225f8ba3f57d79f27c0edd0d));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x262a10c864fdc3491e0dbc5457f9a66ee9372305f2c346d685f8cd1838dddcc9), uint256(0x01ce7c7eef7327d0d59f9ae68f75abb800181890d49bd77cb6897141c47e05b3));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x0facd876ae43ce4572324723e4ebc57c5c4f715ec25087fceb02527f1b987852), uint256(0x1e8e2cf86c39384220a4afea7f7a6e5388fe3c876ea3536872e3158dd6468c6b));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x1b2297eb72307896690a138efdb41b6dde1f489652b8ab9f8930cef347b11edd), uint256(0x048dea33ab3586b70674209bffae9646e5b319a9c817771eedb57e20d0134d91));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x2ccc657f3fd8744d30d9a072d1527c2737f3c444f632312fc973e3e97ec59e1f), uint256(0x21bcf3e2342280d7b806b7b3bd43814adb85ee2a6970272b6f3fd3c4a8302971));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x19a3ee28ab8edddf7b69200e3f3048039a89b9ec9009a4448d34899af7ac584d), uint256(0x1832a4f80c623de82496cf449f0be75a5932066be6e45d3d7de7767550f6e709));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x1ccd8d374b8fe74cf879ea2efaf4dc2439699b0533ca00e7e58267d3546583de), uint256(0x07e4cc940e7f957c605746a1cddc01873b680d5ea0351480d6228320ed31458b));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x04447b518377a3e1e4eee435602899e207eda6a8adf4862bc5c643ebaf4b73b0), uint256(0x1386fb15cbb59ef226415622968c33d625306d7ab2cc7c58c93c09991f407d99));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x2e6f308895730b27616dfd2c6714c8bee2cf8289e5fec4f08c7470ae7a941b8f), uint256(0x1a74c6acda25b1e044aef0e9538f993ba908c9a414e179dd7dec56e845695b8e));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x2a3aaef288e3e933d74fb351d5518ea8ff94b620b7ac5341439f1c9c6785185d), uint256(0x105c0fa9ddc8cd2e63bb7c0f6472cf88579ad193216b1406ebcd691cf301211e));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x27c6ca49dec864a9410c67d418f074bdfb4598169fa36497355690161a1ac594), uint256(0x27fcc990cd81e3b70c8325526b5995ac4db6ec702cfe8a0fc2162f8d9d67ea49));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x2cf8d983ab6043d11a35faf907852c44ac351744777b3f3b2a594955f919eff7), uint256(0x2716d05bfb23dad16274f967732cffd42c38823c26abec82fe5174c1057b0695));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x094141eac56ccab916f703043be6f78e5f8a6d4c6025406ae797bce3a2d82806), uint256(0x26bfb9266d51fe49af8a9eff2ad3f28ff6b72f8f3a279a357b6983b79bee24c4));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x0f8f89a5ffd6957f5a73e55458dcebbd318b772f46b585145f878420f02b5f8f), uint256(0x2820bc979a34c42bcb6c25c8ad9c1df0740562a287537236141048834bd1b33e));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x138ec478bfcd5a04f46440ce37e9827be234447de46edfc600dbe6868f056188), uint256(0x1078af749bdec4d8f1a85d86a6e44ef7ac1462489bdc7c0545efe34324b1006f));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x2abf7ab0528b682fae57c7ca432ad59a1e6927533edd690d03ab3f1e989bf892), uint256(0x0f34b1cbc1e0e6a12f0fc1d121656b35691b96026af8e96975dcdd87036fdc3a));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x2c996c36db409112a178c6b9e2dffe4272f3c06e5c5c086662fe9757e3a668b2), uint256(0x0fb5dcba831420730887ba9b08fd7cb47a5883889e40f918d89fd72cdb51399a));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x222ac6a377afe327e854efa34502f9e0186dcf02f6a5b0dd1fefa0d36e889107), uint256(0x24c549ad2f719547498602ff819b5cba4dd05a52d610f9b9c4a116ab5859934d));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x303ce2817f872975ee18e8620fbad4dfa446be2a60a866f4ddf619326cf25a0d), uint256(0x0e9ec0061705f30c97b08aa97852969b2e0cf61b5f672e540fc180f34b100428));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x0f60e7a7c2b4e7301715cab8655df60cecb224a3fbf8eeeda737537f090817cf), uint256(0x10330fb31bca06186ccc67e86e83913d95e910e1709634fdc70dd97c062403a6));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x002dd67e4bb89c6baea621f3bcf2d551a9222feba81540f8d30e404b840e487f), uint256(0x235943dc25d2333eb874726f92377acfffd3dcece3ef032ef4627c6ae50999be));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x13a224b492257a980f2cbb799637d2a30972888dc7d66276db28c6c53c7b2c45), uint256(0x0e7befe2ee76f9ef010d0f692721e1fa9de2bd629b38929c7cdf7133aaee73fc));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x2f3d8bae34d16ebd0418a6ca0c60b5cb37c13bee1708663e2fd1d01701b436fd), uint256(0x1f160b2df91e651972055112b857ce992b807581d0ebe8170e040eefd956c9c7));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x0ddd1d30c7d7ece7d5551ec38e9491b280a382681ff8b1353b48ae55812fa816), uint256(0x14ac69971ac5303005b2a76f9ecb3a7ea23bc803cf1e9978a123caf6676a298d));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x23fcbd6657739e2776247d6b9e9bdb6698fc98489568ed749a1b82e3870f5d70), uint256(0x16369096b98175283559c3abe7d03490c256bd11ea0dfc77a1666c047a402848));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x2b45da9db37f41472a93c3e2a19543df8914514edeb545f44f080cae7116b2a2), uint256(0x17ee53a17a612c39e3dd358aaf08c1140a842ab5d2df0906d07205ba75f3beae));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x07bf5ccc1d69def0dc16f7e9d714d368de8d30056e34717c23636f4761d46d23), uint256(0x15dc2231ff267bc452c480481d7483065ba3e16d99e47da22b96f345012c45ac));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x0c96cd16701099a9b77319400dc134746b87b345a01c6483f7a9296ea66ba4c7), uint256(0x13fd3ced15fd50cc6abb02b008c92516073355c8d4f8691c6fcbcc5331fe90d7));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x0b17172746830bb8a35321452fe6ab18c48732d07cbe8c059a85d7944af8f8ae), uint256(0x1ca67e993931241904ff95024f6497b76c9c3a217ad9aab7c22bd76bc3855024));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x2cf4f6e216e5787f4bca4e3db4440eb6008eb93d540a68623479772acc570861), uint256(0x0ed32a8872b85aebbc507b71e40dad9e8a2622232d75c99bbb4ca121baac0480));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x290c4278a741b1b422da125c15a654ab8573871456b3e8ca5ffa239f7aabe26d), uint256(0x2266bfb099b604ad66b4a7a319477f0711d950cfc0f89ac644d4d3466e196a36));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x10e4fb805ac5f3797ac1ed50b16943ee73e7e056726f1b8de1b9b5e4fa83ea92), uint256(0x02792b44e05280d67621aaa3d1c13d4f57d06e3b2a25772da95a1f72cb1df099));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x01d204a389ab5d8b9d90460a53eb0121b4c53f7b54e179c775af16abdead6e91), uint256(0x2d3e72f3417b6f3347990a3c6a734558f862134b8fc3c53d1fd0076dbeb91bdd));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x206939eb2587333e01b331af063855c28ffe2a62569e38e0e14e057c81411e0b), uint256(0x1b7a9ff30fc51f85582dbeee4b3b9bec7fcc77bad49c4cc4bc7c14f555cf8230));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x17062f88da891f6629ce6b9d9422cab6f6af8a734e162ca4cb089bc37d6a79c1), uint256(0x2c2595d59a96ac0e8be8829c30ea0caa1b48ca44bf2aa9e586ebb249f670c12a));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x1781612f32bad3314072e541db19bbf59fd1a023d25f63f84838e2e4537f8459), uint256(0x27ccf4077027f8e3e30a65c88509df8f0b4131c29fc9f783a6a34941edf0be2f));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x3043a9376d6f475af8bb18ce2f6aaceaef43598b4a2c285e29f4f654b8dfcd10), uint256(0x2451d03582261032a9550d3be030d7080cda1c0ae3eef8c2823e58b4ecda6b00));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x0795675e383ff07401914bd120cc94cb0de516e7ff87cf1c28c27f1e6b5bb530), uint256(0x0622f29899075672abbb84a0807e52056b4ff64b031b330884b8a1f3f1d90419));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x15b4c38d8d08f06c8c0feda50fb0ad572c02895f88d100fd88ddcb7576ed9615), uint256(0x1b378f3b1234e1e188e8bd7856ca3568382352ee1c841f4c4f0637e174b772a2));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x1edb501ff67255aa31f8289cbc5be9aa4852add95f3b173d306eb14a20627837), uint256(0x231deefc727274c91ac846717317236652d88e6f940381d4875d00fa3188f3b9));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x284a313a0fd08fc1bac6a82e9a9f026b8f97d2d3aad16485b26e852f60e01537), uint256(0x1d9fbfb3148fc3796d934513e1f53b528866871217818a333f7d75d3521dd96d));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x0c484aaf4502a2c1a51420402e792d30a382265c9aedc3474e2dea6d0f5ca2b2), uint256(0x0628baa85c7e8c008a6b17ccafab821434b140498839a6c2c414d68edbeaf8cf));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x2a2385dd392199e8ae23db52d4426b547f1e7f62c0f36399bc69a43ca1c62cec), uint256(0x24a6d4cc2247f1500ff157c7be7c236962c75a511d3db47d989b4a20c6763027));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x06cd74c295dddcf8e945baf61e40c3e5658ac226cc4cebbcc59a20f9af186cb7), uint256(0x1b172a0e10739f4022242c555ef6f52719dcbee23d8616df5b338f39797ea343));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x05e590aef8939e2bede1d2757b14420fd7096f43c75b85962c1e5dcc2d3af20b), uint256(0x05f366af32b23c6df2de19d521d8aa00e9344e0bf83991c6558111272e8bc97a));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x1cf21599d2587b70c3acd17142e32fc131f25451d713f3f73d306201b0b9c5b5), uint256(0x29d5485fe37b3fa7b360ac084c4f5a56cfc446f57933de73465e018ac9189bf8));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x1710be2b4b8753b35394c9a6628364d824e636d6b2c0f08cb2a604f924f12364), uint256(0x1f643a683707735f26fcda7cf806da704c5b7e24ab2e623485cebf2cec5f20ed));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x2a66af20b8543151b9779627d2d354773320941ec2c4f77b839a43519f55016f), uint256(0x0c20dd90f804047964eb69de9ef4dab24072d17cf8c0cc43ee9a1561af801e6b));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x06cc566dae6d97946806e7831ff31b524f5a53540cbceb57e760dcd23fee4d3e), uint256(0x2eb89c0c2f912dfc3cfa417972264e3e8dbc274dd4716386ddf255172d317397));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x1032e71ffa1f5f32af2be53d6cd62a452654fbb8c2fd1956bab5f332ed4747a2), uint256(0x21d2ea0efefb29acffd8e44a70a514c36a082a57c3403e6a52ef8b89d6f9e5da));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x034e08b0f42a7dcf72f2b536ad26a27f506e682918118197c0e0f564eafd2a23), uint256(0x10b6e8660589c1071a7b869f13b16a1edd459c4fe25ab256d91af024b3bdf2ae));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x09ce1cc4a45b4cb12dbceb5ca1027edf9ef3c8d204ac363891a98ab7548dbe2b), uint256(0x1f50d71da984a787da0f1548b56a30f1552f1c8440df9c89cf028af4f27e655f));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x2ef38fb3f5e0ca4be44f7de4a50c6cfa2ff414cb02e72c2955f21de833d65c1d), uint256(0x1c2b9995b5c0fa4323c1fe18e8146b4ed49986dfb3d4e800fcde99891f3f0cc6));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x297504725ecdbcb5b25029e6c429de955bdda63f6653a1243f9f68131b83192c), uint256(0x228da8a6d9e62bb24208a7ba7d5a03c55f99286b5468b6274a4bfa80b29ca327));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x1894b55fc62b30b8f4538300027889d6f9e80818578bf01f443f4768fbbce879), uint256(0x2ec1cb1912c60573dab777b20530b7ce1ecc0eebf0c2809e1e96dfa086837687));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x2f2b2a62645a4eb7a473e90629fe927f05f4f893eefa6b835074ddd91e4f7f47), uint256(0x19f21fad0b88cb26905309611db667d5d092ab27d2133138df1a90c6662953a9));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x2b94d7e0d082f2689eb36a22916a9c056b2ffddd7994c6738a4886f9a831c081), uint256(0x20efd7216cbdf78cb719574dc241bd7ecd362affbbe68b9adec87e93fb59d0d5));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x0e9c6cf9a526ac47f64dcd56822a99206394cbab88671f338ffbbf13bf22e972), uint256(0x01cc951bcdf35db4840980a25edb9c29db465252ec920a2668820f9a7beefa6e));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x172b0c2c31bf5c4c9fa248d79e8b5e5780ecf8135e44333398d6ba28b3de80bf), uint256(0x25dfb4f363b07eeca6f1d35695d96c0e0b1a7da496033d35767ceedf899440ec));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x260b51ec0cdb2dfb0486afbb266db52f2429af3c280de69e9b2b2a84af835e7f), uint256(0x28f6631f9d1fdf4272f91133cfe40644162aa424a70072e3546f65529452ecc2));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x12916f2a2c20f13a0c0521e33947d507ca913b9dc1913cff7ff3e788b5fe1e54), uint256(0x2079a6b26cd8bc653624c21d0cd14a317b618e2e28f20874b15ebbe9c8ae93b9));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x0c7fa5c845418e444b012e4bee716aa6d5f01caeac5f736aacb95144f5b592fb), uint256(0x210dbfaa480bf3ae8808d3b28a8844bdfb03bb7e788eeec8c30f63f2e7edd83f));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x25df55a8a65fd91eb86802e8804db4acbd49924f47460eda6bed164f4b536bcc), uint256(0x06656dfce41df3f20ad6f65fd85da4c57e599eb276feb606f5457791afa69e67));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x15f5f2798e1009e1f6f5a2f586896ad6c4f75cbcbc998d1c1b6e2e39daf58983), uint256(0x2232b0f26a88f9c198edb9b7a1a9963b86f78c21902e6a15ce35c10b417b4de8));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x20caa1fa56cc8dade5d4a79a2d820ab5caedb1c916d64916fc2f0baa01d0b0c5), uint256(0x07c047876b82a2e23254cf15568a67584668701ef5aea82dd52b2b4c6262ff6a));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x00fd78d8ab356afcd18d41f2f0868533f6ddac40629da59b572aafb7e233a442), uint256(0x091ea6f733fa838fd0e53a286bf96b44cb7330d5863b4db46e956cd5e4de1eb7));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x262a45998e46e2595fa1aaf49856fa5b38c42b3ac7152a24abd2072d99007523), uint256(0x0b63696fa23e57e4f0996984c9e032b26f040d5185a8c5a9de748f2c756f0acc));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x0460d8029d6204c5a78f92550bc88d2446b06e03c5beb46fb6aa8b89a698141a), uint256(0x2fa93ac741ddfc09d9754b77b0da7f1f8c31b09d8d95308d1b7727073d5c3b1c));
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
            Proof memory proof, uint[160] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](160);
        
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
