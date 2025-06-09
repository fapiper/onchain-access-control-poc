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
        vk.alpha = Pairing.G1Point(uint256(0x0572456e4ff3b6a95a165442307530dc231c2e662bdd6d22ec108cf19063412b), uint256(0x136368e8d394fa42cc63ad3ff97fe6a23747093b697d99cec4e470ff2c9aca4b));
        vk.beta = Pairing.G2Point([uint256(0x241027de11a45e7e3ea708d5b5d73004e87131eea34ada01d465a81400fd0016), uint256(0x2913f2172b9dd794f653f6a28c7ec5eff3d824d083123a1b821cb053f3c87d24)], [uint256(0x16200c84d765e26bc7353261390d888a4d1404f47a3055c33ea2c4bf12022a2f), uint256(0x03657fdbc175f25db1fa12154d9e9351f6c68cd306837d3b1d75cc2fe32f61fb)]);
        vk.gamma = Pairing.G2Point([uint256(0x290eb9ed49dae540f6d93f2784543c452f96c3baeb6912b1f8bbd50d8f6f7025), uint256(0x0641925525341de080b2e10066734fd4c1db6a3ac5f5c537d81e32d991e630c0)], [uint256(0x2ab7f6df6dd73d84494c571239cb271e8c359516d26caec93f924f6ced9c3b6b), uint256(0x07a205f0401b55b7ee7b62767fc79cf170fab5ae2380eb2b9b667eb4ea8dd2ea)]);
        vk.delta = Pairing.G2Point([uint256(0x17e3c32c48f7ffe0b0582f15383d689a3440b98f1d93a4f75a71a6ee1852077d), uint256(0x0a97826fec65d99d0805a2a930cb16e7d8373988396ec8d39ada9c85ee48ef78)], [uint256(0x18d32157ed26c4316ae36bfa005d1d10c93f783dd9ec0bf783ecebfe894b60f1), uint256(0x2f13ded786c2f0b0ac6469ec359c4c85d472bf4d46b0496a4ef706ea26cfed61)]);
        vk.gamma_abc = new Pairing.G1Point[](145);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x09d8b49b957c8b20c09d18db5e7b9e12452500c34bdef44ebd3a983a3d4391d4), uint256(0x23638186d956411f29516a206a625578f4b2154c737301ac7e073f467be10651));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x25f2d9a03fd2c4c349dab21fa4246e9d3ba95c819b9d726b929620982e2df6ae), uint256(0x24fbb0e0633d800240a7a0ec08ceac80de14cbaf4077c3723fffd344f0f94114));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x24600c106fecf690694807bcf941c719d6f4ecdbb61aa31df86498c46f4e0c6e), uint256(0x26b3dc01a982379efd8d027e18d8e25d88f034c2590e188951bc2cde768ee32e));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x253f4095f4d53ff79973c35d521d790a6ff5e66b692ce99a067db416edf7ed47), uint256(0x266dab6065676c9074f035f106dc49c7854fed119d4bedab9ab2a6ece93b1078));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0400cdb2c876c6115ca8bd5ad02c0f3032ae08b7e3e451598880f857aeec99b8), uint256(0x09681f3c71a8acf5cd687f446a0f22324313f75fe339ddced79f7e60db6e3b83));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x224efff6fcabe2063175b94be921d62279d24083212ac970b68ab86543d095ae), uint256(0x0dae2fab9579360e015550de20679436ef1f5e264cc2ceba834596f690e055a0));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x00ab3d5fac111fd01789e7b5c33982dccb6d34ea1fb2c568c06a29b9e2b4723a), uint256(0x0ac1a034cf37ee23c9e50cbd552ca781d903aad305181227dee8a91411347359));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2a29541f72cbd661462935cbfa4c133dbd807c6aec51d11e0111284d8b1f4960), uint256(0x2eacdc2b58dd2e17875222007f715795581329abcde10c993d8f9028972a8b9e));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x162542fecc31cc4e70a63e78d48f48d484cc0a00c52847b8594141135cb8e2d3), uint256(0x108bf070d14bd0945280f8d15d332b64f7a83de0b7425bcaf558f5465e380643));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2ed10487ab229f8e0d308242ccecbfbca70fe6dca93202c4c6b425fe53dbac2d), uint256(0x0130c4f6536c9b2811d7cc9cae3ba887d40b14af6964ec389be00e9dd0f6a8e4));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x17a360a3f0d45d7f29b93a93401f6623fb3099aaf824ee19666fb18317509e30), uint256(0x01a10bda386397338e39f7467b0266069eab0b5c65f3e67b557c416faccfebf2));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x00fe4e45ddf0ecd913f0f8fc725e20e178a8afcd54cefbce00770be775af11c5), uint256(0x1ca33187b360ef972b27a48b743033693a5b5079f58791d7caa91f3f466b28e7));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x01255444218da16b752f4686dbf4b9ec08dcfd38b301d112c495505347d9a13f), uint256(0x271db3a4dbcde3fd4c70ad0dadd20ca9c27c6e5b912c5c9319c026adad34854d));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2469c5b0c548db7c01b39cec4a701f8fe34dbd92024825b3cb7313234d6076be), uint256(0x2fd21c212f25b2c1f078b2128d8a09aa351c9b40f6efe9cab24063d533504f13));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x22fc4feb7cf38186ca86872aa9be594557b34fda6673e031c8e6e2c0594409bd), uint256(0x27aec1dcde47cd3f04364955e9caf0da8209396add63ee3cc14aa3b89a2e0082));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x20ccca0cd1eb568ef2c8a889aef40ba6096bc7aad032941651e74674d53069c2), uint256(0x13d70d231a27fe448932f590a366acb092d2b23ea3118a397dd54f1b47e067bd));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x04d28527ab624cff8fb8535c646a9668bb787a593d91f988907f7d9ce3fbafe3), uint256(0x05dcf802f851ceae12a458f9c9576bdf550792b82f215296736bdd486fd38451));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2e8409b61839c19854f58cac8fb5475a6b1f01e5d5f7093394d5b54fec7b61fa), uint256(0x20169b76c921bc0403a93bbff5602aacc38c32411c8fcd6274a53762cadf747e));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1f3832e3f2f139fccd3c93cf3f4c05d8cd4304e8e4015a14924840656b68d6c4), uint256(0x2ae8acba317e410634145eeebe17da4a3ad6b8ea082271c3778abed6d47d96f7));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x0ba62f1d3e683f6c7eadb1eeed363bb173331e7265a0d7273e6ffa4b05da5c92), uint256(0x19afb58750a10a1c444b6f60a4807c54f3ac560d689f699ae314f7e05eeeeb4f));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x299008ed8ece7090c6929b08bf296d3c97e4b9b90afb3d3e216b279a3fe28027), uint256(0x1d8c6ae092207d070dcd65f7191c4a30d544a2b9c7cab2e4af436b3044b37827));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x029bd55f10b9669ec53c233da72284757c8cb3aae6ba08777c459fa555506b16), uint256(0x0450099df140b5ffdc61539e80198a8177e2d25d40a8dceab6b61f625532db6a));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2072d26fc496df276646375961c31cd65e7ed20cec5c3198e14ecfe2fd4ac971), uint256(0x2b9665c882d2723934be72bdc17cb0602c9a1f527f35ae60a57cacc9af3b9055));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1b320fa5b8f4e0e5aa58985f329ebf0fff61411e7bd2e510cf0a412415fdcb3e), uint256(0x2df2c5aa57c4fb3efc24877fd5c280f8b06846989c5abe30de57f963d6ba4559));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x13a072c2754c23f8c48e0f5569e8e456d725451b11da01f7c0c61977a67cf704), uint256(0x0e0363a3655ef606b668dffbe0f0b7ad9e7ea9dbd0a1035bd69b4eedccf0569c));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x147ebe96b696a3925a6cb954bfb58ae0b8d0d356ea552f11447cc0070fe5d6d2), uint256(0x1de6c74119c5b143e43742ac92de1a40bfdc9aae79bff1d825eede087820f6b0));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x0a1e75978c78e7c248711b382b2637b4d442b3f96f7731f838d627bdeb402369), uint256(0x092789c364fbed5861e46f33e607e4e6b66044c3988982f632f862f597fa15fd));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x23be7bfbd065d5e2b8d81392104a5bc521b7bd47e838d931a8ba88de3db1e481), uint256(0x03f9cb08b67d2319dd3ad5f4e1f54731ff53100139a1af6362dda94001be6e67));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x04eee69c90f9fe301ce1b55ee611ab622dc5b1e7e05c550cc5698ffe45c9040e), uint256(0x03749fe207873eb3d3db1a45561078b7fd3493039bb769c4ae41271bb6057832));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x041fe60aca7f66a0faf88d71ee26f7066df76f3579068f9731e303ff12420c4f), uint256(0x0d8a3cae44eb29b98f62ee8b1ee4b7b2b72bbf66fb3f62dedb583bbd85a70400));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x2dd19cf3a6bce7fea02494ea36541fc2033dc676dfb811891c9efdad12ff86d0), uint256(0x184937b84ff465770823751f581cf9d306fe12a11d4cc02eeee2c0cb0894a5b6));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x12cc07993ee10e13c38f9537cfc39183f4afc97060255154863c5e3d02cfebb1), uint256(0x051c627a89bf43040c58026ddb478c60b454dcf24b642e5469950fc86d3b4c5b));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x22b853cc574eade224d86093faad31a4b0e575e6a72713caa26e52661eb8af6d), uint256(0x0faffa7050e101bcc2e08a1e025b5bb9c64859db44801be1b491e291e8f1e8ac));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x0c05771a8ad7d55b3b18b83fe7de10c9d86aa745a026b2fc1be3359aa09d5a08), uint256(0x2c5a3abef26b3840b789dccf8b4d98613906b81edb7ca8290a5f25e5914990b3));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0a5f15c720ce7e4beadb3ca0fd94a8415866f95da59f639d5a4e05880b67fa1b), uint256(0x011f25c250807b1691adf6d5a29616e10f2a956e5ea2134cce4d237e16c7d9e4));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x304e807c79ca2966d77ec1cd03b6637a9a34e77d89951f1acb52f6f0f30d7c50), uint256(0x125c1d88a8664d1759229b4e402171f1629daa6ade189c009d29e2bdb06bcb5d));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x2db0f2ab822b3ebab9a3e3fd18c4d831b58f315cc7b6c1bfb387d87242ade801), uint256(0x0d5c3180d48fb844f2416063af1b3312d39d4ede5fe37610fc72c24cdf2ccbba));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x1c4399c10278dab90e1f08844591bf34449f7ee962d1e8cae4a8a5b473580351), uint256(0x05a9be43a2f3f660acd965cbade25a7f44d00b91b3a8a4dc707c7c4db89024b4));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x0c25f5192c39f8732b6c39b81b03657eadfa3ae0bd495fe45f4c17bfc94b71c1), uint256(0x2170cb92aaae05c0ce445100bb39efbd90622fac9cfd3c71d3e39164a4f39998));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x2867d4b198476be980c30b989a4fdfaee847849a00856351825be7dc6e1e5189), uint256(0x0b20a2151a206fa2cc1f1642b7e9b20b1130d5a1c723a9309cbd66e36640ab97));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x1c7746a68317424c90b3b644175c42bcf0ea7d4279cb3bfa48d913c8bdd07c95), uint256(0x041c004af627e261c99fad80374fd20d042d4678862863108bfb6ca8474fd57a));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x238fc17b877cdde91beedda8914693565d6c07254931f492e481e645c0a7567f), uint256(0x284a3953bbdde09a6d58ea69a4719dfca823f8837e4f84e2da61139e82f246c1));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x10d765b60282669c57e7898242a80173ad222b4d979ed09488b7ceaafd90f83b), uint256(0x1605b6925dd8a008e3321be385fe44e5b31ffd3b90da781a6b3b71761497b7e1));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x2633495472d7f720f642f971b8c89e3e0aa89aab188bfd6618cd2559aaacdaaf), uint256(0x1cc9f6e9cfd4a88e6f4796fc948494fb988359d0646e7ee6fa09e25c7a828423));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x09b8d1e5f466f604b714e8e4b9f8c158a4711d065df306ad4333b13a053ed0c4), uint256(0x29ed58ca5aaff9df3b434d79b5cb02a01c4a3fbf0e894197fbde8f899d02bf43));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x1a83fe70a7331a2bb1f0c3f1c643c129afd3811d7f0dfe3ca633ca689fcd4b91), uint256(0x216b3203e8fe38f9811daa3f018dbced61a811a641c9ccef854a9f3aafe44c38));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x208b5749f013f13b57ac8f7a2d632e402142c99e74a486b5a30f06fbcac1f6e4), uint256(0x1fc9e9346b0252c3c26d7899af430923dbcf06acb9357a72a1a966d2e48ee53b));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x1e63046736cc8750fb8d047242274029021327347857cda7f2b9599b9f598746), uint256(0x2e3d87b222d18fb1db94b528818e8317a8f109a3d436e58e227575064564998b));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x07a784a7699de7296ba48e9f2ef33f8ed8875cb7fb35591300bf64ecfca95fd4), uint256(0x0f70cf45d6b5ddc1737623b6386685583ea7f05f41951bad3f74d48fb9aad91c));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x03c4ae338993c0fdeba147947d54a96e286f553a5eae9a61756f70a6b502cc13), uint256(0x20a5ea14c5fa1b22aeb0a9b84cd58006c49bfef144061e70fc2f8b56aede05a3));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x2abf38dbed62cc719f8b61c2218161ff480a29f3baa3c28ecba9d5d3d32f8c87), uint256(0x0b38a954cc6c45653364fa65658f698be66e103878aee624b74ef8f1667ef970));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x2a24460785628326a593bf5ad4feecd0b9041d8461ea36c42ea795db2e49fbdb), uint256(0x18f4c4d5fdee364f9b780deea45cee9e042605720cbb998f93594521e23366ad));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x240ae90ef13b6f7832cd2269123d981c16d101dadec92cb50fa63c298af32f2e), uint256(0x2f7d193d3196ecb6f6e58bdd43989a98513b9fb5390fb9678afafd2559e17365));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x02f2c069c498d4d44c9781c4d62245939b27ecf76f8a64db3ad16538e9782c00), uint256(0x18f3f39c269e142dc230984c24029ccbeae2a700f491fc46a82c3318ee643323));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x27d2f3b968d251889b0373915afe19cf9db457e3d77872887646f1c69830642a), uint256(0x114d0deb27ecc1836a8b75e02126b6f49602d3c440d8fe1708c7fe309e3b9228));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x166902d39d010a4ee34e6b182d17c39b3df90f09de254fdcdf0dd45949025a3f), uint256(0x0481a0e9d56d357f6622751d78b41269e1d1190dc626030ceaba51cfc7ecb339));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x0400b5a5154645e440174c904ea56492af3f0a9aeb99eb99ff5267ec25a2f398), uint256(0x2637adc7b589e6438f1aa51ee62b85e131e386ebbc2663e3ec21589ef0a18d9d));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x152ac493f1af23698ce8eccc0c7dea133458d5d88bd17b3d29ee6b1f72d51ab7), uint256(0x1cbdb3c48316e6a47c05a789601ba973e1bf4e91c57e06aeabd46ee58fc499d5));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x13de5b67fcd87080c92cf312c755e6d0594a727947954988ad6fa3e481ea4600), uint256(0x244ce3afa06e4f3a937526e6b7db64b0448c54bf5f68af8a01766801eb729651));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x06c5b510c0f1bb44a947b3d64cffc656db7a47856e4841bdd620cc8f278ef3bf), uint256(0x07f5c49d9c2e4b88bc94d0e6029ba9868e7eb10d522cbfe0397056bf679326af));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x05744e15632424fdde6eef05c99283c5dff694058b0e97697b5642c56435e15f), uint256(0x04801690d52ed4e069bff57d9074c5ec73174efa5cd6fe201ee2f3b93182f059));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x04a74510b24b7c1058a09f2394b845f80c70f6c5e3b40b1000caa250eccd70a8), uint256(0x0291a6f5379f682d5bb5e4fb2a7d5bcc025af14397d97061a0855b9259f5a57d));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x21bac764004ed2177ba91fbacfa73e416afb379f644d086e76be7ac093bc22a5), uint256(0x1399854547b2c7c5cd6e2ee85f13c3d25490af308da2c75245da6ba12c3fd0a2));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x000cd0b369d9a93f64899f3bdaf1d3df46eefb0c9c2f43e2fbe3726e057b3be5), uint256(0x2f3d489123eebc1f6a78ec590d85e47b1b7cc331613898d70ae282d430a5452a));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x1198bab4322ae6c79eb1406bed736bfa02c8e3ff506dc0a346beef23c05e0da9), uint256(0x2dc1ce0c235ce7cc66279e09c8d828ce5d5122ac50ff4eba61c991f8aef040fa));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x2e6eb216bcd532b7ccb93638a12de94afc4dcddc5dd74c42d2e7168cd656fa4e), uint256(0x0e90893556c8e742f13a865baa6a89b0bdfe4a122397ae6a46e3c48a49750fb2));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x089b0c5874c1d215746408a79b4f62b8e81dfed752555dcf96ef080140537e7a), uint256(0x2a3132ba1503381bb47f0abd9464bee9e15207d9d5442d251229e79ed902efa7));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x2e332aabd25b67efe6d2acc40bc7273eee23643a7d940d12fd7a0237b9ca4af7), uint256(0x1f9ed29a96b30d29ca8ed043d68ec3aefb7bf5401b399db34534f40fa4e9308e));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x26d22e8ac525d779ee118ffed5aafe5991012243424c258427a3c558548780a3), uint256(0x26766b67fa5e9a58f3c17ca8e58ae2f53f38795c8812a0d075775dd33fa07447));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x246f4be872ed34b686fa1f591ef972a0f02dfc3ccca100c499041de607244fbd), uint256(0x0c24a9acb31c5ad942c0c2f1ca808b54726cbc0112a32d22a7023fb6e4a1faa6));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x18846e408b7e972506bb7d231ae522198d9803a7989b764f4529daf45c2933f5), uint256(0x1047cca585eb57cfdaa24483d315ecca3b1f2370d22cb5e279a92c7b4a66a890));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x236046e3b0b59941ca1c80684506f39af6b70fc470723f2ea7e904af7b234082), uint256(0x1f66de50ec6f09a709d61497d53eae2d0d77cfc1fdff4008a785a9d80d327195));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x06a0f0279135ed0d53d0e915f50e2b957aeeb72bec96d4a70e1eed8d43e5e7b0), uint256(0x019180c82aff59df54a68b1ce0166a495410ee3a498fdde7b8b24ee4de6bb88b));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x21aa23e681d9f75ebf6c08a602e73fe73b2a1310b7deaa81e8fcd2d53bfbaecb), uint256(0x0f37709bf00df69ca5543f0c47456cc8fd7454fd7221c6d34b02ab45376db94d));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x1d10f9cd5f0382df1fc7b832ccae358379fa7c8da102fe83ba04fa1d98b52d56), uint256(0x275d4baf8f4bc3f128c40afa5fe3e882ac59df685cc803ad92bf98b60c739816));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x0cac10e913401b8c44fd82778eac30d213fb2fa315af1623b47136b342609255), uint256(0x24268018822b7c407fd4cef219386e43711312c1d4d18bcefdd890ca2544d8e6));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x1529e5661c3702ba9e465c29a4bf4644cf26f853c263113b4d91eac9bb688081), uint256(0x28eeb2777abf082f9d3e0e7cc59f805e4d1aa50a0854cf957a07af44022ce9e1));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x1e9b9fe55b6c5ac5d63cca070a68e6a37475bd2a49e4d793edcff57e6280b23f), uint256(0x1257e2dde4c292689941e47d9f647cc7d10a2483804b237f885bc072f65326ff));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x10743a2d30226191346f10d748136e441449fbfe3dd64f5d2ebf61292b216f63), uint256(0x016d35f360cac308e07cd7e0b9b8c27d913c59f43b195efd4112051db01dea10));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x2e2d77deb1eab4e78b1ba28015d818e3b1b7b1b49d5891f31ac2dc16991628a4), uint256(0x1a310741c46fca4095ce57e6dbd81331640a79b9ef2abcee165cfecd12d6f83c));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x0c7b6bebf5c5f7aaf7f3b77953da5ec930e3e0996b5ce76c975f94348633a2db), uint256(0x2d20332feb4f5c5152434bb3842502dcdc6aa7e9b1ca7e2b76596ed16a467cd0));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x2ec4e79b8f73253c02ffe5292d9cf037f8e1dc95ea9e1086aaaeb44f91ebdc46), uint256(0x0b6ecfee0ec86f4174ee6a6de90b64214ef09c4c73cea8832726651a4e3375cb));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x26ac1e89ea1a48ba0bf30abef7b99016c509e25fc0271da07aab65934d26d510), uint256(0x20de6f0859473376e4c7402d7cb4499fb5931f98640809a8d87e4ca3cbe5af9d));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x1ba589eff8642423b127291445c70e88d221eb18c9015fc1dac61fe1eb1718a4), uint256(0x1de3a4343d19ef2b39f13cbfe67462de16f6b386a78cb38ce5bc5d6be87779e0));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x27eeb665edefff6e2bae00fa2935b22fe27b5167c6c7675ee8a225580773e8bf), uint256(0x2d459803c099404ce50315c68fc1000e64585270c4373e837f668ca67e798c24));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x040c720a47ef583d85b7cd00a3fcaa0021a990295a2a1e2b7e6c563f84481c23), uint256(0x06bba11e2445094ccb30891c67293f48a4d0c874ee7ef452d48ab150ffa6c6aa));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x24521b28c66f46892b99d3a3e5f6b885b7eea45029ba0fab8708555d24383772), uint256(0x0c8eca31ececfd0422c4c76a95340b3321bdad7b7c126505500500030747ae1e));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x04853014babb83fe9c14fa18b45d3129f1895f2e6837126b3846ef9163299238), uint256(0x286f98e52dff85def22ee3272a2b9609adf4ae134ec0e9f29fcaf911960e36e3));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x1223c9ff847e52b8332db591aaaf2f0f373a65e27b4b825c323f80054df3d18d), uint256(0x09706951a896f1aa50a8843f41bb9078573bc16fdc22283b9e68ac3c319fab35));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x2d666c17fd5d26dffb97573f2397e89514c9414424673493d0f31f2fc2249008), uint256(0x2f603e8c65ec522380024e9e5a18339885aacb529120cb4c0bfac6f666ef4574));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x193a2cdf45f3978e137ce4d1ddeb3f12b2e2970a77da75a8f89162a79ea739cc), uint256(0x19c06ef23b73ba74848c00048476d954ac95bdbe82633b3893f19bdb02c8b194));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x09a103f1684dce174e76cc0cb54f3c475b0a077af776eb7060b55c8afb3fffb2), uint256(0x0d4a4b493ee2190e5839d62e4f7d44f7653685444921ece4f523c5786e4ebf38));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x1760d7ab75504b4cd19110e1d0794bb2c4884b92717bee97708ba8e6b48a0d6e), uint256(0x11cffe7e5766b9684d270c484cc4f3f765bd6f12bd6e25122756900d9fa17cc3));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x05d5f6404f10be60c302237a3e1f4351db240e5c13e09c855603b630cabfdbaf), uint256(0x0f3874e884660ab5c4f615dda18ce2108bdf7d138b6f91adfcb75cfc4b687e23));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x14bdc18eff446db6a50189ca5675f7ff2a892019e3c559c6550bc195bfa71c1b), uint256(0x070516e1c48d86cd0c2580eb9cebc9f7c2061ab33526edd60eeacc617dac873a));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x0ac54eab4c0c7e4e40766f8360be2b4ace9bb4bfdf71a540a24203267d0ac02a), uint256(0x2d9f7c7b1869fccaa210912fb004a576ac9cd633871e745454daf7cf05f94ab7));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x05892b5462fef56cb7147bdc34ff6624d869147b06a3d1e78f9305979e333d9f), uint256(0x010892795e6d1d955484da189056c21f560c0df19a0ae5346fa45aaeb11bdde7));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x195312dc172a4dc2a4faa9e0bc8818c385e02e8baa1ebb15dc7b29c901181676), uint256(0x0c89d5d2dc6e238a0be0c72030e7c3a2c14ed355419052bd578c6f04d6a616f6));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x2e3c54eb666d2a698e7e8e67d6434fcea8601c06d21736414111685a04b46381), uint256(0x2fa83ed56e170544d3e722e083cb5881e72c9a5e67cb4080a6b1aea65a499820));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x2333f8ec11e077ed1d87c17136258c8c97eddd044b1c97e63346480449230f75), uint256(0x238b04253806c27116ca2ab02e01d6456a3f1cac16de0d685f5b9b1623f9e3cc));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x1cc34c1b3834c8c993c251bbaf91220bbe11f18031142ee180ba8a270a455856), uint256(0x1b060c4692de24cbe686c9f8b0b8b5983c7c5ad4157f9829a4224ff503feaf5d));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x1bf3da38622a033c05bdb58e82abdd408603860162406aefe3ffbd258613b5a5), uint256(0x039a7ff105197773972d207e748a2941e2a93301ac366fd39068e9d2f479ace1));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x0c8eb4b334da273e500d0c4624de0ab1d8d660e1d1a4fe11caa7a2bfaa838858), uint256(0x23cee634ea01426c40a4116c7abeb92c99b28647b21d5873709e51dfe70b48e7));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x2faade569cc17104692f576e698834921a72fc21b8b2ff2e117a9c12796622cc), uint256(0x063433f49d2c45da7cda06c37e823845afef223efc1362089397211aa95f765a));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x28d53a2d1d5e9032f789277084e8f9b41f8c4de8c588b7ea2d14619c550427a5), uint256(0x0bd7b26e0b5e2afb9b333d2fa2761a3ec54341602254e403c83a92f9d74dc967));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x1cc5d234d4f8d80cc09f92bf06ec3f66975752a0b7308fc316279c3c859dcaf0), uint256(0x00250eec4f06587f2ad98abf7a7a8168153131d3c8eb2d2d1b832aa99a5186e8));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x08e7e02d398e39f1465771216c531f08faafa78b745635ef7c6ccdcd1dbdc99e), uint256(0x273e3bb78913ab4b1cece087ac87a16fa1b416cd893ee08643f78a8d69319713));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x158f2a836d68078959b530a8c30b510e67fea2c4116a8b4e53b315a4b8ad6033), uint256(0x282777c1b1eef3662d1c3e850922ce12ee607d5b1572a068097d47af613b6de1));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x1648251b5201404142d0447e8d4cffdc011b769d1b53b30786c52f04d8420671), uint256(0x0f9d0f828478260720e73f079f95b0112193e393590afb46da6128d1d2a29f44));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x00a76bc4217d08c601c5694184016aeed6c022f72ecd44ae0ba630250fa45077), uint256(0x278a38593da2a7054ac7b049620cae07a4f22020107065f01cd13242bd9f3ce4));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x0eb537d127130f5fa3fb30c09b62cd17037762d4d7fdce18c44ef2f51b51ed72), uint256(0x1b0852119e246fc9e7ba38e1b22df1036eea705f9d8956be3fb40d4324b16b5f));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x0d894cab0f178b20fc38da9df72a26797059920ebf0118321db48554e4b0d342), uint256(0x1eb05b65dc0dbf7efc6f0d659ea7bd350e55e9bd2ae88e393625a36c23343991));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x25bb6ff4ce65af7030869ffb2aefcbb3a31f834c88f61e890aa0f52beadbf6a1), uint256(0x24d3e8d39e49b9ac52938c92b506ca234f522399e5adf25969edbd4eb803e985));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x0d1d020e6021ff0aa364318d4303d17de0e4d04efd1777dda1e406e66bea5bb1), uint256(0x258efdccee4fcb0de319cdb29b907ff2789e90abc054740138bd5ea094061bbd));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x146fb54527094342047e792fb89b513539c2209caac0b8c987c07381b70b212b), uint256(0x2e3d7d540b350c4ab067ccbff418838e2963b7a8f6f5c01de1b6db1b82259970));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x22f1507556f7957fd89dd0af12c7ff805a49f24e6e921cb6db8832b7c4faea5f), uint256(0x0df1b853376867d115b1e9384620ce1cb662c81170c07a53036cf8f673b60b6d));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x2d2619cf260b2d3d49158e5393e46367f73606ee4cf8866e61fd4b307268474a), uint256(0x2747e63676634cfdfab170a28fde6aed66e869361c0ac2685196829ecfbc31a2));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x2bb76b9a190c49e868b12491f69a252dddd2b115a1a5f1621eebbca7c5a493dc), uint256(0x0ba702b38a11c55919cf36409c00e164e0bf9ecb2cdbbcc67152f96bd500682e));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x2f4f159d1533f42cacfa7a29e441604ab30c2c7202225b25be6493933279ea15), uint256(0x1bab69a9e69925237443266074ddcfb1be1e825a6865ae034c34487f5655851a));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x228c83a36ea77721ace1b91aa4104cdfbaf0254d29be24d3004a19072c445126), uint256(0x0f5d219ab98334c9cd49a925cecfff9e68bf79b9b2c481e07422cb2f354171bc));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x07b20d73e37a49f22765bd7068e90e1faa2eebb5f47b851f9655aa83e94eec7d), uint256(0x003063f6dea2a28e0f91818c1aa681ca420e5ddba01d75eeade9b07f2506b73d));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x2f161cb5f72636167c84fd8cf6ea1d0746a8d6467fdcae049f5ca38784910699), uint256(0x206f4b4b6ad420f32d36805c9a4448e8b1e0bf5bcebbfd42ccd774f9cad43f98));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x09c69a0dd87ada4e02907c63f6dca476ee06fbc409560089a7bbd3162044c9a7), uint256(0x2c4e4555d895045d1d3d8542929c61e54465f71b3899738fe52e40feb2d7edae));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x24e74f25bd62c4b93375f6ce35823033c624d552ad71d2aa00270cf5c160cc99), uint256(0x01ecbc939815bbc78bc28897d49bb4ed04840f633a9f69b902ca514aef20958b));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x122099e06df2473a4271fae16ee3baa9de87162a8ff152282a03483a5d27f366), uint256(0x01bd1a48afce296b9aafafd430d670480b741407e8b8a9bd3f8ef14d75229586));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x08818d36769b69d07b6d5ef6dfa4ece1a87b13ccb95ecf3a1162b69725255d5d), uint256(0x2f85ce318b67ddab79aca720aef9adb5397dc84f921a69f1472cea6e01a26fe2));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x029085a900df1290d11383707a046e98bdc38f94952da22d03aca5c759fa6f26), uint256(0x1a47d5a915f5e9df6d5f69c411e4a1f632f478d4e9794da589a4be2422499811));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x1190d2a07fe00f86a445f9339f96582c3e0ad35f837dad793c745ae505e06c41), uint256(0x2e6d5862adfd1a59e7a8d1ce3f5bfbf1a4d4748b7306ced0261e8ecf6dae98e7));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x023342264859ccfc02a42671e2cae5ca149a2dca01d76194c69765438a03fba0), uint256(0x1b303795e5b34958ead04eca4853e402c4e0bc6dca943293c2359f355fb9391c));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x04ba52f7b4d04683271ab0c964a02824f7e6e752a329aa45dd0c852480216508), uint256(0x21747b38769290dfb72fa394f50f5f7870a6e0c1317f11e5a730ddc283867017));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x092168d5844c754646de15c933ef709d383a453596ad495f2a3187987d034e44), uint256(0x2340c5733684a8b3460bebcebab25bf40162eee205eab4bf3e2822bb865e5734));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x2c58ee81020b819b05e56d36de6dca3c172d4e0560613cbb2b77ce1ed6a44e43), uint256(0x178aeb8a0ec3965d9c806e9fdc327a31f3975bb5fad7b8f6b0e1b1ab6d24948c));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x186838c547f775b2fea0607b2a265b0a30f7cbbf60e4ccafc6c12e48b67c900c), uint256(0x0f41cea3e402ede9c40ba026d4aead4058b693708fa7c1b65ce7cc34ccadbefd));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x0ee3b1bb31a708e4a134c962237c9adb82e1aedeaa33e283c0920e14f0fc7de9), uint256(0x024a92d837edb1abaac0c15dc1f0f69e85bef2a3f5e0c62fcbb50d8350a5af7e));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x08e10e23a2a0f67133509877b9bb592b27b8b60de460af93156e0dcaf8648ef8), uint256(0x1a5ef5a7a3ddc9b71946341d0ac904849f1ffe70fd1fe88838a7e0801c849666));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x173ae472bbf2010dc14783d6d19a8dd6dbfcf6d5dba5530257f31e6dd0b33401), uint256(0x04d8307d48da6c3e60d212895fb35b3f2a88ddf831ddb9b3b5352fc5edf81f3e));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x12df79348643456525d7f9c028b676202f408eda8bff23cee8e2e55d7a5a6a8c), uint256(0x21fc7a31ba327b3d64d72f8ea3af44434fbbd45d9aa50704463951d4bf7ed9ce));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x1b7e6a92c9493d6ff3962ee33da7e09d70b3b3fe2b019a9882dcba9ddd2efbd8), uint256(0x1f9ddc946c04c057cb47821b86832ff3807ce2ebc9e3485bdc9301f319a2ac25));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x1e1a1f885baf327ed550131c9dd9bfc586345db68a61f7896bcd9707c65c6650), uint256(0x05abf4b754dbdf19e42a722d7017e021fd7cac71be5a798673afa32f7bc5b982));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x149d2b6b6fbcf96a9cf0adbde5db67505d5b61264d676de52e8108c2b339fd95), uint256(0x1f8cd2cfbfdba509c65fef9d2cb019c4926c2fac19e4d0d0de365020ccc0f618));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x1855a38b5aa7aa47bf920c27e8fecf139363f70b8c8141854b69005fa534ca64), uint256(0x286c549539b6b3c299ffac79f7fdc08c5cb14438213bd4719b8891add0f19a57));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x189176b9134e1f46d1e6df9b066f681ef8ffca3b4041a030265c2d751dfff8fa), uint256(0x258e16ba1eeba31200eff109dcbd52144eda465fb520243adaf5ed356a396f01));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x234f3aa88ae1ca6a2ae67d9426172193b79c0952bad283e92e2c7a28d7579794), uint256(0x1a7bc7d48e5eff0c92f1b3d2332a49d037519969a99601c407906ebed18ed4a3));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x059c34fe377fbc1e6a22e6f08b46c5ceef326f7b26f1661c2b10bb36dc29aa69), uint256(0x16750526c75ed83fc3dc689f09c64e6b8548a7f11c5cfbb5ff8c48227e01e6cb));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x14fb09b4478e93f7ad401aa9407bb9953a890c7bb3ca9cbac57e6d15a2f04e74), uint256(0x159fe3b577e4dc76f6469808164abe96fa0406200f490a7de33b77f664be1605));
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
            Proof memory proof, uint[144] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](144);
        
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
