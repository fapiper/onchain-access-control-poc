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
        vk.alpha = Pairing.G1Point(uint256(0x211f6307476cb9fd20f433aed74927c7329eb9525a5245e28f011ffaa9ec9f40), uint256(0x043c4e0142b3d194e543b61227022a6f2a5fac7ebabb0c8c2976486dc6d9a892));
        vk.beta = Pairing.G2Point([uint256(0x0a4619a10e6c2bca9db1ecaf740e23a86e06cc05a25e4aea474e1177540b750f), uint256(0x07e933571b5b8104aaced50f6caa4399aa5144717ca83e79ea3ec6eee05067bf)], [uint256(0x2b5014c84b52035cf9ad4c917b74b6173e53918ce33bf748a921c2e83023f765), uint256(0x2e489c5cc53906d5e9735697e42b55ad274e9c872cffac14938865860531a3c8)]);
        vk.gamma = Pairing.G2Point([uint256(0x233506e42823245c78359da7f226b786daa8fe4bcb9408a90efb2206f06c9b9c), uint256(0x0715d57b0d580d5e363a3e6a313e3a317fb3671f0e67398c5ba81ce09d27bf97)], [uint256(0x02049aaa1c03dec9b46b09cbe9ea8212814d7e8675d4afafa77a1e8ec60b7517), uint256(0x0e3b38d33dc2ed8b091ea722d8fe9ea1b56da25d3953ff75137e26f213be2b2c)]);
        vk.delta = Pairing.G2Point([uint256(0x04890e75a8a965576774a00945974be366895d1ef6120d9cd7213004013c2f0f), uint256(0x15ef06460bf95351dce7faad75376470da4c3a4424787081e7014a353299ed21)], [uint256(0x0ee010668a968d59ec13577513510ce45c9095d703068be55bac5a7618af9a17), uint256(0x0bdc71ee2a9829ea6fd36ad3a30d307bb826c3044af276ca50f91190a6efa53e)]);
        vk.gamma_abc = new Pairing.G1Point[](221);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x15821ae4cd811ade1c3a3f02402c0308fbbbbf89cb9de8146dbaaecd6d3bbc37), uint256(0x20a38e9a637562a4efef6700b4f75852d739815895f5d79ddf29baaf77be0ea3));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x05cb9757ab4220eca886bc699e9bdf878c9d39e47d8eaf5b4a2921263c48346c), uint256(0x27de045feb709ac5b18f1481ad7f24a66bcf938d9d49667ab912beb593b8a08e));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x006c0f542eaf2468dc1ce78ba35c6fadff49a299c21721041ce1b77c582a83d7), uint256(0x2b6bfed661e27e1417a8a5fd8107bdc9e73053828ab4bba482ad4966a588c854));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0e5d45d15d005cb90646f602bdde980bc505c9d07cb6dc32eb8bcfddd0f7de44), uint256(0x0c10086ec176c0a99ac783b00d9b541619d3d7f64b38af6b9896141bcbe7a19e));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x24e394b69740f6c8ec3d001db098683e1ac1764ba349ba5deeb12e96759f0843), uint256(0x21ecc6e088e46c1cc2b17168c26f4d74f86a054d9f06b6f5a8ae4a84292f590a));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x271ba0f86d04f06638c5e5d7d6fb1bd3c548910591f3c3749614ad5bdcbf36e8), uint256(0x19237e55ac69e2e23be617050f649a0d58d2f6fbce60abca7e64144f8f1b2c85));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1fe218bb9e4c95b59bbc09fa0cf2eb26354cf36c8ec4ea9370d54f0661681bbd), uint256(0x0473931bc55e400617cac72cf659a3db040877fa53f09ce1e16f4640b0dab0b4));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2a3fa3eaed8d233d198f25bc1edf658bdedf0e73f586d9f635589d6c98ece959), uint256(0x05454fb68480ba118d2ce167e78b9bbdc2b14ea7b55d6f6df8009e1a4568d059));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x11641ff09f733e2765e2044ea20987864c5d0a623a1af458d92c18c347736455), uint256(0x1fa86b55fc49cf9434b7120873b464be97733696e03133a3440cd0d7a20e2786));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1496b8277c1bdf616c12b7a3ac5209cffc8dc9e0045eacbae4ff28f195efe834), uint256(0x0e4a6899c55b861894eb7b2f997170599b2e183711fa50b22d6070cf990d4851));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x149195d8b96d6a80864a7ef397756cf219eb08a315da71ebce54f06c68453ce6), uint256(0x24fb4289fcff9d28d7b60947c6df7d4c59b6f5af5636337c479736b8fb7653c1));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x00fc91d8216469f901575a73889aa0e17828609a243a5233313e6f710c159f05), uint256(0x1747cbcfd93d8824d301ea08821b48db9b18ec9e70b04b431d57e0c21dc439e8));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0f7b518376705357a691a23e6c279373620dc213a1ee34dbf98e6f315aa9b3ba), uint256(0x0f6f98c49af8e5c13b370b027d74abd571b1dca67fc417a70c9c73502ee955eb));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2f772a656ec6f92cdc1b6b6f28069034f2504e3d690c6694ad8dd3c2e44ad57c), uint256(0x06772581e89213949ad91b334e6bb51cddad4b164c6299114b7866d9d0dd685a));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0bf0e97081df7885c9f45244cb542535de79db12811a7daf5da7397ddb53e3d6), uint256(0x0c88ece9a5951100b4c94e823f615cad06ff4b22fa1f2431668a341ab2fc4db3));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x2da176cc6072b73222084480fd6fd9ce3fd90beac4d5caafc529e5a799cf813c), uint256(0x0c3ee914861892bab9b9a5847991a2c337ae84429c15e9e0b6231234a5c8b736));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x017391d94afc778a135ccb97856f8d7a76437d296eb81ec78b14f0c532663fc7), uint256(0x267e47f8b0f8fed401df2d46c3317b96169598b910bcb6d3b95f7741121e1cc7));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x15078c3cd9b0bc7785f01b1ab3a168ec62002c20d8529b16f454a989e81c2248), uint256(0x12702f9149f6a16176c5aa615bc0d7ce01b2f87688fe490db8a0abca727b1029));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x21b081037aa39c243de00ee646617c6f9489b10adf5c5084a205b3ba7d2b6873), uint256(0x2cc895c43ea2bf697a8015139d3db8d3be95fc8fa50ca781b780fd7cd00393df));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1b51af36b608e4724c00eade84e760a27deb912265bb9945972b98a4be1f9f7d), uint256(0x280ba011fa6709d0727e23beee0d6bace9a6345778a4cc42c47b1516bc52b71a));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x287370f9c201a8100788c16c0b27e7f7c0f32667d8e20cd8b2b1498d42be9486), uint256(0x1ddbb55bf000720be8e69921ba847542cff206ad479f592c8c48abbf25681413));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x2c9028847eabd626c763a6dc8fd2fdbfa6fe12198b5e2324db0f56b6b9331636), uint256(0x01e8e54a9c7d104212e66b589b3ea323348d9a0a3fbca83fc6e7359e8ea7b53e));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x0d3478e46743078b158cf4e967c7476041b8f428eb64bada1c5c05d7c2ffc6ad), uint256(0x1ad8dcbe504708a0c5bc9cfbb528b4ce7830894544bf3db6ba5ca7dfe82b26a3));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x219c8e541e706501dad6b0dd406083ce84c30d733c8be5c69ca0825864a79b24), uint256(0x08dbc4f00eafe62fc71fe77d442d1242aada494368fc303be309610628779267));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x26c565db5edeacd5f4b68a76733b51943894ff710ee7b3221575bb04c0d664f9), uint256(0x2edf325502fd3284115f26ce150e2d0722f00a8c4ef13c2bf5aee742f4d92f4d));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x0bd27e5108ccae573b76468f3b48fc940eb56b54c448edd1ca95e86270f6b085), uint256(0x12dc5aac46202ab08d91bd75d1349028d57ed6156619c99ce6b37034ed2b3769));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x14bbfded4a9740c26e25776bdf29d45cf96d08e88f306c1a87b701fcbc497083), uint256(0x0a606009ed41bd13367a3e2996520e2bd3330870d601ed1a04570d31893843e1));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x073add72f9b58939ead9e79a551aef8b271a004b75cdee57ed460f2bcba3d821), uint256(0x0335a86914dbd4f20a38cb929a6d23a503b223f05ca076f1db1d71c1180050a3));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x18316a4181bc81d6c4c1511068c20300a0f8dbd17226a8bf1f7d5af02babaea2), uint256(0x133bd2cc671ef60aa06ac2664d930f72fa2e0de4a9b922fd1fa00fc94987a852));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x0ffd7af5edb54b48eed330e61ec5b2d6e0692a13154cfbd7b1043026fab9f4f2), uint256(0x118a33da97395a17ef1676fa204a266e4a663e9bc1d4e84f86ba36d3d497cad0));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x25766852033556b6e76bb031c0a19f92f6e1a304259d08aec5a4938bb0ecfd0a), uint256(0x272e4cfdd2745fb453b8314cb8de72157d0c25008fb0f332f8d28b30f21ec45f));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x0c941f9cdee3eb6ac8ad706381c978ce43577b2d55bf1612e9f3117ba69a11c3), uint256(0x08b385bc7f2713e69bb81cd6b520967bdd0227a4ce5befe39519a2a3ce1154c9));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x031fc77951585fe6a0f9c878f81401d799ceec618fd103f8ed414c7f8f20f281), uint256(0x055eb85ea11e79ef1137ecf2895675d105a9744fa96eee9d7210fc1c2e23de2c));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x10f81a2b368f9c68e38c0258eaa1782e7d188d4b6c43d58adc22f053ec319924), uint256(0x1a0e9e973d9695d5d73d0bf7f79133d857ab558da636bd6d4dc1b19123ef2294));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x1b62f6a04cb7cd44447649965dc41de27286009a4e22accf1317dd9ba58e1f63), uint256(0x22bb5a201bc68833c317ad358fa4d3ddae2ca98eda530cbe78cd17c1de5d5bfa));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x1a281bf7bbea64359431cbb4d1293c6f1f38e0a5eb17d20991a7caae2af3add6), uint256(0x092dc14b52719d9a144a768e91edaef2b9c5e93e439aa1cdfb3a53f2fc821c74));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x08278e665d3d8f187dbe5f1c186e00ac0d7011471835e7b44c239b9c8ba10c53), uint256(0x25018913b42e31b27102edd001167133bed53ad14eeccbdad0c07db7cf7a86bb));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x044a4a5998bcaf38ba7832b6fcdf2cc2f7ed2afbea59b54fdb2cfbabeaa5ce66), uint256(0x00839d8ae276e972874110dfa53899a709d573b1d3d47a69de7cfee782b70409));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x216d0356b27e5def942d85a2afb81d5d5a63b57430b64fb58cd646f6f3ddd58f), uint256(0x2514758bc608e0c2367d1a11f6288c59741aa796547feb8c223e1cb34e552322));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x05e59dd42e3805b63ae93b608138dc0704a5379562e22c642042b1e47218f0c0), uint256(0x00324085a76ae5afca1b0338a74b4dd83359c9c743d40bcf351463ccb6e480ec));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x205ffb2e60acbf8b32bf79b79a60992a35aa77f87b585e908e052395562c0680), uint256(0x1f63af244e41ae9a3bed3b18f5286a8d9557613c06ed6948371db429f05ca308));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x0d27cd951db2b36ee40e49b39bf54e376d3abc74d2508cf6f2507a4418d533e2), uint256(0x1ec3e58d357d16ff7e4e095ac962766b5138a71007fda18d783f3a4b3808c925));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x109cd01e1698a5f8bae139f63751133eb362d1a6b309a200cea670838bd7436e), uint256(0x191e50f7a45e606e9e5b711954ba25716f79af38389003f583478adb28043ad7));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x15a4a189f34ebb32b5c4ef00fc6d92eeffd6b1db1a0c4805eba875578159e722), uint256(0x26d1954f3327951d466eba2cc50ff65b7b5e3ccf9c37d69e8e7b5e20137ec16e));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x1bc567e138444f98865c3bb9cf4ddb113ea583334fc8022ab74746fb77ed5484), uint256(0x15b11c7c74bdc3e7e300aae753d77e4621874115f504c94f7d6d86f7851cabc1));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x02526ff2e6e36429a2d12762a054d9e84d66d2b652db72225a9a05d5aa2543d9), uint256(0x20a45652c771b833f57f5a22a84d0cc9471c10c819dff1de323cf47490a479c0));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x184a010533d5faa85b0d84c26fe6a7173699d522f15e47d68f6c78b3ac45a326), uint256(0x1575a5b49f9131c7b94258dedc46646c0fd6ec63af0d2425da0b25b78e834e99));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x218466f3e10f99f47f82c7ebb9f43c2b3ef8bf3e4ac3d57558a21c24a41cc674), uint256(0x298badd0ab7530121686b632c6af6f6876d4cd39968ec413ccd05355e7f49999));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x18a31ae2c337ca082f5d76a94ddfd3c09ff6b0593c3ee0afe7044422dc700d55), uint256(0x2720773ab2cdcfe95c8c8996ee0562ffa4bb4d8bd72b46ba17467c4f3c44ddbe));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x1cecdbb64ea45a4ac240b076bc4795ea29004e131a20f7915e7d209bed418096), uint256(0x0b1cafac6804f262b0fbc1858ff5606ff658bca292eee96c1624447b86051d45));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x1cd99e18b303c70dcda9a0f0e240bc724c944dc48cf1e7e445989a55dade4b0a), uint256(0x09770fc5cfc3a123641f7bfb57872fa889887fed244e49a213f99eba50b38ce1));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x03fe4fbfd46b16336d1bee5cd2ed1060170ac400474317573f0d6e44c280045e), uint256(0x200902746b805c39ab5c44117343ac35e6851930b74752425c7d7930ade1f227));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x2813cc98f90d1fea2fcc48b97f146b072088620ee72e763331511fbe5a279109), uint256(0x29cf82a2515dd5403ae18b6c22eaa4ae309ce2dc9becf12640d353afc2a025a4));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x17006b4030fdf0575217a13d568dbf2cdbd5bd9483e3306f8fe12b5a123c5695), uint256(0x0879494a476e4f98f4aa263dc2c92e3ed703015dfa531985449f23fc619813fa));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x07c1b2ae395a2ceccb6a1217491b64567d9750b6187c1edf78d95b2d849b382f), uint256(0x19e214db680a89bf17724a265f2e49d972d634d099cd7cc2aebac57fc904f6a5));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x09f0cc9391f72ca1962021a3198b0ab06a32b5be0effb017217ac043ef7b5b4e), uint256(0x14115cd9d492733dd5acab1361cc4218b0c59897bf6a44b0cf8770430bc8cffd));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x0dc777c9f21e529645adcee10da143118ada76cb5392e0cfd9ccbbc4d49196c0), uint256(0x2f463a9cee64e1e6f27cb7c4fdfc04b1802aa12a66d0f10cc1a3297fd84941ad));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x19195568b3741f0718e1b634a55a1e4fc85c8122bc6551fceca8b6cf2b03794e), uint256(0x2ba0fb73661635843b412d98901477c30a52755d66b17eb3b392578b31ee372d));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x06bf947ad92ec46486e56dba0974dedc2d81a3a89a00fd008d1740cb5a63a51c), uint256(0x0a4331a598ac4988e4244be04c484b7c048d6010a37f5df25e521d45785412f5));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x1055ec8751fb745f71757b63aa8012ff8243670008b47fe1655f6fd27e61a27d), uint256(0x245d7055a189e1ee16ceb16a8cc19729b8eae2689a9b919f7b2bdb8bc69a1a2e));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x0ff31294419abfd27d4067d5edeebacaf67be7cfb9a54e2e1b4d8878c8324c49), uint256(0x21fe10089c566ce89a4cfd8d9a63d5927f9825450945f8fa560ccfd04650cadf));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x023629cb1202eea783961490223e1738658ba7b3c366cd174c895f299a813daa), uint256(0x26db11ed2176c67b40a3f022c7e561425a9471d6ef51f280ca49b21a1d5c8787));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x24f1ec5082704d7ff941f3a725558ceb5b57515ea3c397d8ff1ca61794f874cf), uint256(0x0ecf6fab4a2506953a76588da1dc09f9d7a0deb44e5848ca5015a1df4b5fa182));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x0352c1064903dc1950331ec2f91c9759f8d1fb7db62fd48a1338a99d890fde64), uint256(0x0bcc4b437ea96f9d51dfc0c9824d1b03e385d2136ed6d7bcacab36c233cc26bf));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x1cccdad75f46c31746e472ca368adad98045833063de5e42005fc407d325a06a), uint256(0x150dcaebc1bbc925a3ab903afea49dcf169412eb6d50a744d02fa4a6db201e9a));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x077f58bcd84859cf2d57472c3a2058d0143741547af442ca99ca09eeb11fea0f), uint256(0x2e677b1e3c9551c10608b1dab495ef272ebe913626625acd218db9354e611788));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x16c6bfabe0ec58f5136ca7301d1624444b07a55dafda68238a82ab277ded9fa3), uint256(0x15593b71bce3b47c936fd44069dd0b1fe1257c2161722d7aac3df0a4479c9e59));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x1e1bed47e0435b333ddeb1bbe91ec2c4328d4a4748f408997ae379628a3f62ad), uint256(0x0992b4d9a53a45e5ad7450f3ac91e363b2fcfcd179d9e3e97659d456d5a70030));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x0b3df9a36fd5de77af669c4f84cdac6f6dd4deabbd84f8a478828e59634d058c), uint256(0x167645a34a1c51935e92878b9e1a15018b1ae77d8ff4bbea6521b14d9b3ac5b1));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x1da4feb43fbe6cedf45f7a4d1aef0ae0e4440567cc8bcb1bd977dc97c48a0ddf), uint256(0x1b7be60f2d559faa689e00e1ce454e6046638d3f5237f2a857f23a8cd683b7cf));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x2a3fd235cd09524ac2a3551ce4a3021300635d5f3e92e172d33b897e21e32700), uint256(0x22c3138e6e3f81258e96b9a265c26297dbbe0aeecebd1cd1152dc3c44f74c1c5));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x1a21995f4fd01f70b7a3d38ee5b570ed3fdd17702726434c9d1b0d89274a4c0a), uint256(0x00a93dca6f9a75627ca26eaa68d2b639e98f4347ba66b8b85a42ec0426512807));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x2cff3f2f00bff2476bb6b3659b1fe4c4ad890aa46f551c6c4bfa1dabed24d7b2), uint256(0x260fb0f89fdb52717bbd9aa98dfda840ba78dc65c4ede1db6339bd26a88a58cd));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x189a535bbe921694de46cbc405ac49017b59f3e11f330b4d402709909d5e964c), uint256(0x16bc51d94471e52fb3621698327f51129366215a7fd7666b29218c9a44c0c8f8));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x16cea611503aa0065b609eb5382d938d5b45af0f5e0bb80c69092e2c089c2b9f), uint256(0x0b633824f7be966fb5c6599e173559632d120e2cad11d123942ff99dd187a1ea));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x1a0f347aaf6fcd8fdd3a43b328bb69cbc0ca224a1b7824e20a49d36499f81ad8), uint256(0x11a717431a258f63aa86dffc538cbd93b4f6da27a6f698294bc3b7be300c3aea));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x2281fbe765577cf9d634f8d63e778e19c6f5222f0c8f38fa8751a1c7d6785154), uint256(0x246682200d210bf1b01ed803fc5df3d3b9ee0ab66f6c76c9f91aed2c04a1539d));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x027b757e48055f7b818eca42397e08b460fe663d37be3349ee7dda6368c2ea70), uint256(0x00048063d712ff04324d92e7c484c7562aa8b14a133c096a265f9f40708aa7b1));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x1d5b96d810cc2fcf75d23723df9f651ea8e9ce586773daeb30a55a182765e3d6), uint256(0x118a0a6c98dafd48841fd481166cd2d7934d08f287d1a474f5e812d47f4a78f7));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x06c2d39bc408215399a5a0e3923567012fc3189eaa2cf1fbee6caf4f02633450), uint256(0x231c7223ebc7b8de59fd584a397ed25328bb2b8a8ae5f574a88dbfce3cfa4fe1));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x15b1e90704b2bdf30e34b4c9d2af8d15636097cc3941bee9980bdcc0fde2afe5), uint256(0x019d4262ba9e63d049e404fc45c033131b245bc8b6da6464228174265d8464f1));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x2ddaf45d54d0b083a15efb8ea56d8d839405af1f20cc0075512e3f2ccc573e5b), uint256(0x0564a52cfd52629f067935194a063c230e32ae766ca162e8152b5e839c00c9d2));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x03aa91f0dab6baa5763e6707b8ff7ef351010da009eacf5b768983dfb510877a), uint256(0x126d89f53a2c132ca796ff8aa40f21630bad9bfd0de39c477d6531ed8253456e));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x0b996675b87e4898c2df2e00a01a58bbc9305ce62069c809e7456435a80774ee), uint256(0x0fe2bec9738c7ff1cc7ca4664f8c682511bd83771050f128908dc33c189a81eb));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x02ca7cefd5851e3c1a7d46c7d5afb2180312b0876b226fb4d34ba792ab44091a), uint256(0x022826a1fc7cfaeb9189ef6caece779d80f1996a0127b57aa295ab098e568919));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x1881f433fcb09ddabcd3bbc600ac0a0a94aee3eae6344e48b87b8513708ce356), uint256(0x04ee272aec392faea375631263c3dac6a3e977b1514f228c98ac98b2b17464d3));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x0fb25c78a325b842137afc7d01002f13eb96acbc8ad2613d113087ab29825837), uint256(0x00495984f970075feb6e30558bd3d56f0b265ffd008c35de1e21dfecfccf717b));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x2edf214c624dbea5a5787daf81e3c4c5d223a0ed813dcdfe6d8f689f4562cc1d), uint256(0x1c227e4cf5813efaa6fd8058f76ec1a8358da6612c68c1c197a5fe26b356fe93));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x0295ff36e0630d052ecb39e62fbf1c0ff9307ef3315569448b59418ea80570d8), uint256(0x242a76fb6e1318a04e63ba44ebe7eea34c5c39ba78e394dd1ff62a095413bc40));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x11780de58bb596efee5826d897de1f65c802a6d229474de1907a139296cba441), uint256(0x25dbfa140333584415f6fdbd7981aadbcd352eabee1b7c59dd6eaeeb42adde76));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x2552c8bddbdc1f2a77996a5591af9122aedd6ebba8d96653655219403527dfff), uint256(0x11677705c37c4c17bd92046d782ff8ab6a360e6f488ee7f6c3c997ebe0103baa));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x19be6e2ab9fd540275895b276c32422e5e0795ae9aa0efb93b98d22d9e07494a), uint256(0x2d939fcb75c65cafcfaf6146c48814479132046ff2c994cf2bffaca6b5d75c25));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x1892c1b19cc43c33ddd97e95e871efa570e64d3101616a1093c4dca3d8494003), uint256(0x06fe9f970a72e934f48f9c85cd028fb03b0b43be9e6dcfaf242bd873c1130f56));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x25cc414423a6fcc413a980fd953d7ff2a61620be509386e4661625046ef66459), uint256(0x25e0d61a0f4c35e0ae746603cf5fb7f520ae81b8b5d9b476f7c0a1138f5c8052));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x0a5129e68fee6cefb110973a6a0d88cdaca43b07328cb991506184df72475327), uint256(0x14224120053b87d0f7b08878ac54a9b55f46f34a318547c1cd5d21633769e1da));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x2a380dea70be452cf47631223c2d9b3278b6499cc01d6d1226bbc0cacbfa6818), uint256(0x1738410d1d35aa787f4d2e5e8f8d9c821bf6ac83e86524d65ded4b676bf51300));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x22cbe899d2172f25cdaf09ad35c7078d8593f8870c7bcac16dc559990b986273), uint256(0x2023e3ac9e95302a3febdf040676f097b74022c4409340adcbbc7d7f3f497e24));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x0ca8aa3a6d038fbbca4cc5110e4b94157d8070cd66551f440148531bf8a1ddc1), uint256(0x2105cdfdcff0e6fe0ec3fa097ca3b66116b1136ccaf17d0f093e17dfae610f40));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x1a663ee9d8ebae0f66f1903f1e107daad988ac1551a1bef971cb15126fd675b8), uint256(0x0ef0917c8fe975d8ab5c9ac81edb50dfaa5e03608935c5810bacbfdcce1f0f90));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x2e9e49fd23a5f8ae58b7d5946e9c2e0f299bff7fedd99991437e49fcf4dc3af7), uint256(0x13f1f1c2848115512f5e1db7aa640c6c2b0f83da15a87c844475a941d0f4506d));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x1ceaface41396ac20555316e5c49a87d366772830f141fdadf9deab9f31bdf0b), uint256(0x2763a1caadd36f870b94fa93ad9e7c2474270d8113bb694a08b3261d2cf98936));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x2edc5ebd464fe67ae46f1d86624017bbe5c1f2dc5c03ea4c0a3a986d09517e17), uint256(0x2778aae5d998f69e971a2e495e5e71dd66c059bdd2e43723a1a9ba60116d9aaf));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x22d968df64d5b24fff398f7d1982e2e9822bca929b33c1e11d0239540e334fe9), uint256(0x20fe763a52e4b7ecd9f45692d4f7ac1bb59da29c0c61a6f171b13040925fa248));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x0f2152a6fa4fd91e758dc068c463d76a9223a8cdee98a86bde26efc6d55cb1d3), uint256(0x026b9074ce98ebedef8c9423c8f556eff1cde3509b3619722d4e248cad28032b));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x1b6fd4e9b3fd11312d08e69a19596efe9aa7f2f4602961367fe642e0730304ef), uint256(0x0140ae12083851be54b1d2658633845dab633242306c755e1d25f2121b9c7b25));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x1813c4a780823902536ad4d6d89ae2d95182526d2872019f7953543d83dc682d), uint256(0x2835ad537d4ad444cced9fe2d3f16236c588919f49236f94222677e535071cba));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x2b4d1fa1195d5f8d500ba06bc09dc0a79499c1f3c0d2fbbc09e379ff45334d18), uint256(0x1adc730558674b088a3a83ada18fb7ca62ac0bbea1aa302a422eb982c4aee248));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x0a94375b342d97f3649d38dbde2454eb2c60815da1173414a84fe26acd7c6773), uint256(0x027b009993f1679975a67c30c103888c325b61197b77e007f917f53d5ad08910));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x1eb299fbd14a2c9e1deadaf64712b8a757971ea10bb7d43a02e9450bd2735594), uint256(0x0fb2f770cd30e185342653c6b5f0467d12cdffa13c1b9335997bc32165cd6ec8));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x28765f2e470b957595efc34f79d559afb5274e658035eb9eace04e4cb21815e0), uint256(0x24e100aa0cc2d69098d4eae2182879dd52d6e1617675947dcd444898bffd51f4));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x292dec500cdbc4e995ecfb5bf7670bb6934da802e689dff86c790116832a251e), uint256(0x302890c578f9b3ed91d83563962ea9d6e7b67938a7ee58d3da98d9f3e986234b));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x261dfbd98e74478171f79be7d687696949ff36ee54ef46c9301c97d6ec380e3e), uint256(0x1df74b77e139d7ff8ca732c0568e9165de5995c8fac84a2b0bb2e5a673995a92));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x09192293271af77db1e016a9badb7896cfbbd3f307f666ac897ab33f3d7e9dad), uint256(0x220c09955b678cf209af2bc8a934eefe6f498403584d1048b197c2dc99ce70cc));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x089db54b508b97f146e2202dbbd6c93583221913befffb368f65bbad7755f0fa), uint256(0x250cc259d9612f381258366759c5ff5c149334c421416bd7b2518455e3914fdd));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x04974ebd9f28e8a83fcb259accf55a34782e36bbaa4219e5258afad1258db8c8), uint256(0x136685fb1e84b06ecefd9f94028a45b36b260080ed4d8fc8d303d3ae1413bad7));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x2c55d4946d27ec4763d18abbbe3cc9c6d70ddcc92fe0f75950509463470aa322), uint256(0x2d5bacc576dc189946bebcefb383e988cf711a490fa8bc23543e8d6b4e1fa586));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x2ee5f1d941b75ee06d2673b8dd920199ccdae24466137de0339ad710241dcec8), uint256(0x10ad5a710a5317c83a64679cb84b47d8eee2fe761d21b57efa3652df52157b38));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x2c35b707107c9479c5fe95219972b5566793582d45cc3da178acab4b46a06e12), uint256(0x090609ce05cda546e2eb88164aaf1738f2ac76002958229d4824c53f01dc551e));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x1a938079ef6ff8e7dd025c6eca822c09c0ddc818aa73e06b0ee07e0170efd85d), uint256(0x0d5321fdd9023490e47475d3e3bdd3a4d22c609b838365c00d7cb00401fccca0));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x22d0023a1417fdee38eeb33f2354e73a83d4881e9c05d73fd3a4a0fe37d70e52), uint256(0x08c0069fc4b73d733b7a588fc5305fb57c6546c1ac266cdf5305c01f206845f6));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x230601b3055b83c7801b5726c861d21c5f08c5bec2b4d6b8452260f65461a16b), uint256(0x2c66ddcc6ed77c1287b901e080b5d8c076e3a3685c5bf5495a15ecb5ca4711ce));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x1a0155f9688dc817f1844cd69669ca3635e997b3f55c1e3d5ad892cdd7e3058c), uint256(0x1e72f3760fe8e5823a6a0aa6834878572f8272a8c41ff9aec305723768ea55fe));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x163953e152af8b0ae86e15ec142e53e516c9c5a39a4b33ed6188125a8e1f80f4), uint256(0x015382321c3905ca0fc10c0ac256e4f92420043d277296ae58ec3b0275b8bdee));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x0e1798efcecc43465db60e4a65d5b47ae2bf34ce30ea246f83b9271c0c2c17a2), uint256(0x16057a24827641f7052e23c15bf819c76dcb085bea6de3f4bf4bd2d9e7b17a81));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x2b81dbab093a44e561271373ec7e89a5af9fe69515277acf9756e86594978aa8), uint256(0x172c130877fe4c580253a42773d699f569176d0ce9bc88be0c585b9f003fd47a));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x1f838c44573b4067f517d05e04322dea859d47bc08fe13e4b015ae1b9e411049), uint256(0x1627b14d48d7c29e136a0ce08005b8eb138cf551089f6a49f10095bebcf6474c));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x00ee4dc6b5cf64c8dacb5513ee8d40dd507060e466622aad54fcb3eb2fe40102), uint256(0x198a190dd7e1e84a7415d441b537b1095b1b52f19aa0e0b82b903657173fc1ec));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x13aba8832557920d2cb92e81551c062c6ea781a1ea7fb6e399e32791dc2415aa), uint256(0x1067c72db12604dcc48506f64d3de8d84262e5e5fe213a8115c30c9209dd4eff));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x197035a219e5f4901f53108b2d26c7fcdb6b7680d305736cced0794faa069ca8), uint256(0x2b87e0a00f36a793dbeb7edb2a35daa92f549cf39229c89338b83a61677919dd));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x1f0073cb123c69c0cbddd1c6d59ae3de99c23ed30e975ed022b31c8dff411709), uint256(0x14ffc298cdac99caac2e3c157b591797012e67c11b493fcf2db94451d5014d59));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x06ed2c7ace70b479d5d66afe7b355fb2df0df23d9cdaf91fb62ac5c7c3d88b4a), uint256(0x2f2aa11055d3083bcb10109fc561c316470638a8e29ec81153e2a05683968664));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x0c85eb311e26c62531a5f85d9b6acb84f8067ab5ec9d9493679e4a070c9292e8), uint256(0x0fb000d1afd3c569d3eea10784148f0514885c6feadbc9038637f47b5f84c276));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x2b0f9d01c7f69aa3ed851a3534fc4ad989138f8f0e00dee995006645355cc103), uint256(0x173cc657af9b84ccfe6f1401d27a0f80320b9de21ecf7f7e1891c471290433f5));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x1bc98756af0b4eb0de6fef701854029f22ee41eeab418b1e3e6e5f31f4a3f370), uint256(0x0626d6351b3f265dea094c69810993d0e62ddc5ccd2e926abc024704c36c45c6));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x1e82e40e94b1ba5c18c2809d23bc425bcb7463af6d5274d1ac9ed294a87e9457), uint256(0x099a29518e4701ef721dbba265e054cc6a405cc31591a47ed5fe512f23567901));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x068f1fa2f9da78753ab444607109846240d9bbfdebbb072a5329cea31d1d9ae7), uint256(0x116c6792c889cbfe500a39300390b4bda1f86e8d2904a069675547f3b170ad72));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x076a02487f3bed924ad6cabc637b37afb8aa3beb7fbf66426e9930316771265f), uint256(0x2dee8fad95935237b37903651d751e063a1ca9104d71da68f6a4ca16f8766d89));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x21bbcb62dc530fa7ef1721c1f4e82834838304090e381800af7ba34edb504a1a), uint256(0x2625daebe2da8d579a02caa93e11fab4e218b8350f15457f40dff2240501873b));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x249c1ed564c4c49b2d33224f219e10396038ddf7a70a8a3f64c1253db1e06001), uint256(0x1a8a24d26feb915015d0c307cf1150bfe9d9de85f78081a39f0b4891dd4f9503));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x1472259ded2955d4494d8d27514c0b8a564aa9abedf8783b7a43109d9aa2b51b), uint256(0x1c79f17d9e7b1e6d6c520da8908cd779406fa769e08d1ec19ee82ca18bb303fe));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x184ba2ca1df66e63904403491ebe7a4c17ac8d4ea4d03f6d2a4d956b2e52a946), uint256(0x25f7e7a62a6d98cec8caccf963cf2ed5c80f43ca82546565d63367830bb5b756));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x2ec8863b9e4609cb8cf49c3a1a73fc567ca9a0fa63ce124ec30aaa5cda8f3ccd), uint256(0x07170b063f044ec74a6bf4f6230f4afc38f854393841d78ca7a4cdc633d70938));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x2ec2ceae047e7ac58c0fd3e07d7931b4985747172bbedecd83f8586b5937f77f), uint256(0x27fc422f335649cbac7461ca3cbe13db366bdf441ebdd3aa98f4468453473528));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x2e5c4ca0d4441448d5d6a357e29c46aed6449bfb54dff1042a52829b313f2a44), uint256(0x020d742062203fbffe28b17dfca2731f5b87fedc6e48e7deff0adfe1bb022265));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x21eefe4124aac4d1104ac7ca43c7715aac03ae1990f61a83f996d34155ea9f8d), uint256(0x183544edf7c9e7252aa5da1485ff4de3baee21e54564149f224d1e633bf4a90f));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x22297271a08edf142de03f6a62d0d13cf681de27916c10b2b416e20a9aa0a0c5), uint256(0x12647a788ffee9b5d572d951863991eb0af55e2324283e16227f3ff57ee46b28));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x241b6d7d1b3bc51fd43c5b1486c3dd68a728aeb8ce1b8aef3dfb9b357a11413a), uint256(0x143262f742128073eff15fcae110bce18e49e99acacb364467f63581b693b37e));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x231ef7ef1b530c61bf31fa501b84e6bdcbba73cfd05ef7773c6ee3079e02a7f4), uint256(0x066f59ddb4b464273fd78eda4fc1cfc2ff1497e3c397aa78ffe5023227b63bff));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x0305591fbeadf2b555a68e1ca3b083f5b5a9e72e4d9664f9ed1ccba7894c80c9), uint256(0x13cea83ebfb70f24594a83c326b4c096bcd2f8cd4966e3e81e7841371854b2af));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x2208efca71a5df141a2e4041bdaf59db6a086ee620180a7e1c314e34537ff11a), uint256(0x1ad6d72e92a19018f0dc0050b1c4968c291c50ebb25cfc95dd9817258d266b72));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x009b1a7b07d8fb346eb0c9979b3b66daffef3b01e8ea6aec80c759f5cc3c1538), uint256(0x17bbc11cd50c7685e27abc3e42a1b90e146cee384c66ebd3c331accd65b13f62));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x08fa32a66e2a1082da47bd4cf35f4a75d2b281a8026cdd0b965d3442e9a27c5c), uint256(0x1b1b4dc6bec81009a4bfaae4df9111bfeeb6ea464b9ecc834375040fe1232dc5));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x2bb8c8d99d22d6ab587a057434c84e2176e024e4d3e0411343a0738daca65609), uint256(0x05293e63e65584e670386ed50fe774d83619ca71a0b6d04ebb8e022db2b4128e));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x1ef1cd76048ee203fa2416d5af1b10ee6e913ddd8128f9dbe4f362e79a78d12a), uint256(0x13c10707a0e706eb1fcbe5c598538feb0dd5d1a09ae43d06b77f125c6fe5b986));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x1064929b528fc2f1ba0d20c0796c9a64f4f4fc0034cf932ead3b9aec2332c233), uint256(0x21a8412c646005b251823e370e9961e3023853f8dc5302cb6d7fedb0b6f845cd));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x2a1971b6fb3e4160c806b90fd555a1d698d4ba5fb0737be54ee098332e73d32d), uint256(0x104595a93e1c8df1fa031a6b326ac1e6ecee069c3477bec59482936152d93254));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x07a159df857bd1856e012c1555811f2a4b272d99f0b49db5bdba185dea65b24f), uint256(0x0bb06fcf365eed8d492769b1147afd3bef58071f3775a15d39036ac14eef5190));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x0e7198971ac4801b5bc06e51522cec0b6b269d34777f4c342748b3628f387d3b), uint256(0x22c821de44cd8640d68587a0745457c5eb55e52c47327c9988f00c31c2e82e42));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x27003585d42f0492ec110bd2975b25a58c6e1884d28b84103bc96a822cc9f2e9), uint256(0x2827dd0dc27a5ff7ddd24167d5ccb997fbaa452f3bb8bc3e194d058a99476a3f));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x0e60e08acec9e572e7ba16ca2500e3941cf6e4dce5e9f6b7118faf1c44e1e12d), uint256(0x13987ba2b15b937541c0ae8b4255d1c25f33e01b18b6b249f21eb75aa03b3199));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x27bd245a415e090d7f9fffe09a9ada9f5c18aa5c3bd66ebbf6ca4db17aa4ee4a), uint256(0x1e964dc0076af192caee8497fbf83eca4df5f955c194b2f1fe8ba60a038073a2));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x2cbae7d671fcc39ec9a0226980a6c76b057822feeefc4c55e1047799fb3dc3f5), uint256(0x1abebf9becd905c76afd949fe16f24b4311ec18de8126a8be349ac115bd43a14));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x124dc2768d44b96663f22fc36a0a73aa0b5c4bebff3b042e7d1fcb934777209a), uint256(0x2f676355cff88f344412564547372c601f4cb9199ecd822afe9f7597f6401d03));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x2faf7abe05a00b5ad6ee749450888b0a3cc19decafc156147d612b20056b015c), uint256(0x231b3d421e6951e9712f582ba2f18a5da4e407319b76b8d0caf253522d8dc444));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x24f1cbab87611ea3d25a4d5fb6c2c863686d1e1dc08c1578f0d506b7b44cf908), uint256(0x10c8abcb82a5cea1838be4fa133c96de6315d7cd04f9484d1db647dbeae7151e));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x2e2850dc6d6bfba2f3a444da61e85b4cf1aac46bbe3b045fb6058dc89e07ffb7), uint256(0x1660ade3e216f54dd672b1b770212eb75f3f25676b8360653878c13afa47ba51));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x268e1fd7472e6133929a825e999d10f6f642d3f2e438c59b9b7a1ade6dee4539), uint256(0x1d7c5f76a8e3eb118c1e3fa41c651dd3a80924bdb1288f1903de72e9b9e952ec));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x1b4e3381108c96ce68168aa4dee413057314a90d24629050b82639342751f06b), uint256(0x007d4a4f0faba0235c43414f344f5d0efba1bd74737709b26ccd07f96d67ede1));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x27868df40494a6c188ce3259551b5d404daf1d276aa9a53d2f1a1c91b27c3ebb), uint256(0x0ebebf7a91e164ed181d882f7e1ebed25b2164bae362a8e8c407e50fca7ad3f0));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x129adee30deba9cc15b056827796da41a2feb47a19cc06a8457c9d2d9f31d8ec), uint256(0x1a7e228ae32b4a2c3d55b7fefe8554b939bfcce8c001ac6ab91c35051b069a2a));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x269f55081fca30542cfb13131c5ab2ec73786839ce5a61db132d928472ebf6b0), uint256(0x1965802aa6e221e7213ff92cacc4e5e30a44c539c93c1f1fb0cb786a6896323e));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x1e4397acc0912641c95bc1e01fe7f10c3d135be9a7123e7c3ddb3939da301e32), uint256(0x154a16872302c7f6367d7b992305bbf7ab63e76105d46a67f2efd82e8f298c08));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x15229faee87a6b4fc7a755349ae549077432256afbf8066a2a7afa7fd79f8262), uint256(0x29b5392a5039dc79dfb131eef9c713bf5a1f7e50e8f8461b51af9878849c4236));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x20daa83d084ed1b72cdfc44f9b2c81b6e6253e81b0afb1358e89589ea874a773), uint256(0x0f51f6ff53afeb43d8eb49486c7964d413fd79399b9e38c2788e6bac59330e51));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x25ab644a72f1cad7972277604e7c69000869709d9b1ce7671e59af4251b467c0), uint256(0x2ef1743aeef43389e9e98a404afef257bc9d76ec6bf12da11fe3ff3d7effeff1));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x1d03eaa466cfe1fed8f307bbdfe07a754bb0444a934e2fc6eb5d995be9716adb), uint256(0x22a8e16dfc04e1d728bf0eec1a9045621f15f25b4629a85917607a398c551a48));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x1177643e8f35af9999bd4d2d4db738a651663e223b009d369a1f8bcea8690d31), uint256(0x0c771263408f0125536e353c13b4a50e522cdd84830bc86c40b375ede8ef429a));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x25c86bb235c262b83cd6c3576e03c3e89c531bba0b848233e76d5eeecf0ebe72), uint256(0x2dced26529e3ad6c6e1bc8e19c81ab44284fd870237f63b1abd47be838533f29));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x2f566f56a4fc2f5af1926d25f5c050da2d4592b7339bac8462b5629290b877e8), uint256(0x2fcd9a21e630691248b60d5d49df2bb5fcf3da3b0b725e2c27fedfc8495543ee));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x093fe3f6ca9aa1ad16de7e879187597f489a20641c2051337d446cb46b677e68), uint256(0x0f075cb4797e6131726921eacc7ed7c5ae4b45b41737f32da05506b176ec03b9));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x0e098d1bf0b0931929a0537093e032ed61f7d603b1c6fc9f4c1a7912cd0d19ea), uint256(0x1111cf525e98a9fdee49af2737536654ec26c3b7ffe8bbacb9123666a38eead4));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x17a9e178cec9549821a7cd956e305f446d3252d6d5a68d3eed8cda8f9d320d2b), uint256(0x2860de7113c94df49bc7c156dd732b0d3bdd80fa4c9b4a5df9bc4e38c4c2bf39));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x0f5ee4be7fe092e4ed1b54a641c93744b9599606a1c3c8285de29001c612e9e3), uint256(0x1d651e573269d2498baf7179e1d90175bf43310a2cae5d1a67dbbdc9c2d2fac0));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x114bdda188ff61aa55d6a1a621c4f0130398fb6e89e4a0de77d1671a33bfd7cb), uint256(0x04dde2928736b8e141d14003f35f2e82077f0ff08b159592ce407ad0d0ad44bd));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x0cf606378265655750a911d02a0b67ce5b9c3b0b8865dd10556c3ca3a6040f41), uint256(0x283a018d6b002e239d3f498c9899a78711d2cbe78a93a82061b0767ccb81d92a));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x068c9553aa1b2520c5b911ed2b76bebc3babd2764153ded3f16fb16bdbdcd58f), uint256(0x28d40933730c6f7a57a3b28f4b998de3659edbda84734cf43f8f020fc934088f));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x2503d72fa5023fb3580f1e9c0fb5902584801476a838ce85f2f7df359497dd35), uint256(0x1cf4dd2178a30b5ff77b6c82f955e8d9fba4bb388cceff30f5c2fb381538eb72));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x247ac8ee56f60aea90af7ecf51a7d1b1ca850f8788dddecf1a572dc0629da48e), uint256(0x171360beaa1a16d310c2d205feb48eed2166e3283128fd34587e950ff32080cd));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x26b4aa63d66a039caa9dec7696a1263ce1e8cd76c6bab710bb99211f368d8210), uint256(0x1520d33237e8c88052039c3da8ea15d4dfd49133e31ac4fe435d7a5e82b95f46));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x1e1b0b00973c1592963ca4d0a1108a4b13147729eab25ac5d1627bf24932a595), uint256(0x1dd80050cdc27800f36acc7fe42e877aab10ae2c860f4d22a8713721611a9dcd));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x15b7ee7f4472b7bf5eb0219f031a27bee1e9ce37ad0a03bea48b0d7db13b733f), uint256(0x0d5d4ccb2e6b923e5a7874efacff4096e21feaddfa21146f2a40c81020f59329));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x2c13917481741b63fd338b9e41eeb53c1ec084750831fc330fe4aba188aafcf3), uint256(0x1cd96a58dfc935ef787458a709d4241f430ff9c880580bc6332af91d8030896a));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x1864f0b548b03949d1145ef0a2359dd495d3ce15031a3ac56f49de56e951d57e), uint256(0x0b644339691eed9ffbd433c773dec936643d1a46b0ee7f500b2ee9c9da5cec25));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x1a904ebd518df3d973871e12384dc70cf3f4111caad962c79ea6c6b9549799a1), uint256(0x28ce211dafe5a9da884ede50536c7c0cc4cbd74a4cc31b00c2989135b36784c4));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x180aba8825ba02a24133d88859abdecee35be179226aba2bbacb47eed3097105), uint256(0x19515170334ff046ca8d5b34f1a9f6bf72c0db2a2e95769de45a49c5f88de7ff));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x258367a86827a95166bdde488e6b0230dbb42b16d9a75e99bb3fe37517a824b5), uint256(0x22ac1777d94ed5e073bcc8c380b8d55bdd045424b3f3d782ac25d7277821a2f4));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x0a8af6134003310e4f7ac66956413bc407e564f1c26ee19418092b9e1a65d9aa), uint256(0x26404ee9193f09558ee166dc1ef4d8a45ffc5da51e2e1107dd41e58d6d8ae81b));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x2b6422ab5939800e2b0bbce9a5bc8f58109b47e59c7cc6d7f5fe51830dc9f710), uint256(0x025d54366197cbf32948e5b450a93cf43afe76bd2171e13f0cdefe2f209536e2));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x18e4837773b9c45936e72da4c244c752890aece7c5887dbc3771a07783575f9a), uint256(0x002e72e198d433c2785921dedd68e7d1d2da299b78600b7970abe13c6f940a08));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x20cedc697ec65d8c7135676d9ac0643bae58734fd20f8f71365cf5594efd3950), uint256(0x07601c408a86d6ea317db12f19e920429467a57c7b9bba6ac0aa59f1982d2273));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x22c5f3fa722fe15fcf90ddad65779438fd9416c2df8653b1c0865b37a607e858), uint256(0x12233e1de114533f0ca06098bbd761d17b42c761814209c09945dc9da0152b17));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x119043470ecf6510df08005ee33f4fe58927a16e7c8f7c1f33565a3f8e836624), uint256(0x18962024f25132ebf988ee2e5ce0b259635b3318d67621ac5b119b872963fd58));
        vk.gamma_abc[202] = Pairing.G1Point(uint256(0x0b26204cb80866ada4483c27c765bfac9aeced52e9a1ddd63595aa7068ba82e1), uint256(0x09d56ddeefb5f1970cf589e98167f62aabef66d10c43cd491265ee5d84d830bc));
        vk.gamma_abc[203] = Pairing.G1Point(uint256(0x276ce89b50d4407a3ffa2fa0923f67a9d342e614ec7da0358d5a118ea1b98f99), uint256(0x0a1a88d1d8cba5000ca733f01c1e06b32998f320ddc0ce1dff8250bdabee4454));
        vk.gamma_abc[204] = Pairing.G1Point(uint256(0x0c0563c9db1478d4e74b92603067c1bd0304af6ed2900b5acebf664121a796b6), uint256(0x1a58e57fec9d6f02dc61dc17a46eb1bbaafdd1b28654e44d94f243ed5349a220));
        vk.gamma_abc[205] = Pairing.G1Point(uint256(0x229721d9e99b1807b527f4ab73a5ca711706021d82bc6d50f2a2e9d34af62ac9), uint256(0x1b4c3f89dc87f673d72e8127056743847b12120357c9f3d5dfe81aaaffcefdbc));
        vk.gamma_abc[206] = Pairing.G1Point(uint256(0x00f527cc9fc07c014e08803e634f20e47e6c25828bd9b114b6f0bd4d38524ef5), uint256(0x1f24b7521e8c4bbb63d02343c6c57bb84abe39d92a71089f5bde023f8ab8f07a));
        vk.gamma_abc[207] = Pairing.G1Point(uint256(0x27e1eb0eb6f159f675cdadaa90f31cfe547d696fceb73d852dfa258e015dafd7), uint256(0x140d8ea567e68c122025591d3af7f4208b42507be147e6e142254e2a0be84bcd));
        vk.gamma_abc[208] = Pairing.G1Point(uint256(0x0db87235183bead44b3922c89676286b5076905eab006690f194714e5c70cea8), uint256(0x034571ea7e8df649030db3aea4ee8c4242079908e0ae01ce558dd30ff4d77298));
        vk.gamma_abc[209] = Pairing.G1Point(uint256(0x0db585645263a559ecbeb520ef5627e9ce46f7a5f3461dea4b786def4198f4ee), uint256(0x0ef54c14c067b3abee815d212f529cb5144e29df6e66b78c9609e3e025e48833));
        vk.gamma_abc[210] = Pairing.G1Point(uint256(0x130f215716a85bca717b4154e084448e28e81b54133120a7ef0b6b8fd91c00f9), uint256(0x0ec0c9f5119e6d62fc085f0848cf0d672e41f6c610671de79aa434ee427eebe7));
        vk.gamma_abc[211] = Pairing.G1Point(uint256(0x303813653f3ec1573432924d6ed7a96ba5417d7ce9024e709368f84d495c535b), uint256(0x18b77b83a715fb19db383d477176c84f424d8009d20ad152770787a69ed3cca7));
        vk.gamma_abc[212] = Pairing.G1Point(uint256(0x0d67c5828bc81a334a387106ba1fff53fb245e57dae51c790baff69fa5a7c2cf), uint256(0x171994b15e93eaeea2669923940b95895593def4fc28a8c98f6b8c9e49b0c22c));
        vk.gamma_abc[213] = Pairing.G1Point(uint256(0x02ce5cfe5dbc41e0636fe4f6f48a2166cbc1dce70389d3ae3b1d7b66091a0690), uint256(0x0f1b1e77e1b1335a3ba5388cea82da86cc79b55a856ad07dffde22d7d4c1c992));
        vk.gamma_abc[214] = Pairing.G1Point(uint256(0x013dffca744da7313dd7dfdc42da8dfb23a185a82f902a26b10ee56b9c10e381), uint256(0x21b30496a34394cf5943ffb97533e7dc8e6292bc7fc729a713c23412f3317464));
        vk.gamma_abc[215] = Pairing.G1Point(uint256(0x0a81090ef62632e98bbb6b4dcb4cef9b32489a6a35a8d7661a3e200ba156c61e), uint256(0x1bb9afecaee151523f1d1953ef4f2a63b6b8b820073c3ed66548544a4505b97e));
        vk.gamma_abc[216] = Pairing.G1Point(uint256(0x23113db6214aa6cadecf6d5e29b9a99645804cdf4d2dc420c090e2f9df759354), uint256(0x160d7840fcef198dcd9ee49c0f5c045ec8765eff9e6b7337fdb5412e9d624c09));
        vk.gamma_abc[217] = Pairing.G1Point(uint256(0x19adcbce88f2641b5232b64bafe60924396c721e36145e46cf4a8eeb880c0540), uint256(0x1317b70f70b4a88308acb29a1ccffec09ca328da1d235ed83975d566030931c6));
        vk.gamma_abc[218] = Pairing.G1Point(uint256(0x1b1231a68b249f08b11d3225da9016cc193b696be637fb1a4e24162f460c3802), uint256(0x134368330edb3d8451e93bd8bf320f525246c02493f6cf34fe7cc196a246ec2f));
        vk.gamma_abc[219] = Pairing.G1Point(uint256(0x013939a50c92a821318cf53e9c4a3084647a7ed82edca1311123afb8f6dbeaa0), uint256(0x26bff27c83f16529c08b08925d8fa0aab8c2a99a53f68e377b0d12ee6b33acf9));
        vk.gamma_abc[220] = Pairing.G1Point(uint256(0x261defc8218fc91bc462bbe2cd401457c68c50a50c764293947599caf6d1e5fb), uint256(0x164d5b9f40dbdeb5ad2c1148964dc3c64d16e37aa6b14612f34a2b44140617de));
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
