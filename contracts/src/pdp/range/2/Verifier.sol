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
        vk.alpha = Pairing.G1Point(uint256(0x1cdec6d82b297bb9487182a9ec5bd873a1c429f73e69744fbcc379f32e553c47), uint256(0x01d237b4edb860e9936d11882e61c0bb4e692214141f7178fcd3d0259fc9645d));
        vk.beta = Pairing.G2Point([uint256(0x223e3638449261889e24be94f2e10160ebe6365ac8676cd6b3980228420285f7), uint256(0x28bd2d97a6f0904348dfa72b5dc528508785de86cf13bc9f11dc4a352acfab56)], [uint256(0x1ccbe95720567cdea577a36d1d4db18be5093623a0abfd4bac99e572782adf1b), uint256(0x29bddf10a01b8c4f627dd54f8c1047c35b0a836b60f74ceb7865cbfea9f57a8c)]);
        vk.gamma = Pairing.G2Point([uint256(0x1198af1824a03be6a3b68427eff09be88e90eae1cc8f685fed12e75ec625762f), uint256(0x2b152c464e909aaf88a811edb5efa35d9ce9de880c5a22d2ee0b28ea5289264f)], [uint256(0x04769dc13edd71354043385722c90b586163aecfc9cca37ee82438f76748d050), uint256(0x18ca8f6c8b24748abf8edeb15dbe8ceeb09b5146a4a5973f947f764263a2de63)]);
        vk.delta = Pairing.G2Point([uint256(0x0b7f1d284bc33e283adc805a9e3dddf1faedc94a3a05dc8c228781c7dee771e5), uint256(0x257e922ea5b31307331ed27c7cf5f3e8c0e4069dd6045f63dd578d970c57bc4d)], [uint256(0x0a6e3d8f034437e04c1e8ed8eb74ce9d19b63dc3105c8de03128bd961da0ebd4), uint256(0x0e8b67b580b7dc178a38de95f7cf801b0248ee21982969ecd9504664a0b12f8e)]);
        vk.gamma_abc = new Pairing.G1Point[](53);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x156508f8bdace02ded3ef1650e76f3d15733867c71eabae75c06a472c02a1bf1), uint256(0x03ec2c9bdd42f5b42d2c8adf9dbf6d0227b6b22f1227d4c960f97e56916a8ccf));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1177e3f4f99ea63667bb1236ade469d3c56c5b5b425f5e8410601c8725029620), uint256(0x0562d472b20f65e9c64cde009ed09190f5be21bd53b5bfaf112652f0ae496794));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1f8f9c7da710d9ea04ff245da1c6135766a8c4536ce203e269cd613c334e60a4), uint256(0x06f0bc84a94e23638d16bf530b92a603739534a198df67a95220e33e5201827f));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x03cfb9ee59b5a372f5b20eb91cad05a099e90a9a2e942085d693349db0db9589), uint256(0x188b0d513ade4a5e0f9b07290075780c555b9b640cb001167d9300095dd1fa3e));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1e7f219fced408c4d9b0521adf96d8cf253f4a261cfdfcd6f2842442f6111521), uint256(0x1fdd2423e15d67a9c01c5b375b6f32aa9d14363e3708b075cdd5ebbcfcf91f1a));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1798042b74bca88b99f8e7627db35f2266a160f03a4e1238689523b3e94d531e), uint256(0x27d24f1fd6b555c55bdc2a44d79ce085f0a6088c8802a529b56d79b68aed90db));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x07ce9bbe7b8c6b2666fea89279704aa1055817ade22839e42dc95aa1c87d9bc7), uint256(0x1596a426af6fd424c27acaddf6bdbabf9c5415edf881359750d0f1e607132252));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x13e07d9ca1edee23d69a498652869a1ec8842c25a5293fa3bad6527225c8652e), uint256(0x0af3877f98a5a419da64a40aef1e1478571276758ef0636db82662e98bc10de8));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0ece37bb6ab814ebeab4a6f71c9f80deaa0fc7f58f05743d7c0e357f8168e31d), uint256(0x23cebbf2bf002bb0e8b979a16d194fee0c78ea30c066fb926f00420addaf4bbb));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0f7bf66103ce3e58221eb2ea775b872fa20edd32d3e36255467c1458f462e23e), uint256(0x2783bd6eb6f0fc07783fecbc7537ad74de940899002ac488455aa02cb4969835));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1d14ff556cd1eba1a5e6e32495dc6737cdfdae05a17b6a92dc280a2652d49c82), uint256(0x0380ea2e8f46736344ed65f1fb653ea40880551b5d787fefb141bc8761547376));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x06196e6bb90849fa940a57c12fb7fbe27bcc780c9637310b856bcab87422a5a2), uint256(0x294efd29baab5862e8358361458017841d2200842c68246251f33c19fa878e7c));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2116f883e6482b247425656efc77bdf7224f3016c0726c9752e74c519618f81e), uint256(0x0ad33baede0086a2558189915aa56c9ddcc41083c00130a70df37f9a256c8daf));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2c9d5959e6bd8cc0f6f37b111734bfc184ab0045cba93dc7f2ecc512704e2e6a), uint256(0x01f8df06d50cc64aabfdc4dce6bdc2058f600f0e4f469d473a6df8a415df333f));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0d8d40800467a76e25964c27be0934a9b83bfecff9965f24fe1e38c4d9c8ba53), uint256(0x0a539967611fef694ee6276674e0f90a1831ce5a6c422f912ad8b32759648f56));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x27c1da37b3cba9bd80b7fc07c807a76824797ee0955771d175c244f7c9ba72df), uint256(0x0a0ece1d04a75ebc09c0376b52b8595a5dfddcc16fef6409db9fa5efe70c2d70));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1b79b35e7c324ffbb86ea3ace4fcca46bc8ad3d121614ddcdc3329736f3ce46a), uint256(0x12adb0dd5c7a2aac58c1818f9f5bac65c26cd926ec980b3853fd51c3ef1d5bdb));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x28befcf3b31794d39bc6439b66135c6c7d78b59cf69a23389e88de20802ab1a8), uint256(0x25f9b4d02df14f982e8b26ad4d9e4e602d1c5f6ce448c3d71e59ea7f82e68cdb));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x0ea5998129ea62d3ad8e1830b5593b23fc56920f3252f307abb817ead0c2a739), uint256(0x00fd4a35c18d0d00f587c4560550f59ef7a34a9f80b441060d1b8a724ec81e6d));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1987de0aafa88173c3baadabe79f414903197efcd7d683fd4c253622fead441e), uint256(0x201c4381de2a1a5e5daf48bea9fd594d325cc22cfd5175cd280760b6da519c77));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x06e1526e1459763caa39b7c64c4e5965fb28e50a5c065dc87a185e6b4b0f4856), uint256(0x0f9934c307b3719a3d8c367b5bfc5bf586638e37071d99935ed9f4bf2e224bfd));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x0574962e39c78fa0434f024767f9a1462f1c5c608dcbcafdc085286398e16bd4), uint256(0x0e853b4c56259b43f4590b736c3b68c6f100f92713742e60094995bf06093467));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x06cd14fa7e641ead103cebc94a39dde7fb08e24c33da6e26fb10c7d48dcd5129), uint256(0x17707a252e6c426e46d31cf35f75643a5f98b66c7070d9afad8fabb709b6cd20));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x186826780e80e5f955feb722a50c871749e875424dd6ad1ac91465d1751e4b7c), uint256(0x2639c522a0bad1ddddeb641647de84cbd93ae20ce881b4af2216e5660f1568af));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x19eb1782b3306ebb232ca5178e978e4b3c85f8f66be4ff2533dc115a55a7bb6a), uint256(0x05b8bae4ede53e696b990ed0b1927f7ecb1af32712b82a77a1b756833294fad7));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x2ed9469e2870ee8cd6b805cd28ff61bf6e0f35aaf7f849fac74ffbf7804c8e46), uint256(0x152fcda30cb5383541013afecbf0b8572db4352d6b54382e9155de3146365af2));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1b44280a43a50764bcb2cf093d1af1e1f94f4659046e55ca68d7ae1da3eccf22), uint256(0x26a7b3ae1cc2b84f337cae8cf459525cf725d110961d6fb0f0c47434f5bf11ff));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x0e43516d2ab515dcdc67023ac94d187c3d496b450ee9abc0cf77b87d4f793cc1), uint256(0x0757894f7617ca8f55eacd5b7367fd46fb2cbbe939f719460690833895447687));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x0f3ddc88cbc618e4d1ed54ce846270037167ddfa0608065b771e1b9f04a45321), uint256(0x0771c4c5ad7a7235b01884b71994a8fcee579429f35d77a85d3ad2d7bce5deb8));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x1378a8701dda6c30b1be6e7146258427bab6a859d2247dc008e8b67a2f574baa), uint256(0x12736eca0534dced71c49af9899b4b1a798149eef724bb8f7cb8b8d34822b3be));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x01adceb2841365a4dc1e2871aea44dc03615f8e1cbb4e9e2d57d7ae6b43c3d79), uint256(0x1387ce91f49f7ce63ed32dbc75306c6e13433b5ea0056904184455b82e9c002e));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x0ed6a6ba2ec646517e1ddb678839f5adaee98bcc2e43f990665d0a99a8cb9b81), uint256(0x1725c391f029ceec0580ce598d2bc43c231ac232a173500653590a3a16b7c980));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x002e680b2d9fb58bd7e310183da662afe5b96099c2cebbe275e0dc9452c753b7), uint256(0x1253aa195daf398de27dba1b175dd677a17b621d5b1bbc66f833b0e61d0c2bfa));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x1b93491c29f15cd0e3e6613e676f84247755ef321aeb0f49e997baa4caec7dc2), uint256(0x21184839fe30e50c06a5194387a85d3e30d71e210790965f7b6382998702b1b6));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x1ce58be5160c1af1ce4a5094f5ad7eedf20c0c01c49623a604e90e6c46399f50), uint256(0x1288db369021634b51616da8bb745cbaf38883b64282f20d3f33825f7c91a238));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x1c8ac21cf82649d81d7909fc2248245be050dbc11552f9a8e6a60ed4999bda95), uint256(0x2c40b51ff04b65fd76638e8e7eb950ece6152a324b04815c968a333c3d355d6c));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x2a2efa5168045e72232072d051a6769ecfba6107b9dc7aa7d9894c077ed871f3), uint256(0x227f2375598b69ee43c27b5d297319dad2a22264b5f1bf973b958ea6a935158b));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x039a4563db1919ca6397218704bc7eeecf3fa1b8203866bcc88b7d3f88aaf71d), uint256(0x00639f9544da625d44ef2ec61e2638fd87fdfc04f41c622de24f20533287ba0f));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x0563dfb2d6089477d148d4078418795de03db96fbe4ee526556852dccc81f9ca), uint256(0x04c0de0e451b7443597ac5e084a7ec0da31c68a12c553ec0a52cc3a29622fb34));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x0c40d70721ca25339235a6b43e97fca78a28fadefc0466fee02281c2476be46c), uint256(0x1219c127357e04fecaf64be5331d2c9dedbd5871ba8a0baa2bc676ed10cff92c));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x266a05228b93ea39e4b92d3e1e9680571c4fa9355b6f13fbe05cc1bf6e6755b9), uint256(0x1dea743b31191669bd4644a06a977d628affce49837e339ff422aa918de5026b));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x09e777713a34d10f252c1e9f5f3fb7eddf8409961c34065a28ea7970b39d6d3d), uint256(0x1188d64df8b2f9e1abc13664e0041fd5ef4a7831c60ec3dc4d17b0d1d6b0e6a1));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x2c8da72e7af9157b9f9436a0fbf221948b313cbd65d7d8a6889b5e3d8b9ffa1c), uint256(0x2714f90566c12f18c91982ae4b192105e64d2b1846d2c36337c109fdc4b1305f));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x2103822320e5c88c6eaa2bfde0d870b952ccd790755a0d9a3bbe8a1e594bcc8c), uint256(0x18f4f45e8fd8c37654312ad66fb7acc0e0f5af5f938ff20ffde140bde56a05a1));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x0f1441a59e9066898530066569204f126e7820e44861d8514c7d442bb7b51ed4), uint256(0x14ccaf31fad890041694ee05d92c611722b717413ec982afa5f8b402de266d15));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x2cf04018838e61a29fc1598caa6e169d04c8ec59edf54e6725a52423964b1e42), uint256(0x10da610f6055f70597766ae1e356faef597a6446b5abf002a79b064c8eea1a8d));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x266f5705f64bdd75062fd46e8ca5d0c09cc01fd5d2d6045cef58d6a22d3f7dc0), uint256(0x0a95ee057bd1f28687325cc9e2f8a0ee63f5ba7981c90de10334cdda6146d271));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x1c763018576851036a8453b1a11c8df928d99dc028c6b7750198946c3b740ad2), uint256(0x0ecc4e62925ee0c5a5bd35158ca3795cf6b38aefeaad388e679e912f300666b2));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x0aa2569a2bd57314193cad13de80519d8f836606398dc6af796e7a2f7ae45d51), uint256(0x2722b84c542113e927b1f79e99d21de1dbc6aa3fd9b89e96c1fbd297732fe972));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x29d1e3d9225a930ed3cc1e9654b4e09012080752fd84fbce23fea93c17f55753), uint256(0x0765c03a3375a55fd333789f373d10c71831436e05eb1846cc4d090adab5b9a8));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x1bb4ec60b228478d4ec92152ca87f3e13e518e801cead0ed3785ce7597b57b50), uint256(0x08f77f683577d714888cd192271836da5ed999a8b282f566b30b56fffe10b88d));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x1f6168487186bf98832288f89343049a210395b8f65f227e628ff5f7b5e1938a), uint256(0x221b3a40c77fadf78862bb7db3dc5464c83ee9d5e1c4c11ebdc3e85283028336));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x1df8573b475da845db8122dd11036c42a77961a3637a0e1ff60fe972764b83f8), uint256(0x0cd63db47d3113fe506f632c900e5fda7e8a9e4d92f43a18647b9ba0860a537b));
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
            Proof memory proof, uint[52] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](52);
        
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
