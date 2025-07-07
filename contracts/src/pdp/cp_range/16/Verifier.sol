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
        vk.alpha = Pairing.G1Point(uint256(0x1139d783124b5c33e79fe76e92ca40dad8768e887cc376ec4055e1dfce73d2a3), uint256(0x097e1ec209da6c939e326093d54ff3ec785446f31c71f6ee943f7c98d75eaf71));
        vk.beta = Pairing.G2Point([uint256(0x15ded417eb7e702caf57800c5ec20a0efc1a948d49f3df93f96ed584f36ce14b), uint256(0x2da79a3d3627cc9b2183cb63c54ead0151caa638c2a8a135c4a5245bde88e5ac)], [uint256(0x057fb4ccfe31f42bad703fd6e8d709fa457ab008f8d73bffd103ebe47c85f9b9), uint256(0x255d1695b9c7adac10a89850a11b0d436cc9021a31c1cde388df72ca041c1175)]);
        vk.gamma = Pairing.G2Point([uint256(0x018960e76ca42d8705a9c442bb08957caf06bc156af20052604642205e301dc5), uint256(0x1ea8c5360030931649f08c0c4e43b973e778437627b726e24ade0715a709e6c1)], [uint256(0x1e52b592fbc1d0406dbd69436bacda88ce1064a4ba365a219b100473e50ffabf), uint256(0x2ff47760cf5d8ae10b116bc7696c03088e8962ed345f92dd3a1f7d3f2d5e1cd9)]);
        vk.delta = Pairing.G2Point([uint256(0x1eadda637f4ea801cb8abf05702fbe825ed71a40e8ea73595fabdbc12cb47f45), uint256(0x11b0abf83eb722079e3bd213550a79b899cd808587525925c932ecaffe804876)], [uint256(0x1b07e31142bb3dd5ee64c4bbbbd44d83beb84f1b89eabfcff11e5e4c96eb127a), uint256(0x2bf7921b68179be1611198ce78e656b9734227505c42e31cf4c7f48e9fae3abe)]);
        vk.gamma_abc = new Pairing.G1Point[](305);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2e2151bb6369db618090e33c6e10c7c62dd6667274d6daa19fe4a5bbe8df6da2), uint256(0x12572a05c1e0e3131843728de453846604e60b35d66aa51ecb41a417394d7871));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0880c0681070e46ba190eccf82501928e7116ced59928c49111394a2cb16c6a2), uint256(0x2e953f2b67b1a17dd5f4002afc6268697014f721717a9efcf3a573ab4088d976));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2e17a4dd4836531c8c7c07880a73ef39f60a3a9682c75187e178fa497bc4df66), uint256(0x152ea6f6db7fe2b9394ad85379d5c8ca42d53f9daecc45a230c5928522d6b0ba));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1a47edf46d52f30a0411692789284fe4de9bcc0a0df401d665b504a4b1da741f), uint256(0x042739dd59a3ce215b1120a98edd44c32e4207b771ccf329b3bcf1279319c98b));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x112d32103b13319fb0937ddbf770ade57b30d306a69309d45bb2142a0470c8e9), uint256(0x07115f11f074f3d29afd970021921c71dfea612f2d584e6876d8fb8447fb0534));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x02ff192b73a7538d3b8b84b56e285d3450800b3412669aefd06a2ca7149a72c7), uint256(0x20132a3408f503ef4340f343fc49b57a4fb696eae3e8fb958ad20d39c2c5a104));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x2f839f49a86f3e85d64cf77d69f63328294a11b62d12bed7159289022f2a30cd), uint256(0x186b00e74db953c084dc56d33f6ccfdeb44fc3cea6394ebd3c23637c25ee29e2));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0d1abe57a0cfc83b82a3ae27c8b2cfe4f2d4db9a52341a686f271f0228a4df3e), uint256(0x1aceeb453b990a1b8a945ddcb822d1c7d84a61e6f2cbcef0f5651c1f50484a9a));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x02ad5dcbfc5d0fb4d86c00bfbfeaf0fe100011a03782902e1b9e4f785a57cba0), uint256(0x0433e5e288a31712cb6ef92eb61d48a935c5e7c5dcc547b050a07e7e5ba9331d));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x094342ca97104750eb919c5c6177beb736b3d7005a78d611b864c7dd209290c3), uint256(0x0018ecbaa3b0ba8e237efd72bae71e780217c5452ca94dcf71f4bad3d42e95d6));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x28c11fb757838a3a4f107ba750d9c04255fd70643124b4ec400fe303df3ceb86), uint256(0x28b556ad3ad801a77db0793e280497f4b8e9d745b84d1d190ecc69d5bd1f33d6));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1b340bd9ee1d11239a29a2c26e95e42b450663ba2235208212a829088743dfe5), uint256(0x140047dbe9a398fe65fa9f586aa5d449cd11eaf68b0b7db47484e317297633c5));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x16ef3d234a677a39ec7271b959273980b143bb9c617881a24c5d2af9c26136b9), uint256(0x1e9e45fb2115733abdb6326a67a3809b72cf712b8788b357cfcdf32fc1e2dbc8));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1745126f84d02db28e4ffcdd146e69c96234863857f7193ef091409f0f52692d), uint256(0x122b5e51bb66a17fa612d65073dcb6a95ed063ae5a089e1828fd46acdfa54650));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x154f166e77228b717bc24ce8251b3b6d7d68f45250f0df9e18d72766f6124adc), uint256(0x01ecdb5217a648d4acfcaf3e2298111dbc89d79a5940072faf2bff44c169623f));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x120627d452593e3badee11e14832a996038839f71257c625103a13e3f8b6b9f4), uint256(0x250b72697d0cababbd301de461b37ed9f6d13c708c252290bf66cb02e49bcc07));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x0d7a975dafa78d7e8878f482344ed3c6f60f5fcf3d1138c8c1d5fc9d38c288d0), uint256(0x0a318ad44b46b2f3ebc185389333523689d0d1f76538ce7330d017fa17dec928));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x23747600b594279b166aa7d95cac1097c426875072a91450f045c0b69fc97086), uint256(0x17383b5a5ee6bf51d105053c0d5242ee698e02061d42a87d692bc12c24b009c2));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x05e36931a5e3772e4aef5e2007c8b8b22f7966878d133b83aed668df7e38106f), uint256(0x18a6dd4802e87510e38872d1205e8d691d79921bd3adb7e396de6ab602863893));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x174a8e060cf2c9c3173a5277eb3fa2568863be1c9e0fc5f4ca4cdd502333e973), uint256(0x2382661e790322cad55ea4b90338bbd2938f1497d8bb9c9a85262bd108c25e69));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x1b5c64784d152ca403c171264e987f479fd8bcf49c0447f19bfd7294019245f1), uint256(0x092e9fae86c90eae27e29f44e0c1082092472bffa9733cb9e6d5b80608cf4c35));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x01e63daebde3a4d5a054e661e3d5cfcb2794e7e600a85cc9e555c0d17f648d14), uint256(0x1965b8407fd57dc66f0f63d5de207c27b0bec6b3da5c5aeb745338bd88f1a1f3));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x0d6e0c15d428305257c449beffabd65cb72574f083461679adabf9b3d05f8812), uint256(0x02282066e1925db39876afc256fe40a46ca61949fd4ae75f08e07ee2199727c1));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1964fc041008c3527e25fae8b6d0c183e3a30c93a58593f2307dc2f2316640ca), uint256(0x103a2e26c0f570d79fa76414601c27578873a9e1c2512a57cf95b5ea67bcf0e8));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x1ce6caeeb7979d6b33c169fa8eaecf268252e7ebb4261fb244c0c775fa3d0a84), uint256(0x19028911bc9984e21a4c8279f60c0716987f6b26b788ecf0a9300087580e4346));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x1eb158df1962feab20d900399b521e4abdd10a3cf5a196bfaa7ffdd36baca101), uint256(0x2c911c98e1b7b43dfbc6e2010a7a14a316327b6575a3b082f961780d7dbe8fb3));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x0074239b6ab42e508155f2f43e6ce97c3bcd51dee972b41fc9500d029854a522), uint256(0x0bbc5b7cca2259debbe8a928a60177f2c3345b8020217666cb35695ac5e446a0));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2f8eaf3d8c0d534c5f1104c9b29773b3b98bf4bab6189476db42b8b86714ff0f), uint256(0x2991b4ab93c70fb6b7214ec5daa6514fad1eb98a013b2ef3ee591bd989e899d7));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x042f417dbfb737f76aab55e93260f570c53c813de9ff13c16cfff74d38114ec3), uint256(0x185327b294e86716cf39789f751a638bd85766dd26fae2c7868c17f5fddc9b14));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x0ffd1c21333692c8576dc06c5349230fdd8d783d1cf766b8608659d8ae9abaf5), uint256(0x2bda4943418d9393754d9cd1d06f088520a0305e1c549346b24fa1245448b36b));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x29506db50cd2276b6db1fc2829e0f898906cded316039ba449a44393793c81d1), uint256(0x1c2a19386c4ad897aa33678f66f0b413f7f90a9904803496d10dd8075170bcec));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x1e7a75642685401a3537e0467cd6a6720a7130c109d604697ab999e11bcb847f), uint256(0x16ee531b3e3fb41e8664ed9251dce3fd9df7b24db21bcd25cdec9a41ad485d35));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x01d7a51f7e572e4448487caf082e701cf4eb63a86ec3c448750f43cd46de17dc), uint256(0x04bbe98e861f540c6f372782a713b1ecf4cbd549f0b9135c868382c82abdd738));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x0fbcd71bd7ee2e0496408c601216d1d66077b5a0797d5179a1b5c29addc11081), uint256(0x253053971bcbdb10a51b36b992457e1ef96586448d1c677e44ac01f1ca53490a));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x2eff5b754a9f1a7922388932982062561f41e80b41139c7e4686eababc327dc8), uint256(0x0f5c894430e606e866e3ad6126c74d23c534ffd7575c105317d3d433074cbf36));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x2b0ca97a7c11abac08b67b33cbae5564d17cb181131d7f3f1cda8c9017fbfb0f), uint256(0x0f77c53da75bde0e738c6a516ea2500fbd95500da0f4fc364009a516dbbcf667));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x0275aa86b8029cbe82eb702a6fe03e3d3089eb901520dc4e972255d8ac937869), uint256(0x11640b4640291ffa502fd9aac2811ac0907180bd837d780db99d978802d72f06));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x1b87abe46b970a7650f894b13c85067bd6f8205dd9afb6eb643e4034617db2ad), uint256(0x2af3527c50562ab4b08d689973a227d73d5e602fc367cf8b9c8ac848c7d40620));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x1335b3dae2419723ba1d7be85804a3180650eb0c5101795c316f10098d3ef582), uint256(0x0bf91a52426133f0d3073638993f2e3a011d16efba1e5de81dc5a23749b85cec));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x07c0005a31d679f02ed83fdc15354f66b20952b910d62068cff974c9bc9335c2), uint256(0x03fee57f0e08beb6aa9d59c3cecaa78b61e3bd9632770776e4e514be51140530));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x14eedf06d4f3a98e15f6cd40f9a9e3c404de17f0aa877177da7fe1c6f2a38fa6), uint256(0x0a28d236d8c0024fee42c185740a395c97f27dc5c4520c78fac0f26d9e8326ad));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x1323df673aeb00c4f777ed28438827b4fd27433d375344d9644d63b8f2ed5321), uint256(0x2f948f7260c42ec602b6e6f7b13d51b38b5f408042d1aa2f4138ae835908bc5f));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x0f582e5e994227f4f36c25a6a3b29cef8df7117088140a0c68880518a5a5cd52), uint256(0x101516df5e37552c98a707a0f570509e37424d41965113ac3878ec512fa496f4));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x0072375dd9a967d56a10c6afd5bd6eb16058f31cf923e82049f15dfe36c0f0f1), uint256(0x0c7e86c7734d72382489f775e1adb08c935f6ca6ff85f1a1b44dbfce8140c135));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x24d1b7abb00f91f20a2a46b28ead0f496b06b00fd8a4d8cb8391d295e10167e6), uint256(0x1e4d1cef60ee5155947919080072c892a0cfc29669d0b74c6ffb543df6f8af5d));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x1103931651a68357ca1e61cb5c3f78aa7bfc7b35563c977b466e53bcdd2d20da), uint256(0x07a9934db2f7617b64dceefb7cac665dda1e27220189d6f79bbe7d1a4dc89fbb));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x2a92cdcdbc8c864e947e9634636a1f2030064cc140532e74b04a429819ffbfb6), uint256(0x08607fd29ec8defa954b8fd94dff53fe636935f431e339a09e782b2e255cda03));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x152ecacf1419568ed32ab61583e78131b220f82fd650d9795beda2a50430db50), uint256(0x2acb7768348da5f0ed094a69cd4af057177daf7dbb649602abfbfde2fd36d844));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x1617668535e2e51ad8014b22c41d253f13a74ce7ed779cbd33b84800be3f0bdb), uint256(0x237247b7d8e84789b41066b1286d6fbccb846514b2e5b4ecc7fc9e6390e509a7));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x2feba9c45b896910c7bf3a42a7db00799168918430d863a11b8c91faea199fbb), uint256(0x00061b1a780d66a4adc7fed15449111c087da0085b51d397ee83386f6c8f474e));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x007eb2eb569bb5b31742cf004f7a413d8d3a91da5fbee76baa02312b68759d5c), uint256(0x1950f84aac3a10a10f391cba1e72246a26558730f224b24b801aad28359f8fbe));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x08cf8c80dc05d30f7cb6453f35770552fba28c1062cb4fb87ad91e66274c1cae), uint256(0x087f65a657291b473610ac5c27ea489f568839b12b3347fecb091559a54a8fd4));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x1a466c3a8601d95d1d83dc7dadc103514062560abdfdf7461cd82ed98c0e2b7a), uint256(0x0050f787bf00fea7a7706e0521b59af8a9c31bf20ca82c8f83d1f6ca20babf40));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x26d82e31080b19651ff3deb529f663dac53b730d363c37183803e1f8b5d6a735), uint256(0x107e31e131abfc0d3cd906f9475ae25e48e8e4bb6ff01827c87ba776a7fb4ca0));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x259619b018c4bb3d50cf73f524607ea973a2e87357b9f6f73c6e10fb969f5348), uint256(0x2c74e98bc1535465379ecac461fd4d07f56209ded8e1ce5ff91096c32f2f8fd9));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x00d9c54aa2fdaa1103d5f2ece9535a765619a8dff232e7d1cd4f2a3a784cac79), uint256(0x0759066cf2864202df6857b9a4b0fe570df0717e9ac95fc7e38f139cfd9adff9));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x05fe8162329d57cef3742ad0106c605f012bc9e0f8fefe02ab8dbdfe304f522c), uint256(0x1db7e3c4066859abc9b5b6962e98a99dc2b3731faccafa71f490855f0b48df5e));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x0e11e7747a0d43102b9f483b3283e8341cfa608eb29de590a4f55ccb6fc365e3), uint256(0x2290021dd0d0eafe3c649347fe086c15601c89728f65e435a9e72b6a44ca41d0));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x1631d71f9c20541ca9cb584ffcbda7b7f76524f6552442fbe5242d6c95baf1d7), uint256(0x00ff8c452ace498ca839b8c35f65f93cc7e58cb1a31ecbc6f606ab7ff0ed94a4));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x229d7858249f65a671d70a114adcfeec12668c6e0f9555f189a1fe268ad63a91), uint256(0x1838f881098bca804ce453ad824a5763a21f77bdf0a33354aceadf678996fa89));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x14196e4dbcf24a2acc907124ddb6c58e02ee391c3552f43cd7de2fc313080598), uint256(0x2585504a17c5d15c0600d53a4a7630160f392a089a5870ec4569380ac85d0be5));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x2330e737b79464477b57b64af0b89a5cd94a2a81075f0c8e88c4bfd17bb0b6bf), uint256(0x0c8e4e83a3fe75a2e7b7d0fa90195fbaec0184b183a9d1f5fa3822b41299fa5b));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x0e84fc05f948556cc386e3bdf1f93a865a5e5bc24a689b99f9f76d8ef63cf2e8), uint256(0x2c446fbbfbe053f2c9278a9e4ca6c9408404286ee13236392891a3d43dce3024));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x29bb3bcb72621487418d53954879ffbdd8fcfe82ea30f3ca8a09b51fad203c8e), uint256(0x1ff1720b218316e4ca89c37f7a56dca594a8a135717260dea90d9cab2c0162cb));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x074a8d0a9612a2ba20157860be469ba8e6a67119fb627d45ac71db1c35184833), uint256(0x2574fbe866734605da6bdad137939bbf91160c8cf7da653b87c3dd3cc305995e));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x21c7e258c043ebaaa1e232208d3b566253f61b30e800f983339466dc9043eb30), uint256(0x266fe857214ce7ed19dbc9ea7006c6cc84fcaa85c5139f68badd098df7df3ce0));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x248217dc415e662a5397a5e7307f356583bcceaab98acb396956352137b9f9e3), uint256(0x045c65351020a5a6b0d0a2306a706a04f822639eaffa9da507a678d4d442a526));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x23f5838b57ee6984e45d312405d62f5921c5e3f3a452c9d7bd343a79a65c5a7d), uint256(0x028099114e0112040cccee9591b03ab9a6dcb5c5bfc3afa77c2e244d4366856d));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x0c7844907c3d20e00cf96f8c058ca916bd6c8c004fb6b217b95be9021cdc920e), uint256(0x0674945280f6e1d74606ae3d4bcbb732a505d1b451bcb02d311d8b758c201f36));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x1a33558dce8a109b6dc3b0f09a614051fb46171fdb1aa7b07be1974820d5c16e), uint256(0x0d4a6edabfd67f19022af040044b724a42f5d74399bf8ed0abfe9fc80a12377e));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x0be94a955db51114bb2de83bcb37edc2a304cafbed2809705f3ccc4da04d3766), uint256(0x21489307813ec9d81a682cc014b9f7cf5ab3a659f044b4d48de4cfe504584a6c));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x19adddb0c050e660f166dceb5b1add8923b54c0e1fc1d81f4917e2c39bd0d876), uint256(0x033173326552f9b0b93feb2955d59d152faecd80dd858aa39b1851b1d6fab817));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x14e44fb7c32b7d0c24dba68b9ebb868f285e5f6578c0e8b00202299b8c122447), uint256(0x0280daad7665e33c4e4258af6ba74d2f56518ac53acccb0b571ae952193838ae));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x084cbf8e46cb2328a27da96053c4aae03d5ecb50da047ee6a4ffac99cb80b137), uint256(0x168e20d2adb99de3047fc21dfb9ab4999c7dc348e5ba7dcca9a39ba61b14be33));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x17494344ba53067fc5a2c35f8f2d4e8111dee8dac6e83989680b8738e06ee4df), uint256(0x0a01f1fd5776259452eb5778dbc28b9b547baf78be482499d8bd1b1baa78f30d));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x02621257fc200835de20d0aee571d95c16bf5adccb38d25c02d571795d0130c9), uint256(0x148e352888c999db3d544b07725d8fff0a23d6835e139a5edf4d9be89973c3e4));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x2d9a46a9460f2c753532656e951c520ae3e192ed4203e2d6a9c97c629b2c7a22), uint256(0x0e8ee7c45d4619ddf1dbf681b342e75fb651b9b43ce61876b6828d9d224e9efe));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x15c8bb61223903375d0ce1c7faed5c21d27576cbd8e5a6cf4c5041da29a35fde), uint256(0x2d10ec3a4f79b7e16aec57f68c01794214a9e6a9385113f6eed00f774c1d4fff));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x261061ceea1b6ea0035b0f3de307554adfac264061f0fee512d1505703940f28), uint256(0x25e2e95d6220bf4f86430748741d91948f475d138d0ff189d567a33fbfa4a36a));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x22f7eb589525026591f5a704698cb996f9d9f625e909337cf322e0feb00ccc13), uint256(0x3022dc6cae2ca956070c6d402a9e9edba26ec64d65b83a7c541fbb2c4b339eb3));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x14ea8e9a3653a4470bf56c934724de07277c42b1230c8ce7eb3dd52f59d728d5), uint256(0x150864955424ad522416511a89318700d73b9b366174f2f524e92113e2d6210e));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x2d5c6aecfbdf674c81d33f21f4de568a0e26830c1e0defec18b9203be161d3b1), uint256(0x1355064437efc2ea7afb0738bef2016782fbcf21aca3b3c6b60b0627f356c435));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x1dd6737a5dce977a4d715eca01f6309df41a7950d6d56be1de57dd4b1eac2f87), uint256(0x022583b249b7ef4277314f8aaeb5044ae832710cb57dbd972504025b1df485c9));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x1f5efdd73b480bdaa796a3a0514e601dad912a0e65da3b4c0167b1c459d32a85), uint256(0x1d2903bb623ab00f43b2a57f72b176ef623c40f50a5eefb03db6c82bda8ae51a));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x1a5e8e2d309aad25f063f1cf879f9a7f357074c8a3da8af1ae35620e9e170b52), uint256(0x2de83111d976c57bcb061a06188930a55ca34b681c205912a1a3abdd493a1120));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x0c5a2e4396fc89bed3020083d33bdfc8f9de535e2b4c65af77ac868cd2228e20), uint256(0x2487a57ce5c08b1142a6a5b721ae71f871fb6697e11ce7c2526bdc7a5bafe82b));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x294349de1633e8849c16c5fa611883baf67ac27b8a6a4d9b5e106af76fb817e0), uint256(0x0f28c3448deae792073f17adcc3f898eb2ace4852d9447fb0741666a6f0ac038));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x2ca346cd3649a8e3f8077f1c9acaf792a65a75def06a7c53bf8aeb4c7f677248), uint256(0x03d4f868554bd96b72ba1dd072f84f17e9846517322cd46ed04587505115dada));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x1c0cc44e0d62b31fe21a60c09c589830fecd69f609ba5859f610e08145ce9c20), uint256(0x0b3bb9e85360202bd97e3ec441a5dc670b983cb0650d3e34eab593ddefc4c84b));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x082ebd6e5c685ee47a97c1fb01f250300d5e949cc976d952a800351df6da4b69), uint256(0x0e4680ba52689199c34a9511884aab09efd275226660e0fc26b11cffa312d3c1));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x18c2270de12aba8277c9ae05350db806a4eaec2d02dd377589154ebdad83dcaa), uint256(0x2c18f2b00010982c4fef63c1abef9f5e9fa20e2cf27b5c2cbbf20f1328e5aeaf));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x185c36f8e4ec2aacba5bd47e661eb9b5229bdf24847f148e581c030922958268), uint256(0x15ed04f733cc2383a5ead8a0c460826071322d5124db6eef77d55a7146bf9b79));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x1b50189c7a30c3cdd34868df80526432c1876abe410221b0f8accb6ba6b3f01a), uint256(0x0bfa96973f5c6781a69b0785450de07ad25ccaf31f655207482f1001433c4bbf));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x1e2c2fe288732374524b983c3950e6232e393542582a777ba14b2d1c5010a5f3), uint256(0x0b01b3510dc2700687adab6b54c885a7d6c94b5aaf88e37f685cea54cc6da940));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x08fd2292215bafcda41fb1251200e197a4ca03337db9782a67c64cffbddc9e39), uint256(0x085b5c61b8d4c3a2598d8b894ea4817f5e72e4dc172433a7c9c089988cdb51c5));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x29959be2e7c9134820289bbc6a21917c1570d9825d9c93dcc7bff74484b15bea), uint256(0x1f930e04b2faff1531f57f6b7c1f66c9f4a2f2f6373034b5cdd3a8d3fba1f52a));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x293f64b2b24d5f8c4dd623b5edecd4c768acc2130e145a744cb3a05677ac3003), uint256(0x2bac88ba425e9d6734981df75e976acedc85039493f476905b587870a3797225));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x28193d439645caa1e73b086611c23a60344312a16dc85ba0401465a1edde97f0), uint256(0x0f362d958384e99135edc08bb7eacfb3717a663cb5457aa607d45c2621e313d5));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x19c590a27c56795f31fae62b96e8f78be9c0779930550d3cea878b87d14b0079), uint256(0x1c05d768f5d98597a11be4e077dcee3511165f573f95f7bcbd0959e5dcc8435b));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x101a1c902ec36ac96f259d107dcaadae7eecc37231164a349e1c7fd58a767589), uint256(0x061aa4fba6eb0e34535b1a7206a29be3ef2f379c6e065f284f02149999d22e40));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x207d7a2e0a25c1d610cb4e847fe5af460e71fe5be4950b7e143d4359c0bdadd4), uint256(0x03a2ac3f339521ad3acfde4e6c4bcf803b45af59bffe395b4fe93472fac1685f));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x0f72ce53b5d838e2a72569b7d76f156a1f51001c10812f69494071ff87a3950d), uint256(0x02a93444723459edaa26ee4e75be006e315b62388942fc04d9156eb53faf503b));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x12f862184d4d970abc0796318c510ce1aa4164cd01eb17f6b9d64a6336e17ff5), uint256(0x097adf89942084887b256f70ec20cd97af60a375dbaedb4a430f0ef0324208bc));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x00ee34130f8eccb544780b15d959b3edb5666dae70eaa62da10d65aba1a8227e), uint256(0x2182b5bd932a1607fc8c0df448c444cc3570b831959e3b16707eec7753c8c47f));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x1a949ee6cbae8fb8a905f7983805781ec9a02ef2cfcc7c500bf92c710a4e9e49), uint256(0x305f82d59d02d5e34d76f3d8d5c84392fae1478a765ba30d9f25f51c01411470));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x0093099796900d08c8d598ae4559a64cfa4f301d76a795391df1f7b193865002), uint256(0x0da05f95312ae97817a789d0e7f77f7ad1e62cf8d57e43cb4fafd1d29053cdd7));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x1131c39d84d2351392c907c9852c8b7461fcc6bfd1d389e24d49caf948d96fe8), uint256(0x0fcf0efebb90671bd1fa0a56602b3d3b50fa4d80c270a32d442c2640fb411dec));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x2fb0de54b7173934a84f872b5b8934484017deb85df2f8fcf10e3e0dca5d165f), uint256(0x1b536d9a089f9c091d0bb33abc2d0068dbe6674cc41126aae6827b7aa2e51e2a));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x0f39e460a0d272542278000fc4340d2fd777b6f0e170b205850c7bf9ecc9d8fa), uint256(0x200c6fc9f123c4350f5dbe93b0dfba40ba7a1c01592cee98a89488b9f76e0186));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x0e062bd9c6b6b4c24f0cf46dfb71a4a665566c57de5217a3273c960fb273bd75), uint256(0x019a6bc64add142d2cf717d2300d7efaf944f3f12811455a0bedc11554783bb2));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x2cf07497f28753bb07af7df61bec115e4535110c5c84aa9ff21d89c369473023), uint256(0x298936ccbc62c619b086781a0807bf199ceea5dda0dd5902be72397106b4bd9d));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x106d86f62ca44757702e9f1d6c21b510185fb9f6a92a515c1d07c25b5e7d3b38), uint256(0x00a8fd658b8bdb4ef9b15034784b98c34a5a29e93211f6eb32ab24ffd3b4b536));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x1928ac4b04c8c441e381c58df11ce598d465f6eba598dc324a91ae2286979a12), uint256(0x25b05decc275b0b666cb490a4efbf5b13af880b9a5bc529d9b8447cf30f44865));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x08f474ef1aa95aa0adbaf24206604ed04b7cad0ddd0e2fd326776586ff499c08), uint256(0x1b9902d4cac4122ec485e1f58571cce1b3fe7bfd252324d2779eeabebdec0df0));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x02465f20048e7fc77beb08550fa6fe9f4339711aff2587b377eceb1129d785b7), uint256(0x205e67e11ca742b0e5d863096aa7d972d8042b2bb365afee19fbe5c551c701af));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x0cf72522492f9f672cb64d1d2a69590ab1fdbf55bca4093bfa8a164252e72feb), uint256(0x1e4d49a51c767da5ace182a5465cd7b335cf7b025bd981264221bcaa03b55381));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x1cd121a1fbc4f48cfe1fb7975af834bd79bed1691f9b271a10e47c6d9caa6b3d), uint256(0x1579398db0d9b6c857668ae712f003518fa6a76d8bc4d4b8044251e090fe4971));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x1e1620030632b538d01ee335a48ceac1bbf68224345558e92df7f9ee83bfb226), uint256(0x2562e12e3e28eb8c2c2a7841c2d5d3fcb1a89222ae083427bc524d2c0e9652e8));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x2987c2fbebb8fed2f8820dab1c2267b27b50a422ed845e6d7251b1f9dcaa2626), uint256(0x1a725c85273aa4e100a11865476afd9b8031e6593ca665e80e47a7c9f121596e));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x1c1d0e5cefb6a9940c5a637b0af1d9e9294dd95fb98bed8edbf33f98985172f6), uint256(0x12e474cdbf43676738f77ef37c61a8b7e417f5c7357ecdbf082cc94b48d30136));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x097efebfc0ea0d1f0aea69ab5f67c8aedc3c61e8af58fdcab2a3f5f65267f323), uint256(0x2be3efc5dab32a134ed269092b02805050d854bf0f2c3e33bab6190a0b616e36));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x00d61f2ea3841dbb0d8b27d6da1170b8ad92ebd981183161ce16a92c1afe3c25), uint256(0x257c7e0e99aa936a08cff10f54265be680859634eec80f9c537e727e468fa342));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x08dc76d2c6d3cef030512c4a2b1076eaa52de68be4fd989ae7e4afe9b094998f), uint256(0x139410dab09bab81183c97ddd42e2ba13729452c4a9d253d8c84a72c656fc302));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x25dc70a82b22eba943f55d3d86d6bcbb8e7a04c9fa608b868f01f55f76ad3045), uint256(0x1e8e1998384a4abd0b2ab4f0d768a85a97ec34df6a18025189f7fc232a71edc0));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x0cf40552f5031907143e35ed720ae54fc817d493f408d19ba9eb253afb4dfd80), uint256(0x014e922ba464d59cfdbb94b31c78979350b693ef1abcfa2c3b9c903ddaa71398));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x0a1c0023163efade500f10dcad9f05d47efe5bc14c9f498b87b97f8f923384ad), uint256(0x13e85ccaf18fba41aaca9ccf6b2685be4ab427f86ba9d9a402a0204d3c8acce6));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x2d2b58e3cc71968433d7ae5cceb28fc5ced663f4dd221b0f44f5d2f41283d910), uint256(0x1773d7be234a29d490a60eac49cdd064084b09bfed8414822395b250cc95a386));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x29d17d574cf7e175fc1d8ed405457bc57e34695d4c22992aad9eb0a8e5d5566d), uint256(0x132baf9f33046a1f9d94c8afdcb5399b747e09bbb38805d63f685d6720629c7e));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x083db6454c2a1fae201fe5dcf58150d9d92f41ebb3dac06dad75e1a6f188a53a), uint256(0x0884f91512f5510638d33cdb314ab60f19c496b720ae5a0b6d7fe27e5019332a));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x08dba5a482b192b31d2fbef2f0040d665c2d306293b99096ec6cce32a7fc4d00), uint256(0x1e3e555eb0f4a5affc291151329aabd8fc9df3d09b235fc443078ea1f54d084b));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x20b857af54c238915d5281e16899e8d2367c6685489369e0b959f411938de4f7), uint256(0x06abcb0381ce9447cccf772bbf5d1cab10ce469529439c2905f1cf87d3f7203a));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x1403cb921bd8375b2abfd97fe43dbe33b1071680f883d76940b076fa6425ca23), uint256(0x10216f37ea137d28e3f86e60ba2a825f694d5da384c6b7656d70bab80469adcb));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x0b402a8099866de8c14c75e7abcf54abbc7fe221bf58ddc819ee205f3ab39eab), uint256(0x1cb2144c7701531e5283e94feaabc148dbee43abea523ab77059b933d5b9fb93));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x19de1209dc58a4a1d219e7269a2a12fe0a87da319492631e348504f59956a1e1), uint256(0x2e4d09e9c22ddd27370cb48a1a9aebf4e5357e925118687afadfbaff2c9066d7));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x1cb5720cd557d8e65f38a617e142e02050cd2798fef6843d28ddd85e5165e6f6), uint256(0x2a464e294c12df8b47ca96ad763868b8954150307db007c7d1a920cae6e02e3c));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x0a7a6009372ec25ac9fc6c2555c05cf5a488e4b5996c72b66d6c8dd27e403d73), uint256(0x0eb0d00101f866187595c90322a37e2607e60989036e1db557a9be27ea242319));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x0e66c6582a0290fe5a6e69c43009a7a38f808c40b7edff199b4fc807de51fbe2), uint256(0x14dae412cfd5c46ae373c7c0a12c012c2ffc48f84392c2dbf381a022057a157f));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x10c2f5579ced09f7218ba6f04336250e927e2826b5e09b53f37fb112d6d9cd65), uint256(0x2f3475c595dcaf00d897e52bcfcb7ab5ef7fe50e6400a0a273f1752ce98fd27a));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x0d6ea3087e999d6daa8b79e7588eb6c34301111cf0ca5b8e0976c4fad0cd58e9), uint256(0x178e3e9d5aad0639afb6182d2760029ce29f3841e422a02ebc47385e2597a94a));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x0d93e8d1e590b7140a725881fcec4ce17aff18a43d512ea53aa27ad3c42de091), uint256(0x1d569aeba78ba7ac130121daae60ce23faf4ee6720ca65bd72e1776b8e5f7f3a));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x0200108d3f9e71b06bab94f9f383c96b7030f85d9f8e36f640da595442485377), uint256(0x05dbd1191b25cc8a26eddc52b8bfe27fd18c770223682ccf0ac4c4f6182d4c53));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x0038389096ec26b0cbbff1c70d14d571e3a2415dec62ff769dff6f1022e90dfb), uint256(0x065d333047a51b21baed70e97f55637afa021b422bb2f90e00f855ca3c6a8f18));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x2bc0604ae05628417046ae19169c8e5d099fbbdadf10bc5fc6534544a024e49d), uint256(0x2e3b4734c6afa5c8b10d84b2df9b63ddb3b96fcc6597f7ba16793f45e9d862e4));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x2ca380958ced7379134c3032fe285e46e020f784831c1315a900998ee7766d9c), uint256(0x1a4b222c17668ebdc07a1ae54a2ddc4e2537bf4bab7b80982dff0399349e2a09));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x1132cbc08bf58724743d943587eb79c6c3dc1a6a2d911c106479fe1f593df33c), uint256(0x10b502daadf384e5c1382dddb59e4a8fbe4cecd42f2f914f3299fa5f385e9378));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x14f9dfb62370a601d271c729d19ddc6fdb2ce2cc968237c65c0bf7ff3d96cead), uint256(0x2219981a3e87de31cc35fbd724fa0c737d65064aca750188a20d49abc2f71236));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x2a843941a928e299ab66f3f8d42f2ad72033659a5e65cb140b9a4977e67ce502), uint256(0x02d368d2db9eb54b473493cea424a016444f1b9b6c90ac867b070f3c4d8ed8f2));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x1077da82fb04c849f96726bfc822bb036fa42bf1b69a9cf36764bd125d70510e), uint256(0x2ae5c7b7598a1ba1b7ed29d7a7d5a9a84d5484aa4dcb145ffdb5791036c17e4b));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x301f37af054e8d2218e9cf2a2f0803bcc71ca1cd633b96fb262a04c1b3d1dd5e), uint256(0x0c2f596b57a3ca5d1e7b1fb34fe22a422e8bf62fae4fe0f66d018cc4e83337af));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x00f1c3315278ae93a5304bc96df493ff87dac9c9ac34bd9a43685080effc9a87), uint256(0x04dce1df5cae48777c8a0d67dcc46b0211fb77619502a350e87ca2798ee750ed));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x052913ff3a79a58fd239ea0811cf92e052d97225dd4059a4e1d98c960967ce44), uint256(0x109e693e6e594c6158e231ed53a5ab98176f9fcac16e8547f247f625496b95d4));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x03b4cceda4527edc437cdcaeb4ebf02cc9f9a9cd83d3d5582f6f70a9db7db6f7), uint256(0x203aad9e1b7a42b4bf0e8aa0b0c7d04e8f9ee1cd8488425018a2674698fd31fc));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x2fc72edbd3fb9f62f3675ca9eeb15b3ac0fbfdb223afc2abed8f1f2bab60cff0), uint256(0x2454932a78ec4a324d664051cb47ffcd9ae784531d6f3d4362abd8b1c16a4a10));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x2391d1ef38d9209f8fbf83ea964d07b7b5f24f2da68bb600aa64fe3f13a9961e), uint256(0x04a5c892edf7278b7c7eda82164cdc9120ebf12f89c4e4d15dc2149d8ddef776));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x0aa1f4651bcf76f9a74d86a2445e500210c191da9ce9ada322649214075bccc1), uint256(0x13f50d1043d54b6facb0e6cefa0eb9c25acd7beac23cb8f11ce180d7e6c497ae));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x0c4d808296c6fde42ac8151f64e47a2494ce76b93a7bbce37aef09ddd747d28b), uint256(0x02a0518237d0e4c2c9f23d29dd604e725223c04ba9e490534d81757ec458da99));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x238074ae6107d785fc1d120dc13e5ca3ae0f4677106f030ea2be96537f53de4b), uint256(0x0826d37044917e9c60faee321a978e860c5b38019241eec95e4cf85d39b07777));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x0f207f26b92d5d90d319232abe32bcffee381937507dc89cb509aac5dfb20ebc), uint256(0x2dc5f30de89abbee3805f809a82b3f7886d9e0bec71e6016ef97987aeeb6bc81));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x06caf39df1e8ee9d13f1a3939de3953174de783349c557b1c518d1e8c4f09e25), uint256(0x23b7334a99e41f81c2dc4d38a974eeb2ce54193933ba60f74fd426cae70a0c26));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x0de09120b758a08c4a181caf04a37261893fd7e237f6f11106a070bb3a4062f2), uint256(0x084fa43fe4aac83c967e2c01a53fca0bc1e60bf09c710e024e25f74edc83982b));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x21d499cd15398d5c79aa42b5c3aba2cbe56aca4289cb89f509c57fca143738be), uint256(0x1cf4d977acf030c058449e64cd188a780c72c253694cbc79be5f602188cc8f6d));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x04628135938ef83a8524bd38a44b6cfb04da1935c9c355b49f547913a6338f06), uint256(0x01cf1c3c49c429355dbf0ace8483c5e4cd9c4323b3a675f13607e93da1eb19f7));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x18847ef9f5d326e5f6d3f0eb762ab9a230e0a38f217249990682ece6b17ce6b7), uint256(0x143cea15e1bbbca63101eb04ea356a9ecacf0e919a22c5f4adda3e75ef5cfb50));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x2b9eb9fba8c9e4c7744cf25618e31bfc4815cdc9849449316d0e5f5951e390c2), uint256(0x257b396283552a504f51ccd058500f6bd6e728a70338aa3ceb932c710d24dea5));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x00e2487bffe37525c10c393f21e90c172457c702404168047a3419c72eda9a8a), uint256(0x0f08501969412942fc97f5107b12c13a4e58c91bfa6b7d3d81752eeebe290ee7));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x0766034a4d11e76c7369bf256d6b4b56efb1017a49e4744d88012dfc1c7229ff), uint256(0x218a8d8055a96abc135c7171704bb98d7f9cfacf54b8bee629408241d13c64dd));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x20c41b364f41c5832aca3f10fffaa215117fb7441af06cf941f9e06a5cbbf1eb), uint256(0x1ef71497417165601786f88d8b86ad0a145270d597275408d6c07128580d27ff));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x22aef9d7d36402bbfa5e27f0abe8a5d2a9b6cd299bb7c62f8284f4bd2bc459b9), uint256(0x08299eadc73cae8e166c3428002985cbb294d35226a1069a30e2c03fd1648b46));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x199e34a01f2492e3c2f4e8e270376536e75d37929a6243ca488cbeb1b5555ca2), uint256(0x11630af3c183ec5ec4fce12edc3acb10617264f8a68f4b1292b791e800d8afb9));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x2f55e1aa2a74aa798d62154b6d5293dc1296283e7614157a29f5044a83f4a016), uint256(0x04953f9be0a94a162598a30d7a734c802b84afeea64c20859a0a3cd3f297afab));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x08cd73923c5ef8ae3c511b2980eaa3c991ab1f0adb6a473371928d8a8892d4eb), uint256(0x0bdef05044b1d6c1e12c6f6fe1537e909a74ea6fcb95629de177cfe05ad3c6ef));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x23df73bf0f3aaf0aedc8cf4f48adfa8d71debdabf31fd5486879411122d5adda), uint256(0x114d2243bfb8d8e91df98f7c62eb3cfb4fd75210e226e3a8ed200045da7db30c));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x16689d43953541c6829d86d1671de2ebbc048abaff686063700c0971117d82e3), uint256(0x22563beabad97f4050de16fb05b4a800f6e78a70a619b78b216474f43b4f7ab7));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x0d4bbdcf647edba13bd56da4db4e7dc6510592a153d881c06edbd5086804f28e), uint256(0x1f437521e30f8aea39167199618f2434472a8d26049f9b9efa821d07dd9e17ef));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x0213462dd04b8b1e868eb9c1ed1a8c31866b5b9932df787bd7b9253e561449fa), uint256(0x1babacd2a25d33be410b0ce5f810d33b13c184a6abd4bbcb030642c9635e5bab));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x304fc7bd5ba7a4dc19783482da57b16307a028f2a9fd885a43a1f859e2a6a91d), uint256(0x013f8e6be1060ef386e7e6efbea747cf21ac456a3c4998c250d942884734214e));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x2774d7c1a6e3d8895469b0db5cc4270ab46526f933e6a96128070bef7fa5874c), uint256(0x09be5469cfbeb6dff7bee694f154e2b8f57459f30b2701b9335cb18c20b1b6a9));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x25311ac415e7f147df9c4aa653cdca1d5e1115445b89cea9471c771f790e6f41), uint256(0x150feb066362e19374865816481740752a1f3a455fc46f71b026c11de3125a8a));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x0c53ddae00b9d1a0ed4deb655faf12142a45b6bf90d010bc02908277ef4bde07), uint256(0x0964e926a50cb85af1d7045c2a856f1ddbbe5f9f05867429956e8e38d00871a4));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x18cd5ab8e58022c119204e5e07463a8f96cf4ab9d856bc309f1ea4b25b1b6512), uint256(0x034388b8d3f45e33c56ee074b55fbef322e9dd396fe479510075cc544c4ee2d5));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x2ece1a6d4b980a93906d00b50edf83322be8d1dc7d7a167a9f87a48a043a1c02), uint256(0x1df0e71b2a19d3357a4f5cb1d57b4ec44c60787ca731dcecfdc7438d674a02ca));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x22a86fab92507ca314121d7baa65d56fb9891d70c27d89465526d03e0de71de1), uint256(0x19db019dcfe64bc58a5fe415a98275dcf765dc9b79131ffa350f9b865b8e28f2));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x14a7f7ad99e4137911c45f9fcf939b6516af629926d93e4903ed16ed66c36d58), uint256(0x0ad5c939b5a7ce2565646e21562acb569b0ce0b0ccf916ed0dd50ca21be7494c));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x2b87adf75aa7d3a50445c0fd01feceeb5c50ed889e96951cd66908f98cc9e4b7), uint256(0x09364b4520508ee1112c2d0847bfdbdf65caa1927c329cb2bfe66df5efd7eb40));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x008030612c887ce159aed0b8258f4303f2bc02ef3094c06c1c08b4438f545234), uint256(0x23d10094027fcd4d6e8c91e5fd44677d5460d499841622e469eb3d5b6f55b223));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x04192561fd82b2bf71865a95329f183cff9c01b7c1c48e76ec845bf810b6a7d7), uint256(0x2f76729e04c806ed84185b2802ad9f2ae2403507099b452be040b855156c7983));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x183c513bf53069221a83d5ae274859c9a282abfc366416336fb1f106ae31d258), uint256(0x2b1ba7e926a473fd7b3cf7dde19da506c75a47fdf72787da231d33dea9b213c1));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x03b91f24f6b796aa0f95d005a91412c4fffff3bb71613949d4f74456f4d3a816), uint256(0x15e3cd49ec4f0f7dce1df14475ce9874dbd5b692b63e7553685f58cf5e915b50));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x2210354525f3b8ad6b54ba8977e4b127d81b8571a7b843c56fb0ecce15a02539), uint256(0x064638f092d16372c63c27452a33e264031d758a60861c45a0056337f311e6b4));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x0c259577780e2239359715e21e1b43fbec4e0ae545002e30ea7a08320586899a), uint256(0x1f03d66df81105439ec6ddf6a75fe916328c9e019bd48f76556b62dbff2fb60a));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x2e426bb06aba82867096833773df9f9c11f53f3eca78972418f02ec556b8ff7f), uint256(0x29374cc82950161688201fd937f52ef70d6854e31a5864e1068509b614d02378));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x11e70a45877d86be84733a43c6f9a0c2d9bace3a13916c4af51ff3177f8f0001), uint256(0x28f40364b398fc0337b34ae6aceb70a25419a5c2fe76ed10e7b3dd3a2fa7a430));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x0be554537aacb7de7c6bd1fa29bcf9ce40cc3a5ec9f6a4a10449fab4ed6336bf), uint256(0x226b9c8ce0d60f7978b940bfb3461cfe7283132825211804085aa6f0a6af6e0c));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x21e14e6aab1faf3607157c52e928241d3db9ee8ccdaf80734b55fe1e88852c91), uint256(0x0b5adb560cca55dff64333e809df840ea147113c43d6c92dcb151afa761b5d0b));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x08a2089ecff0f0c242455268e7b3079e033b531c48f18469b2b91f4ad07a354c), uint256(0x220ea01cd0acaa37cb3eeeb4d7cf9c75af444c4ab017e0239d0f332d7172c22c));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x11c18b93239e3d499019cfd690edc553dd34d5ebc0f2199dc4c2263673cd8d1b), uint256(0x15963adf674d5c64ef89021db788b50492d315c4b40c4d52d5a70568c8e2c309));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x0f44d72ae81373b13d07c04186b47142945546978f0b3d31b47c0b94630d88f7), uint256(0x2f6c4f5e659fabdcb07002916b5d7a600ad2cad26b963cadd4666859aae803a8));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x1ea3ff373e8168fddbe6ac913748bdc3d1b49a4adb2ff4579e43f67633839955), uint256(0x2ff8951e012ba77af9a8ba50a342811e10aa29fe572acc143018496548867c30));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x1528a2ac384e83c0b101789adef8557d11658d4ac205993727dbae7310f566e7), uint256(0x07505b9eb320447610e0d24326a2b3b6bde2a0f2654ea6dc26fd3111dfcc1c6f));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x067ee04cf3582e5bb20a24a613c9482fc55768f8721db60c2fc5f6466fe45007), uint256(0x1696432afb7cc0d81739df72385249136d75ec9a24fadddd3b4eead86e6451ae));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x3051e3c59dfdf656701436142a2790e1a4352c31fa01bfd55f11b5db7ea69215), uint256(0x08cf5d14c740960b8516824163e4017eb59308b029461f3123188608cffde4b1));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x11516b6dc7b64bdee23070303f3834aa43b4c03ef8ee1e83034c3c153dd88adc), uint256(0x25532137c99adde3b6458db34feae56194eb7920d1d5f5c1e42d79d335bd30c3));
        vk.gamma_abc[202] = Pairing.G1Point(uint256(0x0444d651c8d0bd4ba0fc0453f227414363c3e08a1ef5fee8e48f9b443456cb01), uint256(0x0fc7c02edcc33ebfb0762712e9581ad3ae4fc5c7dec6236b6c6b28b2fbe473f4));
        vk.gamma_abc[203] = Pairing.G1Point(uint256(0x08e92bba97494c49db13ec0b4eabdc9fadca1e2a73ad6ae4b6452bb8eea0a4a4), uint256(0x1d749f3782e1e4e6ccea8493a211ade2cbd09e90cfb49896c96c5707a8b177fc));
        vk.gamma_abc[204] = Pairing.G1Point(uint256(0x28576b74ef5e8e649cc20c748969b4190cc6929c41186cc9fc9a1795a0a5e701), uint256(0x242d513b089f1713f3f51dba2c9be3b0507797bf020ff333bdb65e036f03baf0));
        vk.gamma_abc[205] = Pairing.G1Point(uint256(0x2c35cbea2a1e486942723e2747be2a0104261ce942409ee229dca7595eebdb7a), uint256(0x1603a61d96cbef2a54947bd07934c9f776ada7e323451ca8cd7e1aa296ec4581));
        vk.gamma_abc[206] = Pairing.G1Point(uint256(0x139e1ab1e52dda1c3eca8364dac923477c4db15e533a38783997925d939c8f19), uint256(0x1d6b4721f1cf1c6d900f8ada5627419d8c8da2638a339b4b8d913f33c925499e));
        vk.gamma_abc[207] = Pairing.G1Point(uint256(0x0a4f07da1ad4cde86c03bd4b5d861d11de91ff64a79d8dda8b1116fb31860075), uint256(0x13e77f67ae06081c462e53debe27dec24eacb719aa50466d6fec78e7545b1c50));
        vk.gamma_abc[208] = Pairing.G1Point(uint256(0x0613a0b7e97902dcd09b91eb46fa52bb57a2f4558e7d2b16c0012d3776c4abef), uint256(0x2e07d57b546dace399bdaa55b53d7155fa5ad4e728b35cdf0e699f2da4de0cd8));
        vk.gamma_abc[209] = Pairing.G1Point(uint256(0x247d84d8c6bc21dcf0b0c5ea28884a524b049208e4f008b5813724f2efb560af), uint256(0x29b6b0211c80614a423c888c369c0da0d29d2eed49a433ab03720f91caa89164));
        vk.gamma_abc[210] = Pairing.G1Point(uint256(0x056ae04347f263feb5c5d7bee7b4466aa6e0ab813b811385a1ea8b8da0d383ae), uint256(0x0edbcb57e7e58d804dc72298d3d317fe407c4e3e45bb7f98d5a1513faccfa820));
        vk.gamma_abc[211] = Pairing.G1Point(uint256(0x1faee116702297a42e41834cc8f5617c9f20d58dd078e5d7fa9fdf9f8beee068), uint256(0x2f95eac906ac0965ed3665ed9fae74c6a2dd843597592e1e2bc18b063d023c87));
        vk.gamma_abc[212] = Pairing.G1Point(uint256(0x1365fa5dcbd34f53b30d2e98b90111c62234572ccee812575a831a9cc2722632), uint256(0x17a8b4932f0f3639c19f1120b595dcf17dedfe9c761cbfb8012e14c3981c39f2));
        vk.gamma_abc[213] = Pairing.G1Point(uint256(0x0ab678fc73980bba18e1d53b59f1e1b9224fbd42146f20f4b60e85d36dd6f3d9), uint256(0x0527042a6f1457eec5ecf8cb3f8e9af9f8ba9a6c9d8fb88669c2ec39be9924f3));
        vk.gamma_abc[214] = Pairing.G1Point(uint256(0x0fb2ed8bb2062471e2407244dac12fe8dd8e9293db0e3b5c68348fba89ac87e0), uint256(0x248101db0469820240952cb41c613669aac0d60fdbab0221450ad7c912f0dd0a));
        vk.gamma_abc[215] = Pairing.G1Point(uint256(0x0fcb40350456393e02eeddcef3dc840a6cef448f38d6e72fcee8af8bb7496074), uint256(0x114b1a6476ca117a83a95e399690610d1a2dc5b8d9d9fa76cd00f4e90f7e3d68));
        vk.gamma_abc[216] = Pairing.G1Point(uint256(0x0166c9f519ba3cc54ea963ed4b295fd58b4299aff2376a764f4b944f1c60b883), uint256(0x17f71f2b33f8868b0e6981219efdbab1d48fc4a077070c0c68023634a0189022));
        vk.gamma_abc[217] = Pairing.G1Point(uint256(0x13f359d9c67edf42da68d286d93d76d50b8edf1597c788858c7941d0020b7a2a), uint256(0x1f3526ab0bf4c48b0c44eee3bd1770c5dc1242abda30a0e83f865681d9e8d026));
        vk.gamma_abc[218] = Pairing.G1Point(uint256(0x259751e1d92a28a0ba651cf0e69bd6198d0547d7f3dee2766bb089f2ca4564bc), uint256(0x13540182281fea10871c4445ed41617c50cd37ed17ff25cc63af02f588a09923));
        vk.gamma_abc[219] = Pairing.G1Point(uint256(0x1f34ccd64375462613ac6d7492df41dbde96bfa3a18839728d7ab3cae26dd075), uint256(0x27e67b8252a9e1e57d23ebd3d0d1d6abc590ab1e00c670f7cc7d98380278bad3));
        vk.gamma_abc[220] = Pairing.G1Point(uint256(0x20c9d0e2a8d2bb065f49c5ac0778d5491828c3aec89efa42fe65a93fe0ec9063), uint256(0x245c2935e553f0b1c2883e07b5188200f9cb13d2e76c35772de484305212d373));
        vk.gamma_abc[221] = Pairing.G1Point(uint256(0x2a6606f345a5133fd71a6dc8ff8c88113d8c125ceb4a0b9dce8004489af6b8a9), uint256(0x004372f653dcfdb899a9fb38141d898b79c43387b4648e32be7cf93c2934e36c));
        vk.gamma_abc[222] = Pairing.G1Point(uint256(0x2f72225125bd08c2a518b64c41fc6a079793935a667c521f930790df46197e08), uint256(0x0428e4d2ae08fff4f82a816648741c807fe86ec36d9ddf52ed210a121a298596));
        vk.gamma_abc[223] = Pairing.G1Point(uint256(0x2373aeec083143ecb4636bce78eb7bddc4c69705b60c0c9478f049e717db42e6), uint256(0x13591b977118eba92f42f7d1ba1c1d6b8bf3dc439e1699a05e16e203d3d3dd3b));
        vk.gamma_abc[224] = Pairing.G1Point(uint256(0x119cdff84104d2092ccd62df0b0092a08cbd128f69681923fdef03ea070c02ab), uint256(0x0a3fca59c0f6b44b8e61ba340d43d78373824340280d492ae69c1bf1480bb2a7));
        vk.gamma_abc[225] = Pairing.G1Point(uint256(0x1971086a59f19d878114d635df1a47dfcfaf955fff55f06f2dcfee27279df983), uint256(0x1e188a252d27545eb266d146abefe478724bfb1ef069584cd8cea92a32f45a98));
        vk.gamma_abc[226] = Pairing.G1Point(uint256(0x255d4bf40c595e0e41eb69f81008b5a56fc89ec5db6c3cdf9b29baae2d2d174c), uint256(0x1264acb6b68020724454372de1fbb6e2d3478b914581ffd5cae6e78cfffa91a8));
        vk.gamma_abc[227] = Pairing.G1Point(uint256(0x2c53d46521ab2f894bc38c37da059795bdcdb61cb977d13c49435fa77046f516), uint256(0x2931a1e5bddee11c551910ea26df5774b8da2bd00f0895798bfcbae043bd15e7));
        vk.gamma_abc[228] = Pairing.G1Point(uint256(0x2c7188c084e04b835ec515ced27e2480c89d82859dd1a0ea288806f0c4ed0ec2), uint256(0x050dd89f012e63c15588037af3b18e4fa70601bc66f0273e276c5299bc436b99));
        vk.gamma_abc[229] = Pairing.G1Point(uint256(0x2ace08bcc2e4ca74a64225385ab48cb1af475c0e2afbeeeb97862a7fde41c2b8), uint256(0x2355e7535bbbe9f6052faa037b33f29a7f4eaacc6718896a019bcaeaf47581bc));
        vk.gamma_abc[230] = Pairing.G1Point(uint256(0x1de2a26166d9fadbe441d4b8388c062422fe7e6d7beaae50b513357d6262f1ff), uint256(0x143f15a105b6772b2bbf460ae2a0b815cf7d2c44d49ae02a648b84c3203a9a03));
        vk.gamma_abc[231] = Pairing.G1Point(uint256(0x1a0d7771d9bb4f56b4ccb865f28378a0d5286407462135e903a204fa24ab490b), uint256(0x0505ab251762e6e1f4e26fb7a5d05952019e145984ebae899ad24c0d25518f76));
        vk.gamma_abc[232] = Pairing.G1Point(uint256(0x0884ee8d230f59bb7e45feef4abe36c67816d960cb12bb10202ac344b51e898f), uint256(0x27e2fd7e0ffe7df0267919d6b60654d945d49fb257a68eb1ba068ebf198d69af));
        vk.gamma_abc[233] = Pairing.G1Point(uint256(0x247858a04e55324ea9bc62cc1404e8a66f7fe81c490fff00ffe07904b2ee80f0), uint256(0x2e673d0556086cc980de226f83999f6ce3fa1e3f483419c3dbfd1cc934f1ae4e));
        vk.gamma_abc[234] = Pairing.G1Point(uint256(0x2b48b413a66add80e878f1df626747e579fb2c5ddd45d2af388d71d90af16f71), uint256(0x1cc002cb54aa4d5c4f261672762247ecbf73044f2ee482397d75243e10f33f2c));
        vk.gamma_abc[235] = Pairing.G1Point(uint256(0x0004299988c8cf3b88ce5c2f7c9e8a2553a3678241db430bdfada6f0a6cb0664), uint256(0x267fa945e6af323876f02399be912aac84172265cea91042c05d5557c46f0a26));
        vk.gamma_abc[236] = Pairing.G1Point(uint256(0x1c48b6b39b219d1260951cafe3a3541cfb2f47cdd7b26f60f2dad0425859828e), uint256(0x245d460633acb644c7af5492c8364edbda666fd37f85408bc2e8b01108c770ab));
        vk.gamma_abc[237] = Pairing.G1Point(uint256(0x22651a7fd0552560235eef93754fcb674f6bff367c03959a3b550745fdd9d883), uint256(0x020bbcea9924290fdc7f8a44ccfb05dd196b4c2b80e10fd4e45a57d5ef5cb1a1));
        vk.gamma_abc[238] = Pairing.G1Point(uint256(0x29224c3a8c3922456770f9dcee60b590930f163c0876cd85f5c4bb79f1075a11), uint256(0x20e2fd13438d5699a7db6eef9875eea33f4da8780a16905b2cca57edb1c0c5fe));
        vk.gamma_abc[239] = Pairing.G1Point(uint256(0x298245f41b244d19b2267ab3f7a55301f1e36785085eb42046c953634aa5b7f3), uint256(0x0e79b751d1aeab975aa8bc5d6e7dc528065ed8aebb3c1b413789bc84bd2862d1));
        vk.gamma_abc[240] = Pairing.G1Point(uint256(0x05ee8e5ef7f6510a552127b3d9f82a72d5b2ea53b992f5743341eb40c2d32c18), uint256(0x18564ef23f7bc4615b9f54917114570cda650dbe7564d62862ff1b89616e9ee5));
        vk.gamma_abc[241] = Pairing.G1Point(uint256(0x0834c26b0b9466627b420de8f49285a294ab07b98a5e75d0a760ab64ad54dc3d), uint256(0x22474fe888dd23e1efcf61ee53c2cd4a8874c8b86b4bd93688dbbdc749e816cb));
        vk.gamma_abc[242] = Pairing.G1Point(uint256(0x09d4e2d54219db051c95ab1bb6abaca505573d5a8635abe4065fb5d4f1ca2c87), uint256(0x0f1445d1c9203111c831867f04f8cce7131d21af3bab7ebe14bd0081a85cb643));
        vk.gamma_abc[243] = Pairing.G1Point(uint256(0x23fce679e80dd3c12afa7a2d15e804a2fbdd2c57e60ef052a1c9dbf145accc8e), uint256(0x291e0520f5668457d4cf472f742abf84663eb7981fca9a41eddcea58b8b053d5));
        vk.gamma_abc[244] = Pairing.G1Point(uint256(0x0f69b6ec1d7394c95c93eefce5152da55bf654536de810add78d4b78fac98c73), uint256(0x1ecceab2eb3304b782278738fb3c3cbbd7a89c96432c13a9b2c0793ec8a06489));
        vk.gamma_abc[245] = Pairing.G1Point(uint256(0x1a5ec1df723cccebd6ec11969cfdea3d8fd9449e28695e384a5fd1181f4f07cd), uint256(0x2ec7b84bb383c20bbd777816ded22c2c2233041985a096f39b5a0f1dea901ad7));
        vk.gamma_abc[246] = Pairing.G1Point(uint256(0x1ca3c9ebd5067b795bd6b6614a180453f08eef789baba26699ce7b787158a156), uint256(0x1ece2dd16adcb03783dcbb9f9cfade8a55ed67d39157af040b9de320590730ec));
        vk.gamma_abc[247] = Pairing.G1Point(uint256(0x01e85a9b59c157162b9c10caad5614c45003dc1b973e584b94e147e231143b3e), uint256(0x0aeccc9993868a1bb0dbed08aa55f904a8811d8cf28314faf15cb0a639910913));
        vk.gamma_abc[248] = Pairing.G1Point(uint256(0x255a03e6a08789da77fee6c9db61db09f1aae73f055128c35bcd5e74e95417c4), uint256(0x0f5dbdc548f414bf7a084ed898dccbdb5a106ebc52cae01b0ee01e85a26ec3a2));
        vk.gamma_abc[249] = Pairing.G1Point(uint256(0x18559fd332667944308f107214d0033c8a7e7d3624d83e511ab208061355d0bf), uint256(0x2288f854559a514e9d28b934a9948d56c93417b2771c130f1ea270d5b2757b76));
        vk.gamma_abc[250] = Pairing.G1Point(uint256(0x2b3d84b45a96ae328047051ffb29ccdec3ca34a546e816f43fcc0acce974eb02), uint256(0x024d984ee891f77a8089554ee618aa57279a937f4dd929fb1fa80ecf17b4786b));
        vk.gamma_abc[251] = Pairing.G1Point(uint256(0x265ee9278ef565510f1b4f78d924890cdb819bae645613afb70b8ad85124fe09), uint256(0x1395018043cef5bb76d640363e2d758c15d848eb3dba4df384b85d95a249807e));
        vk.gamma_abc[252] = Pairing.G1Point(uint256(0x1e46edc4908000ba49c3fa73e86257b8c977ac50daa6facdcd83b4626185e04b), uint256(0x29e422df9a1dfe718cffa2db4d69d54da4d6180a0084beb9177599578c731c3c));
        vk.gamma_abc[253] = Pairing.G1Point(uint256(0x2e1311d8ad1b17843f01cdc71f075120fd0ceb12a7742d3e1ea2f8dc7b5021c1), uint256(0x0bace5d57ee9386ea326abbb2af0a068552c4ca32dd1e90616e400edfa3596fd));
        vk.gamma_abc[254] = Pairing.G1Point(uint256(0x29e85ac70c273741bf42a7d2c4d9c0229716bd239743ae8110813ae2e5c4ec72), uint256(0x29cecedfc86eb8c55c8b53d690a508dd22a19860f09f1313f57664cae0c6816e));
        vk.gamma_abc[255] = Pairing.G1Point(uint256(0x24c0ab1513a12b219c27deba626400a46fe47141c7c9dd94aca48f1f7510072d), uint256(0x2155e3d78775eec57e8d7d5cbc9741f4992fd9a1105490f2b4ce11c6efba5b1c));
        vk.gamma_abc[256] = Pairing.G1Point(uint256(0x18952fbaefd7bf2fe6ebda158af7f0570f2e3f6ceef0e0cf4fb098dca382da39), uint256(0x1e37bd731a713aa7d42349a9fbd0c13f76c7a3a7177c2196a97843dd3e307fb4));
        vk.gamma_abc[257] = Pairing.G1Point(uint256(0x2a05bda6e399d0f04783a08f307fb0e2dbf332b4a17c28319de8614a1747f31e), uint256(0x1c8232be706762e0d892d676e91f2f96cfd034fd48fe4ce8916b74cc7fb73705));
        vk.gamma_abc[258] = Pairing.G1Point(uint256(0x1acf2e6362fc60a5526fae3d6a2cc96fa1c522ffb5fc0ff0eca8329198773a15), uint256(0x29b60bfaf8cf501fdfc0f498912a3bd6432fa75e49865428715c19a4d4e71e09));
        vk.gamma_abc[259] = Pairing.G1Point(uint256(0x228c89ae82295e2c3578c443cf7154ab3b7ba3cf6889a132486e1b326ba70388), uint256(0x07efbcacf884cbc163d4c999cb43e0980ec93802975c3a4449e1b7012ce5601d));
        vk.gamma_abc[260] = Pairing.G1Point(uint256(0x160cbe7aebcfd3cdac22eeb5f033e6d86e57bd8e0cf76546569c30148286f0ae), uint256(0x2234d15d80a0811b0031b67f4f184eb9819ad464aed430902069fdb77fff30c9));
        vk.gamma_abc[261] = Pairing.G1Point(uint256(0x2ed9f18b190fc9ff1dc550036f87c5ccaf6250ba6ac5af4d69d8dc5c89206a9f), uint256(0x0838d96ce918ba635300e43bd211c1fa0f97d5c13f643a78305ff869e2ff28dd));
        vk.gamma_abc[262] = Pairing.G1Point(uint256(0x02f116a4b054a856ec07d8cd612d8d38ec1f1582f8bacaad0972ada1a15ddae7), uint256(0x0bacc681f3fc9f6ca6cf6a39d20d9969bf454f4dc97b666346deba2b68f9b830));
        vk.gamma_abc[263] = Pairing.G1Point(uint256(0x11ec823f4e72d25adfd6e98309387fedccf24a5e33c0081c7f5bd5abe75a4137), uint256(0x224fd6af4a47613b8192191479a9495c439427b675ecaf0b08939b2bac560ec7));
        vk.gamma_abc[264] = Pairing.G1Point(uint256(0x0c2295f70a19552728345adbcfc8d81328d5b86c3673929131dac339b964cf89), uint256(0x20559f623ee4f88e3550f59c5d32883addcc3780da76b89cb31a77fd1bcb0a59));
        vk.gamma_abc[265] = Pairing.G1Point(uint256(0x09eadc712cdd1d3e57bed705dfa3b0a4b3b99d734a8b31bc745206c5fdb89251), uint256(0x119417aa86bd5f05295b8867de203fb6fb23d1ca89e67b4408accb63a1cf4570));
        vk.gamma_abc[266] = Pairing.G1Point(uint256(0x0fcb2acab4a7943f5af5ecaf22b8c93ad1334ed791d897f5403c526f8bac5bd5), uint256(0x1efbd975a1f8826eb20b5ed6072201a348cd91f8b91188441cd81cceb30ff1b2));
        vk.gamma_abc[267] = Pairing.G1Point(uint256(0x1ff3b8fe03a0146300c7d0428d750bdf1cd542b6c04dd051ac29b5f870957107), uint256(0x1ee8606ec1088ffb05d2bf3de00ed614c60c25cbf2cc72f545d19a1abbdd1ece));
        vk.gamma_abc[268] = Pairing.G1Point(uint256(0x1c607336628db46e54824266ca7cb2f908b62d8cdca3824653486ec63e28372b), uint256(0x253af03d27482168eda2628a1a33dec5e6e569c5d4e626e2b18dc811f6057a8e));
        vk.gamma_abc[269] = Pairing.G1Point(uint256(0x0578f1be5bfa4803277a293626ef7034371c675028c6efc46fcb50da9db65293), uint256(0x300314f0ba43061d51f41c1dc62a96ba2d4975fb82b1276a9220871e9bc6b612));
        vk.gamma_abc[270] = Pairing.G1Point(uint256(0x0d21bad79755133381896973e2fb0bc798ce41f2e48957e8135eb30217b96eaa), uint256(0x1c54808a218940ed20c716a8a496015b3f518050ea31e910d53b0e6c24fe44ea));
        vk.gamma_abc[271] = Pairing.G1Point(uint256(0x2fb93e561dbfb46b1b139c27e72d02e0fe2c2fff467e20216c0862bc350c8dc8), uint256(0x1ff0662a804fdf69298d66fdfd886bcbc5d45def8ab55e2a4c55e82f1efba4c4));
        vk.gamma_abc[272] = Pairing.G1Point(uint256(0x255582a3dafec7aa17ddf5277af106fffb48562fdf7024064ed32bb4ccbe0e35), uint256(0x1ff8af1a92c23557489930591108a399972b3ad3997166338f5b45ce08809561));
        vk.gamma_abc[273] = Pairing.G1Point(uint256(0x19123c3c6616d795db443c58c66537d345943c5b783900d42522cb35dac89c31), uint256(0x020ab3573df8ecd80deac974294dc4e6504824a0858a9784d214102216943620));
        vk.gamma_abc[274] = Pairing.G1Point(uint256(0x06c837c18417e918865530b331a05cfbb5f568444e822f638e084721f6902089), uint256(0x06887bac2d7cee48d325d83361dd8d2d2b43246f8d8b7c47f0dab30db5ae7768));
        vk.gamma_abc[275] = Pairing.G1Point(uint256(0x2ce20715eb3e5ec1175796a48142a14523f8e631828514faa9b1c4eebd29ae46), uint256(0x0f5d881afa2ac7b57d08abd0d55598c25c373cb6ee2655989b383b03e1569249));
        vk.gamma_abc[276] = Pairing.G1Point(uint256(0x09f97292c2648b93921c04001b6130250f0545aa9e9c77ca60b1fe665513d064), uint256(0x1e2fde7c273668bbdf980c384452794331af6e1e89a79d6712616748b4ef6923));
        vk.gamma_abc[277] = Pairing.G1Point(uint256(0x1b33f56c7db05b6acc4825890d81be064981f65b79fbd301a62e4f1c7c7f0f8b), uint256(0x00faa0cc8a5cef55e4403f004e26d0e1bf56e07e5592c6f48e3135a03f477cbc));
        vk.gamma_abc[278] = Pairing.G1Point(uint256(0x0ddb4df1c1e9b39ab99db8ff71a293882b75980a9b9bcc6acc66716f709f03ae), uint256(0x2a290eb71d037f501857d8c0bf5f3075a921d5c57c99a05cbdae75341fc086e4));
        vk.gamma_abc[279] = Pairing.G1Point(uint256(0x279284a8e9d534aaa2c038da78e281ee5503ece1634d753ceb97cefc9da4cb93), uint256(0x2a237e71dbd96ac0053615c4cf044557229e6260ad2a3455bc02a8bfc0403f8c));
        vk.gamma_abc[280] = Pairing.G1Point(uint256(0x018ab56b1b810824ea86a04a9665bfbe73fc4691fa6028bc9de396a8bbf56807), uint256(0x036ea1cf09a759d16e660a125d73c3613b3da64483f2d230bb31463e7bfd8f7e));
        vk.gamma_abc[281] = Pairing.G1Point(uint256(0x12cfd5efa3f9f2f7a5e5d3c97258cf546d87875eae5b416cdbbdeb6983d43a61), uint256(0x27d9f7ba7f73d4a54e94fcd3676f3de6c5ece95bac20485d175c7116690e6269));
        vk.gamma_abc[282] = Pairing.G1Point(uint256(0x2dcfae81cd4fdfd9f4f84fb0d35725509e874ca33b2f3c798f6272291d571751), uint256(0x0812934970070b27ce99320c30d2cebef61a27196c573e6fc88686d69e657a68));
        vk.gamma_abc[283] = Pairing.G1Point(uint256(0x17317148d0bab2d0a50e5645a8b22e01dae8060e9040557c01b689b9f6d4f72b), uint256(0x1f1527c71ca4aa6dc41dcb82255ed73465910a0986a3b889187d774672715d0a));
        vk.gamma_abc[284] = Pairing.G1Point(uint256(0x09a9805c7452f8b9d26ad379650f98b5b5ed91dfeecea19e8eecf5a6ccdbce16), uint256(0x1f26e11eff0475f3b929072e873815a6adafb07605986edb8033bb2b0d74f48a));
        vk.gamma_abc[285] = Pairing.G1Point(uint256(0x181a2ea7a9315b8594fddf7a96f807e7ef1b149773e8e45a850a2b842300ee2b), uint256(0x2bec1a13951883788bfa21ceaaa046f61698e0980a01d95810a324a2052ae147));
        vk.gamma_abc[286] = Pairing.G1Point(uint256(0x1282774478882395d1e04293f62d723745454becdf09e89f3c1f438e62eb6fe3), uint256(0x2afa08dd774c5cf780d6415afd8413f4ffec12b6e861801402a668a432ffc975));
        vk.gamma_abc[287] = Pairing.G1Point(uint256(0x2f0b224694e1cc0f58d7c2aad8631aedb6b4355ad677e9dab4ff0c904f40a05d), uint256(0x1ea32d61d8973a2c6e19d64b05cdb9d50d03b7b3330d32a2cc4bdd41031a89bf));
        vk.gamma_abc[288] = Pairing.G1Point(uint256(0x08c29b2a43cde528adc29a86e0d18f9e2bc93f5af839689c67d761fd88ae27dc), uint256(0x2e33d9effaa0b2bd6386ef4729ad084d4252bdae8c25e3202ae438055065cd85));
        vk.gamma_abc[289] = Pairing.G1Point(uint256(0x25d3ca76f0580ace91d213679eb5248adf6529fa83c6f8d2a6ae6569e2dafa34), uint256(0x0b6adfb7045190c7801074d3deb06f107b1c3b3d9d399c14bfbcf6c77c5ade41));
        vk.gamma_abc[290] = Pairing.G1Point(uint256(0x152acd16ae08cb9401a6b9e9951db5983002b26452c5bc8f39abebd388204a21), uint256(0x1c6363545cb837bfbdf5eef70d692836d4e3531a6a83ee0cbc15e05b24fc696b));
        vk.gamma_abc[291] = Pairing.G1Point(uint256(0x1ee613c1b7396933a584bb54d9040926f0a61b56a5a304a6f125454319d339d3), uint256(0x08436c7c8731fe4b3beec2f35e6ffeea133c3dd72903f433084a030fc83b4ca5));
        vk.gamma_abc[292] = Pairing.G1Point(uint256(0x2ed6b6217ce638c3aa4356fef4507c388e066423b5ee1601fbd85cedc00a1c19), uint256(0x17d8352a95382351c94bce5dbba2360bf1b8ae0e6a337ec59dc77c52101eabd0));
        vk.gamma_abc[293] = Pairing.G1Point(uint256(0x30341f9dd3a1121c3f486135fc0b36be5b5979d3ab0ea0789f9f1518f8e5e588), uint256(0x2255dbc49f5775d68d26c9983a80a3024dbb2ad4716c312216ed1793564e9db2));
        vk.gamma_abc[294] = Pairing.G1Point(uint256(0x2ae0d3f93b40daa93e7e37f4f1b1f753e26dca31d5839aa9c0b5ffa240cdf63f), uint256(0x146ca95581c2134ba00d5bace07a650f81a493f6e2a73b288bf22f5383425aa1));
        vk.gamma_abc[295] = Pairing.G1Point(uint256(0x1ebcbcfd79c26295c9d6c446fac96ecccd96a26b2bc5d5a399443825b3452ae1), uint256(0x0a4416c52fb7dfc06ad976bb7931bbc93613d1f1087e37936c865dec0bbdaeba));
        vk.gamma_abc[296] = Pairing.G1Point(uint256(0x14cf483c4985c1ad635367cf56387348dac8db8eac8bd1948d682fe98f1adfe9), uint256(0x2b413ec0b2a951cd68ce5b7b1dbcf1c5bb057f686afd5a3cf759edff234bfd36));
        vk.gamma_abc[297] = Pairing.G1Point(uint256(0x06b10fee22e6bc99be16c2ba2c3b471b756933a6abaf7f9da8dfe62e68880874), uint256(0x07699813092b4a4f3b89197c981cb9496ecec10e2429711a639f48830eb6607b));
        vk.gamma_abc[298] = Pairing.G1Point(uint256(0x16ab2611b8a41c33e61e298cd62ef61f6a2387bbfd926a536ea7493cba3600ae), uint256(0x1687842fc56ab4f6d7cc01db01d279656d6617b5554ac404f92bff51bad6db68));
        vk.gamma_abc[299] = Pairing.G1Point(uint256(0x2af2fe6349971f4395d0829e791f162e5212f1ad754e256849c1c75193b5b71f), uint256(0x284f9e0fdb7b9b9396ace5c7cecdadba0ddaeed505c0466eafd56b53e174de02));
        vk.gamma_abc[300] = Pairing.G1Point(uint256(0x1a61af8ff903c4e83c67c3f6c6281b027c89365453e9d5f8af554843358ee192), uint256(0x26aebabbfc05a0c212442cba5e7515de2627e2153208c2a8bbcb84a5a22db1ea));
        vk.gamma_abc[301] = Pairing.G1Point(uint256(0x2acbb8b97948eba6fa45e4ad7c09a7cb7a8a35bc7069d343fe1c9bb71c09c25c), uint256(0x05996c8607198c9b13944f0ff4404a1f016a040aa953aa49e4b096a43ad08ef7));
        vk.gamma_abc[302] = Pairing.G1Point(uint256(0x24e16481b1d99449a21a270200d0b4e5c377ff5192233825b8f4014dfdae8cfe), uint256(0x1e222e7ad3a8b9fdb27cf90dfb410d1a818be5994618be8d33c5fe593748bed1));
        vk.gamma_abc[303] = Pairing.G1Point(uint256(0x0bea10acf4d1c867325aeafb6a2c2899f4b8adda5b1e8bff45e6eb36b7cf3f07), uint256(0x2d11d47fb0de54c9ae65e9e57e6963608360a93dd72bfab6f9c6d43d5feeafe1));
        vk.gamma_abc[304] = Pairing.G1Point(uint256(0x27568e27b538130bd9234a1729966e332cabcc2f4f7f8e1938c2c72c3c80a19c), uint256(0x09904f0c25361f5b8c482583aa9910c72db3519221edc5118ceb7774ad56fea7));
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
            Proof memory proof, uint[304] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](304);
        
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
