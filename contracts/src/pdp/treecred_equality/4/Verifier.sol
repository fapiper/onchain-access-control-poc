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
        vk.alpha = Pairing.G1Point(uint256(0x0ebd16745b686a0359fb7a540315b03d7196409588d5935b4559d3338cad94ec), uint256(0x026b49b1fcbb754da93a7e3ab1bb459c02a9e0061b91bcc8361bc26a1b1869ba));
        vk.beta = Pairing.G2Point([uint256(0x23d46d9390b802028138accb1c6566febec056dcadd55ae0fe0249dc6d39df26), uint256(0x02fef8642eaa3c8ebb7b2201a42969a41dafe09c528fa1253bd1889da8e4d619)], [uint256(0x14ce4f72248f582c915c5ec7d7b2022599c4c5d6b30206ab649ec64deec73fa4), uint256(0x0faeefa189d1f9627cbd8213c4b8dfac5ef8ab9366c9187618c1aab3843fff24)]);
        vk.gamma = Pairing.G2Point([uint256(0x1d3b54caff09c0c5bb1d69a10f81664e0e79a168c49ce1d8008ec197d13d13a3), uint256(0x039fa577b880a4d5449898d2a94eeeb67d4e5139a4f3fe8418a09a4441a1eb2f)], [uint256(0x1bf035c67a4e3a593a6471fe5087ef754e57bec447e6f93c849041185f9ec336), uint256(0x229b10fa963b4b0f62e1453a857782aa997f1e7244551d37d38187b06eaf9ebb)]);
        vk.delta = Pairing.G2Point([uint256(0x2c6e287fa66c8d85632bba122e9c3c63b3ed7a3f66524ec51434d70cca243ab5), uint256(0x251a1180e323a94c92b753fb2aa64e66d9fa0a73f4891d996e77beaa5bdb7efe)], [uint256(0x277a01fdd60bd85eed924f185716133cd141b42a365164254236678681782073), uint256(0x2bbab542b2e48cce5f3014e99f32d4a5a1f2909f8333939dfbbf739efb7d07b9)]);
        vk.gamma_abc = new Pairing.G1Point[](36);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1f6f86d16888a7664f3a733fd5c1dbb2c352661388cd9c9f1139d075eeaa7b51), uint256(0x2f21f9cf3c33c23b7629a02df3a06aca3d0b81a344f2709d2ad9d406c90f4c0a));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x07cfdfab03dae72b0fa6495d839825767bebd3b60043c1fb0c7aad5e4b94f181), uint256(0x1c78c71ca6543be056c31198dbcd44a9f52dc3930c3490d3da2a59c2d10fc3ed));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0af56baf131ad7b2f4a3d6cf166e272d304a2b2f8ef82405ffbd90e5c3277428), uint256(0x2857bdd306b677fe41275058e7aa03f20768406929800825c7db0af19847378f));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x182943d9268be17e79e35815bbf7f60045206679d85288756c0af86b8396670f), uint256(0x0c23cc4fd03ce056179d5f372f9f7501e646fcf97a4c65e219742477c9ba02e3));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0dcf1278ad099ecbd79610388829bc878fed3c1fad49982990add813f91c3404), uint256(0x110e39a85c398b1517ce235dca7d0608382b69bd6bb21d489986b861d84fde9f));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2657cc5ccc7574e8e63f83c09e1b54142e8242640f0b1269efc8ba111079e39a), uint256(0x28241b5a1c318459ff2e9c205120a363eaf6bf3563cd836a0fc664d3b13706b2));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x2a7e53df78786daebd79650e44b7aeab57fb5823ecc4d63ee9cf247735e7e9bf), uint256(0x2e9f6ee5951aba32f07c1d6e50f22b551aba1f1167a48a945ed2aaf526d350f7));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1dce9e19347781c745c244e901947dadb290ffc8171395d822962055c6fad992), uint256(0x1a1a21f8b529c0d606fd5ef2b0c97810928c46a5f7803b70cda302d23a7c36d3));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x22beb6755757163ca03b96698872acf153a9be2c815ebd4b59176a26e0eef171), uint256(0x0fe2996e8d35e487f05d9aa1c7520897e8469fee036cc3ec4fe0c9c0e5d3f267));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x089d0d409bb61c8a852969da01cfc0fc1d5c8822fec46301553d0fb051d799b8), uint256(0x0a1f0b4d085330f3c49bca42cf02924feeebad42d2f1caba766c321ed6e84bd4));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2ab87c66c80d28168c49dd9b10675a65740c6bb06536506b84442f6a3b5df601), uint256(0x1ce0d6f778d981c536b6d1c2ff85d69d9de516f31a34539c8bf8bba3ac905ec5));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0242d32d6d11755f92361341a295a4d96f61ef7d18389be58be64a197b32262d), uint256(0x1653a0f9664395799b047237c78143dd91948ba0eaf84e3dee1cb96a4c9ad682));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2f26f946dbaa88de060ceeb4cd4657a9fa120f5b5cc2662bc586eaf08ddcb560), uint256(0x09a179734d9644875fd587afe4eac2ed91a800bfde113219810d6e3577fc3235));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1f7c377e4761330ad361b76321157faeb4ca06f037e615512dd7338128dd785a), uint256(0x11f6b09676f6a4ce01feaf2be3d0a8af2bf84b94da46e53f540aab93986ec788));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x27d70a68d5ff9d707e6ebc9bf4396db9891a3523841ff64e0e8814fdb485677d), uint256(0x06c9b1a4c983b47c8fab9e3e8ca7845d66a1b84b730ed41e11c81964bbec79fc));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x081940bfdbac3be5e06ab75c02e87e494f3e27e760de4bc378a1490d49fee75b), uint256(0x0ad52923e2fee7c7e2f4c7fc83847cc519a4dfc300c2fbe30585fdc85d7879a4));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2da639985c3c39b67b10ce360186b098d0d8390247d9e72edd5bc489b28fa356), uint256(0x02a1416f53dcb3e845f97d947468a18dffa325669f0f1bed15409e6fa917e85f));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x03aa4f552150cb96055484d04cd2eb58370ae43705062e425ac95ecf733e9447), uint256(0x1d5586049c6fcfd239db8fb2e4d43de68379325064310b48e9055c69bd611c2e));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1073e3e5c05adfe8df0db9b227a96ce9d5c95efd73bbdb559ba6bc627fe860b0), uint256(0x04d58f02fec2f9a335e710aeaf89e800d505f3df40653a27fba6bd0ef9cb2f34));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2fe498d14be92092c38014544eba45588d61a6200dc4f9fb69a40407340efa46), uint256(0x0d9e968de744d52b4a290f64ccf200c53e7c8cd85fd75d5da6ef98748cc7c741));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x0d1a5707a4e0c16a1bc379cfa2baa92efd5ef21cac6f842a81a74c1bd698128b), uint256(0x03cb76fb86a67e21b5284ceb37df8efbc6190733e6aa237bfe613e28e04e2130));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x0cc724051de3101ea2d7f61bad154060f9f48302c4dd18e1eb331a1c384fc10c), uint256(0x0fc21f24fff3700c960c53ca6a2b97ce75e224a2bb1415b3432423155501c105));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x29d92fc2b2bcd8325a1322abe620afa2535802125693f11f3538ac85efdf745e), uint256(0x0e68c6a4f02c010e7f9882e12a3b3eeacd22e050c0f9d517769de26d3040fbe9));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1e8531e365935e0bdb151ed9c553b4a17c774b9dbcc02ba248aebba727386a1b), uint256(0x0383eaacf18dcfd8c5aa2ae78238be1fe16eb9969e1e19ef22d229c65f9e2783));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x2a30b22ca1009f18df3b1022888e6eb9fa849c7451764b3c34df8fe70a1698c5), uint256(0x014f6cc6e8b6e40cfb9b415ad35f056819e44296a1dac86f85a1a5ad8bea6c2c));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x175789c158cb1464f23731d3d365c94cb0a4a7641d16c29662a12dde4fa8dff6), uint256(0x13042654acdfd827c67766846fb6c89a9c3291b88ea3e8467a7c39675861b226));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1f5bc3b9ebd7d57e9a3fc23ae4f071a6c33da0541fea9fa1c386e6cf7e574c09), uint256(0x16d0971d6c40a5bc676fce4578050a609590fee065ae575f4e30a171cfa89c0c));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x0dbac3239597bd551cb1aef57c37ddbadf3afdecd39d35d1bd5160a4508040c0), uint256(0x13b5e60a6d406ef246623ddd1f041ab819e5b533cc7273d63e9ed48951dd1c18));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x02b9c6d6a9c5ede625e87265ab911fcc94bf5ce2fa9a876751962b411bbce235), uint256(0x027a7620c70709657833db8b8bbf2c0b269d6feb90855ea21dc4c90a957a41b4));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x2cf8c8152ab5727c1fe742908b0e73295a50f932115134d4c635afb9c5c4d42c), uint256(0x0555fc2ad638cfb0f46661d7a2dc153bf05ae099dca73520a40f0974ce1191e3));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1bb67508e59dbc3eaee7a9e8b9757c96328d60c2a22888c5d43a19e99cb5aa25), uint256(0x17811fdc1dbc5ea3d35e7aae37a267f923147b2bf1cdcbd35765b52b703de62e));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x2116c37615494e56d0148c8786fd0565c1ceb20235e19ee4a768eda8e1f71030), uint256(0x10afd4c04a22ecd250d76beb654386335ccb25df8fdbb37629c8eea559f8fcef));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x0e0a59a5f1f34e12dbf6b2b3bd2de106e8f24fb84030bafb2716cb0c85bf713d), uint256(0x227ee749c7f9ba49652e9aa74d54cd3f4982f4029d5ac1223fea0a3398e44c16));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x273ff37f63b7e69fe0178a2688ffbebef80d589066bc4e71ef1b6d0533ad6f14), uint256(0x223023df6058cfa557483e8ac0700fae6fc471d8a71b1016e7cd6e7966254c28));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x1214e4e1bdbe549ae81714cc1943a417942496b5230688c44d30a3771c0affd2), uint256(0x1b9840d15ac3ea0d5b79cb7cd02d0bb14fecf07c5f5cb902dc9bb19a3aa29d8d));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x297f1c6fc519a0e18ceee2e4bdfbdc08c36a4a6209917375c78a054976bab86c), uint256(0x0507402a7fd3815c14a2bedec373f9c3be38c78bb7d3619dfddfa82284c0055e));
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
            Proof memory proof, uint[35] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](35);
        
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
