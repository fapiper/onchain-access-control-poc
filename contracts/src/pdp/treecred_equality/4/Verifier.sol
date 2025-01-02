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
        vk.alpha = Pairing.G1Point(uint256(0x023bcbf2427e9d08547f46da63207d0c0500369845a82a55457c4ef2d7826024), uint256(0x2ea028c17db3d82fc3e7c87daf249508aa4819f8bdf8c52d7426ccc7fead1b69));
        vk.beta = Pairing.G2Point([uint256(0x1eadbec3eb9d666392c5c0910158b5dc0095f539f1364cbd9a37ead31db2c9bb), uint256(0x0aebf46211ac0091082dfc81d0ef655c204a220c43cfc6c6a6c1f8202438fe1d)], [uint256(0x0e6282f04dcc85a2af5550477d16c6870bfcda65a0a56ab266802699e0f0d7d8), uint256(0x24bb12bbfe50fce6cb63235d0885fc990de4f8f291d2278d8bd740f63ed22397)]);
        vk.gamma = Pairing.G2Point([uint256(0x0bfed3ca2bef4ece8399881719ad3c6664188cb1c0fd7b3c57ffebde5b2fdb5c), uint256(0x1ceb9bd451b9550b9ba4a0454f981c7a99f479f323d7cb589f29e79c35db3ee0)], [uint256(0x149ee32b29f97c301eedb586824772466508bfe6c37982cdffc50809ac69980d), uint256(0x057e48e07940cd86cbe6f9a2ee63b05cdb3815f08ef81827ee30fa4ef746dea4)]);
        vk.delta = Pairing.G2Point([uint256(0x1180d718b0ad2fb9a53269b59307e6c1c65923dd1a32de1cb34b310dcdf0cc61), uint256(0x22d832e6df2cf9315dcf68e912fa209c6b8c4bd9b198f8fb919fa7f022c7decd)], [uint256(0x11a0f7f299ea5f6531e84fe882ad8d87e5e73b39bc01ac12adb41bec45fc3ebc), uint256(0x2b77d200c97bd465f4d4f46a005dc1362f37aafe8e4cae3bffc9d9c98041a55a)]);
        vk.gamma_abc = new Pairing.G1Point[](36);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1f15db75e9462802396bfa50201400241ed236afd80398953be4436426ee228d), uint256(0x0a101608833849cd26ae6a028c658ba329ae85315232cc34d3901e4eb811ad4f));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x161dbe404c37c775c4f78aa832cef8800a3000941b3ff7a89a3cdd33036aa891), uint256(0x030d6218a61c85b9de0f90737b8620f7d09374546629ed4d4b6258a6ac972bad));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1c9c165edd0681c8b86de1e82bf8f75481d60882d033da87ec0c30087ccf1d1c), uint256(0x2531ec900715bb06a43e00c81577c6bca74d39cca8bc6fa63aa7558fd092d8f9));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x084e536bd2213770f588913da43895ad1cb7aafcf7c10ef342bfdc06983c767d), uint256(0x04c2cb55daac79eb959d0caf67f4a21663c80cfb56b6b411e7062c1625f2c605));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1bdc2b21961b79c68a872647d1b4a3bc04a392ca51d44fa5c1a53e198d255c49), uint256(0x1398292b0c87a5b917245f356a322896433acc5ba34a6879455abdd1e0f24003));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0c6b5322ad54469c784208bf960200e96529e51862c33a8704548522b52902a7), uint256(0x0e8b1267e251c2cded518cb5e2efe9bf4b18c0288631f146e60af692cc52165b));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x022a04ee1338de92a6eaf9f69dbbf184c8633c7e2af9f2b2165f69e5e208c69e), uint256(0x206d422c3ff8748422f3a177455e5805b3da14383e0ac8324bb1ee43cd20a970));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2dc1f84061a374447f69ffbeaa726d36e233fd09bf5f1f58b2b10a16eb47ddad), uint256(0x15c9d463c4ea8af626c49468df492c135a6176c3528fa180dcd0fd93bae87b38));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2f5da913e93655915e53551dbdb4622cb62b63cd01969cd686d45b67a5ee1a44), uint256(0x2634440ec0f92a7c8ad36ac9e6632ee3e76d67ff1e0b9c59d6bcd170ada54927));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2a160088b2b690aaceb83643bb92f672cd677ef3f39fcf5837bcccdcbd8355e5), uint256(0x261b3a1323385796ef8d912d40537addd14f71b161315419bfff80d7cda4fd5a));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x28b9908c57b69b41cdf364b95f843e8ac6f37b54cf34297e2a42ec324e51c82f), uint256(0x137cb703ccf6731f72037041a667cc3a1b13f9367bbbde9311f89a46b753b0d0));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2688adbd31a6fee6f876ec6c437dd51cc55cb47c2c29b56b4bcae3368600b9ee), uint256(0x10e565d0dd3c67063ba1297779554e5f5d379c6b2172b3009b1a4951cf6289a4));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x28206862e2f481187437820eea7aa8cbb9fb04bd8f42293e0f6f7308ba14bad4), uint256(0x1926625f9acbac457b7c35bcd0fd1e1cf5964feb4800ba872737f77b9911fdca));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x05ae57076f6dadd7bbc9eefaccec1e1c98c3b1bd65dcd1f002b47814f6c984cc), uint256(0x12cc2ff7eb590db5179c7cab236aa1e7329be302cdb773ab9600243c59c8622f));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x135efe6cb571c1d7aa1d47676c8c6db74bddc741ca8e1784525786dd6a365f5b), uint256(0x2cba3ad6b0a90ee9b1a1609f755f9bf30cef740802d68bdd84e9fbaa46c4cc27));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1ebeb0dacdbec2f29aa6cbdbfb4a6d3478a8b0f232008d65cd3aa6a05c9deae5), uint256(0x18de2f0f9f4463e0305f9564c67e2ebcafd64e79f703b8fe19f4f95a60b38e3f));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x0c31750d0baf091d610682929c97f89759116bfd59e3b7448ec4cfd5d6d1229a), uint256(0x21884d1d000ecb01d39c47a16b040befa6884063ae37fa6a612c690df71ecf2a));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0dd13d0e119977b7e5a22a8e53dceedcfe2b3fe9272a1795e3ffff145f7734e3), uint256(0x0ee50ae88a35fdc0cee9d2890827e6a05d053dc35c41fc1a31109ae745480489));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x20bcbf37c67866bbe919595633758311fc93fbe659ac8fe8a5d1426ab429b20b), uint256(0x1ca0721800d2666bf76fa5bf3fa349e3ed1547a85054015defaf46f58e4fb7a5));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x002a372f9865a9c4969c4bc463b1478766ad70393c43a67024c2b63dc25c5bf7), uint256(0x025ad3b5c3f7c6cb4c06b2aa8bbc7b187d0810619ccf4946700b25b06893d0b0));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x29236ab4a06e1bcf4773f21928c431d9ee3667b3d5da0589be8ac178f8b7dab5), uint256(0x2c6d997b2225a78ba9c7697ddcb639f9da60a2f3c5976b7fd2f0df6f5470c2e1));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x16d049895389defa2f42670eb13399199ec5c30a6ba730a90e608c01c99e60f8), uint256(0x29c0458d27df630821b8d06df79cfee8e5135590cea67d114f0d329b852ba5ce));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x01bd28f0c45c11806167fba840fbbfc42f6663fe902ac4325ad5810982438b17), uint256(0x2edda64a2debce867afa63277aec7bd800b5e1357f5364a8810ad5f68b0fe83c));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x138ee506c086e9921cdd35f51d6a013cf3849d99952183824b16299a649875e9), uint256(0x0bfa63fc06351eeb56be3d7fb0a04b6bcbd6424eed0033b6076381e9b4bbc62b));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x297fef60b548d995214d1ef4dae0ac6c46da3654b57a33ca8b9a256740365e0a), uint256(0x025a599e914182c38ba84147456a6b63c3d83f0555254a359efe76c76acd07f2));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x070d979fac712a62ead0040f7c5370bd87af97fc08432585295fc3d31538aa2d), uint256(0x1699b25827f03b7335910106bae3cc99dfe4d469502b2b376a66b3cbfbdec650));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x03db7be1e4cbcbce8bc00ba1759e6340830a7496f7b53ab725c6d32222c467b3), uint256(0x0205f64cd4226e60b339c9837c64024564964b4c9ff817b80fb2269bc7eab27e));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x0b3ea7e54871dff4a2e1641224185a22f5f4818e6fc17b8428346033c2e776c5), uint256(0x1f6a7c6d1198592fdb648e36bbcfa56c55aef5623371f21e273a28d0d6bbe208));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x248f12a3579fb30bc9563653d67894feaf672ac9d2ede206b3fb3374910ac5ea), uint256(0x26441b421a22b72b888cccdedfcc539b3eb5a4afbbd749b30ae913dbfcad6a94));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x153ab4a0527b9db6701eee554e8b934e84126e828d75ca42d9488f724907f20b), uint256(0x1fc08feaee09d5f38a6e273f0c35d66b61ed17e88676cbbec2bae5979b0048b0));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x20f2643442243c3ed120dbe75fb018e61491b14a4019fec553a345bc81643717), uint256(0x1d2ca94c6567b90f23810408b36d1fb7eaca503721a79b22ff1220354a595fad));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x11ee50565c4757d22a7bdab03491294524030e0b7958a06f0d2c52c297ffcc36), uint256(0x03d7111af04e32d0061b121c955349f3a625a1a73cec492e89fe0f6b2b484e55));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x2a4a0f5017e8c2cf0900bfa6d618a0bcc8c4a03442c1abbefcbf0344c5cdce1e), uint256(0x18f815135a85d4653fa95b3b59669507fa72ad3226b1c2d642b5bcf9243a61b8));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x2200ac2f816259325be9760c7ee280cd0f1119f0ad29e3afd93aea6ad7fff83d), uint256(0x0e652b6b0cec3e13543b57f180569bdd4c35aaa69b4235c915353627fafd9db0));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0f0919f99d49293aa7ddfdea1454233bf494f7c7fc0b3c92766e8c3493d883f1), uint256(0x245296e4b478bf9e64d4be1dec734f90a253dc2f849f98f5eb2378aa76e271ec));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x0c7bbcc75c057a7f70ce9ac087982e4037eace1fe425175ccdefa104a4d8cbca), uint256(0x2c2dbda6c9fc7bd71666d257e41e1207d9d00136141d13bdbb093ec6e7ac600a));
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
