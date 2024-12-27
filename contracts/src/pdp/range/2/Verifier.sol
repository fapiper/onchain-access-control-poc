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
        vk.alpha = Pairing.G1Point(uint256(0x22683a6fa23859bbe3cc565e730230a551895acc42689c4b103f8e2a1dcdaf05), uint256(0x07a784cb90fdf3f82bd2e493f6586735d87c4f9e9d2b11ab8044b6198eaa5bf1));
        vk.beta = Pairing.G2Point([uint256(0x1453b34e721ec91dd8d761af2a7dd2edae160c5e7bd53e21b0f2837f61cd8fb8), uint256(0x218f6088bd58cf8d422745fd9a6fd8ae6e11a45d2fbe54c5e4219201bc9a779e)], [uint256(0x2fdc7418d2ab77b5e97b877ee0226ee4cf83d3b513dd0b09b9bf11bdaa05cef5), uint256(0x09ee276cf7a1782bb2f6f440d0fab0e19b1229c03889c725423f91141aa93c6c)]);
        vk.gamma = Pairing.G2Point([uint256(0x23d2e10528b04bf0d10feab3b8d5c273d69007d21b71a78d8f05fb889affa396), uint256(0x2425c22c5d36cd238da2274da1aa56d587b0d892d9b1a1752aad491be14e9d95)], [uint256(0x1219e21d013101fe9cc38a0315aa2382ea3f5f69a6e780580ab23f6c9e98033b), uint256(0x1e8c977b1693424d0edc762bd1ecc243fc0f14b2c9fb922b0519ed89768db9e1)]);
        vk.delta = Pairing.G2Point([uint256(0x084df087a38ab61d9b9818a9c332cfa56bc24d4b3edf8c733f39b222c98a13b0), uint256(0x2796f9bcdd696729461849a67e82c189986c1da9da18ea75e3ad48b8536d46ed)], [uint256(0x04738522d9dd76d76320eea05801e4f04cf6f547615e7c214accb8ef96bdfac5), uint256(0x236e0555f5e3ee90f805cde4e988608ee9c13694dd98f3499e0e9e3aca760e18)]);
        vk.gamma_abc = new Pairing.G1Point[](42);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2c34fce28e2986c84e5fa0ab6566c01664736831a6053af36dceff20e4bca683), uint256(0x2f9aa0d3d6f9ac27e8980356ab758321a6968348adec5eb5d8e1fb42908f14b8));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2fece1f2c044c58473be21f6cf0974fe178381be02d5c9fb2dac6a5fd2208084), uint256(0x212a89955e972be9259c7143b84170bfe1262b7d1c7d468a6b518c085bdb2119));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x190ec6fe0fa79dfa26862780ee200b6528599a24e77e40c088f8884103e2ca42), uint256(0x0965474072ec05d2090843de86e52932952cfeff04e5b26344b7aacabb3f678a));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x29dbf6df26cfc97fc76c25ebbbf27b9dcae955255ea451c129e4f1fbc3af1ce2), uint256(0x2ade45081751d8b7b4c84ff7181bf23d53ff9bbfd6853e102e154786f22ca116));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x049932fc722dab40200e5b2d7a2b22ad6212bf83fbfca6fdb09f1db7c74a8d84), uint256(0x020ed5ab81758a6f2f82e4a2ed9ed2ae1c3785db43481c3f713c3ed9511772b0));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x143ccb95cdecf47357dd77ffd87474ea9c7d18373b10642eb4dcda573316ee12), uint256(0x2c6c43660b31efe245153e54f316d589547928734f99c13deff7c9634f46b951));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x296dce32d51631a106d656be7420cd233e5451fda705b34c9f8ebb218879f0f0), uint256(0x2cb43854c3eeff7535df83be320a73469ad1ed552c0d8e582e39016edffe9f1b));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2db82b0ef352741b079e76650166aad30c0e1759aef216a78ee4d464344591a0), uint256(0x1c20f1c72410bf5a211a288e6afb6f27c44ca183a3a63580b098fe30bfeb5772));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x01abf4c4d570689c9dc7ec8ee35a475525271af3e33303be5f23a877f72acdf0), uint256(0x23983bd0ddef808681e91a47d4bb1bf9d36ac798eb29ef609ecd98bbda870fd2));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0b7e59ad0f128cef4e6ec341e221ce5eeb8032adc6a274815696f4072d24fa9f), uint256(0x006f9cd09cad36dba9f402e92d9099a4d45f4a78ed1818e6ee6f6e058bdfe72d));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1f3c135e3f6fb5e93dcfc187d67e11df686a5079a019c5a9e4909791b9dbb309), uint256(0x2d724cc582d3600ab4381a4f852312a7b22a7653dfe43d1b2f8ff7ca86971fff));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x01220edf5faa0fbb01641201b17a119bfb3803ca80b29b7c60aa872eb79db2cb), uint256(0x2a03ec140cbabcb99e0a729ecd13baaba803b626af38122920cccea9ab80ddb8));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x24618a1ea493ca0141e935bb4f28015ac01d8186f21d0e97ef5b91c1aafb24b0), uint256(0x2a4392700e531ce7f6f209a0aff5f023f70861837261ed14333a8108bd0cf9ff));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2c3594e6e828223415654efe1805f415c461be4d3c271031cba738eb89d51cce), uint256(0x06ec76141f25ec4e27286f24ef61bf633bac879731a35da5ca41e1731f1225e7));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1de337f52558405db2d32dfda5e738334faa895a1ae1b1eb71e6ee279c582f80), uint256(0x11ef525ec1591cb9637b7eea6948afee64d41a1aea4bdfcc21d808d2dfc101d8));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x05602844cd25654c50df291ffa055dba6ff8f8d8e8f950e5cec06ed8b7dbf6f3), uint256(0x1322e56d157dd5ce5ce875e06d918189ba0bd65b26fb09223a362531bedaba8d));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x06b7fb644beb05b837b4c58ebb09b3413aa0bb7989d92d22b25556cb0ee35489), uint256(0x0229a382e0aa9e26d9b7bcf0a3213bb67440ce1fc43cff9c593e35608e9bb7db));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2afd9226e01f48da41c64f4152e7d228f08d55e940f75c18dd079a517299fed6), uint256(0x18cff4deb1c41201b49b8a669b6b502f479904d938dc1175d220480df539f137));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1203acf2f3890169cd98732ad94a1f8f3d69f0e26b47c2c60eab5ab02e6d572b), uint256(0x16f6952e757fcbadebe9f4e4b453c3c69f366172b8f09d571e1fc278dd96f420));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1bb2511a7fc333b6e030751da6881e023906e5603990f9b3a57ecc9d2244d9dc), uint256(0x0f82a88776b50e3f9da12281c71bdefe1675cf51573a8c6419f7c3745cbc58e1));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x1295f9003c9cb6b48cd721b86d96af9142526ea10462f28e7c5c4497d70f8315), uint256(0x04a389895d1b5b728e777c33b8c542851eacf06097dab26e5200200b414c5e44));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x17a92af8775afcd46f8c82e8ce17ec223bd1790a70f2074a27bfc0ab6bace70f), uint256(0x0687684941bf59b32df41b793bcdecde8392a9a67dad3e954847d739c9252f03));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x0af77de4138af59e95543722cd5b80bfa40c3a5e37a40ead5d1ebf140ca99688), uint256(0x18c1a58a6d0f421e624b59e797c3bbad647bfd76c51cabf51b3ff0177611ecaa));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x030ed76d04dc2e0330fd3f41d0142a648a0159fb48722715a31d19665a3d3b5e), uint256(0x10ee2796d31599ff7edb5944111fc5593c56102806e0de32093a552741c2b10c));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x223fc563176e8a14b27d5b079397a6e3c424dd46df7dbbd9a773db1f1f6a7960), uint256(0x0f00710de239fe55a1ef7e2c0d52f3292bbfbcfb3eb8d197bda6c9472ba6da3d));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x2c06ec3fba35b0fe61b880a769ddb0a315f26f544dfabc825c73fd54755e6065), uint256(0x05126d3d5cbd0613221be5aac97cd545a8d13761e57c916b97350debd958100d));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x2d2c913749f98bfd77d8c7c09a67626a55d60ce8f15c62bfbaf97bb4f576ee21), uint256(0x075ee77a149cae86e82c1f9c77698d01e5792bf5ef07e69450574a2b628b99e8));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x17dad901794ac8b7c88a319bc7507fe3305f725cd69df0df5b56c6f5a6166388), uint256(0x216dfd668b84980353e255230844bca0fb734187a46838b31275e6bf300ee0bb));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x0760bf604fd84f694ce43e6d193b9c5c872b2d0f5d34582996033232b7d03372), uint256(0x176f36f1b2ffd9b8eb78bd291872f67553241e60521d83499fac72eb69415162));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x07fff60570c746646570db88c8262b8abdad8fc9c69b15843575e325a6d745c9), uint256(0x0d64f23c866d042979c92b3e3cccda519521f3f566f99d31c2101e1cd222a2e1));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1e675ac2990d7976f18f1384a16f91344c6ef1b3068cbf695df152d4561930ba), uint256(0x0bfdcd988f155a8660fa94a241e4817a6bcf9c05409e213f085b24dffb26ee59));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x27eb9c086468460e1c54847decff5a73ecd7b6cd5f06a224f2bc419de281df10), uint256(0x2f8f7cafe7794c6c0fa8b4bbd8bcdd5a641898b89714c078a0447e05ed7b079b));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x2a3dc64aeaeb6982aabdd004ab28cac348fa7a76ec31a42ee67cf2ca5ec3f1c9), uint256(0x24a4634a5211e65baa5a65e2d2755ffae5f0204a19f88032bc656806b3e6ebec));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x02cb70f4ee572251c7ae7e582048723760c3366901031ef9be4b70a94d37693c), uint256(0x2b5ef16d3017d858a4eb3ab382f6615cfad169e1c64331392b13a372b3cafa0c));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0d211f21dcf566fe1165532a450fdc6afe3d72fe946073d0f27b77f749fa2fe9), uint256(0x120af09139bacba61435e1f748523691bf09fd49d7fd37aa72d8c7f4bff93446));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x2f02132eb8081e00b9b43502a5bb7613a44695710dee6520bd05f65340c41572), uint256(0x17adb974dd6d73fae223518f62bb83d3dc3b07cd3656443d3aaf7dcf5b0615c2));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x2e970e4eb685bda223e39558b6421eff54680106f6670aef4687e9820758bd7b), uint256(0x001115571af2a758305093310379a04f0c3012564bb8bfe924c36f58df063a2e));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x1d7985e1f1a539cdb020c29b7286af60020584ace05d7c1763a109296b47cd60), uint256(0x185035471170c1dde7581d96b81f989afccacf1f070e76ddd550fcc0549344a9));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x199d7b0652851f889ad596efe23e4259e38fc6c9536d4702bec939e39fdde995), uint256(0x099f05ac6fb76f7b9ce6110ccdfba31ff35372e5c97781655be188928b076b18));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x1bbbbb94aa3e762c4248c2509fc786e1d260ebfb48807d3b5d2a801ced3d9b88), uint256(0x22975cdb4cbfc40f285bb5df4eda3a8da80aa91210c030436de4e06041045f89));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x2b288ccd17cc97036c9d1f44ef446423917123ecdc9f631b7aef37f3c6569e4d), uint256(0x00160a6e9e273c5070bf7a42c1675d722de75f4dce33744e92f8af5bff8e9c9b));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x0009bc323ea516e564580e73f20bf30fd674c482167fd8a926225ba82f43ae82), uint256(0x12de5da12d88d2218d158ce4c4d9e85121583186fa15a453487f6bd7f7495109));
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
            Proof memory proof, uint[41] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](41);
        
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
