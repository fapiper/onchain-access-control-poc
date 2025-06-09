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
        vk.alpha = Pairing.G1Point(uint256(0x1f1c6f8d7133f5a644745e10e5170df4d8914ecd70eaf7911edfcafab64befba), uint256(0x29b8e552f86f248aded3d67964116219499f6c50ac0b7e24e277b63cb979e6cd));
        vk.beta = Pairing.G2Point([uint256(0x2af68b13df7e49095148a55f4844f32942adab819c35afafcabeebb718ff7df7), uint256(0x072bd796c700cbed2901d380784a0765e0b64eb3a7b7372e36fc18b9c65dc134)], [uint256(0x09d1a52e997e26b00cb2b4fb865b64f7407cb66cdf03f0dd878f9df5316c44ec), uint256(0x1b244f8e1d5054a62898e6b37e1cc8e8b45fba43d091fcd8d59da440de27673e)]);
        vk.gamma = Pairing.G2Point([uint256(0x24683e78005f622f50709c1c12e7f4ad6f54caade65dfa669ec5ee4420e1033a), uint256(0x119062b640d97af97a12f78873c795da988778939e07b6831d7ef16c1e82be4e)], [uint256(0x2a7c8d28fee6bd485ede3053378019c26e5270f07b8e8403cae5386f64058e67), uint256(0x2ad31ae102965ef14f36a70868e28ee053bc6a72b3cf0f5ecd5fd4cf381779b7)]);
        vk.delta = Pairing.G2Point([uint256(0x1bfea0eac067a6832743b5f2a7d1140aaadded0df29925096b87cc6c8366a33c), uint256(0x20c1ef23aea110e790634954387b8f4b5c5a608d2011c6baafe8667897bc7650)], [uint256(0x039523d51750dab82c58e93e10a86a21cbe1983b8ff8c787d85fd33a12211e85), uint256(0x0bbc6894db1626c861483acf62746d02dd168534a3cd31e7db57a46a821458ee)]);
        vk.gamma_abc = new Pairing.G1Point[](53);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1a26f2ec912f0ba38502f8d4e5eaa032814edcd86849279b66e51f21ef0647db), uint256(0x08662da54a2fb0d3854bc7a9b69d97a586fff5c0e0f10d530b6642ee2233ebfb));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0124853cd7be0cd700cc52405805cec3d827df12b7cd4fd0cf0c0d1aa57016a2), uint256(0x03e8ec077d715be3fb4585993c69fe42b519d97d5eef141bb5defd7e1af1461b));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0a9b66777aff548b7fd8fbf21c53df15f97decf4a15ebdca03b4591f413e52e9), uint256(0x04acaa1de9f3dd4ba84746e43a5efec86433810eaccd34ca82960afec4fea6bb));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0c3d9aa5df468d9bf312b9937e2300e36632b47ddee51060eb78a79733d67a15), uint256(0x16f8431285c1bed0d1c985ad7cea9172ed94fd65d4b85884f2bbc7e885f57de4));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x04f70c039bfa82dd265ea293f9ab213e9c6874ab6eaf37cd06bbe59fb1144305), uint256(0x2785210be190069d6c71392f2115216d61e908b764e061b1d3e1bb7aa3f2aef5));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x199ab90cc79068db611f8bc311111ffda864abac65b0bfa4b1b62e836b34dad4), uint256(0x0403aa0957afafb7d0713d406cfd6f505e4574c8552b0d397eba2f0973e12026));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x136c903d355046ea1ae8dced997a58871c6e852eadd5a68840a406a8d20a8cfd), uint256(0x00c0b9baf5ef0a8882c3c0e185e5b1177cad5581536db442f9deaca8285b1154));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0575910311381bf9b7422ee26e71ff363b8076744bbddf59f1a432f6350fd4ea), uint256(0x0bb8c6a85814cd2f901cbb1ccffe07315c95bd878f241e80ecfa49619619498e));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x09e0c533583adb23d2883672477cfdc82e12bbde9356d509f663c02c836e9fd0), uint256(0x17fec191f5ab29fddd7530043e76dff01d3fd48feedd7d4f129ca46984b5016a));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x02b9e07aca681f8ddd7e25ef2abf7e5c32f04d97783fae9a5be0d18e9836647d), uint256(0x1a19c00c3f5d26f6e4e3dbfdebec0c3122526a1c0dcfc048637f90e4c3f0e87e));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x29d00ce88b07c6a80b28fbabe0e5b57248b4ebaf61dff5a39b5eb1eb09b75a91), uint256(0x021b110663abb9916656df9495555801d9d7aab1d109cd045ba4ef4f556a7fbb));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x204ebc58071a8f2686e331253a3a3e67de17e4a67f85608f7db0e5c7dd2bc7c5), uint256(0x040b7cf7c2f101f0d7cfc3effa456a491e72518c3320443e3cfc87563992646d));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1fe60fabcf15bba6742d89bdd830de76bcd49f462314f9fad32d76d95ee1a9f2), uint256(0x0033e857815fcf9e16a9c4cfb68d3df17f58562c224b061103b1b8d43007bc53));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x191869a0a5a58e8d789857daabdb033f13c2962ef0836e1e413e31b098efd894), uint256(0x271c487d30953a3d6a1820c0a141193495dd2943bbfde55b928b8d337351142a));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x272cb94ee56cd3c6e19e5cb53d13f33daf2607d894bfa7ee3ecde4fb33f545c7), uint256(0x154dbcc9641c55a74cd121567e9b1dc760162a1924b00e6b3e558b680b99db67));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0fb503f233a519a1c5de4a65b81820a06a22c446509b9ad5319d6593062e3d94), uint256(0x138530525d86086d2429ddf2fec40de121ea7c6dc5d4f6d45131a285fb221318));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x094e182b50be0ba7f545177f7378182fcd34dff6061a8421c875598df6aa4e93), uint256(0x04a5cf5e84a1ec250d529554fbbf90a1c6a0d414961461222c4e658d966e9567));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x019a880a6029d90ac20a2873b8549ccc982a005fc3f799ee7fecab5d608dc236), uint256(0x0013e3ef1ce9ba4ab015da4398fe3cf0751a24d2df291382fbf38577f2a259e6));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x07a851f4c11d1dcbb568a413a897b4034bc6283a429f6130187bc1a1e1ecf06d), uint256(0x11c9689f5bbe6b9dcfd0b29ad8148e73d7b836d667b73229cc118b48b9cbaffe));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x04f178312a155ef34aa277a8ad745a40dd259d92c31e2b5ac125586c5ac133ae), uint256(0x0bb3aa1c1597f3bea80c7f8f27c08a3377ff05bbc4aae46b1b7b61671c12834e));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x0e994ffd6660ac7774451fc4a20d021497f900a6371a497f426f3c8cd2f1050e), uint256(0x0f441b6fe956f52555972c9b03d96c3ee3e58b6bf746c65eb2598a74b9f8d525));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x25de46dedccfc4f02b415d2301c88cb1d533b6c74f56ed64635681d8df3e802f), uint256(0x2b32cba58d38c8a7557b5f51d5b85b99e883bb8f605e22a6fceae8cde6eaa4a4));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x18938377015e5ff05cab0961c58f7ba586830f27e5389313e0f3196dfc7208d3), uint256(0x2b0bece353e5af0f2083d1a5600b740e7792dd87c248dd3665d1f24ac98c71c5));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x13a65d2eda15011140b942d7ab3f78db7840d819a32afb5519b51363f029cc73), uint256(0x11d58ea90e32945dcc3b0ea309903b2f76f21df28e83e7adaa2b5cb3e849c04f));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x15951f5be66cae42446aeedd77ddc56180be8e744e321ccc7f2430aa93864b4c), uint256(0x2d451bbe69748283de6e072ebc0bb30a137ef436c073ccee8153dafc2bc6ef15));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x263303f6a62d890b3fdd7451f7022a13f28c7c803b307772d8f0481dfde314cd), uint256(0x1b33cede871afd2ddef718bea586707cb2f7368902389145b5ccf1dd7ddffac8));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x10cb64be7556a1e70b65314df06edb2b1556cef8d82194d1d4d61ab8de585783), uint256(0x1c3974389193293e257c5bead3a2d3819228813f53231072d1600d142e4bd46e));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x01a7de50a2a2de2ab93c8af3548c908023212599df29a8d35be7d8e19a2ddedf), uint256(0x288ff6b4d9d31ed600c8e65bc70163c17b027b7c830f97fc80a3d0245967880c));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x244a234b0547c02cfa3f96fc98690431c0c1f9153d295b0317223acbe07bbfb3), uint256(0x04aecbf0b873bdbca193dee037e120d62ccca60e42bb77a9381b55443727fff7));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x2dd3095e44b20001b7f9c96c90a25a924042e4c79218784404c7e96f3ef3b6fa), uint256(0x00960f6c93b115e30c2d4172cacffdb9a09778e3b60bcdf23774949341ee6818));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1d9c5ce379aa3dc48e198be41205c3ba849b870b913dbb40f4d481c38a021b0e), uint256(0x2cdd4a7ea7aba55651250df9d7c96d7e554d1dabb817e2a8539d1db5fd35068e));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x107577b5e8a01fdad71fb7ce62c6db918fdd90bd1c47de6247813e325064eee4), uint256(0x2a808209246ac6c6949a4d315398ed2f3fe9734e54b40fc9f87ae61ce07fcd26));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x28a4840ed0cb970db3e7043c7a309526a58f68b7a7d647cf2dcb922964f0c63e), uint256(0x1ec8d81820437efbab272ff778fa67ba2b03ec97ea9770e29afbc094d4b3c840));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x1a68dbe74dfa4bd578716907bfd1c871a8c153932e44fa1d796b88b8624afc9b), uint256(0x15ec4f96657aa3690d7f46bb03254986cb2ecab26271c8c303123c92b131b22f));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x2a34daa8c9f37e87fbe6230d596770b9366350e2f513c6c139c7a76fdc3d2ba4), uint256(0x0d74844f20f44950a0e7f3e71ec763a3e1c564f280a1ff2921316d5c03eed64b));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x245bce2c95e0003c51010df9a5fd936a5ae252680ad53423f188b5789a0f9f16), uint256(0x1c3661cf648bb36b05b6fb73b37d9991ea9fe41b07d80c2c8a71a5fe4e01c539));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x16dd0aade3ee3638ba4f07af05aa65e57a6dd9906c1bf88305a5c8dedaf8c983), uint256(0x03f3f5e6ce028ee83a56fa922c3ca195512739a01c7ed7044296ca1a98ae45a6));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x0cf7564ed12a0bcca9cc82a0a7100dbfe728fe49fee1ac1072c03f5556e5996c), uint256(0x0c0b98c237c9c90ac3bb17ac86a85a808297819f2f4ece8772971c71e45fd9a4));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x20553bf9ad0d54d7a3e5425d21880fd1eed45b9e775c23bd78c67351a46f1b90), uint256(0x2073164bd5947a26f3efa0bbcd0f79cdb6af0c58270b1bd4dac7794b08ed4f55));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x19e81401ff2b16bbf19a5ee8597d3dbc4ea70a3944f50de5d5d534aa16b6d1c8), uint256(0x29dee837687424b2bf5693c3e4a8486b2bfb8e669a4f55844b60cc8d69841598));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x139b7e42fd4abbe63b77d999c89000ecf0912af4015f5416510785e597d433fe), uint256(0x13993f4d0463977419f8100a547314b39a705d76ba04af0378062ed35e05eb19));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x1c7dfe0d58f8cb20be324685d4842a501915a33acebbdc647a12171ea2e181a0), uint256(0x0110ac49cbf1d667dd99644fd9481b1791cf11dfaf6aeb00632fbcb8698974e3));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x157ea988441012ac5b9b4f12970ad7dbaa5f3d9e3f1b1a06538ca56006c27011), uint256(0x0ddf3e2366ab6140029dd530ebcd97e863e1eaff17c2712a83d380c316043e12));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x302f0f3e81fa085085c7aabebc8266a234e81be726eedadd169fe8c5de1f316d), uint256(0x18d4d6b91788415eb2aa668211434b6625c205f552177a9fe4a19d18fb0abb4c));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x2ec71445124c49ce3d113d8227896df576b6a25535c13d57172b9cd89da270dc), uint256(0x1689af7bdd7049cb22fb6cf61d96241bafaf84511e357df89f72d865029894f7));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x29242dc3aa868809ec3c4c2c561d618161de11b17f40487b34d3d93320370ba2), uint256(0x14d1732b4083e380dab44b7ae1166a0d62db6061542636e0ff278e41571f165f));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x15c2911cd793ceae933932084d1939c0ccbf7191437ca895ebb4b080ad0cee7d), uint256(0x15f4bf843f66346e07320a03e529a744f05866045934fbe3040332681ba6c797));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x1f18c9462442b6dc9d90a7c13b3f8c748b197a4363ca58117aa29b3a2cd475d9), uint256(0x277a91b41e669adacfa335d4dfb779cd85f35a66d74c3f34574b80c40586de25));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x27830318d2e264db8586474ec9578bee326baf25f0428e0394a0cac8f62656d1), uint256(0x2db1f8a6998e234a4d57441760ef4bba76cce072088fda974eece106ff7c0481));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x25308c23dc1e84b02ef870b32a2ffa967a833fc638790e19140e6fb92d53f886), uint256(0x08e38ebe8d2ce80735599d97a784f2c03761bf7603f0ab3201ca23cc4185e0ca));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x1adb9ecf3ffb1050f1b2007dcfb0f70371709b17f7818f5a949c30d56c713a52), uint256(0x1cff838e655fa3095e7bf2b58c9fb99d810d3d3f6ca3c7ea5300e1ca9635f6a0));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x0a2e88c9dedc8338a2d27525953782eaacec58b51ad00623455d73b216a271d7), uint256(0x227008aa87643b40db832a7a8cacf3d4ea1f3fe41807cffb8f7503582a066cf4));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x1c1475f688248662caf281efde42876b5371e7f6fec0d83ac790965fd4a1a4d2), uint256(0x10216448edcd0fb7974f310c3289f3b35d278a2cfee35e4a34fc64e329e87c0b));
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
