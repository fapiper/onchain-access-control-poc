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
        vk.alpha = Pairing.G1Point(uint256(0x257e2f626628e8924e000e6ab0c6aa2e16b51774afcf9d8f7e4b45839e7489ad), uint256(0x2b4fc061c724412d377990a2b1087e574d2859e7c2891427fb04af8c70450cc3));
        vk.beta = Pairing.G2Point([uint256(0x2d83b8ef972bcc61400cee92ddf21a6a714240166e55d5a3cfe06a2dadf86fcd), uint256(0x0fda49bfe049f19a567cdca12c568934132b0e2b8eceedd9c290f1d514abdfe2)], [uint256(0x0f008a4bffdfdcf6f75ff108fa66926dd0819f248d526a1516024d70a3a4ed38), uint256(0x1034fc6012335bebd7a2eed621f62e609b37ebd2358cc59c96db80d4331c80b9)]);
        vk.gamma = Pairing.G2Point([uint256(0x05f64eb8fe009935bc939e1be0c2864437867cbf60bbe850d392713d9785a539), uint256(0x0292ea1c54cbf4a245bd747f42fddb5db1dfec0e4b6b1fa0408bbab84ff6b578)], [uint256(0x2e0c6f29203d71ef93fc856633377f1605db9a2624b1a96bc2328f10eeaed168), uint256(0x0957d5211284ae349af05ccdc72ff5a01835e7eb06e55ceef69d37ac65e8d9b1)]);
        vk.delta = Pairing.G2Point([uint256(0x27a3f5b512e6ca77717a3910197b3c64f32a2cd93189dd833aa68dbc476ed168), uint256(0x18872b76152dca1691d1abf5867115922655f4fac1dacffea775d9b726026247)], [uint256(0x04b93fb5d66fc444c99f8b8fe6c74508fbbb1100ff939e48425e93b62456bc08), uint256(0x0ed9254f0e24c4d69f114d3842aa18d46e45209a9d0112f0afb4d6589608b651)]);
        vk.gamma_abc = new Pairing.G1Point[](60);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0b2da8fe60b057ca0f0213650b991b5d9d41491aec65dd67578ec1814e63ed63), uint256(0x02aa66f38c650310473ef4736bc09f83bacb76ea28afb04e7e1c07c25934b892));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x19df2ce42dfeb0357f2a931756439441807528e010b18608dbd65cbef1d31d2b), uint256(0x238376d4cd4cc6bc09e0dd674f7ffa48c45db90f6b548178db1aac555fad4b44));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2ecbdb7b9ecdbfc169cb538f7610c19a7f0b6a8d57914d2fac1fd7a8175748b6), uint256(0x1ca248248f1cc115d751a2f36cb277972896c7e2dcaf9ea0d928f57cc9835089));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0e084df849e5c53987614218782c6105a93aec6691dcc28741b2aff36153882f), uint256(0x20346317cf9dd81e3f7c6299e7bdaf15c69430d132c31a840f913ab6664c7d5a));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x15a8f0f29cbca9d993a5e9af64ed86faaa71b2153ab063455da21b03e1d46655), uint256(0x08c8c751ed5e6342afeaf5e8f7956c2ed250a4cc1a100b4d311e784726880a7e));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x177a1f7381a6a36f7dd8dfe84f56f7225497cb7f5e04301ba23bbbd1d3c0faa7), uint256(0x10d6ea11b91e4b29cd2395da8bf7b0f4aaaa9d9d758611fcae630bda2fd92619));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x28389eba4e35beb0fc117d75385a1a7f6556b34200e2cf1017c4602b5de9053f), uint256(0x09014554371b5656bc92b703f157899436fc73aafea807aaac1d79160fbd51e6));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x25ffbf61400f7586fa25c0e1e1ef82bfe49ad1681a5e77206de71212b8d2126f), uint256(0x2891098fbd11551bd54a821ae1f2aa71cb0522b6271ba075ad571cbf061930c5));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x283bfa25d197ec3f4878dfddf9bc668df26d4f45187cad68fc099142b0de4519), uint256(0x13047b8a40931c61f41162cafcc73f3528297c193a1451d550db1330f3e927b9));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x05ad5263b3f9a80a79d319beeaf16ac0ca2ba3bebaa408d8dadade96cab38eba), uint256(0x016ffb1ce39d7ba835045e6d4c3113d1498abd443fb102c7df22bac43bbeb55c));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x210084c92a9860609263297f49b5e9699494859d58c721d2a4c4aad4866eadc4), uint256(0x0deaf23a933cd7d899276ba7006f14572791399b530d0661228d823ce333c659));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2566e25996fd4989c7493fe7311c5925ec9e15d57b6ce8e7571e658ae7f20c69), uint256(0x1b018b7cd2552052b0acf6e3d06ea3c8e7d92969cbcd134fe8dba05ceaf82fd5));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1251516480f3f0ee848e48697226eb95e30e1b075bbb7b2c66a59c6222e9f5b8), uint256(0x14304ce750f9f2fccaad4b2524f30c5e3b4317c8b3dbe42e5c1a5dbaf5c4da32));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2eb5cb4b89daacdfada2dc81ace3343c70cc0024f7cc7246a2f7f28aa61dd6ab), uint256(0x129d26898ce5ac5f17dabc988d442d290118e1680a856d4ce7689065fc8e6c04));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x037036f08712569ca9ef9ef96fe02b7b9ff87976a83d17a1f8a37f38b425cff7), uint256(0x1b2f20d5d9a506bc2f38e8336705fe948648c38fb37fb44d21542ecc79360333));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1647d91827538a40a85cdcda9a5ece0ee95d15a6cf60799199db44d2d92a2f5d), uint256(0x27ef0773c2cc3fb20eae9f59993f353b91b0d74bc5e7b99a5a2e8ed369d1ac01));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x11b87ba0eea8b115d95065ffab75759153b822210b22507ce020d6fd2186bcae), uint256(0x00208369c4e7a2f0557da7aa7cdcf5e438f5db11a63c9c0826a14946139321d6));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x26b2d30af43bf890d94c50e729eb448bdcee5f40b1a0a5b3a5038cc11ed06c7a), uint256(0x262d2b5d12731ea152fea645b5cc09ea9247570fa725a44d4fa7ce2be3a87295));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1ff8483c2b434b8bc28c21a3d2af1d6d59a77b8d10b31a5539e90044bc342a86), uint256(0x2252b4e83f4c95f57cd9f0c6335bf2a3a8dda5192ad3726a78008adb9be2b8f8));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x068e5925769a76e5b3f56643dc336139c992562cc19aae79443d80f42d3575f3), uint256(0x0914deb98ef9e8da33ce814fe36c98bcc351c27439a0201e9382a99d92d66335));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2112084567c1f1e198f4a5bb87c9300a64e28af93c9c73af17121f50ee379d0e), uint256(0x28e58c328a2b2bf106c47aed825f0ccbb212677a69226f64fe6691a9552d8521));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x08d09d479ca6945dde18108b634208518dfc5e667366f6273598f9501a176e9b), uint256(0x2efa73f955c3fc04d2de8c510e2250334d07c8b94c9642319ca58bf16c9e99b1));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2d4fb42388444fa0b19d59fd31e5ffefaf38587f3a824b1877ea3d75749d674d), uint256(0x18e288d30aa48faba7adea75e523a26c8f737222a18510b53b0adbad08cf02bb));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x04ed0b8935249e2d316cb955428f3e7deabf6ca0ee9941cd09e792d35f916bbc), uint256(0x04ae9ad17bc3442ad76fe3945778206543df92014c7a3aca8e4ec28bcbde9616));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x01b24e260b582fd593877037dae2f552bd9da60a86a1a827e8712f74e0dd3b2d), uint256(0x12ac292051559451cd69df728c4c997fe56e4c83f6f0873f510b775da7130492));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x07a4b1dfb0afad9f6992f2de3d201eea2984ab74ad035280fd3c856693ed0e65), uint256(0x0c15a838d3c5707544d348048e526c88749530c4c7e515077e3ad6004ec9bcb3));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x177d57c31d9c8226eed97940d3749b3e3642e8276128e01382910ff2de2aad7b), uint256(0x15d666c5d00a0363a73e1b69c20d218fd39505fda4b0525332f23a5bd12b04d9));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x0d8182b90b97c123caf7c8102797b5a76d1d6d296987099a7411d97f7657df89), uint256(0x00a0bbded195b8622616b8708b3874c18aed1deff29e5dbfe22c18012ba60399));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x0705afa3ddc0f4c948b44512af78484c79c518e1e315ee734925ed94df09fef8), uint256(0x1032ea07e38d2920a4046ca010a186e6f69a80434be2e880a12a04e652dc93f6));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x2b8f4b40f51f84ed721bbed1c380c283bcb805bf916a31da9f886ca5d1436100), uint256(0x071ba18eda63f26d0f7fd11478c5fe4961a1c8f6c3c663ea72bec999faaa0187));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x13ab3f20c46ca21e2d2f73eaf72181da1710671d9938dc9d35677c37c2c71d3d), uint256(0x10d1980df03da65e326b0ad3bd1745bb235d4fe57c831882857c0069142a2e1e));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x062cf217d3758eda97aa0d9a6d7702f1661b36eb2d1b4026fc361a312b306c0b), uint256(0x1c76fce9f58e8430b63e7734df217c9b1d9ce8ce90c0e089ecbee575bf0b52d0));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x2dbd1106a1427219314b5bc7ff1b3cb0b3c6adf2c23e23d03f2288acec0b4f0e), uint256(0x2cf440add7698064a52980064d8f40b82ae22d0ef4476858398aa03ac514fc04));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x2089e4b6cefd17febdaef15f603dd167762166e036f5e4c288258961827a0b56), uint256(0x20829b994e2fe3dd9966372b9274e999bd6dbe1c002d806e6f4262d318cc1729));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x03509af5676e8222d3ae8b1658b3efeb55b9ddc40452719af213354d29e935af), uint256(0x29772316ad68ff389f20043499b204e45326a2d123f89b7dcce2e06e25481463));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x0465aa9597e7382e9d30772d43f260ede297aef834c8aaea7713599a3f8dc794), uint256(0x11615fbc5b34655a13a243d3512fb2d6b13af2d71d1a3f5073d8365f8a9d1d3c));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x034225be0380c083c140e83ea445bcb62b8b10041deb206ee436eec813f8ab19), uint256(0x0a958dfa0197e139732ebf26aa111490cab0685561b61b3e007ce64be3b93d74));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x164b20c0c5f3e94a936661d69e02fc146e83ed4712c4e2bd9a02e569f85e9bdd), uint256(0x2b069e47dd4b08b9b0c6ed5c008508a1da30b680bb36892c590f2dc0c37dba50));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x25b4ea58dc98175b6e256007e3925edf2f96b7d1b34f527b827d54392c7c06db), uint256(0x19caa6d7afee14ec881746289db70ba629355d5cb99da08f629a2d1b64b301a4));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x01d766d9fde59a68e657dd3dfcb3d443b5dd4d36e6e5f87ddf5b7f3af28d5838), uint256(0x141b261bf9a9110877e73edf3b6d6c50bf63e331ad71c5767aeac9f443eb492c));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x008c932ed209ade9436dd1fb0759c322125e79b5629e7326b463905c03bff84b), uint256(0x15e639256e6532311822352bcb999f0ae30b5336c4f9e539215ba10d50a72898));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x02fbfe7c94960fbfc477150b8db71c4cea5fc4cdbbc60aa2d5bc871e4e8dec5e), uint256(0x0133af5a216a45a2d879d9c5ec454798f93d5af3bda3e3c2764993ae9e6a2b16));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x1b8e1d4692178109d26c020507a0e88b73cb449bc1a0f3c394c2c25a8624a688), uint256(0x2fdf983b13112a5cc268ce6faffd73023bde26f0e74a104e7fe4878a7da93efb));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x1024b9a8fab827355623c85947da661805f583d31bd6ef366437f90e40e7358b), uint256(0x2c50e99be74c529e32e8d665a53ee7f87c463ea8ad843dbc9b5eeeae514ccd7a));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x258271eb2b2f3a74b6b993abf70a4a53486598b0f9488b8dfd1be63deb9fd748), uint256(0x1835d0727c7de80cda1491e71de297f539acb176f97ad95ecf4ad7ed30ef43df));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x2af049d330480e6f90e8b950efcaec88048b29c3471f881d91dece6183f4cd06), uint256(0x192cddbe974491aab5df7f82108d960ef6763fa31b771f4e29ef64ddcd35dade));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x2bb3cc749a6c22fb9c10e294080eb77c4078cba9d43d6f8d4b8ac4ac277acdc8), uint256(0x0ee963721d7926513b962735bcfe709a328e9267c8904c92ebc55cb2b63587ac));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x22323816590a6bda70a699252477525d96229c4871484e087b04bb817cbf7318), uint256(0x0643b55f7b58398435365824037f1c0844d062a8f4d706c7cb07acec8bfa55f4));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x2bb813942a843be2cd1be8c6eb6cd6c7018901916a8fc5c35720089ec0c6f123), uint256(0x28d9726c763d811358281a773f9617353eccf72b732e40dbd28f054e9cb9a05c));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x1d0fed091498962991c45ae9316cdbd3f254555c5b49db3bdc92f4759a41c62e), uint256(0x09d2a2ed03a3b83bf1abba49fe3f4776c42c8f9dbeb68271ff32a87bab63d0e1));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x2dc78507bed73c1596c4b3d506ec8b96ed9be1bd73bb72cb4fa8fd122dbe670e), uint256(0x17ff1835bba2e09a9d021bd586616e63303628d951d12a3fa9b21fd75be6b156));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x1b1a6c305841560d90f579a7fa696b8ccbfa9b454a33d6ead1be54f118e7b636), uint256(0x03b7980fefadf94aa97ba22074f7f789659463dc510a2567e67b05458b0d5178));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x2103ec4ebc3063f502676e31c296845c3e6c9f772429f55c856ca25488c69869), uint256(0x0db2357cebb979967b6b4a27a65bb1c8aacda2bdfa1249cf48dc9b234b813fb3));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x0802bdb41aca214b526fa7bc6413f4032f347502fb11b1de5394a3db76812da4), uint256(0x1607a4ffd7214e4a58c2ba746717f8b87aeeb3eb4c9a73a06d14986b85ab5292));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x0f08f93dc267f4a47c09a983d81021e12586ca22b91f86b43c30b77ef8ced5bc), uint256(0x2025248a1369d71926110bb4a19841abb1024a3e7b386bf13acbcf3b32cc4508));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x2cd65bf02537e22b1ff5ef8d3c47e676551116188a8646f3570a58a8e7848394), uint256(0x269bdeb85265c4be1e0d9faaee9d9cd31149377377197216bf8a30faba532ef0));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x00cf29991a869211152eb394506358062909c23ce484c0530e1d78f2c90ac94e), uint256(0x081d729aa64e6e8dca3a8ceafa75cb7c2ea3e13d1464c4112268a32549aedded));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x231dfe9aeadd2340739f90394d9627e0dba3cb2b398e19bdf264ff61d9be5dce), uint256(0x0fb062765f29ebe75a82a4887e74b6a22f542099632a67b278bce9e7e8b2779b));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x1f255dd4faab8aa0e7b18b7b838eb440b59e72c2d952e60462b85277057e1e3d), uint256(0x258993b57fe6c138747e72bbae3d43d3d98007b6edb8a668c12c4ea24d8618aa));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x072dbb5d5f018f1c2e24387f321ea3d2c40679fba1723aea42934394665ba366), uint256(0x2b39a91c51548accb20259a4023c8e6dfac303f1f24e5b5c0cba4992c2ac1c1b));
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
            Proof memory proof, uint[59] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](59);
        
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
