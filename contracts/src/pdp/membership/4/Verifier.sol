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
        vk.alpha = Pairing.G1Point(uint256(0x03e7f8a04de9eb63206c07b393fb140acb74fb6219cef13bb2e515177b909a96), uint256(0x04c57fe365075e6e83f9a0294ac78ef3a025f88d0d42e1cf9583a5657d856600));
        vk.beta = Pairing.G2Point([uint256(0x20077c32f917d9615bd30e4aa1ffe1e3a4eb3c15ed8d2853911b950f86983d50), uint256(0x2e11b132d3cab1171171d5d53c44210461c87ecf4923da8926caf117fc292466)], [uint256(0x2f0e1261b5b83e7f37c95306d9e58cf70dea4e8ecde17d9de3f5250f81691946), uint256(0x286b26a4a79b658cd9979cd2636d651bff9bad2dd075cd2c30dd749dfc5f7314)]);
        vk.gamma = Pairing.G2Point([uint256(0x1ed07339ffe157bdcb4fd03efff70699a152f08645c067710650450ad4d4a688), uint256(0x0f1c7217047df0dfee4bad69eb9ec8912377b851edd86cd61f491d6dc5a2859c)], [uint256(0x2d99b0c84c97cae304ade7d078f362eb4d2fb58c5109fdaa93942a438e849e87), uint256(0x0122c1b5387dcfa6f7aab3f399e72fa32c5c6cead281b04eb37e71431daa43b2)]);
        vk.delta = Pairing.G2Point([uint256(0x01305b8c615002af3da75b9156b65049bf6d6eae96b1909e8e792c2ffce27969), uint256(0x0c76da772cfc06493c0d958589fece27c2ecdfafec8177e0a7e238e69ed00941)], [uint256(0x16ce36b64baa154a0f21a6a90ad4795d5490cbaf1761185b003e13805ee28cce), uint256(0x1a104c7829e5523aa964d921a83d194493681fb76ea5c81589da8fe4ce040d49)]);
        vk.gamma_abc = new Pairing.G1Point[](221);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x10743aa820229d0b48dfc8753d5f0d552ae20918a8b7a69257f4220dd6408b22), uint256(0x07e4ad5a25c2bb0591ef21ae1edd74a77dd91f2fdf152ef3eeff28392dd9eb8e));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2fba89f8c287c76fe6c20699d76732a81f2f15b9b04550f71c465ba5575283ff), uint256(0x06b252ac646c7494c9be3c6a5f6887822ee665fd504fe7d1172402606c3a4a04));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x19fcdad4f84137b1f0959c7c72a727d8fef48b4670621a08d30804b0e26ac0a0), uint256(0x0d4a753d26108814fb22e7f7e024ab7b8e3e097a4be5444ef0035f069e3df407));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1621fa07baa9f30f5f0283f4bc6bcb93a2fdb2999a814f5a9b30a7b06c7c637a), uint256(0x1e0822784889e360bccf995c82ebe97aabd3ccc75370414ca27940dc6bba8003));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1a646794235d68b4fdbf64af475d71be6eda0d2f07631ec2326663d4cf095970), uint256(0x04f66bfce90b351c7a9f08823fb9f08dc06acb53e4ad34946332ab54bb48ead1));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0a9be455bc0ab0d1cf7da30a69c10655362b9e1a1f356e1b879f7e66e7240707), uint256(0x2f4676a80100b7def00f1925014078514bc85f3bad92c779584c6e30881d9401));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x027ad97722cc74e51a9987a78eafa10f1199bd947c3bdd65ee4bb5bc357503fd), uint256(0x1f79e7a69990d6ad7263713249639da4a13af361305ec5e917421a4cd3ffe092));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x20637b1c1dd3b79580ba16bb488877b9cdeb3758e326032e717dba3e413c5069), uint256(0x04bca3d23a2c5cfa9d29ec3a31f82aaadcddb643f8d93751eee24dbfb37b4fbe));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2c0227b52392bdf1f1fc04f0a2d9cc1a87945a7dc162c4617411e6ee7720d575), uint256(0x136222def3b79f47992d3f5be3be5d3edecb3d80fdb4c8ef4a9c2a077da6fabb));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x044c55f34afd527aab8b20f7c3ab366de0a6dbaa7070f25269dcbfae842f92c7), uint256(0x07c4cc178879206344e33d3ef1b726f88f23fec387d0a7000ecb20587d76c7ba));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2731b132a05ff3ad2af3ee309b1a2b4a8ab66ec65b459f7b106442fc2fb0bb1e), uint256(0x04d9cda666bf30c77b8e62d07240b95dc4ffedf64ca70e0e730d0c6c87793073));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2a1872a71d9a78197940dee202bef4832c2a4e4e86ec6864730a980553ea9b5c), uint256(0x053d86da309b277641ef367270578e7162a4a96450bc433541e9bc12f2f94ae7));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x07d57982fd44bc2305787f8c777d802c8d17e9c59a39b7e9021a1dfac5e14114), uint256(0x0b0aaede2a606aeae053faa1f3516b2074d771ddc490d4910db65cd265a71beb));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1d50eb10f47e463e156ad9173f6433ac709a226949ee2732f5a117d64e7fe341), uint256(0x128f3e601d83a9d36bc40c9e2dcda6a0526f2cb0655fd3cf7bedc37b719b3168));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x170e02303096028e5a44bad4a16beaca88b01fb2429b3b10be2d2cb85027becd), uint256(0x05a56554f79f587312423aefe1f8c28079f25951a99834b2d5f87218197c45f3));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x29fa6968eeefb97118a466b67d436f93f8d44c1374b123005d94a1dff6ee3707), uint256(0x2daf44b0b83d58fd9dce9bda58e1167e107ca1593ede87f1b91a228f0d640dc4));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x0e3884c404423526a852f8dcf35cd2ed7b25f87af477364254ad25b57a9d8689), uint256(0x12e38b1fdad45ff3a4f4856dbcdd40216dc64a1c3f1648712005141db01570f2));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0497dbd90bbbd3933f9a49ceea6b1d3b437271352f6efa1fa4127b7c0b2788ad), uint256(0x2db044302afaefd179897e5749bed6d08d4135e73661158529e7c1227f8bceea));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x16336a683537768f555c24ed0ea8446a895bd0278c1d499d52d1775f75795392), uint256(0x2ba03a61af8cb1f03451a56374034cc7c6795a3f4a5f3cdd006b42be8aa4bd4f));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1a17715d4a0018c5f0d491457d3d895fe43e70216a453d98c6dd89df2e57a864), uint256(0x0646f4f4c6dce057f9a83cae537064b6d881743acc512c0eeecca2fcb553b32d));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x185a80fd2e749a5269053623822b6d70d20ba843c3961e7c49dd141e23c0e8b2), uint256(0x175e50f9d5b71e14f0c46e9b30a797903ecaac1e58bdcdcea3daecc10e86f28d));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x10de9844c051133ac7109234bcecaf338641c93a96de2d1c5ed022f04033668c), uint256(0x11959f94687de0ed0325940c9df7a9c22d4641d7641ecc4d2caf9a76e6e22124));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x0ebbed0354d65ba5a791b1836d4edd1d90fddc9ecedd247fbe482683da939dd6), uint256(0x144a8824bbae42aeb47cd0ee07ac906e0e4333cd3fc92eba7144873074f862ac));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2141fc70b835909fa82281bea52d53aeb6084b4d7e9e093d316a9d49f106a843), uint256(0x1ed04388b594090b80a5b9209ff80d08fa6d5934beb4a8f2072c9f541843af35));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x27648919f5fa9000d497557072daefb5dde77212e4ca7b8f7733779e6b3387e2), uint256(0x1c9f050ad6f8882ee498e38d8765046ae6fd4ffb42f4c79b050c015512e9278d));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x062f6d01551a01232e2a52fe765503d43924b3280880cf3a134998aadb9d034e), uint256(0x0e844d3cfc037ad107d6384b70b7932e879b49fcda76477d3464d98966939bba));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1b9c06cbbf18bcea0f443525658dca28078f1b1c3fb54852153627c65ae22d86), uint256(0x2e471508d2861ddc4ccbe083e85e43dbde5339ff779596d7fcf09866dbe7a545));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2b8fa48cb83b2183dc355cdea44a727349f1e901b5dc7cb0bc5142c0e44fc5f7), uint256(0x039598493354e48465ed9b4c60ba4724e28252d3a67239388be6d9ebabbeb3c7));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x0a8933c09f70af89e192446b475c6940dd0b1ca3d5548e730504a78a1fd10d24), uint256(0x1fc044c0231af9b0d3a1fd7fd8042e1f7cf1f02e20fa0eb77e5025b4b89299b2));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x1a7bb186ad1ce3f1b9dd06e613125e4e48d3221b50a5fbca835ca4fa17259b6c), uint256(0x01191dd1bc2fde0ed229a7d82766acc1c3e0d4e0becb52685cb77e1c63342092));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x17137233f84f588b1592cbdc11c554d03b13d957fbed8198d193cbe00b5fe57f), uint256(0x257831328f4515573b371e83f3a96ed8b4d1d785fc5e3ce05dabb99859722473));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x2d4779eed43b8d765fbfdef4892f1431dc4869ca2b4a4807510fe42c6ae81acc), uint256(0x197303603bc2f08bd8224ef6f56cba51adba83682ce979d4ccb8ae729b112ccc));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x2c3bbbc0312fc30c040afc0c2a83e8dc2157829653b36a467ec5ded31e489cd0), uint256(0x297b39d7b84ddb3ad5600a9e041cfb78c26fac2eba1783c4d3a99c68fd2de1f6));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x131d3855b92b1221f3ce92b78c1f729fcb039b013e16a320abc818a077d24599), uint256(0x2e14c3387247efee3f4a1b46c98795b9ecf83f86f02037fdfd7d68ce53934a97));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x11a0beafe477217cd637600f3b7f7c782b6d939b52383992149789010a459b91), uint256(0x0c010b1574ea8362063b95619d41dc87943561abbfea037949471d84fea09cb7));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x1fae60ac796a6b68af7317b4b572e2c85cdab6182dbd4b2bbf339a1f5bb3729f), uint256(0x281a6ad17a11116e5088f03375e14242076437cc467fe19650796f82f786217e));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x2b20219f459ecf5c78e74381a69b51a13e2b275ee5e8e3fe7de9fc9d45db6a50), uint256(0x2329d55c54868dcf3cb9f7d8dd1e4ce30417892dedd581aa3df37f0cbd88d24f));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x05a7de383ddc7b614412607f58ac5fbfa3c5c2996c68b3ef8185a3979d325b08), uint256(0x0d7373ecfcad9d03ed534791ef723cceba4b89b41623e382e6e1d0c3dc0e3167));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x1bc4cf57e020f1a5c0d75ced7221eedf1d0e7f9b3ce83cbd4565da24daf3c12e), uint256(0x1229cae7eee8450132d4e0b2c9257dce12cdadf2597760c06a46bad6ef078f5a));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x02b7b75b7fbd514fa591135be3330412c9986105a25302c9fdf689312b3fe70d), uint256(0x08b410bddf24faa55e97fabe1f74d130b218b63f2603e3025f8bf3aeb37e3343));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x1788f643006c42e2322bd4e4bbf1fa59ca8a3a7fb445cd38ffd397c3e5816239), uint256(0x01eb6ce6098b21ed189b5a5cb51d65ac2f678970866451134b0c551e6b7c52b0));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x07a644f513da5efb04ada087fa475838fb74d296c42dfe4282df7968fe6e7d8f), uint256(0x192d9673ff52443fcc0827c5b6f97685057fa2384ff106d4373d0ce501375bfc));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x02948598f2a167c4eb8da56e7fa764621d79788c0b926094d1b0627d008bdf34), uint256(0x14b02297a52bad670e67385cf47a48a72a31b02b3130f1092935d4be65ade72f));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x1ac21fc54649b5b4e468212d295bdf5d1d1c87e1421742acba8a1dc055271095), uint256(0x231a00a5d503b3a5b1b556e5743833dde66197e494d60913b3b0666fcf0b3d59));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x191a5b4bfdefaddcc57fb976fe5c88673d9fcdfc982ec6ac4cb61c1222dbaaf7), uint256(0x08084504f0fc9efff7ea5981e648928e24bc00613a938723589a3e6e6f776ea4));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x2d1758b0de16b7a44f15f96c53be07c93c24bf1f1fb4b83a7b6d394500a8582e), uint256(0x14fe7ca6a4b269896e5620787d0f779ca8d34a79f8d45d6769c87675859e2e16));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x14b3c29d8f22c7411afd93b16680193b5f6a4cad665771289f904d9214d2357c), uint256(0x1b929ca08d6854153d563696d44995d5a303d50335e5516d8d4234d52cb36130));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x143ab1aa75b9d1ebea442a99daab724cf390ec0e5257000ae03aa60fc4f00a1a), uint256(0x2da26167f875794c9f231ff4853ac964db6cfe8f4eed4e15608803028c3edef7));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x0cd5602518ef966c60d1768b2016312f6c2c92ea39337482a26bdebc231bd200), uint256(0x184bbec2a41e8447cae6bf3b389c8fba58a8f6e8555ead3fc6b24064e5934254));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x185ad83ac0613b86714e7831dc7989ed79db9365e103b80dcd1449cdec8f6620), uint256(0x1998caf355ee7addf852f20486281c8ac877422b9b4c70741511bb4b5295b90a));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x1f698a7387f4429bee7515eb73465308c24bb6861116b379accffb1c55a02ae2), uint256(0x23d457577fa96ac3caebe473ee64d0b994a6d63ac8dca3f82e46eaa65719a1b5));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x10083ededa3e4fdb29f4c12ebe70fc86aa1bae84432550147e658ea7eace4555), uint256(0x2f946dee1178010ec4f4836a6fc3a554f886c6c766271bad68bf8a2347a4d3a3));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x0574d1f6cfff9ce310f35c45a7c54ea9c08f223397b7bdc7e0b037c5de725d80), uint256(0x1fee1a046ed9f3b80f9159234e9d85ed1aa4d05e2dfdc66f56d3c3c195ed59db));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x27a636f4c5ca1e1b66ebe1bfc7ce12b3dbcee777917e489b228b0848b04a8bbc), uint256(0x22d793c5a4b72b95ff389c4f9c43528a5a17f2b249e9432e52532353fa0a98ff));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x096d27eaeb6d94ec5e013173ce82d3f8a732c346447281a37c8244e4a48b0b03), uint256(0x283e5f0513a8b26155d4fa2f0be813f8eb5aa4b6f0c2470621840694d68f0ad4));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x27e5abb8f178afda883394efc12a611028d59288190c9b819824c34c6d85a55b), uint256(0x18ab6447f12c687cf84b89ff6734f54051d5039a7bef724de81b7b128b9f490f));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x230035ae4e32cf9e531d579312ff20b3ae205caef8dc04ecd1deb5365eb2ca8c), uint256(0x2982ae949f6a214c5670e1400edba4cc64cbdf4c9eb89cd3e25cd2804c46bf11));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x273c6b874ad79cb1a03ca809a3f3dbdef126644c0ca0ea412d95e162e9ffebfe), uint256(0x09e60524ad80630ac37a7045a775b7383b1b55a4a9eb3e4e1e409cb1e9578874));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x0ec66d926f84eed4edf6ddae4d78f05ff92ce19950f0b678efef4c703ebd2921), uint256(0x11bc344bcd59d72bcfd444a4357c2b7df831ebccf969e234b360c3891ee79309));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x2e1f56adf842c3da2359e40c332063b6fd7cfb87812ef572ae160668df6acebc), uint256(0x1e28ea6de35991b1f846eb01d73056e9007a202e0285ada3c6d6ef2c8ffaec16));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x2500c0ca77da07a8b29abe13017850007d01baf87421059e5d8a873003335f65), uint256(0x1b38be4a03758649b975eabeb5e654e8d11729dcbf98b865603ba5e701829f64));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x2057972b625067246333d82d68c9768478a737cc85b8bc1e7ffc071719d2f404), uint256(0x091fbe065f4e7e1870f93c7703e44c14081f344794275ae1f67572791b5470ab));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x1bfe1a5762cbe16836f2ad3ef2a37de02a4891fac712f50bd0295c6678161fcc), uint256(0x2c55983fab45276d79cf1c92732089395075442d1828f8844c86aef623a0be4c));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x05258237906a90c43a68cdcefdb01cf4f90c313fbbbd8efb97db1c36ae3b3ed9), uint256(0x0e8742cfcc00011f256ad98b607bfbe74f5f252713996f85989ffe6792d1ab6e));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x1405016b48dae14b652b1c650ee28f455f1f196fa618e191a8a99d53ad60294a), uint256(0x060881d883ca5c1a9fbb414e7cf78ee9e8c22acdc8571c0b5cb2b68bb1115b02));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x1d4d1b787a52863544f6ed23dc12ae8277fb77099f96a52b1484f28e8f24676d), uint256(0x1efe1f4c6eb7b499e3179cc804584dcbfd81f26db2d6cd5133406c80e09e54ea));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x18ca888ab8db996eccad97886ecf89c4718e286e094c3a5b4f0ef8a31d3d2e78), uint256(0x0acb5809f00c092853359f72e8376f13bf6e1dd9a1a13cfa3db2ceb22ae29512));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x0723ec76247a4cac37e125f2c5b1dbfd1f42d40438c73b66cee1018d3a8bfed9), uint256(0x2ad353288fc9464faa611e63cfa12cf520fe4b96e8c04bc018f0d9af0446d91b));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x01d693fbe78aef8a59dd82fab3b266ec4f1d5f3929700e49a42bf99461e0488e), uint256(0x05113c24766df51f7153d8614b2643cdded06daae23871113bf6e1eceb1c37cb));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x004a9122f1989fc22b5ed164ff260fa915cc5db33072edcbb13441ddd6624574), uint256(0x16c4f0bbdf1ebe00b8e76a2c6f6678eefd4145cf6109c080e2e3dedc743de94a));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x29aee415e0768486e452b7aa07371230a69c1dc83cd6add7d0656ca66e422d39), uint256(0x1c5cefb96fefa0791c1c6914216162ee4832d0aa4719720bc365a255b6b5ba3d));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x2dacdbcc1165aca3f036edad6561ee810979dac54ffed1e781502e7d86f52f4d), uint256(0x2301491375ed6c69cc186af61ba6b1581c97170fe658ac04400636cdf4319471));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x2ccc6c32a2b1cb6728e27e0e5407a5324e7f48f1d80445f1bb9abc7cfaf51df4), uint256(0x22c04ba71158a16b805a155ca56ee7d761379c90db40af40d10f373b4ead38c8));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x112d759aecc53b04acf969f1ec6ce17dbdd0278ccad441506c169ce5faad4d93), uint256(0x118f02df980cf4227b5ffbe481fa71cf335d1d4c41d351eb770a04830d086bcb));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x276f4639c35c34fc81d9d8cece0691e256b6e12bc1a0095544e51c3fa4da33f4), uint256(0x2525394460cb4dead5b1ec6fe7d6f112ab650843ead0e768edc944b7134e9693));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x1f48ef5f9529cffbf96f9b6d9b2016c1f02895eae9c5cf5bd5ce90df4d9b7c96), uint256(0x131b6c2974324d0a7d750cc51218e2a352d0919c81dc95725018f53a119555d7));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x293fc64002488464c2e584ecb954ac4f2614477f7598d7aa71a318160b643bcb), uint256(0x19853806c0a2894c60831ebe148003d102ef1b031e2c1e68f4514bd577e0914c));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x05cc212430fa4c77f11d3924a677e6cf304c3e2718321ada7977c6f2396cd57e), uint256(0x299318324fe0fc55c2ac9cc48bc4ea76e0fd76fda1e6ad9d7b4443ff3972998d));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x2434800d2c9b8510def8aa502a8a63e4aa1448f77bc6bee3b79332b9c9dd5cfb), uint256(0x041b99f88604afbd733e39830d7bba5e02a7213a27ae8a41d8ec4a6540350459));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x0cebc16e4a7a52071b1ab7b404fd32676fe028d5d05a0d8380c3c66e6d84ebaf), uint256(0x2a1f5b29113bffa66dbb2424be3b4a3da43431de370746938cb309c41126e87f));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x01a3247fb6239c5d4bb6ed2b7c0b9efb8bed3d9b28c69e129901b3db98b580c4), uint256(0x0dc7ebd85e7715456a320903f13ee1d7fc8137604b70e7800a68108ff4b4554b));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x02ab613d6ad377d09ffea36adf869ab5b86d828109f90e06e7f4942a7c789988), uint256(0x053547b6f6b698cb2158c25feb88ec514b60cf5478b05c6839d0cd22b7fdd452));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x24fc6089caa7a46db4eb033ac1e92c0a2400756fc58cbfb825b8ab602bf7f282), uint256(0x2e38cae74ed165446fbc3649e7afdb4802fbaf30bf0c02cfe31bb4dcf6924cf8));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x0979943454e1d84bd6abc2771549dbafd46449edfa499b766027b1d94a5ed94d), uint256(0x0bd151b4af9aca93cb4b65cd84865a1782c9b83d4cd6edf2e29a2f99a17c1e5f));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x23fb589d5ad753def8f7b3015afea1e15318c262d2bc90e8f21571fcc45accf0), uint256(0x2996165def0ec09ed1bb692b98f225c0af2fae6af06abc553b4228a4a8150d72));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x158ff75bd1e1bbfeee929ebc65067c142de812e76347737bf88c40b8e77d2176), uint256(0x1d55aa8a83cd3e1c3d81f69907c7168138ae553d5f5c04d72c28fdea81f60d49));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x069fde1852d3a9c18911dd44ab5742cdc75601e220216889828a1138f50066d0), uint256(0x277c686484e6346a689f46a256085213ffc2b9129176931e055a49a977fb76e0));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x19046d60853a09afd6c95f2a4910531b47e6febcac19a4bfade58d9a19864486), uint256(0x086cb521f66754cbeb86ee34028d9783865d457592aad637f3bdf0b56a2e58e7));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x1c86378945bdacb34c70586e2b27d4d1000e34dc8d59d6e172bb8baff882fadf), uint256(0x292e6cfa9dc12433082fd4753c7f76adce31d7760fd205a5de5dfdc5e09d55cb));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x2388adb806cf8d4d4ba7fcb01533408e68a0968442d8fc46065fe4e7b7d412fc), uint256(0x1e0c1c000c39f3a0cb3a73c2f411d963195b61bb567778fd85659b03643dc417));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x2f8a9765ccd08fd978e619a0e6d962cdb6e3d754aef573e4da82c16463574c89), uint256(0x17a27f691250373e4a73dccebe0dfbacf11ebb9fd767326332580217e81130b1));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x07f339ffa93a56e2fa1caa2ec2d56e2e0aa46085c171e9a8e408d3ae45b37458), uint256(0x12ed2d11ad14c41ad1e94fd978fced7a65b3a8372df7a4d53d04044b29b65166));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x256980df076e7f036c6d3c4441f32a8965824b5c38dc410e5e5ecb51e9398663), uint256(0x0f5bc42818acc583f0ddd70f2795f87656587dc86e0dc8787c07827dd098fd18));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x0cf925df00d4e7b770952c5d0468e0433f0c6721d04b4c068a3d8eb754fb9bb6), uint256(0x288b681f8a9b4d39af93da049a5f183b136949a3f3e1d2a8d4c0df95f26fb2a3));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x12e4153da7e946464c8bb78fedd712b2fde0f829f849552f7617bd8418974e45), uint256(0x187b8b06a81149d90db23e7ac00a19403630c206a217b740b14c48b1d733f667));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x01683929796fbd60ea01eb0e2818cfc95c7f906899b7a11399e5fabdd1d77c69), uint256(0x2e191a6cd23dfe2081b465a4b26b81ce935c78f89513eec0025c8914ed785d75));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x1c816d6c1c182e21795162f3ee8c04298d199bf6eaf847cfa8d5b1f0da6529a0), uint256(0x13e81efc0e9f6f335398d9b5980a16dd4b47f3afa129ed90f9ed086e2587adf0));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x253a6ff8ab9b92ce31932c25acfd868457f85b265484f027da0983ffe1fe42b9), uint256(0x06d2557c57fb1e7abc292988872e0626c4fde30b68d3a359355248303c54cc68));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x00c163a7ec5d62b414fc7e8c6e6ac532b87c72b905c781dabd0b39d332496926), uint256(0x08ba4bb78a90d169b6141446814fb339b9ab20e6790de329e96219de1a62e021));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x158384669d0339d2bd4b3b48abffb1ed6badc987a5987bca1c7f3fd03517930e), uint256(0x0372dd126d5016f472965102f6ffe9944cc4b423f78c3688c0c09b2f7701281e));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x2848e03dff5f7898b4b5cdc41d3169632fb3888907a605bc9bc8a21e7cf3399c), uint256(0x2ef8c0e2861ed2e193433cc4568a5d3e81794bccc8cdda00b7699180d71c89fa));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x27912fb38765b3245621262fcaa2585844e13cdf6ed5dffb3d57ec9adec905bf), uint256(0x0f32f3e6d411604999b9419c49b0fac083db58a1059adab97254c7af7fe00515));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x1e86fd191c88a232c9d46af8bdd516bd99501244c9e39220f9cbf46dc942c00c), uint256(0x11d229a0474a0f277b0ae3ec49ddece2107838266bad45b619df430f1da45e3d));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x275bef08b04f92a536f26db25e56a54d88033f687005a6fd6b2c0100f38b4d02), uint256(0x0b91c9a2f1195a57ac4f2c2284f944a4e78f9993896fafa2b065d2ad7fcc4938));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x1e5c2621ab537d33875b90d994cd8ee20a0740b50ebbe91932a03f882bb29324), uint256(0x2fe2b79e70eb9a8b0cb14ba8f8ff2f70c3d5ba5bb453e9e9740ef11d7bc8d779));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x017cb71c4ed8a53da9d4f6bd80dbe4debbeff340830746070cc1ef3cde8bc835), uint256(0x034d9a9c5b997eca151dfcd701b0f28c1e005fc0360f86a0bcf29c0722378648));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x0512f1a19589956fb0b15bb3d0c91f4c99a1e2e4f6bdf7e62eb1a7a99a7a4b95), uint256(0x000c79f4fa954327a1cf42555e261504a4323f4e7e5ded91217615ecec0df05d));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x1d3a2d51d5eb4183c4064adc732985ceb5cec008ae2da93b948afd30edad0ce7), uint256(0x19cedf2af9df2857d7a8890a9110bec45e060e962daab41277aca627b105df32));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x3012bff1d265b84a03e2177fca3a410cf13390ab5b30ad5b439ce509e289524e), uint256(0x2e12b39654ecbbf14f0bb83e78d842887187f2c61dd75c433b40a7bb0b4a0c16));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x151c26321fefe6ea084a408e3f305a1c7009e227ad5da6d1830eb8699fd6161e), uint256(0x222bb0c8dd7549e1f128a434bc4439bddcf4c9bd131b6aba11e5b00fcd099c67));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x2ff721cd617e6754aa93a6ef55cc5e3ffa64aabcf846f7588aca4e674bdfd433), uint256(0x2847e563667c675eb12beeafcd89e434af50fd208df34b77174fb3c7fee10cea));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x00e98e7d94e373d79d507f02647c78f013b957fd8fca8298e8f8ee4e077ccc91), uint256(0x2910bc56062e564167aa77757886d7aa13cfceeebb8d73a8b3ec5fdad863b0b5));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x302bb5d8c23fef4bb4b4c72b4e4d24cc9294f82d9a7599be9bda0f49efa89322), uint256(0x2edfd123bd78df3ca3ac855b0c0d94b498278729a617b1754aadc415560b82bd));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x1a8339b16ffd3e01542b688ffc910677ea2b0ada33c391f20b098062bd69be1a), uint256(0x2c8cbeb23566ef51731783eef2bfd7cdfaa7faaa4dd9dc55983d4f373bbfa742));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x222e9cfe7f02ab936c87e67a8b742a0581ada2f388833a587a0f95e8d20dc2e7), uint256(0x1f6230b8e40f0322b1adc185beb87d06b08dc1c5448d81ce4fdec6270ebed0e1));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x0dd22396aa52f11b73bb8e996bd92e22c004bb0e3f8634cd8c6aa6b5a3a20774), uint256(0x1b0eb305d23fb19a0fdde7c89a383c0d8652458979558448186f15df59f41a53));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x0c2b053f9df25ae721b8b5f232a30ee58d1349d127b5a8d9cd12f0e1903ae344), uint256(0x248907672978349abbcc62f47d4099f3b98328b43064b19708d767045cf72468));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x048033b5eb94993807619f4becfac9e6ef07cb29f92360a4b9640ff333be9828), uint256(0x15e1b490418682d89bb587e97f4b4c0ca4c3821fc5ecbbec9de806bc37252b9c));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x10255533043e08dd81accf304b9f56667d9e96c27ee28d7f907151b8a2c7e585), uint256(0x1fad9af3df35a1027883902192db4e6b198640357a7f33bc0f1f52d3e3646fd0));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x23803e5cc1b393c2775aa58640e3b6829e87509247aa3e2f6ae56a7d4456bb51), uint256(0x17de43b425db93267d93ea2b7eba1f9fd134532885da0cdb0590ce4dcd3abf37));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x134af3fb4cc8dd2fbe3963031818256874f963dbd6c3dbd24d8e3609344f38a3), uint256(0x2e8c81c11f940c09695a0fb4e2f221002e2ffab6ba259ff417576b377e1f2ea3));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x2e2bcca51f7c004d08e21d5dd6059baf738e03a0c812872f0d5fe9bea8c70601), uint256(0x2ca2d6ddb67344617488b23ba08dc67677e8c22b46c43a8a545b89461b705875));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x11c3855cb8a31d8bcc2e2f3260c1ac0aaa7167a146c913ffd99d27a6ac2773ff), uint256(0x290d7a6d936443a52d3108c3415f2e3062fa67767fdacc38865cc302e378ae93));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x046626731cbfb8a7e524f8baafb1a5833fcb1caf84b4ac1693633a73793d1eda), uint256(0x067f65553e261fc72933c76f2531d58cedd3ac21ac2c6d3670e5598f37d1d2cc));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x1086a39277709f14bafae8c66f920b789f50afde2e3b247b92fff19b471484ba), uint256(0x1b6d1db9a208c92743bd22d95009cfc1eb5e3e509733885ce2c51044b6fe1185));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x028af26a19d4a3e05ba00f3ebd819bc4b8564eae4aa8f2e33b9c5ddea6692c98), uint256(0x2125467fd0e2b37717aba5efe6d1473d7e34186ec438ff5514396b44cd65baf1));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x0ac0544457ee6a5bf1ba1174c812ef4b5e221013ee7566ee588bb0b8ce272ef1), uint256(0x11f18a93e966a53cf1d129c94786d03966cc9f8dfcff9753afe2e02c84a75329));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x0ceb4c99b16920b1f99c1d78b4ba3ea303ac97ed8e6f19a2da049121efe26cc5), uint256(0x0149829a9c90920e1efa634cb39753112551d6c7457c892c96944c7fe8691142));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x2d2b6376fbf41c58956895fa6b5b8f398adf51970d05873a689be1fc89fb8317), uint256(0x2b25782f8c98f7072d48b2ec4589f077bb166a5fb83c409c4a8996385f553be8));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x1093f27c6059c7c39483f7ad8a8ea10c69f7baeff64fc3df5d01a30df5ffa4ff), uint256(0x13d1aba3d615d936af873511b88066c866f891e6de3d2acdd1b62a27088740d6));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x247ee08390c5faeaf365a6776f4caa4fd88c055583d823a9a7997e147b9702bc), uint256(0x1e69f9d4d776716e37aeba1a7c5e089fa7eba0599e27fd32c8d6cd4f4c169e70));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x121c2a2adbcfa2f3658187fde366ae9b59cc9bac7e7ad902a53ba951ec74dbb0), uint256(0x120cd0f37c436facf1b1d9caa8aa3aaafcf91617611660b8b09b24548759e770));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x1ad0b154c710459190dc0ac23989f0d2052f95cb449f84551bcb211dcd32724e), uint256(0x289eec672107a11aa73c7f07073949c996eb88e45cd556f52501077e8607a61d));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x0aa880a1a8d545a6e8b8d2b610a9576f58754dd2a506c2883191b92cbfcd0edf), uint256(0x2d8db767f15dfa36839c3034241d176d456e661f709f94b4fb775d12b1fd6924));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x2f6265413c38269def7fc9e460794a1ecd1f8ada1da8d3e70d8f59b78eb581ea), uint256(0x12cb45fe5356007d7a87abc9f7ecd6d0752cba3cb1c048db965e560cd61bd372));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x1201eb88008af989812914baeced1893182d0915f0435b4b5e2e0982acce6372), uint256(0x08ffdc8b2f1ca88b0dbe287e2be54ac2c20a30d48d6c5717de7f35befafd9566));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x03a2e574a7b4be7e7e07f542a69e6986d775f6b5e95076d26640cf300f466e28), uint256(0x12a68b2140a0182659990e546443ecca0364cfacbce3d9c833abd6d82ce6e01a));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x19c993878c2ff3155ca66663602e12e078f014db04c0b73fad3c0a0b7d356eb2), uint256(0x1f7243e8e96e17ff72c7e32a85fc2f5a0ebcf0294514c8fad1c3e5f3c68d1213));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x0908e44f6c2379c1840045f654aad4be04e92d9a3f7d4d2efeecdd8adb6d6cd9), uint256(0x1dc9c674ae70765a17157ef14e3333bc713bb4cb15312b85190cd0edd7080094));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x2ba8e44637cfd00f1b3fd4e3d8dcd5e2bda5abc320e6057cc5dab7081cfe7b4d), uint256(0x026fc1ee6a30fea29382555f027c5f2762b6cb1c20df9cef6cfe317475aa1ab6));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x2ced5f494e3c5fdd37dad63590e102c49af62779951d3253838880772fece5ad), uint256(0x144171352e3988fd4067ea0a727969c0ab542498291f31513e0ff0d971636a01));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x1194264683549cebb4b9dd847c7f6df9d57e790eee609e8921faacb98a2e0550), uint256(0x2d407fbdb56feb9717f486bbf559096f83f7fea7f5f47adde583bdac4f24b9a3));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x2b5fd4731e568d580078fdc060f6cee73e67ebe775f8fef7feb6723efcb15424), uint256(0x1de2f64715ac072b5ad42471b3515eda7f9523ac7188a8356cd0129fe4f1d60e));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x2b0a90fb856307200c6db48831c547b103da97bfa46be69700d78ddc289cf237), uint256(0x097dbca502a14e311b3df2e5441a4502e547a2431ca6d73a99943e18a61b6ecb));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x1f74a73280a67643ac516e6ded12d7d309cd0fad93e6dba54aed991208f2d9e8), uint256(0x01877d3147a884a1b3eaf2694d3f296f6dd5b82a2d7c0e7cd8c873220fee9383));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x13b528cc8ab8e60dcf0e2752782f265bc443490f791a9334260e80a38344befc), uint256(0x18349cd8cbeea800d060dc31d6dbd4f2cd306a42f80f2a946c2d4f61357d236f));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x15ac493f18ea363322ceb9d1b1b39563b8cc71c7be8c086787402786dde376c5), uint256(0x0a7746477fb459d9716e4490d888a5fb61ef74788c15d6d55d90d20bd9981320));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x287ea0a5b692a8acd27e4d6eb08ba389692516ce6c90d24147bd4e4bfe7ecac3), uint256(0x1bb64f9a65f0c062f11355d56ba043e73d2f4f2d2dd7989b44dd4f32ce8312e2));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x0a8f6841fce3d4d0216cd78cbc405d3c8b048432c393f3815bead303cf0ff74b), uint256(0x24b157d93d85b86874398d591da6a1c88f763f9b83fd8707a1b9e0e9a6f40bc0));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x0f3d80ac47d6f7c5a57a719a6fc73b386bf3a4dc6b2488cb11045c1d24c1b437), uint256(0x173c786f65b04d0602e9c5dc932c732711e1e588b695030d1671f0860e95debd));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x294fe15b33bea93616088d7e8737a13a3443666092107f7c13c857d2be7e9896), uint256(0x0f2dbcaa607c3c4c9b30f910667186fbc72842f839701282ec35b032e60adc1f));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x1e60ced1fc1764d7d0928d25f2342a33dbea980278c2afd29b5c0107853ff87b), uint256(0x25bf551834acf3c082e3fead7e76bc0712b582114500ee66b3b1f372a1ad9a83));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x23a32f31e75d8bbbed34890a796a77cc6d21c4c45eb94660ce350ba0bb82588d), uint256(0x21f36a169f3346635c7901f1b394a83744c446f05dba253f20cc0d7f619f15d1));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x0c33579372bcbf06e425dcbe1c9e8bf2356ce859a0323f65d64681b05eae80a3), uint256(0x2e21245fc8044956648fce9c4f98f8a8e80c1d59c01feb08f3b932d9f01494a1));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x09856ad89dde6f1437da0b0439a63dc6d177f6af6735819c29bfb7a1033f3126), uint256(0x2a54a7da7565cc1c1ee19b57795859d58ddc3bd8362538ba84b67032dd42c3db));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x0ef9042a4daf39d4fb01c1f57ab2f64aed5095af20d6c0b1d7ae36ab398d5f79), uint256(0x052c0ab3d86970bd4272031325004acbc1ffd2b68d948610ff2aa0719af1dc89));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x05ca9f37b08a1ea995125133f44de463725dedbd3209c6c621761e6dfb2acfac), uint256(0x060169991897317338664d5813412de0c4c95c5096a385345b7230ef31a215ba));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x10f56628077d5f072d2bd3dbaa2a76274dfbffb72dd1fdf6987ad5799208b729), uint256(0x11b594d22dce3caac2e5bab68b0de855ff9db77102edc631cb7890279005a429));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x03fb3d196821493d7177bea97b860348edb709793d497871f303ff0553b80595), uint256(0x16fd487d34bf651c8ae02dcb445c1de1f49e3587199827efb2e10950cf499788));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x036c2e3ac22abcc7812304c6a028ba0605e141662d35cb88b50de86956a9b8f2), uint256(0x08858f051cba4118970d53e5e96d261c7c06d43f48973952e0f663de94466186));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x02709aa6277562c91d5ad6a64a9db4ae833170a6537467a5b2b0650fd192d3d3), uint256(0x27656eecbb00a36947880185ae4c6532edf2edcbe745665557ff28a1d21280ec));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x1677a1df79f6399311e54ac33971f263ae35b4e5badee541a9003beb7d9e726b), uint256(0x091487a2b13e109a64c14f1ec8c53889bd56131d6e0ec1779a44eabc8b0d305e));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x06f8c20295fd0208fc1c67f64abde253c038b542216a783f288729cb21931ce0), uint256(0x28bde279805d6c6953cbe3035fa4d4c2c0f543f749157c0140f16e54f9ef63fb));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x02d55b0933a25c414f76db1cf111404fb3fc98798a1f4eb46817f060c61d12e3), uint256(0x29bc9f6bc15d63f27276abd3682e15de096ca5e355c30c3728fb5f8c4a738751));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x1f15cc27d512af4b691897e6cb3ca42dad58000677bdec63a45020fd2df62ef6), uint256(0x266f4bec04dcf9d17deaf5f542e8faec4af16022d8770327b1c489922e470fc9));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x23b796ca879e369d8306bfd76071eaf6149711529a9b7fab277c863e22561615), uint256(0x2a3b55f77671d736726b13420ae4796982108f8fa7ab1b54829abc20d554f459));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x0db164e7b0fced3bada4eecd3685ba22a950f165b98bea3ec3dac5d4addcdc32), uint256(0x022894cae9f3ad0656f27fabd47d9e781609e13bf730c398ee401e26bd0852e3));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x1ed91ef468fe8ddb79bf5b2fb92a25fb9125ebd7b5adcf89a8713bafffa0ea42), uint256(0x0d3ff429596c8ab5177d4f3320b5d8fa006c2016ffe7501c66b69f189e584b40));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x243bd009c7fd5135169edb708bbac7f8c5290baa28c5a675c4a305a4c786d184), uint256(0x2933efd5092d7128301e475c941181d97ca860053b2c258db8245a3781df241f));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x247e5786b15c95d7105ea18ea692ae8313441cc5b28045f3fa9af34b6d03e4db), uint256(0x11d0041550cf7cf50584544836e2d40e9d76c72cd02070b2f1bebad669406c11));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x1a28b50125af198661688263b1675808c81e8e80086084cde2b25d1980be04c8), uint256(0x12c1008106c51764b8845b9d08877d9630243884bf51160f94888133e1dd8ac6));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x1bcac925264c763ba1705ce7a9413cb25d69d77ca83893f6b819e3edb1284055), uint256(0x003adbd648c8ebfd64187cf24b87863fb1106ed86d2dc6c31f72951944777727));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x2aa7843e718c25afd1e875c012e641214c322cf392d2ce22dbe50a41d2897a6f), uint256(0x1787bbb03250ee374c20cc466f64c7f3c7e159be194fd33078f1b07e6e31effb));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x01f86c915a613e2917b346d53ed7bc79a1cb845db89f437382072e28f975abbf), uint256(0x0b4c689bcf27753f36a234579e012692e1fa19202a06c79ab4f13e30f36ffa6d));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x28c80ac9a09d1aeb2add0850931818c45ea98c26b7cf60e50a1382a73596cf66), uint256(0x119356fce63cab081c04caf63d49c8e1de57038555b4b93d4ad790c44396a5b8));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x21c80f7dfde0ceeae0c2186a14f5cb61f594314ad08ae4577a40aa182eed4448), uint256(0x2f0cd5c849fd162bb4413a17f6b5e3a4125b83980a52f33b4cd3fd8c8091bdc6));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x04973a254f45f5a19b93dbd38d9b85d5eafffb0bf39a31805aa1364bcf0eef08), uint256(0x0293bcda46a8a9efe04ef656de25869a8f6a6e026ede663fd0b9aeb00d47b7e1));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x298c825e9a8da137b3474cb0ec590a52706fee9ecb64ab1175d54ab985b29b1f), uint256(0x16ec4a071b0b50d0cb52d3e27fa1d516afaef4423cca71466a3d26cfec8b61fb));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x2a5e74bc405c6f4e2b38e2f213eec9b1c430d36006866861f68bf76aea31cfae), uint256(0x2d46dbd89b8817cfa680a30c6b1f3c4c583ec393154e267c45c6e8e8dae63cc8));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x1edc73638a4fab4df2800fffa62e96e64b02cea04949d6c9c78b0d0047a1ffb5), uint256(0x047778107f4038cd623d1b28f7a2d2f3016730bfed9de824a9929fc1625576fd));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x0379904931bd3752b003ebec381536456df9597911b11c6940d1fbf881543534), uint256(0x0b511f2d32c05ea4738c4f56846511f7c4432bdc247d5c8627afccf916dc7c6e));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x075e50aa157cbb4c5a81d9b8f25e9509b34fb476cb3b937095f19c75d3c1388a), uint256(0x2f170e2cdcebc9fdd09e97a5674b4fb68527e9b86eea01b918b8a807004d95f8));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x008268a336aa427565426b98649599a028f76434e32d64fc3fec27c3a4db471f), uint256(0x0d015a1b0a1f2041adc28cfef0cb5a5b6b48522d3e2ed7b75841f3f07b968fac));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x0cc1533452b27c7ac86876a7b46acb85959d36797c1e465e6a3b59b35edc06d5), uint256(0x022415809e40e51761bac1ca387df63b2721bb92120df7c14f0f00dc747db666));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x140aa238c0b752ec8af478942e0115adbd1f254a9d18e4757a11d9c591d794c1), uint256(0x0f1f501711f50824cb35d97d31f79c0734fd8b09f49184a525d76715c2c320d9));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x0fb82586ead0496f65904c65709b1aecd86da9931d1aa4dc81c7839f2e0cc989), uint256(0x1c9d06e91cc7ca83d96cf65db09e84868ff4c40bea4377444cc378bfc2ef0590));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x084573809829ea65c8f6186bf0d536661616dbaa455cbbafa936054972507973), uint256(0x0fcb72f0e0799b683a5d38446459a92e0613710af50fa82fae9be540359a32d5));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x1a42006a3d84df3f2e645c86d2589da865d8b0596fc135fad8b87dced4aba8f6), uint256(0x26f98d8ff10d1be3b6dcf9fd58e2c58d41f25384e028343048a70c52baa7a60f));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x26c4d0216d038a7d66e35d408f2d8b05af03a744a52f41de7236feffbc122e92), uint256(0x1a2114332687496eda8d7db05981d0c03a7787273b29745081569edbf8841060));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x0194ef435698cf68e7db8965b28e8b60f75f5a13a043f275fc2df32ec1eb8a8d), uint256(0x0af1bb4babb93ba010b41e9772991580a87e504b528376e8df00ce6b4d4db863));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x1796eff536a2ec245b15a1e3b0546fe09e0e69db95e4a27a2c12b2ae2f2f218c), uint256(0x0c62c5cc1a85ef90a12fc71ec774ef1b3ac0d6eb733f21ee80a0a3382017047b));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x0a2be6ad185fc1bdcf07e89f790fe4a3ac871e5b94148588f4f19382c8dc32d9), uint256(0x0d7c162ef40f9af1f66439eb67b7697280cfa93265e80f49ee9a6b1b1ef67203));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x28a62a7c7ece389580ff2f5d610894fd85f9cd3fe66fa2356683c39ef6271d01), uint256(0x158abeaf3332ed3812fbf01e79aaea2e6d1fde5b60222ea7e8902e2079cdf705));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x23c28a9e34d94ea3592490518e2ee6e871a681565dc7d518c170f257a288831e), uint256(0x287c456c4ccb0b6c36bda79f3abef74d67dd4d04d538ec5e2d422b37d31708db));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x0907c0dacec23c157dc0ea75959c779c762d916eee94945e1fce99c547868e49), uint256(0x096f13d3518805a553e787b0b7754fcfdda51d4a397d28142aa924652684c698));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x040e61d4cb650a1c49cdfd15a47e05b436c9adda91c984de085494cc72649663), uint256(0x2fd2ab84d327878240de63664a1f87b2860452741a74df9f3a2b1198fc59cbed));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x151048bbc4b029fdc93e5c7b7fdaf4e473fefe0630b1a411b54c9efe241034f9), uint256(0x2cb655309a62c7cd2b6f1f94be98a1ed834091e9e5e400e6e3660171ed0340bc));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x009c6a8a6d361595b0477f42b404fb41cf5cf6a399a89ba45e6bb46e2a8e0e5c), uint256(0x0d294d0e6308b3207af914d93bfcd785c5739f7aca6a074e46ba9a0df3588aaa));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x24da02bd5e72d14057e3bb484356596b19f99c439e6010cb464c49b737e38370), uint256(0x0f74ce11ef2f62f6ab616f84b10ad41a58b3f6780e3a97342195caef6de68841));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x1f568b519f9868aa7b417a32e20a884c869a8899378035fcd2133541e4f5fa14), uint256(0x2f1dd4560a9e1573677f3d0cd96266d5519ddb1e41252402221f472711792b88));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x0ce9adb8bd1e344c96e85e195b6aa82aaa66435bc598e0fab35fa571f2cd6522), uint256(0x1d9c98308af95c495ed36cb8acb35520f586f53c4c3291cc1d11365622635baa));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x0bd6a6535b8790b58c3b1573e4d4cd9f3a740e18fc403c0796a6553bb1b59740), uint256(0x2e067886d84efeac94eba29759caed47c8b887191ae6767e09ccab7a70880864));
        vk.gamma_abc[202] = Pairing.G1Point(uint256(0x08f5761c2d9fc1fd88b35df51e675929f546eb9e63558de1522b60782b1ce272), uint256(0x291f8b88e8447d421ddb89323ebd77bbc76b5bc3838547b6a8548747f6b07746));
        vk.gamma_abc[203] = Pairing.G1Point(uint256(0x0843cc0cc404a99d27a6996493a1a04c944de542fa940f82a61f9517e3213612), uint256(0x249324c43b146f4dfce1cfcae973ddd12215c4dc09048a5f4c73e7b1f29f03f0));
        vk.gamma_abc[204] = Pairing.G1Point(uint256(0x0ba76bb7b9e2ef1d505604a19f33695a8d4d6eab6bee2bbdce0675311f06072e), uint256(0x1c331b9e7e2755d3318610201818a4d60d7c633a7b7707c251037785bb958f80));
        vk.gamma_abc[205] = Pairing.G1Point(uint256(0x0cf594fc06374d2ca8bf2900a6afec4e5f6ce3f67d9b3ea25dd396fc8f5bbfb8), uint256(0x0cf945ed97d0aae8777f8df1dea201ab5b4961ddb5c0286a9aabe4901a0499e8));
        vk.gamma_abc[206] = Pairing.G1Point(uint256(0x05367865f3163f601c5755867f31a251993832321dbbfb4d4ce8a95b888e8d79), uint256(0x1c8772d3e1d24f2511f451bbd22cbbe2cc9b93f6487cdec358500d47449dd03d));
        vk.gamma_abc[207] = Pairing.G1Point(uint256(0x2c07cfb92129a28dcb679adf1a79615edc950cf9954f1744ee964223d06a609c), uint256(0x18d783567cb3c492ad52230cc40e02811fe3bf51ad848d09dd7ffe32f4eaa1c9));
        vk.gamma_abc[208] = Pairing.G1Point(uint256(0x17a4c465c6b155b6cdb873376a905877ba1036405095bf378cec5323c8bb8981), uint256(0x13fe1ca36b4692f6a1b507df6537e22a3645eac2232f64c5d60053c943613efb));
        vk.gamma_abc[209] = Pairing.G1Point(uint256(0x2c4a33eacfc461a96c8eb5c1918a7027ac24b7c95280d5c11ed9ec8e64b77daf), uint256(0x28468786a3e207e677122cf4db3acac26b0d6802a5e8be98e0412be0f45998c7));
        vk.gamma_abc[210] = Pairing.G1Point(uint256(0x214140817762a045cc6795eab001c279fc6655241f9a56347592a32ed679cf60), uint256(0x10634803f6fb4347dac4ad79107659bb7e59183550c57909b73e808f52dd4fee));
        vk.gamma_abc[211] = Pairing.G1Point(uint256(0x0460cfbf4d610c79248a02e3d0513322ee39001b6c187674b7477665be1fa71e), uint256(0x160d8949b690b3ca55fb0e5e345eb295a11c3fb0fb1ddac08462ae4fb0230ede));
        vk.gamma_abc[212] = Pairing.G1Point(uint256(0x20ee8ac1a4289443e4c547f61f82bc3d25a97c844cd4fa944c5d5fe026c908c3), uint256(0x241883ea0d7766a9019e6131c40533bde77eb3aee8dcaf283fa9a6b225db97b0));
        vk.gamma_abc[213] = Pairing.G1Point(uint256(0x2fff9adebe83f587f3b835cf2c82e8aba60b081c64f2ecba3859f237fc99534c), uint256(0x2aebefefe3197d4cc3a169a4a3455462759358d6e98c0568fde5ca0bbc338b6c));
        vk.gamma_abc[214] = Pairing.G1Point(uint256(0x1926282a20cb4fcc2102fbec72b4706363adcf69921c40a7df5002b9640fedde), uint256(0x11cc0180bc736678b0ee85e02cf69ac33d9cd0b713ce4a8c97e84eefffa0edb5));
        vk.gamma_abc[215] = Pairing.G1Point(uint256(0x037396689db8018a9e741190c312d58dd5ef75d89f78e6ea7519930a0bc182d1), uint256(0x0cca7f5b5c981e1babbe38ef0c69dfb29a9bc5c2a81864f7da87bad1015bcd2e));
        vk.gamma_abc[216] = Pairing.G1Point(uint256(0x025d1cbfa379f201fe9bd4dd41122847d3dcc8dc2930709f390a8f18f7b81880), uint256(0x124a6319cc1f739d64177009bddaf5720d11d554606c6f460954b2055dbe898c));
        vk.gamma_abc[217] = Pairing.G1Point(uint256(0x17ca232a51a733f3cea18fb612546aad21dea44b078c9d2b7fd3105a5e863109), uint256(0x101c666c61ffd32afbec6b5a04a117917609f8da10982b1412cd735e91755fec));
        vk.gamma_abc[218] = Pairing.G1Point(uint256(0x2d33305f13034a0454ff5831a4ba7d390cbef66208447982c048a221ae625d2d), uint256(0x0bea83cce925593a5f785b3f3316f8c514bd2af29ea1c493c11b667a99a65820));
        vk.gamma_abc[219] = Pairing.G1Point(uint256(0x10508a4d2e65cbca9319b0855bd76a23b2f9454bde47361fb6b1b2ccc306e6c9), uint256(0x12f06f59492af632956cad822a83ecebbba0db6af79bf92c81b05642ffaa002f));
        vk.gamma_abc[220] = Pairing.G1Point(uint256(0x108faff3c297cf63262d47e35ec1cf520e829dc475611a5c55687f108e549cc3), uint256(0x2dccc3a3dc199e11f7a20fbcfdda40a12390371cc5ea913ee5d25963d685cced));
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
