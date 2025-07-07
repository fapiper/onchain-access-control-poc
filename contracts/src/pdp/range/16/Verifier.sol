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
        vk.alpha = Pairing.G1Point(uint256(0x170fc7eac03060d5f10296f9a625cb5592318b11afa3f1e30d3a71c87b5b8362), uint256(0x155e18edbb08a636b88a958924efa85453e928608261ed6e944ac7e92bb19ba2));
        vk.beta = Pairing.G2Point([uint256(0x2809fc9df42a18c43a247de99e02d40cbb5ee3096d5421a31dacc0e344659ca1), uint256(0x0ed061cdb76eeb17d4abf0ba9a8ef8420d5b9e4d79568253fb3e1f8230da88aa)], [uint256(0x26453d211854e53b8dfde6346e333b5a4aea5e025851ca6e3492e9cc7051fea1), uint256(0x0c97a36bf1d0698ab3efd4ff8946563a584706849c3cf4a116f3f6f06389b9b5)]);
        vk.gamma = Pairing.G2Point([uint256(0x2064d53639f1a6180988bbc2fb87ac938270043b8fd1b1ad070f89d97d82c3cd), uint256(0x1983969262ebd2275aa48afb0ce3d8b1ecc1e4d57b2746c8504223cf8a3289b9)], [uint256(0x2559ec868b1470a84d498d0cb787693f4e13ea1320400f03b705d488a3fdfff9), uint256(0x2bb04adcc3fced548717eb550d77b2a4cc604a77a74f2b139e184f208dda1305)]);
        vk.delta = Pairing.G2Point([uint256(0x298e94e8faaeb2138fdeb5311f39eaacfcfb5ed941bd7267186df802b0082ee0), uint256(0x071a325c9760b840ac5f3a3c57c574a7e9c4a6876783d19bf5609d2bfa3f975d)], [uint256(0x091fca7f865673550792c3bb0f209c0ba4acbe2f9a1ad5df810debecb6256390), uint256(0x0bc47c574372e5ad450fd18fba2bdde75eec1b43f79960a0c1cc67cdd7790071)]);
        vk.gamma_abc = new Pairing.G1Point[](305);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1b40e721a302e1dcd73f99e6a24b379802e8e70a543dd452c3587a20538fb6df), uint256(0x06e67798a76575613fbb20eb8ce6440f131431374041d0644a6453e6952198ff));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0da6ad14a157bf17eecd8bb5ba3f643826c1309fc084068f6cb8f7e29cc13d7a), uint256(0x168760c020e08d4ac56d745a4a921539a1fae5408fb82148ba11d9c892e28e02));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x08e256d9a1f13995c68d786d9957d9aa7d8014103a7dadd51ec4a867c2bfe649), uint256(0x168a55134eb966cb1b6b40a499dcf8ab26fa91cdf4e44feab3401c705a92f545));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0a0a92d8d1cfc9092a219b8ef50e010fbfb2190fd348d1a92248306aaeb471e9), uint256(0x016e864e83b597287ea89547c74d4a8f218ba6f3f75d9f34628a67a24a89ef59));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2ea27385adc5ddd171d5b5f62829fbddc1293da3dec524c6779891ad159cd93b), uint256(0x159b18e09c33d8976439934f2d307794a61887863229ef4c406b149839e8d284));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2c7be29918d39bbc3016d1ba0ed8b72c1e94ab184467e3a3927b1afc6b2c3858), uint256(0x044b6b5b15d91c5d04d056478c31c294f70921b47c95a5b1ec7875007f004f16));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x22fd30b37a049d95561dc34f1ce864b7506f43664a88ebb8dc9de6384958024f), uint256(0x11a93bc50dc53c98e9aacacd9980d85ad87bdaf1263aa8d466cbbb97dee1d2e3));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2ebab5ba527864bc7a7c0e519dd9cab7a1d87557d9e3818ba6eccc5906576978), uint256(0x0f9a1c50e27d26e06d2b52d3f0ab750ccb5e8b7fd5f11a0c549c6b0791995d1c));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x14b14a1ae68e42a7d1090bac7211ca51b2eea576f0e5f81472dd1c53687b4280), uint256(0x2b7ae1237f92c342ba5e20a38e82a1e7e48a2df46d76c353223bcaa971212cbe));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x247839a88a46d7730846265ff30a55bba1cd64b522b57601e98d9aae0b0d3829), uint256(0x1429740815df06a34800d82c251f987bf9af77a2d110a28cd81b3c04ecc6cab5));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1218d3e22a1e62f2969af547671f66c0756d709aa9c9bfa82f82279c1dbfe511), uint256(0x1c90df26e9573ac0564167cc27cb612bfd17feee7c6f6a7b9bcf819dbedd4e7f));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1f06b3999e53d34b283fa0468b53587fa28da879616c50252df1a683d4938f75), uint256(0x1cc0c6171cac1c90bc74e6e4a3779197dac67fc0bfc5712e6f041212be6b2611));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x10b00531d031a7ddd19ee3dcb3455c3803c8673fdde210f9cf368d9d38c25a06), uint256(0x0a885f8e54e6c93170c68f03810c4053cbc0d6318be33918f567c9b114ad7652));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1eb88740a5c432c5ad151f54794a88a69c75b11c8923232a2afbaa59120cab43), uint256(0x1b6d028ed86e80d332b873226e515c4a6e83ed23bdc341f329664558ad04b64c));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x273b4f6c5578410b34ccd6241a9cce71ffb0b56a0187a1534121268e2753826d), uint256(0x1fbd87c5df9e54a08702bdd45ee370f401fc04511aa9a3a6d2bd3b9f149289e2));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x118327704d48a75cb37f825e312f780896c56dbcedeb7c23f7030178091ca580), uint256(0x0a2128eb919f2587616b73097a0374b60ea58eb7c17d5f4b268ca43ea7a570ed));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x11fc587e98c0bcfb9995664bf895b676c7ad4a5fb4f7fdc59e7ffde719ae83fb), uint256(0x288ad2c798de9a6b9a2a921d4e0a17e91e685d0722011ba357702842f910b903));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1dfc00440701ae89c360c3b0382fac47e717c00d67a6aab70a88c134715fafee), uint256(0x0fdd81dae04c03f51e5ea9b7dbc330bcf8267411672082ae2b50d27ebeacad8b));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x27212862aad2476c346995832479de6970ad9adbe153fd289d986e80711bb15f), uint256(0x1dd4005a727ad686482f9054bd5cb56714a2ca0e858f8689f5ed5302180d88dd));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1aca480b4fade3fa649ada59f6860534a5336c8c43c1c074b5b5c169fc0c4a00), uint256(0x235f4f7bcff501dab5c0440d6dde9c7825152dbe32de48947fb34c2cbadb1d9f));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x03b26245c4c77ac5497e8de835c2b64276add049e65cf845c47ea46062ed3ae3), uint256(0x02955014841ee096ccd311053946e445a25124338ac578058a67991e31b3a098));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x2d866170e14731b823634d636b90126efc1139e62b7ee22b0f5b160fab774f1f), uint256(0x10be4aca8117fb975719f3ff28f54d69ac9e1ed45ea6d5bb2bace67ead68a086));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x262ec87e987f48f7854bd15ab73f810595580e4a2dfbaf262af53ad95be0afec), uint256(0x04bf00dac970b855d79d14e5419500c1c0a4948618fd8ebe1b9c529531513b43));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x29ae3eaf5847a520c557b075d3d7ad885d714473ff84d906efcf1224e3c438cd), uint256(0x1f3a503f3264b53bb09c13a7b6cc20cd8e4d50bf4c5c861fbe9a897e60750df2));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x0c39b43cc5f2c6ed700efb27b7050800a0382fff585cd85e2d7871584676d30b), uint256(0x1fa4720c52e52ca25dba48ddbda9c5a82a1ccafba1f00e886073821df2492880));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x297b543b19252b5694a511877030e5475a8a85fc8bff7d7c3005570934910e31), uint256(0x1280df9617b1eac5f8f48aaf1f71d6a35a2d5d439f6c466243a7a697500bc04c));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x2466999182fdb3562a42a6714bb74fa715919661a1eee1bdd13b068cf9ef9606), uint256(0x17d232f87f4d58f93ba942b3f18051a546a9da36eb034391a560e1436be82204));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2a03ca8172348bdb4c004e48d6be46bd5b6340acab1f2c6265a0e9996b0c29e3), uint256(0x05371c876f6ca651a824bb28b0fc655c8800a20b0f314421d8dd8a8f1b18153c));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x17ccf36a4d3ea4534587cd94415ddc96b1a67395361e9909c74eb6e89c3c31f8), uint256(0x12e03d47ec8238df528f9bc3bcb79ef913f97f64371d2e80ba4cf7861254d54a));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x202abedb406834d4a44750b289f2189897343a9da4327c15eadbe1ecfbaae20f), uint256(0x03d01535ef221dff921cfc2dd68818e2da62f26a3831bdf657268b88dc46e18d));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x02800a7f2e244e65ca9eee5802e3110f514a384cd95f441f8a68fd67a51e2a72), uint256(0x10d6dc01eebbbc7468d0cb622e5a2a13412d1383d93095306f1fb37502866fc3));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x03ff293d632292868c2f2389b202fa0bf8c78605af30a16e7f9c4400b3bce78c), uint256(0x18cf52f768b4399f0afe1886037d3418283ceb408f6ed26b4e4d56fe721d82ac));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x144c2dbc8098c036c18246378feb7e9dbf4fba7174328b8193f16ea9a7f0f4f9), uint256(0x04ed1498e8fcbd4555d08d98bf8276db0ed901688b6b7cd5252f9e5941626739));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x1f41efec3f2feabe53ea532133a0e6d080f6a16b9a09712a7e0c17e91dbb5870), uint256(0x0a3af7f31aa6bc06eaf240704472bcce154f4b72bcad3aab8b77d7f26d7c873c));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x12214925ccb9a8cfe254dc9072d9b2fe4f5679bc726cd8fc97508a6cbae3d30a), uint256(0x2d449c57633d3d9ba045ba9634fca13fb22b891cea19b2de7cf2394f891c4502));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x172614bc42ab98180416592cea7713be7f7837aed3cba1fa4487d18f8c153c5d), uint256(0x2ad1a077a96cf0cd3aa50513a5d1a42967d5b20059a57d0f6856096aed7de471));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x0cab0486765edfeb8bd1c0aaf857088a5c5d5d433907e25cccd3a2962507500a), uint256(0x1edcaff3192ea9959a83ba4252f4f83da4bf062a550b43d005b33e89e735524e));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x128a2401ca065ac8aca9ce458972eb4f503780f9a5ccd448ee03f267fba03902), uint256(0x2a8b2cb629a7345deaab4d18db3f9668af2bd463da9eec4c9d086a071782f28a));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x1223fba099dcd49475958fca6fedd65d69be03f205b849a8417e7a5f777d5c94), uint256(0x186ba7c9dd4c23d942241c815a17b9a451223b84336d2c8c44149be5a12b19e0));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x2f6d15e9efc314040814b664bfe671b28b6bab907540d133da8768e7e2be9bae), uint256(0x262ea4911c713a2b29259107da507da4f87d7ac25ebd911ef7a4d5d3f8da1a3d));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x15421ff02d1ea3e59871e338960d6b758b9439fd2ce87cb9000c79a23e4c080a), uint256(0x094d1490df0e7fee638d05646e8a745f2088ef3b3f11d07664a5d8a35a83a3be));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x1e96b4c8adf23f95cd4e055a2b17341732bb3c89f326f7b7d68980f64b16c26a), uint256(0x1f3ec355a909a997be481ed65734b9d3facc055d156d122ed25de031da4358f2));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x0655e32d8b1bdbae89667da997b30924fcb0449f32df063d25b1a2234daea83d), uint256(0x27c4284d9a13450ed183183306cea5e8e5f54c52f7fbe9987cc3d014a831d86e));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x1503008690909ee2f3044d03ec0d2eb1dd3b93aac06c99eb6449fc9151f45dd0), uint256(0x0571a176ca7f172ce5e6b603a531ccfc513f5fe8223eb32137f204f797cc81ed));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x115b73537a90443ff6904769365ea673310f72b00cc4c32e88a0ba91ccb60eb7), uint256(0x08679d4b9bac84ae644c6de7882b6f746e7d8e2eaf803658c4edddf17c66003e));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x148ad442f2758c0fa188b51f4c954f18627dfae42da3ba088157b9abeb17a6cc), uint256(0x2fd7445e0c4a3c327312a56cc7968f21a86bdd6ded30dbe246561705661159b0));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x1c98afb8fcf9e68cd91da1187d028f0fd721f857bc18c4a3e66368c885a06dc1), uint256(0x139fa126ac9cde06b5fc929a8b9ee34049eb895b7f2f0b378b6f0d248044378c));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x0a509d75dc556968189dec9ee447863cbd910630826345f7094cca6a45623f96), uint256(0x095af350102e551e72113273aadf76129280caeb3d18b38901b69467f9241deb));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x244b339bd3dc482a8f34ee66fef2411c22d0e37c42e9a3720369665d7a4f8d9d), uint256(0x223d847e08eaf73145a69f44847a5fd20404e8bd7eaafc44420503c576974c98));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x15b7ee90b783a46fb575b6c67492c1247910507f7c960849680bdfbc0f9d47a5), uint256(0x1932df9d68e090b7529684db0b13198fcd5fab6877a370145372fbff673e3ff7));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x28bdac98114422794f5250b23f22b9fcfe881b45e5f131effad6500950d2b264), uint256(0x0c71fcc849289c3a3bbac6b2552eaf05509867c7f67822233f68c5898bfad61e));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x1316cad9455b99cbe325e9cd0268ecdd94efb1f65240b20b700deef6ca5339cb), uint256(0x292d11cc9224258d96ff9d3fc48419e754ce9e382391af3656c0eb633dd584cb));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x2e8f8bf036698a88620ac44077c7bc91f2174b198309c61a6835ba4da32d982e), uint256(0x0626930e0e46311b6b31694eeaa759f131f0b8a1fd431bb29d6df0404f1af935));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x2c3b95a1a801ddce4ac169b2d10c07c7dd548ba8bbe859da9d1d26d5478ffe36), uint256(0x0c312fc48ab9ba3ee9e87a3ac8050bf69a53dc447b263ff2020f3b85501afc63));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x2ed0ce6788e0df2256dfb2779146a0f8fe56d26cdb40664d444ad7a903f5bc30), uint256(0x03f2fc177f2d24e26019679c435e24c9da2bae465404f6c6748152f60492c941));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x153b281f9c09dff3ed876a66328fb4d931251a38904b8597e7493f0aa5e219ba), uint256(0x2eadd3659325c23444fb9b9969ffdb7402f64102ad07d8758bf078a46717fdc3));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x1689ea10c9836b9ce01c07a1884974f6d4a6277811ce162936e0be0e0c6f2e36), uint256(0x211ac23ccbbbe9998d57813e1345e72271dca60c6b7cd8a1e55fd88b08c6cb5e));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x160d1189582a0dde9d1e23d5a209db705c6a6825d8928f25c02dfc36adbf905a), uint256(0x07a21e5be08e6719593efdb9c3ff65f725d3ff35a9bd28a501e420aa0755916f));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x0fd2b1e1f519ebf897edee84f0c6df8a05b313ca575acb4d895f2b46de701b22), uint256(0x207202e2c3e653015edd60f9feff8257fd834d245310e5d91832789dcab64409));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x176f02e1927fa5f8f261dad3ded6f2718c5f1ac9e7087db9ab35ec5f78a2f33b), uint256(0x28599b5748564fee19d29b479ebf582ad5a8252afb6ae8873b843a94252549e8));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x21c6bb82e5bc5bf4843ca230042dfb8df403d7e6a3eb3a431198ad4c2664609e), uint256(0x0f51dc6e840f09268f8dc2a2f0f58aa63814dcb5e2f523191cdf8b30b4140e45));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x23a8d22f8cc17417c701ad5f30777fd4387a4af5d4e8d29c7656fc133ccd3ebe), uint256(0x10f20a878705eb138d8347a86005a44abb47c58a276c0957681327eb5bde51ab));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x2dfd3a4582e4f81f0aec953cb554f6e05834d854fa31ade09fcdfe461daa1bd2), uint256(0x23181c4fb084812c01ed8f6397d7cc92ea583e4f596f1191cea15359139a2f04));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x025aff0ef9f6e4c8d1e93d752f8960fcd239ab8de78ea437b73843cfe2bc823a), uint256(0x263b2c245dadc17d3754bad69bc237caa7b5265a166b9ee7fa188a56c404bf0a));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x00e33d070c9c458c02158e595ef79bbad7db42468714aee9e705c0610db0d6ce), uint256(0x2d0fc123578b53c1b369514d9b266e1bbb7c43426d813b01b77a39876ded28fb));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x1355716e16bc8cd8ed63016da32f99b816ab4796b81ae86a625eb3e9c5dc3d47), uint256(0x1c074f97b8717c3e02bdf7ba1cf42dbdd49fd5a9c5a2424b761bb195fd2b31f1));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x2bb8de1808903583f369c2c57a68ccd2ca4c102a7267b13a593427a74ac39a66), uint256(0x152c05fe94cabcaf5c6dfd0cce54cb5d6606414f39a974a9d5ef55e90e3a2047));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x15947181e4a277d4280ceadcb3658f3bd1b5732c3bd3e256545728fb60f1410f), uint256(0x132e7f9cde97ecc0fef375e7aa39048736d67324bae30966b54d616b85feb6da));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x1fcd6015d23d87142e81d932186cdb7a07a9263fa75701235b9e65b567c2ee49), uint256(0x1a948dc8b40a6ba1b40c8e77ad37d2d5ed98e3e62ab6cc370dfeec4306bcf432));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x2aba8cc585922e20c91455dd4f413431f5b0dbb04577131fad63e7805b828a76), uint256(0x14c8db947d092c0958859f930ce9314ddd8619ad1227f35bb23e79203b48e9ca));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x0be9a0f5837bf0caa2371a1213efa2ad2a429f6c1b43354b0d408ff3a789a011), uint256(0x20b5b5406ccb23253a3ee00447d501ac0b176d8476c2c537cc9dc89296bb4ecd));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x05292bd63743d55c7ee4976225459c8cfa6999e9209c3717d6cefeac2363df81), uint256(0x04dfa2c0e62cac13a7aac8d70ed53cc5a149301f333bdad548dc356a2de15665));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x1365031927f431a34fc1227c810ad868e8f7ed910f9cf3f257d40e61aa431d56), uint256(0x212c5c0b4bc486e60204efae89b5e9733e538351a267632fdfcbda750ffebc25));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x0c0ba566d8198cfa8adb150b4718fed1eb81ad0454b6b52f93364e6efe545bbe), uint256(0x271598ada773f0e9d71d0a7427ca7d1a527a6699f65bfae654b5e311ebc504f0));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x21d51032bfd9b5c33e80ff7f2d9e05ca93667171e47f7750a6d453e8ec1a3fa5), uint256(0x24355bde9754274eb376208166cdcac377b208ba0eece3c0b9907f256448638a));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x022956ead1199ea222e2a66f0af7283609a41c4080c45e172d60d0c1c015221b), uint256(0x2d4f5391f2d6de8dabc76addc78297a8cde08ee5b39f31bf3bf600d21c4515c2));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x079a63db4be5de4158237a07188b4cfcd312c8490807bf3acfb32867b30c950f), uint256(0x02def99591321604666e029465eb61e4ea42a6cf2f983fdadc2930e7be505399));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x2c80af5b55791d6b2ab3487f33793ef2ffc495cfa2ae5dd9e08559cba9b374e6), uint256(0x09107fbb7cb35853867b7be0b3c5de3deee9289bc67f7afc824e37b413e11ef1));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x1ff247420f94e45fea26d6033f5ea7e706437880ab67e681da33fab292efb4dd), uint256(0x116e3146c8aabcc6ada270fbf2a1753f19fd10ea37a68afa2218aa8e392304d0));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x24a2519e356c78c8d5f681870ad004570a12346d1cb37e993097d875cebe9e32), uint256(0x1acb0c2c59c5853fe70f74471f297d04ccf7b34f744d0d0f5282d3250cc20d56));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x131da10ff6132963070325e24690a7308fdcbbe86968abc09f2cf4c9283135f4), uint256(0x2e87db2b1470bc2229ee1e1ee23f0fe659dea14bb391e9b2ce95c37bef127534));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x19a715215d6bf347faeea9e2f666c437dc818c3c5db04ecfe5ad81dcab74afd2), uint256(0x295ad1953b52cf971354e3f4c41b764068f8477866bf3fa649c2db5e1a4c38a1));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x28ad70874adb3db443ae42904c62ceb83da6c55697e094e8c08ef4618d8dbf8f), uint256(0x0e6c13bb515ee41d530985e1d823559269c39651f25c5f6e5bdabcd9100b7b6e));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x0666296419aebb984b39e56a1c04f4525ba80415542e8b977c34c8b277c15ccf), uint256(0x0778883463ee92bd21b795d3d3bd94a24dc04c4a1b39243151b953adbc5f8d89));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x189ff65add14d36e57affc4a715fa362e0e566973ab3d9ce18579d907a4a0a03), uint256(0x2119c490e0b3d8e3b057cb36161f18d9f5c13581c030ce259694ae738292223d));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x22375706818abbe60f41e471d29876a3086404062e3d76170319a593a1fb01e4), uint256(0x030a4dfc478f71b8a2e85467e49eefee844429c5fa1cd2bbf93602dd1eae667d));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x26b49a21ce98d70897d64c94e103742d4ba91ee39ea31f92e18e6d5ca849249d), uint256(0x0ac603a4b3e99310680a4da3f9a558ddcb955211a9b11bae0525510a0af8981a));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x0f0879d4c5fa7947b5c7ac833c1929d86da4d1fe2ce0d68216af43512706ac54), uint256(0x1eb3334ffeae2010f3bfdbcf9aadf3766347b6508d9ad12ae461dc95775d67fc));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x207bb4a427c3ec22412bb1a47b1b65bf444d061afcd914ab556c925a95ebe103), uint256(0x03194ed51d86b058e629045ea5b6c92e8a76e78af95494611e2974d9030b0971));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x252f95f6fb4fc3b95de66eaeff247c79e5c17f44d3e9227b376799384e84ac4c), uint256(0x2e2fe48f58d65e9e358d7e46d9de882e5d4ca6c215ae8d5e066bb85eb06fed17));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x2ad872ca6a784d5f27cb29e5542d87deb662b28172e07548457d6d4da6ae9cb3), uint256(0x0eecb6f93a76441d61124b8b6b478576b64dd011fe4df4d62bd3fde4e5767567));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x1b56e44c116e615ab4b4b16ca3e0a27dea252361274f46585c2a48a401c3ed0a), uint256(0x0e9667600dff3514dfc04f525aeea44a59f5ff6ba9d9dfebd7611a5e8b3c893e));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x29558c63d124bb802fdb5f2baf85a5e079fe1219b6a894fd4c8e86a84d1c4f6c), uint256(0x209b360bad1aefbac0e5e1dc99bb33c715c10b86e1a582af3322cc5962e71c53));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x1e67c75ebfbcdc7794c9e469962ec07457632bad1cd6a4cef87898f6d42dafd1), uint256(0x146b5cc1cd5953d8fb86660e63902d0023e3a80686976d1a33d23d3fd10ca258));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x0ae0e181c88cd8d3aaa8022fc394de53f99e3379457cef6abd7748103e3fb897), uint256(0x0ae8d735e1960ecefd0cf129348f435a1165cfb1b76a692c86ea1e073d2fd1aa));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x0077e8dd73dcfffb5438713f219ff48ba13163f116df02ff90c28eec9d74bf7e), uint256(0x0f9df919ef7d35a6919ca9a1fc662ae3cced8c029e91762cba4eecc0d2e4c3f1));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x20d0a69b54f4108985d56acaeca7da073ddc3cd41062f6540c3e395e5f0cc2b2), uint256(0x19fea03eb24dffed64fac751899f9f42cef4ef0774017ec8e718d8622caf7a52));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x2aa4df4125aff844e98ac1e5b2860512232a02975603971825896e5215265211), uint256(0x25a555881ea5a65950ba57d577ee15b4a101e1d2542dc5e4f8603f0fd7643dca));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x0b29a60591dc65365dc4c7fc7fc0adc58a06cbcd31df7ff59075526954e6c775), uint256(0x0d749ab10b304c7f6d5125b6a0646864a4851bbef8eb95307ccc8284a6cd9ebd));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x074c65d75452eae4581d89c6e4c2b62820144e9d8711f1594e06fbf7935ea218), uint256(0x2e5214eb0b02bbe3d4f23fdee8fd71085d1e8ad35a2db44933e49a3e9c70ebcd));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x1bd41ddb55b254b69af7ad69f9a9d3374bafdf09992babd525753733fc15f3c4), uint256(0x277d39f12bdecd2ce90458f027cab2598640aa12bb3c6ebe917181c488f84b37));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x227d636cdd648461802db21e7232177d8de3dce3e9f2bc2d2e12820486425423), uint256(0x18e44c8de1acc4ae09708939395c1c5af20b2dcbddd122df95340fbd4070ecd7));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x09f712c0d5562892b2f787e6a5cfda51e4481c049e51f0917ecb68dd106b6723), uint256(0x225fd453d194ab7ce46c6b08dad1bd46a5b3c9d30af8326e1f467bbcaeebb9ca));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x1e335af6965bf510a67b6ff614539a263bc88834613b202dcbb27ff6a686766d), uint256(0x27d448df8d9c173a65571defb7060219c51d5c8b7891f2fe261282b829f4d89b));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x2b8b3e5011dbccbb3a2f333a16c5957c5c1ec76e0c99cc52ccf63cd9119332a8), uint256(0x0844f973a305c1d12d5ba86f05c6246c2eae30fbe87a508bda68c72ca18c0fdc));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x09136d2dcc69136a51204df835b041a520caf9b7a118932c75838a4034369e00), uint256(0x2a17c09f1e591e47586ec6e424c192f877cd8ca3ffbee1a62bf0248d0bcfaac0));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x19e3fc7a60666dc4c512378c2d4b8791074d593fb7ff901f157622ada82589c3), uint256(0x1beb02ee19769c4ed426a012ed2fc1e9a584af5a6df8ec5e166e44104444bff1));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x15c5e2c9ffac9619b91a3bd329ebbb8a358836aa155b28e72ce6defa230f1561), uint256(0x2ab822cdd6520e44d3cd70335f7ae16a31267faa833dfdbb29d0483abd115f9e));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x107bc0559de084b16de01e94a8bf7b512207535c34776862ed2d09173ddc3a3f), uint256(0x0778acaed08ef90e56ec70490ef2409305142123092e2faf5abfa65f66a0f54d));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x2e11b803c4a6f35e0868855e1a278dd5655a17a17f0cf89faa5681c4d2384157), uint256(0x0548824955f9a39b905730dd505c3b772b0c9a2206aedafec47c6dce68476b6d));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x10f02c6fc8da45ab950554619d976078c225e8318a09199030c2accefb03a4ea), uint256(0x0c34c9fd9d24c51589ec3820f0f1d1662332ef44bfdee73b1693a70df4295e0f));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x1cb50e4fb45e37ceb1b87f96e969ddee62f7d3848403001d523b6cf6f0a6df60), uint256(0x0fe0db2b13efaae9585d65bf052901a605c1f6dd2a88c38a3ebe72ab19d05193));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x2155db480eca9ca179538a030a9455529e48a307483bcfef1634fae45ed874cf), uint256(0x2e6aef066c3f88a39887c133031af0b363486f49830a51df380501a49320442e));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x1931ac628fc9e28577cc221245dbf7e262775fe7b4430adec521c003db314ea0), uint256(0x272c7c24d169839f724c5da984b5b54fe4f132fc9db3e1847c7bb8a4d03a795e));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x08a1ab5e6e032704a39ec88503f27611e068cea18f1e0da38f4a26062ab12de8), uint256(0x1745f310946d52daa15524fcc98fb5669c4d9088bf123ebd5aefd811a0e819d9));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x12aeb3fe1570340f7d89737941e4f4f59d1d14fc890d6e35ee931479e0aff2ca), uint256(0x01cc3aacd8ab4d55793927891244975ae19228e6cdc3515a495f96d80cda0af9));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x12a8f5811e592b1a9850395a714708ab95acf513ba6763b5b2d4fd62304acd59), uint256(0x02064d3948a2d9529c1e4853b1ad1dd8b61239796e8cc7b41757832f1df839c4));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x00062fadc83c43d243ab835e4e1ae410cae7755f306a8b01e93a49b8a1e0fd77), uint256(0x27dee5f5c98e74fb984b420e3f5f3da6a63e89912a3d4197b0f4671b2ee64c36));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x0b3863ed58fe8968ced1ac90bd11c9dc27942edbcb23a12fbe2a7c7bb267fda7), uint256(0x259e39ede4a8b2bfcc5921e22bb0f9c4d027389090cb4132dd24b61939d8c6d7));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x17fece58766b9c2b7b2df876ce8168ad2fb0f601ad90437081ba2e596e6dd824), uint256(0x12d65e874e90e8989ffbf77a1f09d8ddd8a96ca0760d41562b4e76870ddfaca4));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x0154aee0cae5b7a66b74d0ba17c9aa1a22423bbba78df4006077752bc108ff5c), uint256(0x1e1bbd2f44dc916399d9a838ea14674a24b87eb1bc0af6993ced787b79e2717a));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x227ae1243ae259f7b791bfb7aef207f3255820b0c6fcb839a0f96f8e9028e77f), uint256(0x18d03ec99d589fc1da9d33fbb8e5745dfde0851065244d88a8d2bab1aaf832c0));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x143abab9c55247fcac890988055f3b0199fccf93e9821da73bd2769020bb4be9), uint256(0x0ba7248f9a5cac7992610eb5b6605f49f46a1c01863886dc560ad8a2b6e82df6));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x064e3882228b72662371c9f981617473246109d14e48f92bf8dd9105777820e1), uint256(0x13588fecfcefa3d090df731f062f1601b020994b3be97dbc7d6706877727a85c));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x153c8b158c13d36ddd3b413935973d2a4cee9aab4d01c1418fb9b2c360c0911c), uint256(0x185ece670fcb37b8b88d0bdc9409f55ef483257cc6f8ecec78dc24e516aefaa8));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x0f8dfa284ad489ac019272215e780c08d2082486bd0034391de8ae5fd54f6f4c), uint256(0x0a10e559c4b4d563eaa3c7e202fb9e28ce0fa71a4d0acb5058ebfa595ceef2ca));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x16a63d6bb71243a253ceb904cbfb7697f9e4559445e93fee1e964057c7db44de), uint256(0x231dc09811a6e9e3709bf5a86f5b086f1f535d205c6b6e069632f0d1051a0b48));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x1ee8a1cc8afe1c8dd52bd68cde1d306ef839c83cc0b24b3fe0163d5b099db3a8), uint256(0x23e61396310da904b3cedd484734dc705a770d65f91debcb881d093a7e8d10ae));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x0814d0c2289cb2137ce060de99a80d1169de78b27529165dc2e3d8ba3f2a08c3), uint256(0x18a6a636683d1034e383b302ceeeed0bf666f248aedec08112f4d58f528c7734));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x068736642903cd4cf650c9deb82d0301512b750b5432878a6a3fb2c8eeca0d65), uint256(0x2035a615251cb28b24f2207d973aa6648c41d2064b87796867063fb31e3bea44));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x10e30f6abd7f3e793302b636f0902650acfa3ecabd457c50a5cd60d0c749fa76), uint256(0x20507f3753c1589c55c1768945e10e856ce780a1e7e97e063bbffa5911bd5940));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x1962f0b57e8bc1cf89160b86338fc27b4e61498a0b45d78d1e52d4a9fe9617b2), uint256(0x0c86c0589832f60092e9e551e632f55405aad0acd6520f73be3a9b9d4e61d015));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x26d2af4538dfed1708cf42535065c05eb3d93a4ae571b4f6c14617e27305e59c), uint256(0x2fcd05ec4c911575ba05471af64532e47161509ca5ebb934391e6ef4fe772c21));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x241041780cc6df48c670e9e5b3268bcccdbaf3d5ffb194af3c25fc38e5c37f7e), uint256(0x25938f3dc833931f2dff35b195276bf3901ea03fc8b8981035e497479e896035));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x289274e554af0b066486fcebd620c543a38aa69faa1a6af0ba7bfc57cb0ef6f6), uint256(0x13b7afe1dfea9db51ee06a0c338297be8c42bfc28159b35471225bbc03d4f571));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x13818b6023d450809a4fe5b2cbd440cdf27160e6d3061914409a3e5c75129783), uint256(0x080dbf6d266d117c4a5096cb222e59946e5df140fc3a66e985f42ad175788d82));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x19bb2f5002ea977666257e95a7e3a99e5426553d1497e15f3e472c48eef0c1d5), uint256(0x13f1266a87d360d4da0394d3a3c9ec3262c27e1e8ec0f68c06f2d7d0e788fc69));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x0c9e036a9d52c7a084bcda34ec7983031ae06b79ee7e4ed6e4e5bea983b3ae71), uint256(0x203426f05d5c93f66c0017e9f6f02f44d739729bbdb09ec47c82ea3ca6197838));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x2383c5f3515e6f2f31c6272167bc6393f02c9a2a65324a0bcbe17e52c9880bf2), uint256(0x09f93a925d8308223d52d807ae649678e71bec01ff8e02c07d1a0b0e797661cd));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x1823cf64b4a1e727d31c0cf593cd8c4e8db057d577168d3a6b4b33128cd6154e), uint256(0x1c8116bce4cf638406510c1022b31ccf544a121aa19d785851817d784ba3fbf3));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x0de0ce8f495e337cc3ec6d1057e2e2945d2b489d0cf6b1e781085f27da6fd005), uint256(0x14ddb5cefc928a6a0a35f1b42a386a02f30dfd297c1f2549bedfb685f964a602));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x2518ec924d4d3248b6687d641a4fd9241be007b68433966d0e297e2a84678619), uint256(0x2dd1fea423d30f90396584fdfc107b973a9fbcff04deabe6594d3c65f21175e0));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x2469cd831069f893c881ff317c688c4e367d756992f31bd5782439e0c0adc2d6), uint256(0x15b98e05cb18c773651c79a34da02c989199e9fe65e8c9ad29321f0e78f3fae8));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x0d1ca7ceecbe125f54f6d1f7055740812c6f17e44927cb64c1a515eb21e6165e), uint256(0x2e135053fa803c6d07aed34e8d0b23c04eb56bda8f54764bea942aeec6105561));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x108cf70d6b0d5f303231cc78c31ae5d9e13c375d3a296c517ae271659eff7540), uint256(0x1cf7f76ccca16027576853399a235d7b654986779657e78a2a8816fe8fbde062));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x0b449750fc8fd5957b810d3b63dfb0462a77996da5cfb4d3997b3d9b923c2e2e), uint256(0x1e4f4965466c671c5198c619a39da5355e28e9fad1868745c8678bf58159c6a0));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x03bdf3e95b226e8b68919c7384773ba1bf65e4ba2481d329560f5cf47c9f0378), uint256(0x1995159a60e066010ae11d88c649d0ea49e43c5b044c43f9ddc3b1207bf89f31));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x055bced013eccf0cdaa2d445064f1ec4a2e37801a52c32b9fe3af534e91adc6f), uint256(0x3051965fbba1a674404f342e43b6d2cb65f14ed571c0a0017f097ddf3e30b382));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x279b69ef1d5f462775edf7591ce9411def616db6acb77cc9ef342059aa9e202f), uint256(0x043bc301f3d7544298ba1aed7016edae397aa7af32f55b8e0fed895abcee9878));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x273ab87926f7f55f4b7af82d81eb034f26d2f6adaf254b3a1876748e8666d285), uint256(0x12c90b7d922dd07b25eb45fb0af4ad008aebe272f98d3acfd13a12af0fba2524));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x1dd1e1eb143b4336e10027d25966d421c93f17180b2684061b431cccc637037f), uint256(0x21c09536fbd3ff0dbf652ef9233b6666fd7b07e25104bd32c86ccd06def18ba6));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x0b2f91865133cd3c00264e04847daa6eb63c12dd2c7eee6e529f93266d8d1a1a), uint256(0x22740a10219b37122e858153e4421d9a0f4ddcd52909ebceb80d0624a308f371));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x250b11c3efa5b0b3dbc647137f3a9f91c42359b09fd1fc747c61850bb3149842), uint256(0x0d43bbdefadab5f6d11ff11ee7fa0a921d69be9a93addafc8f5cd978b666740d));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x0bc53291e66880c97d9f87b3663ecb541fd1c6313cffdf998ce5d9165dfabc35), uint256(0x23da055a309b8427e54a2aef4c0492ab2dc241c4b001c1b398426083c49d7e2a));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x2f595e58adce3398fe649915fc63ce6b51fc7e1d46469aecfe0b2ca3c90f8c9b), uint256(0x14c440e94967e988bece8aa350bbec9433df546976369fef3f4df5d235734d5b));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x0ff549e1a5b4f1559defcc654c37951911b47822a255f9d9076dd42f8c0d7266), uint256(0x12a9fd201a8a2d7a64370b19a36eb8b010d9ac73004953247af8d9b3a2348498));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x1a2ce1b5c1af07067003471928912aee42cda77e5905285db6aa6afc81e0fc78), uint256(0x04750198a88105027b93deee2a20ae75dc52473d4f75846b9736ac219aa467e5));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x09a90d742fa53a6f170f978304b3c270602c5d80d86053911a07785730c08d15), uint256(0x138224f19de413e3eb84d663ab88d78afaf4bac00e17c1712b6fc852415b6810));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x2ae4488005efdacf500865a66537a6c34ef950eb7b576ad065f48134e564da17), uint256(0x1b2b901ad3f0466d8af5354b4b30d69c2965fbfeb0cce77279fc438a9689970d));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x2bef08a7b14d3564fcdce7436dda71ba08eea3a3157b5e3a9e6e2ea947f07819), uint256(0x0b02943af67b8b9050eea176f0b3230529d181c53117f5ab22ab99c6d11ed67f));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x0b9b7d7c0eb0a9fa362d1cacd6189dc0250214dce28d41be7798ed2063614673), uint256(0x24d8f2074fb633c312564e294465084c1a78fb76ea046bf159f649f76b15581b));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x116dbf999fa44a71966075c1bc8c7cca2b2dec8736d154c14d9d2d50fb13db9d), uint256(0x2b26fd36f0ddec9a6665767cac308273cc0c40b167fac9b818dc031cdd7fd175));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x2e31cc6bf313d0ea6f490379168089d290b5472bc66eb1d67daf0593ed3ff3fd), uint256(0x2ed97b32792d9e1be13b7ae2251c395b703b885f89092797c7fb6bbf42fb17a6));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x1585776914682a522d75dd43b685517a04fc143b227ec20ae3cc8a5fa179808d), uint256(0x1e18a98e9e87441bd18624896390b6f847834555ab1c60f260f8c67d03df82d2));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x127cfbe3d47ea726b6d8029092fb3eb1f5f527cf4db894682793fdfc14e99b18), uint256(0x0ca8e5e07a37989cfb31434ca4c6f22401d63a9519404af678788f5d394929c1));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x25ffb9fd2d9af197ae6e6f787151f9b80a2309e9d2ed2afdc23b5f597e438f73), uint256(0x0278b8fb65bff8aea9edb65ae8cca5406b5b94868528292a0215d18159641215));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x0c6047e4ae924ef51519fb8789cc87a6dc7775169b3bfe72fbb26600e6559400), uint256(0x1eefb988d017f92341f3667841dc20d3f2b377e4c66320195b4c55de61d6e163));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x0e3c4d60e5ca8b006f01613c3e3400d0ca9c54713b9961bcf83ff7667a6da1e2), uint256(0x0266c6e48a7bf773486ccda6117b2b5f5d6e84e372ffa45b9a8f0c408a856f5f));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x1d80834f879f884290f2c2bbcb00c99d20e951db568d737b50de9678b9f920c0), uint256(0x16a7eab0f1c62151cffed616c5a7cbf58dd9e07890e6845592050c5764a8936d));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x0cbcd0f327f5359152c9f1770954925576e3ee644d66edac492ac49e599a2dab), uint256(0x18cec292a36d535df5e68a5b554254293f41a33e7c3133bd1fd4250c9671d2c8));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x199a1c74b7b05ebdd75867d1d9f8094cacc7e38fd05fcd410ae5eb00350b36b9), uint256(0x14fa0f2556484d9d9de7221bd44beda94b700843c20df0ea3f2f7868fa346012));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x21be5792f1ecebb8fe25c6652d330d6da8a5d5f23c4a2a9565018a2648ddaed2), uint256(0x27499aa884947ead499e38afd39a3c880d093e5f9ae59488d267c0ed79e5fe8c));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x0440536c074ef6efc259d3d14cbfdc2fde1cffdd0997b814b93bfa5ece030c4e), uint256(0x27b118879c8d74f12e9632cbf97a9f94617bfe9f56ac3ea586883e88fef56469));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x19a382e58b46dbf330306bbf08eec546ffdfc47a3660d3dadb5085297c988261), uint256(0x295fa927c136c14738753f458b0d22ba19551bb6d7d178619a137efd1a3ddd37));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x0e3d09b23dd2af862b173d459e429418717cf59746024be17d5c0d85f11a3163), uint256(0x2b6aa74569209830a70851f949e33d93e991b36b2ff2b648da0f35e23789ec45));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x0ce38ea06a9eff8860bbe78071f2defd5987cded13fd1fa61f7353f88f44b6bf), uint256(0x1dd122204f87f4cb8992e2d5127187619ee74e1658f5e61a0be073b08a2c2b64));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x11bc9f819d3703b17e3c404ee6fab861a2efa80961563434d9911ec4ed6a00d2), uint256(0x16ae2990a24f424aed949108d7ba3dd73d895effffe3a49f2073f02e5c73924a));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x0af014edf0033c3d4451ee4835d211f89c93a63c6c17408c4a3416f26ff1945c), uint256(0x28408344966f79bb398ba905271ecd371e16f3a8ec03e12b2b284999943a22bc));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x1a42b7bb01592b8baae17d34aea6cad44bf60c026fe2dc090647f1c62233565e), uint256(0x24e0f268059acb75baeb674d11f1c1754290b913c8fbfc6796c7cbe25ac18d15));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x0b696411bea3e6d638e36a07459368bb37f90bcca47e8494e4662ae9ef18f9c4), uint256(0x23e8c2fcba7799e11ab1abf75a835d9c028529d0fd7649746f954b3693551391));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x24c7e68940d65986dc180c4225cbef8dfcdd809b618022f7cc11c96aba9edf84), uint256(0x182afda55fa0b42c738653e5c1cfc5a22cfeae6006a35a9c17347bcbc4eaf248));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x2e9889a80aab703931e057611f886e76b535fe1e62a778e8b7ac9c8eda005361), uint256(0x08a7d79ce3bd78b907808fa750cac460a06c06864387ee69d27bb0578d34982e));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x28a7e4c40e2a2d1e31269d438aee3b0b3a2ce37aa0754eafb5200bca027b6fb4), uint256(0x0d37beac22c1a2fe00bea35c010b1b38cea78761a37cf9e3fe533be62975ee46));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x003f9f640c7208f40a6eb69d28e9d4943b1ae9ce101c55dbe02afcf9672c267c), uint256(0x0ca50b6ebc5956c94efde3e4103164e6bd79836c7130156bae598eda499fadb0));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x2e2da1f229605c1a35770541977358e130854ea5e20689e1fabfa5d5c1fc35eb), uint256(0x15f109758af97b889bf044cd8fae53d758357df394c50a4ff75c1d52c1c3aac2));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x2d6d2297639126d22015f56f66e4a529250231e9f14d6c12e9f2a312b0855d27), uint256(0x176dd7bf2011013658ad7d847402e0ce5be97564e727f60e8cee65a3974fc65c));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x14b0d599270cefa1dcb9c53bc983bf9798f96369380d5aeb5c1dbd2d63b9597f), uint256(0x041c6c1d8aaf9b436290aba00e8a535343b85958212349ce8d98659b3c65c86d));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x254c4eabddd9ed9a724f4addb94a4845acef68b7026675fcde07db051a32d671), uint256(0x2be1f4e5df86095a7e2d56f2a23a86c797479333e7ca1cee7a6541675325a558));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x2b64fe9e8629b4f6e5fdc5f93de0797a0aaeceff021184994dc3cf474af473e3), uint256(0x269c22ef572e795858aae20b6c9fc4bb8c60f46989401d817dd013d51fc620f0));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x0a7d55b438dcc0efa50cafb6e20bfcf487f2865c284196d22e59dd695e1f6483), uint256(0x001c0dd76fbd273c0ce8e3ef6c513724a10a287048bf317d7c6bf7ed6990f9f3));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x2538c271b295b7a2210aad221da77c3c4b675b45ad9888184942d4edf7a7bf43), uint256(0x09916ca29afd07ec1a371941dae0568c09ce26092d9298215799d57ea71d292c));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x07fffeb62782d700abdaee5316c0249d3445a5ce96121924377b748b3dee2de0), uint256(0x2424f896ceb2ec1eb586cb67fdcc153ca34e3ca0e5b582616d3a4428b23ca870));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x08d632705d7803db675e77a46e7cf88785b3791b697106081bbe84a70a4edfc5), uint256(0x17dbfccd04891f574dd3422091915e6cb9d6df82ad314a68e6d51725e0c4fef9));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x13f9fae80a8bc2b2415dd47cd6996f612fceaa8f4d261871ea98d7435a781031), uint256(0x0197f6aac9110eedb78900cfbae47a4a1afcdb971435d32923c919d7bf2c1267));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x26d052393eb57f009a972613d72eb8b1191f8ca59a3f7bf712f30db3075ea476), uint256(0x152bdd6a165b59e485fe055060922cc1b4fb670874aecf90aa555e37907644bd));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x1df2dad39df43a8aa9c331c13f4dff12738c4d11e52138019c6bc849ba5ad97b), uint256(0x1d7cf9f94d76192ed4f7dd5a43f80172683383a4e0b324624a5b5b28f2fe4d6e));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x03861377f07a7d81bcabf74e7105fbba79a6ff987c955bd430e2afc36eda59fd), uint256(0x1edd5902d554d1bd0e30a878c3a4c6818a4d1f4cc9844fcb252da70acd8af224));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x2cf52220753daf7932d4f1b546417e3e8c83d7702b7a47057983d478b0f812e9), uint256(0x06d7b755189ebefc388a4af5e1e94a9965861f74d03633cf48067295dd463772));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x16374de3974ca244a3a4d7cbeda5085133ae6d67ece3114d50a265a2d6e29eda), uint256(0x2cce411e9644a501a7b694f78acc7331247bccc823fb39036bc118d869ce0023));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x0e26651f3ee50c809092806758fb71eead7da74a685fc604be2f6371f8accb51), uint256(0x2180650bfc9fe35c70d0835f1982219fc306b4c02cc869f3e86a2409fc3a43bc));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x29d4cf1dca37d88fb6d37e85906878f797da113105a28e7571dd71eaffae020a), uint256(0x2101136d2d85266ec20edee26bfd42e9bce8ef52ba47b9ae0690cf8d7fece986));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x134b8b1864e39ce29cc861a301a72ddc968d2ceb923b042a24bf7ffcd997d2a0), uint256(0x303d6f16898d1262c2d5b1b49480179d21ef09f7ffe1feb26037da3d0614204a));
        vk.gamma_abc[202] = Pairing.G1Point(uint256(0x0d49ace59a68ec6e7fc88f7a7bc5b8b46159041d72844baec2cf30294a0da678), uint256(0x0aefd889a5dc16f41a7535eee5db38bbe014c88db989329d62b6cc838242b259));
        vk.gamma_abc[203] = Pairing.G1Point(uint256(0x19a7bc4e5d03184a782e6e44463d769e2be0d3048fb411cb6aeaf14ba9f43c95), uint256(0x0a15f538346f85bae22ce4181fd724a23747cbf747d4f64dc8da9cbd675e4727));
        vk.gamma_abc[204] = Pairing.G1Point(uint256(0x029063b24ffa331ffa47a9bf85fe131188e368d6dbb7345624b76ed8f5b3eea7), uint256(0x0928a9fb81fcee27bcdfda39e477d7fcc5a1bb455db6690c3448da3413f2ddfa));
        vk.gamma_abc[205] = Pairing.G1Point(uint256(0x12f0a74aa723b22ac193c182dbc102c367a180d24a1a04a4bfa7b360044305a7), uint256(0x19093fc7a8d8875f47a961264365cfa040086e07d40c0a130f472a39ffc0b71d));
        vk.gamma_abc[206] = Pairing.G1Point(uint256(0x0037c4847ad571f0e2cf10a6c6d40537bcb69e87272df9605ce731f172dd52df), uint256(0x012bd9d1d87aed1fc66b77aae184228d31a0e336a6f662f84a4319f6398c4977));
        vk.gamma_abc[207] = Pairing.G1Point(uint256(0x280d32196625fce79c18cd9709532f781fb7a14b32e0cfb28cc03fb95724ea15), uint256(0x2e2af34497aacaecf968315cbb6ebb68506c594cf753e0ec63d7e4c5e4eb5a09));
        vk.gamma_abc[208] = Pairing.G1Point(uint256(0x17b33931e2a5240af0298e0e1a94e7c085fb1ce5df5bb4a600d942fa49ec2fc5), uint256(0x048ba9c0159517ce4a6eb0a8df8303681a2c72c25c0b72fdd53688300d339fba));
        vk.gamma_abc[209] = Pairing.G1Point(uint256(0x15a9cd5d1366273bf32f5393c85e6011672321efd69633c78122e69ec81ca517), uint256(0x0b5d51ae3160bd18c70207f455ca0ecedf60050762f3820a1fd271a38d3f25cc));
        vk.gamma_abc[210] = Pairing.G1Point(uint256(0x1724c74019500767ba15bad5eb2cb18b35be02fc5c725bc50e3e7241e886a0cc), uint256(0x1033071714509caf333786e38c4489f4c49184bdc56acd1acfe3f52668e08812));
        vk.gamma_abc[211] = Pairing.G1Point(uint256(0x174d35bf24baaa6bd68653236c837061e8858c5fb86e6a6d14c080e7bd08e466), uint256(0x03595c3a89d9174583a7883b841b23780363d296c880a74fc4b36138c9f13af4));
        vk.gamma_abc[212] = Pairing.G1Point(uint256(0x13735b4a8d34d2f9dc157007629ce5c50f70139dc2b85d25a7a401896fa2afbc), uint256(0x13c75a7bbe9c0c795579c9b773c95c2296c1d13c4bdd73848d6664e8a1838f16));
        vk.gamma_abc[213] = Pairing.G1Point(uint256(0x0fd3f5357efa1a7b984d2d31a2edfa08abcfd46bb95f66179ea04373924822f0), uint256(0x2901241b41ca796120bdc07970b4957d6c9ab6e529f9c92f35abd8ab6607919b));
        vk.gamma_abc[214] = Pairing.G1Point(uint256(0x0b2240403502e825f895e169f594b24620bebc07001f67468fe3e8cfe8f4cd68), uint256(0x06d19e4d0496ac88993a44633b28dca8160f0de955870de2c80866098ac84d33));
        vk.gamma_abc[215] = Pairing.G1Point(uint256(0x1540055ec34b629ea20b9011bbd183a79a0212ca5b1f9f8fccefed758e7e49b0), uint256(0x0b9c28c74058e7cb7b8878e7520be82c5bdff7d58a63b0320102cfe34bb5aace));
        vk.gamma_abc[216] = Pairing.G1Point(uint256(0x1a0b8888606e4ea364dfe961ade5ad19b683e46b3b4f1e304051d0e29567cd71), uint256(0x2fe3e2287b8aeb52b51c1d19155cc07e0d579a54dc5fdc9ab870772d894d0d6e));
        vk.gamma_abc[217] = Pairing.G1Point(uint256(0x2a1ad893ac30d71cd142e917f1af040bfbca74c9644e6e3f1311b356142ed036), uint256(0x1e5b794afea9b61ad5ecb1dfb279469b7eee4ac780a04fdd899ab725c8fc685c));
        vk.gamma_abc[218] = Pairing.G1Point(uint256(0x28950fbee167d115a2d0f0103de88c2d31b0ad212062ca8ac9c22f15e2a96d28), uint256(0x2f77f030a6da9919cb27a838a6c46e183c0d1012b52e7a58612223f04306a9e9));
        vk.gamma_abc[219] = Pairing.G1Point(uint256(0x25c343dd3a056ece11507d4e4d32dbd0f378d9f668d02e8ebc0a0c6254f0b526), uint256(0x2493262caef752178d8dafd9f6a3956f01ac70cd1144bf475cbf8253f9a7d04c));
        vk.gamma_abc[220] = Pairing.G1Point(uint256(0x204d1f794e3de83af52f6ea3572050fcd750f3870c7a97f8ce3e31b39b428c3f), uint256(0x028e3825b04cb6b047bc2395cb8162820a8951b571163b3a23391071e9e6ee5d));
        vk.gamma_abc[221] = Pairing.G1Point(uint256(0x09ef6602ad929d1f9900cdcc6e43209d169896661a241660ddc93c21ca427d8d), uint256(0x01004a5d5bc0675be34498d40b3b19ef0b5a0a75a4c09cd268a083d298c03377));
        vk.gamma_abc[222] = Pairing.G1Point(uint256(0x023957d5e3ac3c38d08e81a002bf1ceb0055971afc9f88424c93b78af2c3d759), uint256(0x27f470e4eba8b204852acf3caa90838a31f7dc6e9ea303e17c35b4c5c59f99dd));
        vk.gamma_abc[223] = Pairing.G1Point(uint256(0x03fd6d6d829638710a460f875ceee84502a6400c3eb427bdf9e4a756d41bb67f), uint256(0x042b4d5b26bea7e573c378253d0b18f61d6fe1b1e4bb517b7e829cb58f53beba));
        vk.gamma_abc[224] = Pairing.G1Point(uint256(0x24c33f7dabbd1133a84a1f8456f31c8fb6add6b4051ae03bbced529009897dca), uint256(0x2ff8a3e574b745f8dbde2fc497c91b7afcc609af2a363e81d6d2e95d5abc2639));
        vk.gamma_abc[225] = Pairing.G1Point(uint256(0x22590bc71f70bb295e70b0800445f506036d84ab5c274394210b5b590be50cfb), uint256(0x2bad5cfd66f7f85e484cc5d724aa559f7c88292088cba53a1fac4431db8b656c));
        vk.gamma_abc[226] = Pairing.G1Point(uint256(0x002ce9a1bb7b9b3cb79a773dfa90fe64ab49bfe6e43d7d3fc1214d0614ec5030), uint256(0x2b65b2c788b968bef0a0e2316d176f12ed3ee5386c896ca11e45abeed8c9a58c));
        vk.gamma_abc[227] = Pairing.G1Point(uint256(0x2d130341848a197212c615d93738801649f37cca4b5863b520794d75051de39b), uint256(0x0a0e5ab387fd4b2a031ae6f20c1323df9492ee785dba51eac5962d9e05337161));
        vk.gamma_abc[228] = Pairing.G1Point(uint256(0x2516f243131000bc95b68218df0474a7d07b60aee0b09ca51cd466fac689ce22), uint256(0x2ce7ef52d5044e7790c2bfe4f5d9c859f61ee06a6578788dd4a87a042abf51d7));
        vk.gamma_abc[229] = Pairing.G1Point(uint256(0x12fa69a85dec1d49d055e31df26d71c15dc47133bc4961abd911c4bcc74a0b11), uint256(0x0a751da7e11db96f8a0246ee759c89c976861747c5e169747e97e5562f8f1315));
        vk.gamma_abc[230] = Pairing.G1Point(uint256(0x060cf01b3f3c1d3ba5e0bbfea6a349b4af2e3b5d0a3f22ae9ec58fed2e66498c), uint256(0x1232dd27eb46f9526d5c74774a5c18f99136d20b2418d66983139e83c59a2e30));
        vk.gamma_abc[231] = Pairing.G1Point(uint256(0x0f188d2cd0b825a7f42cd1ad9c99e763773693521573c42a3b305bcd2fb60881), uint256(0x1614fb1c50f08c8b9902199f036aace2746a97808f7ee3ec2901948a3c43ec1c));
        vk.gamma_abc[232] = Pairing.G1Point(uint256(0x2d9215d417c84972647764b82962a075a17e8dc11fa900ffaf494b893867ce4b), uint256(0x1a8c6511f13ba913dba3b320fa80e37f55760536ef2fa142bf1f92a98c79a8a4));
        vk.gamma_abc[233] = Pairing.G1Point(uint256(0x0c6fc403e438fa76aaef170c253ef6ced23d23788f12063bd563ac7813ef1214), uint256(0x14c4b278ce5d2b192b622ac7fbe769636736bc46f7f7c4a35b1739b4a424e50f));
        vk.gamma_abc[234] = Pairing.G1Point(uint256(0x2071f7457c1044ed285797e6aa76ba25c232e600f9b76d5a78d113fbc615d7d9), uint256(0x10267a5c912f1dc478369980e9b55ffd2399479aef6f12a540df6ad83a2e0cee));
        vk.gamma_abc[235] = Pairing.G1Point(uint256(0x082c499a06756ee9eb628cd9f57f26e1e04c61b60e63ab40238d0a0d2c3e3398), uint256(0x11cdeaa461c739ca695c5b8713dbf2e05ef68a96d52afb58ccede8a0016278b2));
        vk.gamma_abc[236] = Pairing.G1Point(uint256(0x1b2160191167064fe8eacfabe36dfd58f565a569a29440f99a97d16ef2e7745e), uint256(0x2709314cbb281eb878366af2c913c1d2d40e94d7845e9d8c0d604fe8b32695be));
        vk.gamma_abc[237] = Pairing.G1Point(uint256(0x14db07a16145a31b8957cf166eb0a3252393b1cc3ff624e589aab06176215f52), uint256(0x15cb352c1aa6f6933310b4adecef0c64cdb086e9e193739ebe577aead8fbb5cd));
        vk.gamma_abc[238] = Pairing.G1Point(uint256(0x0c9de7fbd223902b9a77598d6b1910b5848ce2bbe250eacf35d5d79e4bf634c4), uint256(0x2b81a7938586c6796b56a4c13535f3afca56edb4d34b53f9164de3a8ffc26689));
        vk.gamma_abc[239] = Pairing.G1Point(uint256(0x163be64717a205b28bf43f047f317b184318c0822040506b43c405859579b8f7), uint256(0x2dee51df474b7f221768db89fcb1b26f0bdf90f1e3097a425fbbc8329ee88eb8));
        vk.gamma_abc[240] = Pairing.G1Point(uint256(0x0b1e73501ebc3db72d2ef2e3ed4126753bde127de688c5f8d5527ef64dc9df2a), uint256(0x015f5f507b03ff62b30fc48e549ca5e8b86dc26ee85a3c43e354d5dd907bf931));
        vk.gamma_abc[241] = Pairing.G1Point(uint256(0x001a706c28d5c02be5ad49e08ee5637d518922ba15ea5438ffd9cce298d139dc), uint256(0x285484cfb90a4da62c1f2692949e5bb7858dfd914e972496bdf46bff41b3725b));
        vk.gamma_abc[242] = Pairing.G1Point(uint256(0x0ffa4050d46b8cc7326b058db908ca5b62f65b43c15795c587afcd1f4bdd9326), uint256(0x26ba34d0fb224f183dad6e9a57f9a46121a7fc10a121b5e40da8850f2b3d537b));
        vk.gamma_abc[243] = Pairing.G1Point(uint256(0x22ca0c764fdabdfa1752c91ad79246c542556763d339eaeef83f22ad68eaa029), uint256(0x1728417100528f0e6636abc6bbae5b70dcb365814add7ed1837f02c3930fbe69));
        vk.gamma_abc[244] = Pairing.G1Point(uint256(0x29d6a11481f3a5700d32bd95b3f68f3c88d5d4563ee9b132677a98496a61f64b), uint256(0x302b89aa6f9dc42576093cd94505225a9937da435cc26413ab5faff6eb3556f6));
        vk.gamma_abc[245] = Pairing.G1Point(uint256(0x2fca5f89acef1aa0170d562797945c5557d52e57d4bd231601770940cce2a8b9), uint256(0x0fb57973725db08a02fab163355537cab7acf07db9a5511c1a861aeb6cc34e2b));
        vk.gamma_abc[246] = Pairing.G1Point(uint256(0x246390c3b0aff1bf1ad765b0eb627ac123685949699b7ef611c3a117fdaff84d), uint256(0x26451e69ba46ec66cb42da8de6017093d5e92ecbc0c3419b41ff0ca5b33cf399));
        vk.gamma_abc[247] = Pairing.G1Point(uint256(0x13d36eb75a20efe1a4f2d4b4882149e38caabab9679b473383a23beff2cd7345), uint256(0x2725960eda0a708c71d810c1411bdec6b1622654a1a6357b276cb15a5a658649));
        vk.gamma_abc[248] = Pairing.G1Point(uint256(0x071d1917a4309ba242206f15d68c06d83fec97c0ca7efb818418c4a3a809d0a1), uint256(0x067393c5e9614413dfaf01424ef84b7521e271008726ed813bd9e3c08ecbc81f));
        vk.gamma_abc[249] = Pairing.G1Point(uint256(0x24eee1c6e410b2fe686ac48ff30c49292fb9ae93807c9534aefbcc78b33755fd), uint256(0x090f77ea734bf18b6c529ac88f16493211b31f74724f2c320ec62fad00da0de9));
        vk.gamma_abc[250] = Pairing.G1Point(uint256(0x1f750709ec8106e666380e13520cd763af00d2008129a7d69f3288644813758e), uint256(0x22cb8d43b26ddf75fae22115d787eabdf492e3d9002ea6a3edadf3470123a45b));
        vk.gamma_abc[251] = Pairing.G1Point(uint256(0x3049939669da6523da2de9fcfccd77f3033c99ad5199c2070f699fe009773a93), uint256(0x16d4bc520dc268eb1500740b7cf594cc07ba169adbdf687c4ab002ea9f07bd18));
        vk.gamma_abc[252] = Pairing.G1Point(uint256(0x2f5d7dbc997a849edc9359d6df0eeedbb8d2c7bf5c0643c6871ec1c333923e27), uint256(0x09cba5773a8d983f42d8d1d5a1cd57e07c83d08a5a1388d7ba66c8b5285bc26c));
        vk.gamma_abc[253] = Pairing.G1Point(uint256(0x1ba09633ab81c3027960fdc596148625adb7bbb6d2d210ea5d8b39827785ca6f), uint256(0x15d46acda24841f4bf883a56d4787db69b0c651401dfcc3b83bc2737446aa363));
        vk.gamma_abc[254] = Pairing.G1Point(uint256(0x217b18063cbfd24e25b1c25eaeb4b36cc595750d270d94eefb9372c22bd9f3dd), uint256(0x027799885f5996cf2e73556b00b673dd9a3409ede2049d1737dca625fb496836));
        vk.gamma_abc[255] = Pairing.G1Point(uint256(0x28f12b334878d3d13c8ab16f379b71f8db69f676e5d1774f85ef4e78b80cf48a), uint256(0x1476f604a93bc919fe3db9ed064951ab8490fc1257cc95ebc2f13aad47f06250));
        vk.gamma_abc[256] = Pairing.G1Point(uint256(0x2dfa2c0058893393f89a72cc5546fdc0d21542ea96a1c3dc66dac04d7bc49216), uint256(0x27b631d67cd58b42a671bd34e769015a24e21230c920bee9c63b3767a1357126));
        vk.gamma_abc[257] = Pairing.G1Point(uint256(0x032872df5485e68c67d345e732f1fd35040bd0764510c93194370a4aec1fbcb1), uint256(0x146a17a4cd36bd53c6ec756f86706de5fc845c607c341706638008184401d9bf));
        vk.gamma_abc[258] = Pairing.G1Point(uint256(0x12db0b43dc5a1e00db2349b25fd040048f418a70e9c60d18141289a475cbbe55), uint256(0x19fc957384820f0f0f478d626054d1b1dac6b5dcba07fa11e1f1f57ac2dfd3a1));
        vk.gamma_abc[259] = Pairing.G1Point(uint256(0x2b86109821096f347436477628b4d2aa796f7baeef208083831f14bd23e44309), uint256(0x2530e865a6f694f47974f88ef2e9ef1ab021242022ade98229e8e3d9d577bd2c));
        vk.gamma_abc[260] = Pairing.G1Point(uint256(0x26fdb95e27be697469b736980377f9388d2c3e8c841f04a46d9fb42e7a3d0a9d), uint256(0x1afb9b4876d0e90e6f0eba083036c3660c0782abfbb02c2918cb39d9eceac39b));
        vk.gamma_abc[261] = Pairing.G1Point(uint256(0x21395d2724358d13de4090a33940c0fe608a8c689bde5995a53f2a520d163002), uint256(0x2ef4490013ef11c0f6ea03de2ededdb5c527cbe602df6ed23d91ea691fa1187c));
        vk.gamma_abc[262] = Pairing.G1Point(uint256(0x045234bc042b309427378d77f58268741d8ed5e2f2bfd845d875a4f280e30df7), uint256(0x1e978097b41fd8a894f26d7fe1817de17abad00b3197a486ad0c826b16394e19));
        vk.gamma_abc[263] = Pairing.G1Point(uint256(0x1fef330d2370bfedb6f8cdfae049db82f5dbb60484bbc965f14e60c52376df58), uint256(0x1b827a215809e0f6b8688812a285f35150c8553d0be0a15ffc7f311f1aeaa7c4));
        vk.gamma_abc[264] = Pairing.G1Point(uint256(0x1ef9d3764d46b7ffbf1c2335624c08e31dbb76127b8afb56c287263000aa3732), uint256(0x068a192a20a88c5921da1707ef800356003daf46fa071916f5622ec970288504));
        vk.gamma_abc[265] = Pairing.G1Point(uint256(0x06d911b6da545aae2a910eb2f97035fcd2785c9da83675904e79a7336fd9b6c5), uint256(0x0a5bb4004cd21718c64203cc1d4de817f4c22e4640b8a6de44281ab747ee4b52));
        vk.gamma_abc[266] = Pairing.G1Point(uint256(0x0aae11727121dfe453e76b61553a86965df087209ca8ce42aeca7124ac23a64c), uint256(0x275bbb57614b5f2efd5d96783d73214cb368777edfdc8fc7e1ad1d133f86f87f));
        vk.gamma_abc[267] = Pairing.G1Point(uint256(0x0d300285a25265b76610db6ec4d8d070d0a4a0746aef55951f118f8dfdc4d65e), uint256(0x231068ce2489982636d4f66b39c947420d528523b21bf9e418caab9a33bba8f3));
        vk.gamma_abc[268] = Pairing.G1Point(uint256(0x15b4f7d88de9611d0dbfb50db3ec365f2f4b0e47c92b8904d872ae40ce84d86d), uint256(0x28bf3212dc94faf804345653f9bab7e6d096cf77b41d719dfe76dab72f84ed1c));
        vk.gamma_abc[269] = Pairing.G1Point(uint256(0x213526d030074cff405e9d3386317998239d8ae06e02be8f24313ed62467b6f2), uint256(0x0ca9ca6c8b961a5bbd724cd9b2bd9662b399a1db78cba202fae85fa092021b5d));
        vk.gamma_abc[270] = Pairing.G1Point(uint256(0x1c33b38b62d5a6e2ad8bd3aba92ace124f6980b913631789cf7e8d0afee7c27f), uint256(0x11b47e87763499df6a15c412e8f2eb44fd56f6957882ad245525073aed530cba));
        vk.gamma_abc[271] = Pairing.G1Point(uint256(0x179d04a58053813ec0be49324586ea9fef0f9635d72f6c15bb418c903e511baa), uint256(0x0813b32720a0abe1e9effc990a2c1bd1ed3bb09533f4daa563ca5704804b398e));
        vk.gamma_abc[272] = Pairing.G1Point(uint256(0x269c2ce9c43a6a6ac254447e8c058b613f3f58222bc733eb510561bad6f800e6), uint256(0x0f88d7e12a5eb3ca9aefe726d8f774aa019eda6e74c2c7cd7decc77065414262));
        vk.gamma_abc[273] = Pairing.G1Point(uint256(0x0eaa2c681739a93f055f8eb6c48b43a5b510edd371e29ead23057832d3d41825), uint256(0x07844bf592ae997d5bf10837b12ed316c6f0098870c4416dce0f8b5f826a38d4));
        vk.gamma_abc[274] = Pairing.G1Point(uint256(0x1938b0cc13243b47fc9d346355c5c5ab179286dfb820f464de185cd4f5f1c654), uint256(0x1aa5871545a2abf8f4025c6f882b3597d17e78de47a7e4305bfa1ff98c967b59));
        vk.gamma_abc[275] = Pairing.G1Point(uint256(0x085fe18a2558e4c778a75a64ddc4f00ae0ed983568f7d04d4a3c156c91b6949b), uint256(0x290a2502f289bea112e2ae5d8bb47d71266491c6c368c5ecaa77998639289039));
        vk.gamma_abc[276] = Pairing.G1Point(uint256(0x19951839e3f3ea4be1f09128efa8feb4acac32e590a17b909696eb40f2167f16), uint256(0x0b3da0d2617f53ba74a743abd03f8b1f3dfa10859de5793e611a2af010d73501));
        vk.gamma_abc[277] = Pairing.G1Point(uint256(0x0bbf1e834480eddddabbae17fe15e37f51a08f7df8eb0aee309548eb14f67099), uint256(0x234ae5258d5e34f46b943c88e91049bdfe720a9ec3ca5095b74ecd286ac63c11));
        vk.gamma_abc[278] = Pairing.G1Point(uint256(0x276e746a78afecb98317b3a7a78451a26ac8f6b9a7a598d3653bee16296680b6), uint256(0x025ec631d8826af9c72991e3677a6ce8820f417524fb4262370c4cc395ecab0a));
        vk.gamma_abc[279] = Pairing.G1Point(uint256(0x1d8b23c6ed6b404d41b00e1e8ff6567505c8992fd29921d777f862a699549df8), uint256(0x04f9b53b6763679d28aed3c41f3347540f7ceb7147b73bde9763ecd6439082df));
        vk.gamma_abc[280] = Pairing.G1Point(uint256(0x162b3f2cf1e1a6d4d7444c746631f0cfc661a839ff5a19d1abc860d69b903bda), uint256(0x2c4adc0b2ffa3aa1cc07937cde3f6723f73a34825c15888c28e42db7c260c4d5));
        vk.gamma_abc[281] = Pairing.G1Point(uint256(0x2feedd5bd569a66829b0b0e34dcc9ee709452f09a7354abafc188b26b344f383), uint256(0x033452e337b042e664e8f0bfccb1901b218fc5209c719fb15129816517ddabee));
        vk.gamma_abc[282] = Pairing.G1Point(uint256(0x027077c3aae7ce411a15d1dbc18f53b18c14a8c30e00a5397531e2db834e2710), uint256(0x13922625f3379b661fc86840b4ad2c1bddea55337acef0de6ab31de09eeb5433));
        vk.gamma_abc[283] = Pairing.G1Point(uint256(0x1320a2964872b9f94659b7371bdeeed3386be1992b00212b8f63f4014dc2847e), uint256(0x14c82a455c4944e055196d737c19a4b2e31e6f96a6e8fb83a0808e99af2e14e8));
        vk.gamma_abc[284] = Pairing.G1Point(uint256(0x0b48247bdebc0c3ce768705962710b74edd2f5a82fa0c2f7913b42b53544c0a3), uint256(0x0b565c895da2639f3ed5fc8ed3b98552d969afbd806baa44eca4b7b6be4b5a35));
        vk.gamma_abc[285] = Pairing.G1Point(uint256(0x22694fae18c53463427a06696e32c1c6a9a4182ef34e79f4c6dc6751486a4e82), uint256(0x17c16ff6a4d195e581251ccde9e84866c5f5f08bcfdac6f9c43cd9fdbf8dc30a));
        vk.gamma_abc[286] = Pairing.G1Point(uint256(0x0c3707ff8469fe58c4f36248322fe83566a1cdd15b211cd8d583c0738137e751), uint256(0x1806a468e6e976623e98f259640e88a5e9f559c914d32803846f59f6c15c836b));
        vk.gamma_abc[287] = Pairing.G1Point(uint256(0x27952c27e4462b9c8b955f21942e3abe1a3cf808c793706de2920c316d5d6314), uint256(0x145eb9de4943cc02fdb849ec9ec2876a2caf6983a13f0a8b212ce9b029f23cab));
        vk.gamma_abc[288] = Pairing.G1Point(uint256(0x060c77ca01e254a87801108adce9d67863a859f483b86467af65e283744978af), uint256(0x24a653d3144e39d8ed0dfae10eda231cad4f4aa3fc3548e6714a68bb6d8ceb6c));
        vk.gamma_abc[289] = Pairing.G1Point(uint256(0x23a641eff0ed0754a5c078e9fc1e252ea390b4ab87a9db9c6f0dcfecc1785b85), uint256(0x06c9aae8ccbb4ab1fb9a82fef76398bfee4e53473eb22b9abe213ea55886a533));
        vk.gamma_abc[290] = Pairing.G1Point(uint256(0x2de734de334cd492628425f7d445a1d6b39c531dbe08b8424cfd73848e0e8cc8), uint256(0x099a4317a3c4fd8b96978a638ea72f00a09727ffbb4e436bae4b5293b6348ca7));
        vk.gamma_abc[291] = Pairing.G1Point(uint256(0x26d3e5b20ddd674a4107a2dd6433d8e6758c170c36c17ff6f6f1a6aba1855eab), uint256(0x149a0bd024eaade8468df826a1fd12324e2000ae427e09c5a371a5a5be45a08e));
        vk.gamma_abc[292] = Pairing.G1Point(uint256(0x08e36a105bb8f1e1da3a50988ed8c12f1777df8dd87ae872149614df86947146), uint256(0x1d9308b294f8aa8635e7a40f168817caf5537cf1a983c4dcf85a13ae4e08937a));
        vk.gamma_abc[293] = Pairing.G1Point(uint256(0x125362b12b9810c7a47e5ee756668e0963d1c0eea04bd42aa0adc8b1b1d82161), uint256(0x064ac89934b66efdd61b2d2e68472ad31c0f2138e0ad8400af71bf726b685c0e));
        vk.gamma_abc[294] = Pairing.G1Point(uint256(0x0c9a0e15344a8511c510bdc3054d4921a20628139653474fa227a2714cb94d58), uint256(0x277f6be5557f8b803bccb55c577153698b0120597f7406fc989e41d0a4383dcd));
        vk.gamma_abc[295] = Pairing.G1Point(uint256(0x0ab33f46f9635435ee5288dadd203d6c056b3e312b95e3a196e4fdca7d354acc), uint256(0x21245bf62ccce061d896a20f6c5cb33cd1e76ad510595fcad79dfb5e3fa76dd8));
        vk.gamma_abc[296] = Pairing.G1Point(uint256(0x0bbeb15f2f289bb8b6eef7459f4272c7f4b0295b175902025a69e8a5c210da2e), uint256(0x30187900c15c074a8eca5520861348bece7d069869517e626aa35d721e0c2320));
        vk.gamma_abc[297] = Pairing.G1Point(uint256(0x28ccf4addd6dcd024395b41b0d6bcb08aabf2e3cefa2572d58b4ae424fe68653), uint256(0x03b50293aa01f7294f0bed54eeae1653de30c3b5dc48ad80fed6811a75746311));
        vk.gamma_abc[298] = Pairing.G1Point(uint256(0x217ce15552a2fd1d3c423ce075c42ae4ca7765aa5dd2878ab9e2f20d657689fe), uint256(0x0f9e66bdbb8326a86c5b54bcfa8a614caf8f4e0fedaa4a346742c530e8690206));
        vk.gamma_abc[299] = Pairing.G1Point(uint256(0x2039f3055a1486573739550e22aa788e312adcde7083d52cfd1b707455a0bd55), uint256(0x069dae2c491cc09874131bb481290d6c27544340a4ff1c4f397fc4887091213d));
        vk.gamma_abc[300] = Pairing.G1Point(uint256(0x1c29962f324b070b41c078df0e536c7acf121ac046ee168020aa0e4e03ec124e), uint256(0x2235e7ce01fd1cf055bb30b14939d9b3083ca47ce5798c822fdb3ebb53c03eaa));
        vk.gamma_abc[301] = Pairing.G1Point(uint256(0x0b80b095c42a75b2b329d2144758e96c3fb3e30cf1fa621ad0a0df1badc46bf5), uint256(0x0ad613a2a7ef69139b6322261d12cc58fae2455be06ceaef131cb35b55bb6157));
        vk.gamma_abc[302] = Pairing.G1Point(uint256(0x1e37ee61c6738a06789aae0bd60f6b1a404c18feb34431594810bfac0f85df8d), uint256(0x2098d304c669eb93b620df6e6ab7f389a33309abb3024e6cb84375edceb802df));
        vk.gamma_abc[303] = Pairing.G1Point(uint256(0x16bb73f3782892c8a5c6f7c46297d6885aa08972aeb7371301e0bf04c69eef0b), uint256(0x0ddf07765dcfc60bd7d894f181886c374552573c2f5556ffd705e77bca060ffb));
        vk.gamma_abc[304] = Pairing.G1Point(uint256(0x05625b559a984024a169af37a1110d0dc290cf4198a3df86f06948e9d02c155d), uint256(0x0a2f93f905b710b5f7ccef053722bc0533366c52ac4f444fcbb91b10e4fd18c1));
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
