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
        vk.alpha = Pairing.G1Point(uint256(0x22e176910d6b3c9e12142034b6b827ee2e17408e7d3ed70d1fc5c6de3e2c7a44), uint256(0x2ad08e440c82fe5835e33c99fc0ee32a48d7c0302dc93749feaef5d943a922f6));
        vk.beta = Pairing.G2Point([uint256(0x19e689fd21cc3f37d3cffd30fe46644ec43cb19f5c5d28bfd1b44caaf3d0eca0), uint256(0x22f5c0c4edd6940494c36aec30f131f47af765416dd04702e992c75a84985f71)], [uint256(0x139160aa08f2f8f396cfbe97f385c89916a157e110c98bd9f28c4979bfd5d5e3), uint256(0x0076122e5fbb2710648848ef94559d1b35814953811234bc5b09d86cb19ce5c3)]);
        vk.gamma = Pairing.G2Point([uint256(0x134d1e36c25960e389ccb67ce75c8067096eb246fcf746c0c41ade162d5a9fdd), uint256(0x0262e93712c235093306c1175bddc6a06591df5527a3b09b98f97874e86dbff6)], [uint256(0x1d82f8709e1bf814861355cb6cf124277a9b50a565afbbe7ba7978c4d45859f5), uint256(0x2545aeebb1054b2c3daf6d8596d3502a083938996986b09116597c0ed731fb7a)]);
        vk.delta = Pairing.G2Point([uint256(0x221ed0357d90c68aeaea6c8775776946131ef9485e734476ebd34b322784c33f), uint256(0x11f4a2a4237c3e5583f8ceeb89802080eca285135abb8ac44385ee389258347b)], [uint256(0x2727f580f7cd3b264f8589e0b5cec0a6fdbf9477ab164768ebe3e7ac19b2f881), uint256(0x118467a8a0a718795b4c58b4348881b4a33744548acc4e6115aa8224149d0759)]);
        vk.gamma_abc = new Pairing.G1Point[](62);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x20ee152b002f415090a79df5727e7c3d797bddbe8f48ca895b9245dcdb12433e), uint256(0x0f9eae5b53e1f22d9c2148617904abee04877b4a8139e41982cf549d2520de06));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x29cd95ad53d2d3f811bad2ac9dfd9a61aa4977c0e21f8a701c74ab2cbee3ba09), uint256(0x15b63a4a3a2a6964ba80fdecce0cbc5d6bde718c5892eebc62483a061b7ca971));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1a520677a39f7b64f512bc586e0ceb6b28d4ca45b59d72d79c3c9fb080411a32), uint256(0x0c00ab1a8489420f33e1c4927888440c845420c7e220f89c65f458b55180e120));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0f4d35e6e591bc3efb44a18fbecb8dd2cf19edd524e376afd6e63e1f835bc34d), uint256(0x24f45455961923cadfa267001e4f616edfe4ae7a82d980240373f0e246d7bff5));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1f8987487e022e0f6b13ec6a7fc5ca6cbcd3fa887abc7c41022cfa4ee35edf2c), uint256(0x28525ca83beca293798be459f4729db01cddab52f619eb9c04804f55d84dc784));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x19d68668f3a20641cf87fa4933a2a2a97c94dc495d4588c067bca26cd6d57566), uint256(0x0741c4d9b9215f5531e7edba6fb14c60da3f46d923e1ae308f2bbfb9a0766edd));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x11d410d3195ffe1852938b99688f532864e6f1abafde9eb1d028d1fec4aabe08), uint256(0x0e5651ba6526b84461fca8cf6b9cab7ee6197a5a269bab4eba939bfbb5d84e3e));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x21e85afeab8658a6414572e64ab7a5cced40107dc3b5af0a3ae980307a03eea3), uint256(0x24ef430e6bdbc134d0dec4ce21734ec0ac13522a42439f9b0dc1fede2708de69));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x10202e270ee40b92df64ea27920430e4f2e8108a0e1552accaf61d6e3e438aef), uint256(0x219c4295c800f40e952de4b84bb0e4bacdf8bf270301ab5a2c60fa114ed0ebee));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x03709bb190153b23a4f4920c36e8cc0d614e84fec5e10f70b41d58c097b6f93b), uint256(0x1dc78a7aba1d73c8c31215c8d042ecaf732dba361cd4474d33421e0aef12e267));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0c1ab2e61d48513db200c4580ba68faf38d221a60247d15f9179735623c34dde), uint256(0x0fa85cf9e12faa1f0aa99922c8d9bcb5d2389e5734a2901fc4804071797240da));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2451a384ce4b52b6cb0d0140c8de81f2f823698376c141aead714d15ed14ca4f), uint256(0x09bf0b41dfe97db215425e3b0a4aa899acd798c352d3ff539d97b2cf4a9e6b59));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x09a611efeae789c5751992ddab51a3235f70c985d376e7364995ced49d26fb33), uint256(0x15438f0b9ccb65c548449160850ca57f7604520291745ca1470ad28c35371cbf));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1880d85734579f591211884e00eebd2c1e67d5356e63c70d84f612af13b33763), uint256(0x09341a8b9c2c1a8d192c884a41dee16d6e6a71a3331e2a87033c89b162c94903));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x18f3e7091ebe2baf4f2dbd4160a667fbf1ae194fca03c946aa7536e1b3274bbf), uint256(0x0b3c60c454f72044f0046d20c41c0f120f2abc9ccc97f9c85040b3b0f44e28f4));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0c3b618165b879a3470b11dc7a31277fdd7378167f52339eed2857954f9dc645), uint256(0x1f9da914145be6485363b814764349307b9fdcc2c1535c6d728c99ab2177ce47));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x09995ad65ea41ef7353a9d225e03935e714af5222ffd7e14b2b78fffbe535236), uint256(0x29d9f3229781979aace0af1d59045c2deac7053eadb5c61831da2e43fc3e5283));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x170152184c4b2246f63feb98ca3c75a344f05fa6337d97329aac13abb5c253f2), uint256(0x11369b552cf3c90e6cb190f0f122f281aff37586c8103bbfc4e5dc75d1cf6385));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x039c0f08ec7da6909277a7b9ab1c39bd4e74029c9ae6a29a72bf8d97eb38758b), uint256(0x2e35229e8bc4f1ae002fece0793ac1577fbcccd00874d806680dd05c72391420));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2af979216e95878c449bf4a95cae7bc354790a6405de80fd0da3651fb993b5d2), uint256(0x2b11b9df956e6fcc4ffcf9a37f7f0fda4bc11ba79c55e1be4f1f416d5d5c180b));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2c48a4046aabc44c7a3fddbf972f8551261ca5e00fa28f6c6ec8e2b0da1b4a9e), uint256(0x3057a52533f9725ea2d4270f52cbcab756297fb5ec0c24f08215ddedead9ab7f));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x2e761c0d8cf4eb8c8332a4fdfd6ee54edb8ff577c7990423d8498f46224acb80), uint256(0x04e17dad1589f6fad2f1c8acde9449acecb33e7e2a3e7d0f7f1f2bf7d5b52625));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x24d0e442a9b4381c0c0e823e1616facb4a8a529dfdb9186247207f8a97d3c939), uint256(0x2c1271e48d399865fb399eb3623e6b87a8d41282e1b0f5aebccb880887a51e46));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2f7f1c14864ba19bfb1acb2ff9d64ce6afe24ab4e36dc6a53036d0bdacef0a5d), uint256(0x01c0c0ef11c4ad0c1fc80d1e5237c07e6fbbb27363d7fc8803341353e3950b27));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x25dc7d9b704c4fa165dc2a0ccae3c3e901d63490b0b3e08f99b1f3771ac23341), uint256(0x2def8cec7b1db95b6174ca5decb8151a5470c58da36aae4a8ec5f43d9db25798));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x1fccb5c4f9cb2c691fd423c4b8eec6f57f57505eef78bb954d98d54e89ed6bf8), uint256(0x22a0108a0fdeeb18e00ac3e99120fa1a9e520e4b6bcee317da8a7f7f17ab333d));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1c46b2fd89b6df89aed5a5929f49d11ec5ba57ebcd414397c052980d46963713), uint256(0x036580e53a42ed4303c7c43773f28d2b5a32a2614489f6cefea05e99355ce814));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x064c5f10a381e10562388d5a45cfeef1e22bd1180755536b7ff8be9be3efc9dd), uint256(0x2c1b1593c9dcdf85818e63b897b1333f5a0bbd17f3c890291a8e0e22847fd599));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x1cfd33675cef5aa112289531ff084a3af0ba65ffcbac8619de25bf6c93b8c605), uint256(0x1dbc37096e236b542360e3307c575f65235c1a93c38802b0446a034ce6655b3b));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x0895353dc3060e41ab005ebc6de2eccd6477bd436e76a7a2597011426241a10b), uint256(0x1d4f4bce7b84410289280973f503b912c826acfdd18f4107d3d26beadd536c0d));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x27c6a1bc75b965564111bd7f68ad45d019627b68c0dcca77a0068d11ba06c8c0), uint256(0x208c2df62a9ce1cc696d08e3b01b5a95a582942409f68c40280b1ce76e20f67a));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x161839aef7794014fe9b3ba7f9669373ba05ef70cbeae281d7c0c4713ad6e8d9), uint256(0x2503b1af0c3c90178640a6c92d8dbbbcd5392a3a2963404fba27f121f7b0fd08));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x2d4b6532932870b64ca00efe283dc1c4aa159c7918276a2f216e5aac9440d565), uint256(0x0af2ad2af9f56236816dc2726fcb68ea01d87a9c18e1e616a84ba55b095ee035));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x16ad6208e824b6f958963776815fecd8c280db5bc2cdd3157247ab797e1c9974), uint256(0x0f5d78859f979564483ee4bd572f0fee7413c1f29530dc8a6fab26263c6952cc));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0a30329d989469d0888dd0987e39c6160a6b9bbe7aa3a2360b263265b83415d0), uint256(0x10ee24f9c7345c17629f7d04f720fdf4dedfab4cb8670ed88600f084dc42d3ea));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x090e68ed746693559beefd5c9e549317276db445efc731a425045bb5e5dbcc4b), uint256(0x041241ec59590775891f29d58c5d04effada6295d723af59aabf03af746de2fe));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x0abe077a8c86b2588f33d9902a485d1bb2e541f4890a82402c1254646013c2e0), uint256(0x2befea93516576da6edca93fe47f73d484d3f3be58a43d3c2d707c3defa52c92));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x1c32ac57daa56db7f1460364d2a03f0e8aeebcd47d7a5da0c66905ed3cd46f74), uint256(0x1579ea895818895b7b428b59a2936cb3227880b414a82edd3eab7902c9906c27));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x19cf0a3f2f9195ed5d04a8c798d8ba186380013f07e57f0b5b4078f00ccd0bd3), uint256(0x27e70e762ccee8bf0e699105f76291b6527d6af2beefe8e5f3921711a5effc19));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x01b27a606ae928c6295f7f13841de84ce8956d23e512c259ab4e0a7d452f3474), uint256(0x0449d11c7130ee2142b71d1bbcfa54fab44f9fe876afb98ee04aa6a3a1c27c48));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x04caa62b6ad71fd82745f620bf9481dc4856ddad4a001e897aa3f1143c0e3542), uint256(0x02fa7ad8fdbbb4c37dc5a3439a9670e127732da91d68917f9a7442b5774b2476));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x0d79db78d91ed6fd5b2e54026076cc17779aeef571b0d00d129e318b83307470), uint256(0x21ab3da1d4b633c240939b76da15eb5a47dde753d3723093fb961a05188e217c));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x1a19d8d51bfa9d80e91f0d4b8b2112d3e67dabd3cfe3b92e071cadfeb7602a4b), uint256(0x17af80488ac0a0930d6d694b60574149629cad9b9ea1bf62322ca6d34d4126f2));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x18cc6debc3aaaaf6a88b5fc0347208a44e6fe31b14a41e712dc6dcf43480c987), uint256(0x1fee4ad5112f9000e15d2c0440c47f2aa9bea7200510f783de6ce8bd582cb7ae));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x0b6657a3bdbbc8b501c6f066948c3ed9bad0ae6b0855eca9452bf0a212d4c7ba), uint256(0x10d5bb3ae107ca656e2b365b7fa6edf8fdb2c42b75ecfc7c9a9f13f75f1feb9f));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x0997aa0bf7e4a6f7b3cd012cea724f4697a3e897b049b2bce00ff5e93c06037e), uint256(0x19a0ad32146e6e919d87266bc1824f56120ec31494d135b9a1bc54031442ff45));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x24e60c0e65ed9e42c6d0f1dbc7ecda9d4ec916251137b6c29725588b3981e6be), uint256(0x1a01b771899dfea5c56c797c4fa7e7e862999e0a50fabda04f7214415ef4f179));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x034f110b267ce8367be193bb3b142737b3551e95dba86f909188a6f79f81817b), uint256(0x0046fb32875c33b1c5dec7726ba9d20656a6796710f49bbe5efe9fec2ccdf211));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x1af0ad56d2f453c7a7c331504b94998fc554fa84891d87651fbb22066f4ca017), uint256(0x2bfcadab28502a3651f5f32f5d59c2674a1dc6ba1a86227b191a3fec6f216480));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x25f11811a0a4eceae075356eedff35dadb8f049198139629b23dd85799c5e3fb), uint256(0x0ce2614263c5cbd2ce1b67c2da76ec4c4b1118e99693589e08e180990111c54a));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x29b060e6408e1ae5fefce60783475bea63344f4f9e1f080142617400d416020e), uint256(0x23d5074e5cf4b3fc6d7507eb35cc5b45a90b223561ade1dc93ad864f6e773bc5));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x1328c41469cbf3d4c7cf5a9595c4036c9802e97b7a03c2ef79bc3c749ce6f2c1), uint256(0x2af82da31974b62d7087cbe7ed2500621fd3181c37fdf09b821b2ad2f4b0b6ac));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x2a9df1d6b781ee25fe2e8b29222b0eb741deef59b42a6430f6f22e615b833353), uint256(0x07c0e5bc669f649bae4e8c18acb1ca9a53bcf8cc43f6e54cd14ca19d42106876));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x0d4f5a55726310e09440828e38f5d52a76e3b680c32fd6284b0178e6d92ef4fd), uint256(0x0ab1120f1d32c5cc3f18f8ac28950aa70caa0d6bdcdf1904b241d7c1bd690e09));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x13b101efe26a6a9104b37e6cfbd4dbb0eedd3de2ae43b31afc3703e655e62b8d), uint256(0x0e699a656f2d8bd81ec417a42a70faaaa6de4185f352f73a59e19391a0997871));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x141352d5ca96a1f2e450ccd2cd4342f4c1b4e472aa970fb1ae564ac713cb645f), uint256(0x1c9cddcd2bfd32d0021346db8f29178b00168d85494869fe02ea569f8f12c7ae));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x26f8f0de23ed212159ed12b27b7ce2e1b264315127f7baade872f6c054661a37), uint256(0x29cc5aa7fb1b35a795c42a57e2bf6ce6323aa3845fd7aaf47a8841f157bedab5));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x0b4c2e16b1be041a9680c1d615c6db4f7be2d227fcca01b8e82e1d40a019705b), uint256(0x2157083e25984ff65d090f2f16f459991e30d8c7adb35079c4a612f37e918c4a));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x11942f86583ff533b6b73ace86d58d7a43d93253301b5ea6141582ad0f6267a3), uint256(0x0a9c134b5c8d621716ea61a6dde9453e819a0ad48500863942ec5ab9a1fad7e9));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x0b07673b03a5659af370c4f18db8f9bf3944c1cad5036a995ef3c2d6cd417fba), uint256(0x08326ed808100669fc08e23cc02678736fd9770fd1c5a69e44cc7cc0d151176e));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x1a2f067ec7ed2156e8b849aa21d391d8b07efb3b1fc675d6adcee5c6a3264954), uint256(0x001996c7a9eb6410461279ca64e7fabf2b263a8d57a38b4f5906d3a868762b92));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x0698edecac0a815d35865970da826dc87bf21b52617e66e333e143048a3cd619), uint256(0x106ebcfa738019ea4c9ba618915a206a15fe1059bc565a3b8df27cd733b7e3ca));
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
            Proof memory proof, uint[61] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](61);
        
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
