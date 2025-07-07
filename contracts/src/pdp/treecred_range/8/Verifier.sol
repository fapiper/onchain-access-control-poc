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
        vk.alpha = Pairing.G1Point(uint256(0x265e51e541b8cf2c7e10f557641fb794d1284090d01d08d6f1e56c7cb3659c05), uint256(0x115e973f554893314952c59f6537eac276e6a38bbd3ac45e6ef22b07ab99d374));
        vk.beta = Pairing.G2Point([uint256(0x14a7ad526b8995560fdbca6d1a734b9ffbb049143f3f7654a24573bb0db3da11), uint256(0x1338eef727f710229d9a2b3c92801a451639229f857c8531a2e78fcb0d0d26b6)], [uint256(0x13b04714b78a2fe08aed6406c62bcf8c3ba368006d8a82aa06d11b3fe47df1d5), uint256(0x2e34c096bb2ceb14d2257e6679488a0cf5d1cbdcb81968b3803310844e0d1fa7)]);
        vk.gamma = Pairing.G2Point([uint256(0x2ff6deac4bdc399cca1091610a594429653b801201aa88d32f49209ec4318350), uint256(0x2ec57183738fe8c4043beec24871975bfcdf515e0203b33f74fe75651163f835)], [uint256(0x2b0006656bc89169ca2c5c254427ae9b567c290fe289e0b24821764b9472f6b2), uint256(0x26ab738698e99ecb7e72185c06fa0617d08412c4565ec5d22a856a4b44acd15d)]);
        vk.delta = Pairing.G2Point([uint256(0x09ec6f4bc193a479694e7f7775b8a67bab30f25ec466e849ab326012a2ab2b78), uint256(0x0e9885c925cbf5ee5ad687060288dc7f6ed01d80a8b74677c5bbd0805832e719)], [uint256(0x2020f6d9813f66e70c1b5c960f3282bc0ed4deca423aeeb190bb2bbd80d947ff), uint256(0x1146e4bd5ccaf6cebc5d96de4f76ef60c82f1fd516586b1465bd46b2e6aa5533)]);
        vk.gamma_abc = new Pairing.G1Point[](44);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x21ead4574e876b2c61aa2c81e3c6e8a7e53753f1dcaf42d153206196a7a31c9d), uint256(0x1cfab687bbe260f1c31c093dc443a7149d9452093b1d2eb620c0fd1d100f6483));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2bcb710070a555ccbf521db10b094374e6ec9e42ede5581de9ebc4562877cc70), uint256(0x295e8beb123652e2121118afbe1afe697b8faff460efcb42bfb4443e001959db));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x20f1968096b7625c3dc59c42f4098a26768ae0dafff442918486e1e4686a5c1b), uint256(0x2d1d86b74c4600457cb320fcaaf8d20f3ceb9ea9450ecd74b25f146ca886f067));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x20f22001f6727accdfdb7737cb818714d07415a33436565d9134a554c7d7c1ca), uint256(0x01b7eded7cdfa117406a1b4027f58ed93a66d9bf40b331b011027a28aeb577d4));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x01fa422139ce422bcb5a95bf46141a76ed3dfd4e2c86df155f19ded5ede76e53), uint256(0x116ea2a4f3fba0ed80922487769c71f562bb9c895a81db9553bf949e840e11e1));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x240c2779e168503a3294912f4c3833b040b92d5e986360c5735627695e27d295), uint256(0x184f6ae46462c82e2c003cbbdf80c0c44f9944bc60305299ca152acfb78683d8));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x06c811535094c84f3ad2676a70c461ad4ad93336346cd83ee43e929afc30cd75), uint256(0x0afdbbb82ff4e24a49aa2ca017f03c3815fd25ae7f34800f19030ff6d84bbb12));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2cd1b3dfc869c78a879a56350bd18b40d5dfc04f3f90b9d40cf2a1e9187f0adf), uint256(0x2d1e8d1c1474bc3b3651477f7601a68e28507384ca3940f571f2743bc3e52b78));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1419637396cc866b0d8c4be40bc5b42b03e6c319ea358998275d2bf8453b6118), uint256(0x06b01f818239b34065a5a6abd87c5e171908540675c2c29326dd0cf6edf84a5d));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x15ee0f45e2be2608de0b23e475d4a34ed9245660ebff7287b5c59fa09c04ed76), uint256(0x259512e1f10116e6c4450c66e96ec2b18c9db7c9078dfba0f76ad7ba9002c7f0));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1d100af493e5c2bbc28593a13dad584b93ccfc5f1ff95a333d82d9df29643e21), uint256(0x12db5e4495efd717983e0b3995a1f5db53d5da2316331b39d5171ea595cbebec));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2b10f505523c73f1d9416090a2f302ebd76e0eb0f194505855aa42f7134fd482), uint256(0x122207b1dc6d5913d4312c2adb21c654b2c68b6ed7585777d9dd99732b55cf95));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0360c1383d44b261268e63f759274a587e15ca4e6441e490d76e931269760862), uint256(0x071f6af0b0e7cbe659c2edc3e9ba47756164d134afd3b0e8cc1ee38394ec30d9));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0ee00036a3782f0d74da579e01f3eb2579a1bbfa3e7a4d412bb652a351ae3a1b), uint256(0x198f01323421e819767a9ffd351bdbd2b64471a6e35acf92c48ad24f45ebdb4e));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1f381d6133d15fa940934749f486896389ebd1e0b5365c59fb0e060a0ac7a8b7), uint256(0x1d9f94f31499a2661de7f62b69df4de73d14be6e7d16c950b9ae2931afd9dfc3));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0575ecaf274fd26e5cab0ad7ff836731068d8e88ac7ff77889a62a87986f4426), uint256(0x1428f46eef4aa4587156700c157306ee6dc8d08d12f41cfa8172ca663a1c3560));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x113aaa3dac84c82a591bd0cb6d7fef4b38089b8f7273387d86a4554da0573ce3), uint256(0x01ac119bdc50f332ee02f273cccad4fe048a6f24615a4ae6c6c2f6c6c1bfa2ea));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0603497dadc57cc51ad2bce81dd4d653b48420a1c1f8600a9c94c94256378a91), uint256(0x1ba4c1138c84e801edd5f5ddabf4378ff798b135b9ebb299a2dab1efe3e78015));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x256446cecbc6bfd046888b18ac0d4d7f99df5e0a39830d26560b11111eea389d), uint256(0x1d8f416921213f6def9f4f175f757d591ef9c1d3d1ba7026998b09506fbdacee));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x24f8b51f50b96cf173e336b2ba1efb107f07f65ca238b3c4fe46e5900c957f80), uint256(0x2866698c0db1a2a1ffda16413c2cd320ad6d9e2d7443d03f4303b47e9ea0b23c));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x02bf10d7c0e9407754dc5715de678898bb224bd9f9348eed39cd0e7eb33af363), uint256(0x24b346900e691d79f320b3302b0b9e9d224f4e96bdcda5dcf74c1cda89807632));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x0da3490ea406f0a5783cf9ce5e1fafe820a12ac5e365d449a5f754953dbb667b), uint256(0x0b2da72f7d396d74c020c1aa75151aa1f21d9b594740345d4297ed4eea86ce67));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x1a24ba86c2e07164b266d3c3d685a9b4a57877fa3a43ae56797a61ec017f6456), uint256(0x2f59d32b31098e36b8dc0fdb9d3ba3cb525627bd45cc40f8d6d1744bba418a32));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x107fc15f8d9b101b1e9067686ee11e16575734c08b54a94b240fc148e9fb8c4b), uint256(0x2d080f5ec402a61256a5f208ce774e3080a627366b353f5e7a49d805e290eac7));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x0652f5416b92e65b26af22dfa7c05fe633e93380ec828dd1ada00c4d28e6b600), uint256(0x2ce9f70579549a0dec6c2cb7f0d5fbecc4646483b8b4697cc8b919b15df6e47b));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x2f1df274b7b0152127b6cc5157cb0869907565af7f1c99174048feb51abe1375), uint256(0x1743a6185890c4d3727955b523e7638babe8b5fb3ca949ee2b34e8793de168ff));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x096e599c47a6cc94435fb81fc356505dbe1392f2a7ea9d5198c0539d7f2c7bdc), uint256(0x0e21d9e98286182a3f93b15a70c99ba996cc7a1912b0c366d89e62dc9e2f9a95));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2be7ea3c28cfe78bd632a991f73dc0e32ba9356b2b2bc06ba372b6989362643d), uint256(0x27d9b07a23a463a6c2c6c62582a1016404ca2559da925d68f69d598a2684cdb3));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x009078018c73dcc35be403abb394bfca895de46031b705978b47f546d4e5a7d1), uint256(0x22e7fccca87952dddda966c40e3cbf09c9cdfc7302c9ebab5f7b3b18b49a28b7));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x2f64f4cdc8f361984191d46e1fb76c6d36b9cdc58f2bf9fb93448e99dbd35959), uint256(0x2639cf39808c9499e4d073d53dc7870b1d15de78387a1b4fa82f7f2b130679f5));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1877f398ad9cff3b59b8bb0d753f1c72194a42fd03fa909600be1e1c883e2f9b), uint256(0x19bf5697bfcd65977bb9434b87655cd2afd5e14882b5fd355748a26c71ae9e8f));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x068ec653e4a2ec1a6e7e27d743d551be9707089e0cfe69b307f391990b612672), uint256(0x19233103d7a818d2944d7b3cf9c1f2c65925082ac1640e30323d32993cd0ed42));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x07374ae9ecf41ba85c985bdd2bdffa49c31752587cb67b2f6d9af715e459f1e1), uint256(0x29051dfc20d15f06830f0df4cb76047850fb98544057b12c5e80b54fb112ffdb));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x28ff94d6f56b4304472282786e2fcad7311ee3a3405ba47b99d522c1545a5923), uint256(0x26762304b7c88745aada25e3348c0dc5ef1a830213b94fd6e25c74bb61a2415e));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0686d2dbdd2454070370779e612fb8cb449fa93cb7e4fa7f4952d2698bde16f1), uint256(0x06727186be3b102e97f5b16f961c7a5ed7b32615e8253dd1e29ae1014c7a77ab));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x0d1f4b95b6588505306de9d5b4484846cccb323ec6022bdb31953a380537a112), uint256(0x114036f6eb503c420c500e72f6ad43a98e87a4060d9c21dffdb8362f36ec2dfc));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x16f8458cea2f68387663220ff843d41bf75a98d3a0f71b3b665bd3d8b096a298), uint256(0x189fb1db24e31727a4dc2f5555be354a00721be6ee7ab394277ffc9d6c89b08a));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x0a97eb30490a66fdc4d4b1949210838f2ced85ceddd392d11c17ac49fadfe9be), uint256(0x1578921155554bea530610535780f52ea387a8f71fba53a499a27c5fa36b1b42));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x20c8533ec9abd49610699e94bd2d8d87d70f84895362d0d7aa6f99d7c49eb7bb), uint256(0x0e587d1a02ac7437b270bff19fd5c510fb6bdd706fba569e75700749ec4cc0fa));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x2b73b05a3525be07fab57fdf16d83e1aa2e0e54854907621614604cce01b940c), uint256(0x18f7a0a199c9e92356b1ea8c2e217ce68d112bc60c241d23e03c319ce9cc6d8a));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x2cae77c879ba9c9ab759ba8544872e49e18e9061f2e2151a0e72ed0ee1ceebee), uint256(0x2b9cf49ee05246432d7aa4ec7e7936127b7991be7e3c59e14f399c84cac424df));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x06e84e3d4dc01692a7cf85e74b19fb94cf09f33e980f93ec6805edd40fca5786), uint256(0x1967aff1fc79ed6e881f373ec03acf366810d115e2173a96d6463a384f6c0022));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x211aac068e6c029747051505618ee58144b95340ee83170bfca0327da563cce1), uint256(0x10b17df3d6e604d2a42dc32f0086f40e9b25946598983783c4bdc9fb04873781));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x12cf803122f5c7ed987ba2bef5c1e6a09f116e1c315cf5eb712a1b5b23240c09), uint256(0x148f0255babf89ab7b1d84d8f6ccc7d15e26cc562112aedb83968ff5b37576f8));
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
            Proof memory proof, uint[43] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](43);
        
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
