pragma circom 2.0.0;

include "../../circuits/MerkleTreeChecker.circom";
include "../../circuits/eth-addr.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/pedersen.circom";

template AddressHasher(){
    signal input address;
    signal output hash;

    component addressBits = Num2Bits(256);
    component addressHasher = Pedersen(256);
    addressBits.in <== address;

    for(var i = 0; i < 256; i++){
        addressHasher.in[i] <== addressBits.out[i];
    }
    hash <== addressHasher.out[0]
}

template VoucherHasher(k){
    signal input address;
    signal input privkey[k];
    signal output voucher;

    component addressBits = Num2Bits(256);
    component privkeyBits[k] = Num2Bits(64);
    component voucherHasher = Pedersen(512);

    addressBits.in <== address;
    for(var i = 0; i < k; i++){
        privkeyBits[i].in <== privkey[i];
    }

    for(var i = 0; i < 256; i++){
        voucherHasher.in[i] <== addressBits.out[i];
    }
    for(var i = 256; i < 320; i++){
        voucherHasher.in[i] <== privkeyBits.out[0];
        voucherHasher.in[i + 64] <== privkeyBits.out[1];
        voucherHasher.in[i + 128] <== privkeyBits.out[2];
        voucherHasher.in[i + 192] <== privkeyBits.out[3];
    }

    voucher <== voucherHasher.out[0];
}

template Voucher(n, k, levels){
    assert(n * k >= 256);
    assert(n * (k-1) < 256);

    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal input privkey[k];
    signal input voucherReceiver;

    signal proverAddr;
    signal proverAddrHash;

    signal output voucher;

    // check that privkey properly represents a 256-bit number
    component n2bs[k];
    for (var i = 0; i < k; i++) {
        n2bs[i] = Num2Bits(i == k-1 ? 256 - (k-1) * n : n);
        n2bs[i].in <== privkey[i];
    }

    // compute addr
    component privToAddr = PrivKeyToAddr(n, k);
    for (var i = 0; i < k; i++) {
        privToAddr.privkey[i] <== privkey[i];
    }
    proverAddr <== privToAddr.addr;

    // compute addr hash
    component hasher = AddressHasher();
    hasher <== proverAddr;

    // check hash along with merkle tree
    component tree = MerkleTreeChecker(levels);
    tree.leaf <== hasher.hash;
    tree.root <== root;
    for (var i = 0; i < levels; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }
    //merkle tree check doesn't have outputs
    //or it works or not

    component voucherHash = VoucherHasher(k);
    voucherHash.address <== voucherReceiver;
    for(var i = 0; i < k; i++){
        voucherHash.privkey[i] <== privkey[i];
    }

    voucher <== voucherHash.voucher;
}

component main {public [root, voucherReceiver]} = Voucher(64, 4, 20);