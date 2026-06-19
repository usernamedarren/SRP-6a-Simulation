const crypto = require('crypto');

// 2048-bit Safe Prime N (RFC 5054)
const N_HEX = 
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

const N = BigInt('0x' + N_HEX);
const g = 2n;

function H(...args) {
    const hash = crypto.createHash('sha256');
    for (const arg of args) {
        if (typeof arg === 'bigint') {
            let hex = arg.toString(16);
            if (hex.length % 2 !== 0) hex = '0' + hex; 
            hash.update(Buffer.from(hex, 'hex'));
        } else if (typeof arg === 'string') {
            hash.update(arg, 'utf-8');
        }
    }
    return BigInt('0x' + hash.digest('hex'));
}

function modPow(base, exp, mod) {
    let res = 1n;
    base = base % mod;
    if (base < 0n) base += mod;
    while (exp > 0n) {
        if (exp % 2n === 1n) res = (res * base) % mod;
        base = (base * base) % mod;
        exp = exp / 2n;
    }
    return res;
}

function generateRandomBigInt() {
    return BigInt('0x' + crypto.randomBytes(32).toString('hex'));
}

const k = H(N, g);

module.exports = { N, g, k, H, modPow, generateRandomBigInt };