const { N, g, k, H, modPow, generateRandomBigInt } = require('../utils/utils');

class SRPClient {
    constructor(username, password) {
        this.username = username;
        this.password = password;
        this.a = null;
        this.A = null;
        this.sessionKey = null;
        this.M1 = null;
    }

    generateRegistrationData() {
        const salt = generateRandomBigInt();
        const x = H(salt, H(this.username + ":" + this.password));
        const v = modPow(g, x, N);
        return { salt: salt.toString(16), verifier: v.toString(16) };
    }

    startAuthentication() {
        this.a = generateRandomBigInt();
        this.A = modPow(g, this.a, N);
        return this.A.toString(16);
    }

    processServerChallenge(saltHex, BHex) {
        const salt = BigInt('0x' + saltHex);
        const B = BigInt('0x' + BHex);

        if (B % N === 0n) throw new Error("B value invalid");

        const u = H(this.A, B);
        if (u === 0n) throw new Error("Scrambler u is 0");

        const x = H(salt, H(this.username + ":" + this.password));

        let base = (B - (k * modPow(g, x, N)) % N) % N;
        if (base < 0n) base += N; 
        
        const S_C = modPow(base, this.a + (u * x), N);
        this.sessionKey = H(S_C);

        this.M1 = H(this.A, B, this.sessionKey);
        return this.M1.toString(16);
    }

    verifyServerProof(M2Hex) {
        const expectedM2 = H(this.A, this.M1, this.sessionKey);
        if (BigInt('0x' + M2Hex) !== expectedM2) {
            throw new Error("Phishing Detected: Server M2 proof is invalid!");
        }
        return true;
    }
}

module.exports = SRPClient;