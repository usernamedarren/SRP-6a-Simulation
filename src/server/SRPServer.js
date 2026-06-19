const { N, g, k, H, modPow, generateRandomBigInt } = require('../utils/utils');

const database = {};

class SRPServer {
    constructor() {
        this.b = null;
        this.B = null;
        this.A = null;
        this.currentUserData = null;
        this.sessionKey = null;
    }

    registerUser(username, saltHex, verifierHex) {
        database[username] = {
            salt: BigInt('0x' + saltHex),
            verifier: BigInt('0x' + verifierHex)
        };
        return true;
    }

    getDatabaseRecord(username) {
        return database[username];
    }

    handleLoginInitiation(username, AHex) {
        this.A = BigInt('0x' + AHex);
        if (this.A % N === 0n) throw new Error("A value invalid");

        this.currentUserData = database[username];
        if (!this.currentUserData) throw new Error("User not found");

        this.b = generateRandomBigInt();
        const v = this.currentUserData.verifier;
        
        this.B = ((k * v) % N + modPow(g, this.b, N)) % N;

        return {
            saltHex: this.currentUserData.salt.toString(16),
            BHex: this.B.toString(16)
        };
    }

    verifyClientProof(M1Hex) {
        const v = this.currentUserData.verifier;
        const u = H(this.A, this.B);
        
        const base = (this.A * modPow(v, u, N)) % N;
        const S_S = modPow(base, this.b, N);
        this.sessionKey = H(S_S);

        const expectedM1 = H(this.A, this.B, this.sessionKey);
        if (BigInt('0x' + M1Hex) !== expectedM1) {
            return { success: false, M2Hex: null };
        }

        const M2 = H(this.A, expectedM1, this.sessionKey);
        return { success: true, M2Hex: M2.toString(16) };
    }
}

module.exports = SRPServer;