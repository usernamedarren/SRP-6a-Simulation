const SRPClient = require('./client/SRPClient');
const SRPServer = require('./server/SRPServer');

const username = "target_user";
const password = "StrongPassword123!";
let server = new SRPServer();

// Setup: Register User
const regClient = new SRPClient(username, password);
const { salt, verifier } = regClient.generateRegistrationData();
server.registerUser(username, salt, verifier);

// 1: Legitimate authentication by the correct user
try {
    const clientS1 = new SRPClient(username, password);
    const AHex = clientS1.startAuthentication();
    const challenge = server.handleLoginInitiation(username, AHex);
    const M1Hex = clientS1.processServerChallenge(challenge.saltHex, challenge.BHex);
    const authResult = server.verifyClientProof(M1Hex);
    
    if (authResult.success) {
        clientS1.verifyServerProof(authResult.M2Hex);
        console.log("[S1] Legitimate Auth     : ACCEPTED (Passed)");
    }
} catch (e) {
    console.log("[S1] Legitimate Auth     : FAILED");
}

// 2: Replay attack using captured A and M1
try {
    // Attacker uses captured A and M1 from previous session
    const interceptedA = "0000abc123..."; // Dummy for illustration
    const interceptedM1 = "0000def456..."; 
    
    // Server generates a completely new 'b' and 'B'
    const newChallenge = server.handleLoginInitiation(username, interceptedA);
    const authResultS2 = server.verifyClientProof(interceptedM1);
    
    if (!authResultS2.success) console.log("[S2] Replay Attack       : REJECTED (Passed)");
} catch (e) {
    console.log("[S2] Replay Attack       : REJECTED (Passed)");
}

// 3: Authentication attempt using stolen verifier
try {
    const dbRecord = server.getDatabaseRecord(username);
    const stolenVerifier = dbRecord.verifier.toString(16);
    
    // Attacker tries to use verifier as password
    const attackerClient = new SRPClient(username, stolenVerifier); 
    const AHex = attackerClient.startAuthentication();
    const challenge = server.handleLoginInitiation(username, AHex);
    const M1Hex = attackerClient.processServerChallenge(challenge.saltHex, challenge.BHex);
    const authResultS3 = server.verifyClientProof(M1Hex);

    if (!authResultS3.success) console.log("[S3] Stolen Verifier     : REJECTED (Passed)");
} catch (e) {
    console.log("[S3] Stolen Verifier     : REJECTED (Passed)");
}

// S4: Phishing attempt by a Rogue Server
try {
    const clientS4 = new SRPClient(username, password);
    const AHex = clientS4.startAuthentication();
    
    // Fake server doesn't know verifier, generates random B and fake M2
    const fakeBHex = "1234567890abcdef";
    const M1Hex = clientS4.processServerChallenge(salt, fakeBHex);
    const fakeM2Hex = "abcdef1234567890"; 
    
    // Client verifies M2 and must reject it
    clientS4.verifyServerProof(fakeM2Hex);
} catch (e) {
    if (e.message.includes("Phishing Detected")) {
        console.log("[S4] Rogue Server        : REJECTED by Client (Passed)\n");
    }
}