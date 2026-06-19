const { performance } = require('perf_hooks');
const bcrypt = require('bcrypt');
const SRPClient = require('./client/SRPClient');
const SRPServer = require('./server/SRPServer');

const ITERATIONS = 1000;

function calculatePercentiles(latencies) {
    latencies.sort((a, b) => a - b);
    const sum = latencies.reduce((a, b) => a + b, 0);
    return {
        mean: (sum / latencies.length).toFixed(2),
        median: latencies[Math.floor(latencies.length * 0.5)].toFixed(2),
        p95: latencies[Math.floor(latencies.length * 0.95)].toFixed(2),
        p99: latencies[Math.floor(latencies.length * 0.99)].toFixed(2)
    };
}

async function runBenchmark() {
    const username = "benchmark_user";
    const password = "StrongPassword123!";

    // BCRYPT BENCHMARK
    let bcryptClientLatencies = [];
    let bcryptServerLatencies = [];
    const storedHash = await bcrypt.hash(password, 10);

    for (let i = 0; i < ITERATIONS; i++) {
        // Client Side
        const t0_c = performance.now();
        const payload = { u: username, p: password }; 
        const t1_c = performance.now();
        bcryptClientLatencies.push(t1_c - t0_c);

        // Server Side
        const t0_s = performance.now();
        await bcrypt.compare(payload.p, storedHash);
        const t1_s = performance.now();
        bcryptServerLatencies.push(t1_s - t0_s);
    }

    // SRP-6a BENCHMARK
    let srpClientLatencies = [];
    let srpServerLatencies = [];
    const server = new SRPServer();
    const regClient = new SRPClient(username, password);
    const { salt, verifier } = regClient.generateRegistrationData();
    server.registerUser(username, salt, verifier);

    for (let i = 0; i < ITERATIONS; i++) {
        const client = new SRPClient(username, password);
        
        const t0_c1 = performance.now();
        const AHex = client.startAuthentication();
        const t1_c1 = performance.now();

        const t0_s1 = performance.now();
        const challenge = server.handleLoginInitiation(username, AHex);
        const t1_s1 = performance.now();

        const t0_c2 = performance.now();
        const M1Hex = client.processServerChallenge(challenge.saltHex, challenge.BHex);
        const t1_c2 = performance.now();

        const t0_s2 = performance.now();
        server.verifyClientProof(M1Hex);
        const t1_s2 = performance.now();

        srpClientLatencies.push((t1_c1 - t0_c1) + (t1_c2 - t0_c2));
        srpServerLatencies.push((t1_s1 - t0_s1) + (t1_s2 - t0_s2));
    }

    console.table([
        { Scheme: "Bcrypt (10)", Component: "Client-side", ...calculatePercentiles(bcryptClientLatencies) },
        { Scheme: "Bcrypt (10)", Component: "Server-side", ...calculatePercentiles(bcryptServerLatencies) },
        { Scheme: "SRP-6a", Component: "Client-side", ...calculatePercentiles(srpClientLatencies) },
        { Scheme: "SRP-6a", Component: "Server-side", ...calculatePercentiles(srpServerLatencies) }
    ]);
}

runBenchmark();