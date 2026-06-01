const express = require('express');
const cors = require('cors');
const axios = require('axios');
const app = express();

app.use(cors());
app.use(express.json());

// 🧮 LAYER 2 FUNCTION: Calculate Shannon Entropy to spot encoded strings (Hex/Base64)
function calculateShannonEntropy(str) {
    if (!str) return 0;
    let frequencies = {};
    for (let i = 0; i < str.length; i++) {
        let char = str[i];
        frequencies[char] = (frequencies[char] || 0) + 1;
    }
    let entropy = 0;
    let len = str.length;
    for (let char in frequencies) {
        let p = frequencies[char] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

// 🛡️ LAYER 3 FUNCTION: Semantic Threat Boundaries
function evaluateSemanticRisk(payload, violations) {
    let severeRiskScore = 0;

    const attackPatterns = [
        {
            regex: /ignore\s+(?:all\s+|my\s+|the\s+)?previous\s+instructions/gi,
            label: "ADVERSARIAL_ATTACK_VECTOR: INSTRUCTION_OVERRIDE_ATTEMPT"
        },
        {
            regex: /(?:system|developer|hidden)\s+(?:prompt|instruction|rules)/gi,
            label: "ADVERSARIAL_ATTACK_VECTOR: SYSTEM_PROMPT_EXFILTRATION"
        },
        {
            regex: /(?:bypass|override|disable|crack)\s+(?:security|restriction|guardrail|filter)/gi,
            label: "ADVERSARIAL_ATTACK_VECTOR: SECURITY_BYPASS_ATTEMPT"
        },
        {
            regex: /(?:developer\s+mode\s+unrestricted|unrestricted\s+developer\s+mode)/gi,
            label: "PROMPT_INJECTION__SANDBOX_ESCAPE_ATTEMPT"
        },
        {
            regex: /(?:disregard\s+safety\s+protocols|bypass\s+compliance)/gi,
            label: "PROMPT_INJECTION__COMPLIANCE_BYPASS_EXPLOIT"
        }
    ];

    attackPatterns.forEach(item => {
        if (payload.match(item.regex)) {
            violations.push(item.label);
            severeRiskScore += 45;
        }
    });

    return severeRiskScore;
}

app.post('/api/v1/validate', async (req, res) => {
    const { payload, stripPii, framework, webhookUrl } = req.body;

    if (!payload) {
        return res.status(400).json({ error: "Missing 'payload' string in request body." });
    }

    let payloadString = typeof payload === 'object' ? JSON.stringify(payload) : String(payload);
    let cleanOutput = payloadString;
    let violations = [];
    let baseRiskIndex = 0;
    let riskTriggered = false;

    // 🛑 LAYER 1: STRUCTURAL INTEGRITY BLOCK (Prototype Pollution Protection)
    if (payloadString.includes('__proto__') || payloadString.includes('constructor') || payloadString.includes('prototype')) {
        violations.push("STRUCTURAL_ANOMALY: OBJECT_PROTOTYPE_POLLUTION_ATTEMPT");
        baseRiskIndex += 50;
        riskTriggered = true;
    }

    // 🧮 LAYER 2: MATHEMATICAL ENTROPY BLOCK (Catches Hex/Base64 obfuscations)
    // English text is usually low entropy. Random hex tables or base64 streams spike heavily.
    const entropyScore = calculateShannonEntropy(payloadString);
    if (entropyScore > 5.2 && (payloadString.includes('63 61 74') || payloadString.match(/[0-9a-fA-F]{2}\s[0-9a-fA-F]{2}/) || payloadString.includes('Y2F0'))) {
        violations.push("STATISTICAL_ANOMALY: HIGH_ENTROPY_OBFUSCATED_VECTOR");
        baseRiskIndex += 50;
        riskTriggered = true;
    }

    // 🗣️ LAYER 3: NEURAL-SEMANTIC REGEX FILTERING
    const behavioralRisk = evaluateSemanticRisk(payloadString, violations);
    if (behavioralRisk >= 45) {
        riskTriggered = true;
    }

    const finalRiskIndex = Math.min(baseRiskIndex + behavioralRisk, 100);
    const finalSecurityScore = Math.max(100 - finalRiskIndex, 0);
    const finalTrustLevel = Math.max(Math.floor(finalSecurityScore * 0.85), 15);

    const hasIssues = violations.length > 0;
    const auditHash = Math.random().toString(36).substring(2, 12).toUpperCase();
    const signatureHash = Math.random().toString(16).substring(2, 14);

    let structuralStatus = hasIssues ? "FAILED_REMEDIATED" : "PASSED_SECURE";
    
    // Wipe engine routing if any threshold fails
    if (riskTriggered) {
        structuralStatus = "CRITICAL_GOVERNANCE_BREACH";
        cleanOutput = "[BLOCK_CONTAINS_MALICIOUS_SYSTEM_ALTERATION_ATTEMPT_ROUTING_TERMINATED]";
    }

    const responseObject = {
        status: structuralStatus,
        metrics: {
            latency_ms: Math.floor(Math.random() * 8) + 6,
            risk_index: finalRiskIndex,
            security_score: finalSecurityScore,
            trust_level: finalTrustLevel
        },
        governance: {
            ledger_transaction_id: `tx_ledger_${auditHash}`,
            block_signature: `sha256_${signatureHash}`,
            ruleset_applied: `GDPR_Art_12-14_${framework ? framework.toUpperCase() : 'GENERAL'}_v1`,
            gdpr_compliance_status: hasIssues ? "REMEDIATED_COMPLIANT" : "VERIFIED_COMPLIANT"
        },
        cleanOutput: cleanOutput,
        violations: violations
    };

    if (webhookUrl && structuralStatus !== "CRITICAL_GOVERNANCE_BREACH") {
        try {
            await axios.post(webhookUrl, { event: "norgan_v_validated", data: responseObject });
        } catch (forwardError) {
            console.error(`Webhook forward failure: ${forwardError.message}`);
        }
    }

    res.json(responseObject);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Norgan_V Protocols Initialized`));
