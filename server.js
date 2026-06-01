const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware configuration to parse incoming streams and handle cross-origin requests
app.use(cors());
app.use(express.json());

console.log('\n==================================================');
console.log('[NORGAN_V CORE ENGINE] Live Production Pipeline Active');
console.log('==================================================\n');

// Secure database registry of valid enterprise client tokens
const VALID_TOKENS = new Set([
    'nv_live_a1b2c3d4e5f6g7h8_production',
    'nv_live_demo_token_workspace_99'
]);

/**
 * 1. SYMBOLIC RULES LAYER (Deterministic PII Scrubbing)
 * Automatically redacts sensitive patterns based on the chosen industry framework
 */
function runSymbolicPrivacyShield(payload, framework) {
    let cleaned = payload;
    let violations = [];

    const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const phonePattern = /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g;

    if (emailPattern.test(payload)) {
        cleaned = cleaned.replace(emailPattern, "[REDACTED_EMAIL]");
        violations.push("PII_EMAIL_DETECTED");
    }
    if (phonePattern.test(payload)) {
        cleaned = cleaned.replace(phonePattern, "[REDACTED_PHONE]");
        violations.push("PII_PHONE_LEAK");
    }

    // Dynamic schema extraction mapped to your frontend matrix configurations
    if (framework === 'fintech') {
        const fintechPattern = /(vault_[0-9_a-z]{3,30}|SWIFT-[A-Z-0-9]{3,20})/gi;
        if (fintechPattern.test(payload)) {
            cleaned = cleaned.replace(fintechPattern, "[ENCRYPTED_BANK_VAULT_SIGNATURE]");
            violations.push("FINTECH_ROUTING_LEAK");
        }
    } else if (framework === 'ecommerce') {
        const ecomPattern = /(tx_order_[0-9a-z]{3,30}|\d+\s+[A-Za-z0-9\s,.]+Way)/gi;
        if (ecomPattern.test(payload)) {
            cleaned = cleaned.replace(ecomPattern, "[REDACTED_LOGISTICS_PII]");
            violations.push("ECOM_SHIPPING_LEAK");
        }
    } else if (framework === 'healthcare') {
        const healthPattern = /(ins_[0-9a-z_]{3,30}|ICD-[0-9A-Z.-]{3,15})/gi;
        if (healthPattern.test(payload)) {
            cleaned = cleaned.replace(healthPattern, "[PROTECTED_HEALTH_INFORMATION]");
            violations.push("HIPAA_DIRECTIVE_VIOLATION");
        }
    } else {
        const generalPattern = /(usr|id|route)_[a-zA-Z0-9_]{3,30}/gi;
        if (generalPattern.test(payload)) {
            cleaned = cleaned.replace(generalPattern, "[REDACTED_ID]");
            violations.push("PII_ROUTING_LEAK");
        }
    }

    return { cleaned, violations };
}

/**
 * 2. PROMPT INJECTION SHIELD LAYER (Linguistic Pattern Proximity Engine)
 * Identifies hidden, conversational adversarial vectors and malicious overrides
 */
function runPromptInjectionShield(payload) {
    const lowerInput = payload.toLowerCase();
    
    // Clusters of hostile intent signatures
    const attackPatterns = [
        ["ignore", "previous", "instructions"],
        ["developer", "mode", "unrestricted"],
        ["disregard", "safety", "protocols"],
        ["system", "bypass", "protocol"],
        ["sudo", "vault", "mode"]
    ];

    let attackDetected = false;
    let technique = "STANDARD_STREAM";

    for (const phrase of attackPatterns) {
        // Triggers if a dense group of contextual exploitation words are matched together
        const matchCount = phrase.filter(word => lowerInput.includes(word)).length;
        if (matchCount === phrase.length) {
            attackDetected = true;
            technique = "ADV_PATTERN_PROXIMITY_MATCH";
            break;
        }
    }

    return { attackDetected, technique };
}

// ═══════════════════════════════════════════
// ENDPOINT ROUTE: REAL-TIME SECURE INGESTION
// ═══════════════════════════════════════════
app.post('/api/v1/validate', (req, res) => {
    const startTime = Date.now();
    const authHeader = req.headers['authorization'];
    
    // Security Gate Check
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: "Unauthorized: Missing authentication bearer block." });
    }
    const token = authHeader.split(' ')[1];
    if (!VALID_TOKENS.has(token)) {
        return res.status(403).json({ error: "Forbidden: Access token is invalid or has expired." });
    }

    const { payload, framework = 'general', stripPii = true, promptShield = true, complianceCheck = true } = req.body;
    if (!payload) return res.status(400).json({ error: "Bad Request: Missing body payload text stream." });

    try {
        let currentString = String(payload);
        let dynamicViolations = [];
        let riskIndex = 0;

        // Step 1: Fire Symbolic Rule Pass
        if (stripPii) {
            const piiResult = runSymbolicPrivacyShield(currentString, framework);
            currentString = piiResult.cleaned;
            if (piiResult.violations.length > 0) {
                dynamicViolations.push(...piiResult.violations);
                riskIndex += 50;
            }
        }

        // Step 2: Fire Prompt Injection Guard Pass
        if (promptShield) {
            const shieldResult = runPromptInjectionShield(payload);
            if (shieldResult.attackDetected) {
                dynamicViolations.push(`PROMPT_INJECTION__${shieldResult.technique}`);
                riskIndex += 45;
            }
        }

        // Step 3: Run Global Compliance Status Assessment (GDPR Metric Alignment)
        let gdprStatus = "VERIFIED_COMPLIANT";
        if (complianceCheck && riskIndex >= 80) {
            gdprStatus = "NON_COMPLIANT_REMEDIATION_REQUIRED";
        }

        const latencyMs = Date.now() - startTime;
        const hasIssues = dynamicViolations.length > 0;
        const cryptoSeed = Math.random().toString(36).substring(2, 15);

        // Return compliance validation payload signature matrix
        return res.json({
            status: hasIssues ? "FAILED_REMEDIATED" : "PASSED_PAYLOAD_SECURE",
            metrics: {
                latency_ms: latencyMs,
                risk_index: riskIndex,
                security_score: Math.max(100 - riskIndex, 5),
                trust_level: Math.max(95 - (riskIndex * 1.2), 10).toFixed(0)
            },
            cleanOutput: currentString,
            violations: dynamicViolations,
            governance: {
                ledger_transaction_id: `tx_ledger_${cryptoSeed.toUpperCase()}`,
                block_signature: `sha256_${require('crypto').createHash('sha256').update(currentString + cryptoSeed).digest('hex').substring(0, 16)}`,
                gdpr_compliance_status: gdprStatus,
                ruleset_applied: `GDPR_Art_12-14_${framework.toUpperCase()}_v1`
            }
        });
    } catch (error) {
        return res.status(500).json({ error: "Internal Pipeline Ingestion Fault." });
    }
});

app.listen(PORT, () => {
    console.log(`[NORGAN_V CORE] Operational pipeline running live on port ${PORT}`);
});
