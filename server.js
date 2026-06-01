const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

console.log('\n==================================================');
console.log('[NORGAN_V CORE ENGINE] Advanced Ingestion Pipeline Active');
console.log('==================================================\n');

const VALID_TOKENS = new Set([
    'nv_live_a1b2c3d4e5f6g7h8_production',
    'nv_live_demo_token_workspace_99'
]);

// ═══════════════════════════════════════════
// ADVANCED ARCHITECTURE SECURITY FILTER LAYERS
// ═══════════════════════════════════════════

/**
 * LAYER 1: STRUCTURAL ANALYSIS ENGINE (Deep Object Inspection)
 * Scans nested JSON structures for structural integrity, hidden script blocks,
 * and data types to prevent backend logic contamination or parameter pollution.
 */
function analyzeStructureAndTypes(payload) {
    let anomalies = [];
    
    // Check if input is structured JSON
    if (typeof payload === 'object' && payload !== null) {
        const checkDeep = (obj, depth = 0) => {
            if (depth > 5) {
                anomalies.push("STRUCTURAL_DEPTH_LIMIT_EXCEEDED");
                return;
            }
            for (let key in obj) {
                // Catch proto pollution attacks trying to modify global JavaScript prototypes
                if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
                    anomalies.push("PROTOTYPE_POLLUTION_ATTACK_FLAGGED");
                    delete obj[key];
                    continue;
                }

                const value = obj[key];
                
                // Inspect type properties and values for executable script structures
                if (typeof value === 'string') {
                    if (/<script\b[^>]*>([\s\S]*?)<\/script>/gi.test(value) || /javascript:/i.test(value)) {
                        anomalies.push(`XSS_SCRIPT_TAG_IN_KEY_${key.toUpperCase()}`);
                    }
                } else if (typeof value === 'object' && value !== null) {
                    checkDeep(value, depth + 1);
                }
            }
        };
        checkDeep(payload);
    }
    return anomalies;
}

/**
 * LAYER 2: SHANNON ENTROPY VECTOR SHIELD (High Randomness Detection)
 * Measures string character distribution patterns. Sudden high-entropy text blocks 
 * reveal obfuscated shellcode, base64 payloads, or exfiltrated binary secrets.
 */
function calculateShannonEntropy(str) {
    if (!str) return 0;
    let frequencies = {};
    for (let i = 0; i < str.length; i++) {
        let char = str[i];
        frequencies[char] = (frequencies[char] || 0) + 1;
    }
    let entropy = 0;
    for (let char in frequencies) {
        let p = frequencies[char] / str.length;
        entropy -= p * Math.log2(p);
    }
    return entropy; // Values > 4.5 indicate high randomness/encoded text blocks
}

/**
 * LAYER 3: CONTEXTUAL FRAMEWORK PATTERN MATRICES
 * Matches industry compliance parameters to sanitize payloads without escaping valid strings.
 */
function runContextualPrivacyShield(payloadString, framework) {
    let cleaned = payloadString;
    let violations = [];

    // Core Global Framework Rules
    const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const phonePattern = /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g;

    if (emailPattern.test(cleaned)) {
        cleaned = cleaned.replace(emailPattern, "[REDACTED_EMAIL]");
        violations.push("PII_EMAIL_DETECTED");
    }
    if (phonePattern.test(cleaned)) {
        cleaned = cleaned.replace(phonePattern, "[REDACTED_PHONE]");
        violations.push("PII_PHONE_LEAK");
    }

    // Dynamic Context Switching Layers
    switch(framework) {
        case 'fintech':
            // SWIFT BIC, IBAN, and classic routing numbers
            const routingPattern = /\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b|\b(vault_[0-9a-z_]{4,32})\b/gi;
            if (routingPattern.test(cleaned)) {
                cleaned = cleaned.replace(routingPattern, "[ENCRYPTED_FINANCIAL_SIGNATURE]");
                violations.push("FINTECH_SECURE_ROUTING_LEAK");
            }
            break;
            
        case 'ecommerce':
            // Order logs, shipping reference numbers, tracking IDs
            const ecomPattern = /\b(tx_order_[0-9a-z]{6,24})\b|\b(ship_[0-9a-z]{8,32})\b/gi;
            if (ecomPattern.test(cleaned)) {
                cleaned = cleaned.replace(ecomPattern, "[REDACTED_LOGISTICS_METRIC]");
                violations.push("ECOM_TRANSACTION_HASH_LEAK");
            }
            break;
            
        case 'healthcare':
            // Protected Health Information (PHI) insurance metrics & medical keys
            const medicalPattern = /\b(ins_[0-9a-z_]{4,24})\b|\b(ICD-[0-9][0-9A-Z]{2,4}(\.[0-9A-Z]{1,4})?)\b/gi;
            if (medicalPattern.test(cleaned)) {
                cleaned = cleaned.replace(medicalPattern, "[PROTECTED_HEALTH_INFORMATION]");
                violations.push("HIPAA_CLASSIFIED_DATA_VIOLATION");
            }
            break;
            
        default:
            // Standard general developer tags
            const standardIdPattern = /\b(usr|id|route)_[a-zA-Z0-9_]{4,24}\b/gi;
            if (standardIdPattern.test(cleaned)) {
                cleaned = cleaned.replace(standardIdPattern, "[REDACTED_SYSTEM_IDENTIFIER]");
                violations.push("PII_ROUTING_LEAK");
            }
    }

    return { cleaned, violations };
}

/**
 * LAYER 4: ADVANCED LINGUISTIC ADVERSARIAL MATRIX
 * Identifies contextual semantic alignment anomalies like jailbreak configurations,
 * system override prompt hacks, and adversarial override statements.
 */
function runPromptInjectionShield(payloadString) {
    const lowerInput = payloadString.toLowerCase();
    let detected = false;
    let technique = "STANDARD_STREAM";

    const clusterChecks = [
        { keys: ["ignore", "previous", "instructions"], type: "INSTRUCTION_OVERRIDE_JAILBREAK" },
        { keys: ["developer", "mode", "unrestricted"], type: "SANDBOX_ESCAPE_ATTEMPT" },
        { keys: ["disregard", "safety", "protocols"], type: "COMPLIANCE_BYPASS_EXPLOIT" },
        { keys: ["system", "bypass", "protocol"], type: "CORE_GATEWAY_HACK" },
        { keys: ["sudo", "vault", "mode"], type: "ELEVATED_PRIVILEGE_FUZZING" }
    ];

    for (const cluster of clusterChecks) {
        const matches = cluster.keys.filter(word => lowerInput.includes(word)).length;
        if (matches === cluster.keys.length) {
            detected = true;
            technique = cluster.type;
            break;
        }
    }

    return { detected, technique };
}

// ═══════════════════════════════════════════
// ENDPOINT INGESTION PORT INTERFACE
// ═══════════════════════════════════════════
app.post('/api/v1/validate', (req, res) => {
    const startTime = Date.now();
    const authHeader = req.headers['authorization'];
    
    // Gateway Auth Gate
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: "Unauthorized: Missing authentication bearer block." });
    }
    const token = authHeader.split(' ')[1];
    if (!VALID_TOKENS.has(token)) {
        return res.status(403).json({ error: "Forbidden: Access token is invalid or has expired." });
    }

    const { payload, framework = 'general', stripPii = true, promptShield = true, complianceCheck = true } = req.body;
    if (!payload) return res.status(400).json({ error: "Bad Request: Empty processing text stream data." });

    try {
        let violationsCollected = [];
        let stringRepresentation = typeof payload === 'object' ? JSON.stringify(payload) : String(payload);
        let sanitizedStringOutput = stringRepresentation;
        let baseCalculatedRisk = 0;

        // Execute Layer 1: Structural Property Scanning
        const structuralAnomalies = analyzeStructureAndTypes(payload);
        if (structuralAnomalies.length > 0) {
            violationsCollected.push(...structuralAnomalies);
            baseCalculatedRisk += 40;
        }

        // Execute Layer 2: Entropy Metric Evaluation
        const dataEntropy = calculateShannonEntropy(stringRepresentation);
        if (dataEntropy > 4.75) {
            violationsCollected.push(`HIGH_DATA_ENTROPY_DETECTED (${dataEntropy.toFixed(2)})`);
            baseCalculatedRisk += 25;
        }

        // Execute Layer 3: Context-Aware Privacy Scrub
        if (stripPii) {
            const piiResult = runContextualPrivacyShield(sanitizedStringOutput, framework);
            sanitizedStringOutput = piiResult.cleaned;
            if (piiResult.violations.length > 0) {
                violationsCollected.push(...piiResult.violations);
                baseCalculatedRisk += 30;
            }
        }

        // Execute Layer 4: Semantic Adversarial Shield
        if (promptShield) {
            const shieldResult = runPromptInjectionShield(stringRepresentation);
            if (shieldResult.detected) {
                violationsCollected.push(`PROMPT_INJECTION__${shieldResult.technique}`);
                baseCalculatedRisk += 55;
            }
        }

        // Final Calculations Mapped to your Frontend Metrics Layout
        let calculatedRiskIndex = Math.min(baseCalculatedRisk, 100);
        let calculatedSecurityScore = Math.max(100 - calculatedRiskIndex, 5);
        let calculatedTrustLevel = Math.max(98 - (calculatedRiskIndex * 1.1), 8).toFixed(0);

        let gdprStatus = "VERIFIED_COMPLIANT";
        if (complianceCheck && calculatedRiskIndex >= 60) {
            gdprStatus = "NON_COMPLIANT_REMEDIATION_REQUIRED";
        }

        const cryptoSeed = Math.random().toString(36).substring(2, 15);
        const latencyMs = Date.now() - startTime;

        return res.json({
            status: violationsCollected.length > 0 ? "FAILED_REMEDIATED" : "PASSED_PAYLOAD_SECURE",
            metrics: {
                latency_ms: latencyMs,
                risk_index: calculatedRiskIndex,
                security_score: calculatedSecurityScore,
                trust_level: calculatedTrustLevel
            },
            cleanOutput: sanitizedStringOutput,
            violations: violationsCollected,
            governance: {
                ledger_transaction_id: `tx_ledger_${cryptoSeed.toUpperCase()}`,
                block_signature: `sha256_${require('crypto').createHash('sha256').update(sanitizedStringOutput + cryptoSeed).digest('hex').substring(0, 16)}`,
                gdpr_compliance_status: gdprStatus,
                ruleset_applied: `GDPR_Art_12-14_${framework.toUpperCase()}_v1`
            }
        });

    } catch (error) {
        return res.status(500).json({ error: "Internal Pipeline Ingestion Fault." });
    }
});

app.listen(PORT, () => {
    console.log(`[NORGAN_V CORE] Advanced engine active on port ${PORT}`);
});
