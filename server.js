require("dotenv").config()
const express = require("express")
const cors = require("cors")
const multer = require("multer")
const fs = require("fs")
const path = require("path")
const Groq = require("groq-sdk")

const app = express()
const PORT = 5000


app.use((req, res, next) => {
    if (req.path === "/analyze/file") return next()
    express.json({ limit: "10mb" })(req, res, next)
})
app.use(cors())

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY })

const upload = multer({
    dest: "uploads/",
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowed = [".log", ".txt", ".pdf", ".doc", ".docx"]
        const ext = path.extname(file.originalname).toLowerCase()
        if (allowed.includes(ext)) cb(null, true)
        else cb(new Error(`File type ${ext} not supported. Use .log, .txt, .pdf, .doc, .docx`))
    }
})

function readFileContent(filePath, originalName) {
    return fs.readFileSync(filePath, "utf-8")
}

function detectSensitiveData(content) {
    const findings = []
    const lines = content.split("\n")
    const loginFailures = {}

    lines.forEach((line, index) => {
        const lineNum = index + 1

        // EMAIL
        const emailMatch = line.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}/g)
        if (emailMatch) {
            emailMatch.forEach(email => {
                findings.push({ type: "email", value: email, risk: "low", line: lineNum })
            })
        }

        // PASSWORD
        if (/password\s*[=:]\s*\S+/i.test(line)) {
            findings.push({ type: "password", value: maskValue(line), risk: "critical", line: lineNum })
        }

        // API KEY
        if (
            /api[_-]?key\s*[=:]\s*\S+/i.test(line) ||
            /sk-[a-zA-Z0-9]{20,}/.test(line) ||
            /AIza[0-9A-Za-z\-_]{35}/.test(line) ||
            /AKIA[0-9A-Z]{16}/.test(line)
        ) {
            findings.push({ type: "api_key", value: maskValue(line), risk: "high", line: lineNum })
        }

        // TOKEN
        if (
            /token\s*[=:]\s*\S+/i.test(line) ||
            /bearer\s+[a-zA-Z0-9\-._~+/]+=*/i.test(line) ||
            /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/.test(line)
        ) {
            findings.push({ type: "token", value: maskValue(line), risk: "high", line: lineNum })
        }

        // PHONE NUMBER
        if (/(\+?\d{1,3}[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/.test(line)) {
            findings.push({ type: "phone_number", value: line.trim(), risk: "low", line: lineNum })
        }

        // STACK TRACE
        if (
            /exception|stack trace|traceback|at [a-zA-Z]+\.[a-zA-Z]+\(/i.test(line) ||
            /\w+Error:/i.test(line) ||
            /\tat [\w.$]+\([\w.]+:\d+\)/.test(line)
        ) {
            findings.push({ type: "stack_trace", value: line.trim(), risk: "medium", line: lineNum })
        }

        // HARDCODED SECRET
        if (/secret\s*[=:]\s*\S+/i.test(line) || /private[_-]?key\s*[=:]\s*\S+/i.test(line)) {
            findings.push({ type: "hardcoded_secret", value: maskValue(line), risk: "critical", line: lineNum })
        }

        // DEBUG LEAK
        if (/debug\s*[=:]\s*true/i.test(line) || /verbose\s*[=:]\s*true/i.test(line)) {
            findings.push({ type: "debug_leak", value: line.trim(), risk: "medium", line: lineNum })
        }

        // BRUTE FORCE
        if (/failed login|login failed|authentication failed|invalid password/i.test(line)) {
            const ipMatch = line.match(/\b(\d{1,3}\.){3}\d{1,3}\b/)
            const ip = ipMatch ? ipMatch[0] : "unknown"
            loginFailures[ip] = (loginFailures[ip] || 0) + 1
        }
    })

    Object.entries(loginFailures).forEach(([ip, count]) => {
        if (count >= 3) {
            findings.push({
                type: "brute_force",
                value: `IP ${ip} had ${count} failed login attempts`,
                risk: count >= 10 ? "critical" : "high",
                line: null
            })
        }
    })

    return findings
}

function maskValue(line) {
    return line.replace(/(password|api[_-]?key|token|secret)[=:\s]+(\S+)/gi, (match, key, val) => {
        const visible = val.substring(0, 4)
        return `${key}=${visible}${"*".repeat(Math.max(4, val.length - 4))}`
    })
}


const RISK_WEIGHTS = { critical: 5, high: 3, medium: 2, low: 1 }

function calculateRisk(findings) {
    let score = 0
    findings.forEach(f => { score += RISK_WEIGHTS[f.risk] || 1 })
    let level = "low"
    if (score >= 15) level = "critical"
    else if (score >= 8) level = "high"
    else if (score >= 4) level = "medium"
    return { score, level }
}


function applyPolicy(findings, riskData, options = {}) {
    const actions = []
    if (options.block_high_risk && (riskData.level === "high" || riskData.level === "critical")) {
        actions.push("blocked")
    }
    if (options.mask) actions.push("masked")
    const criticalTypes = ["password", "api_key", "token", "hardcoded_secret"]
    if (findings.some(f => criticalTypes.includes(f.type))) actions.push("alert_raised")
    return actions.length > 0 ? actions.join(", ") : "logged"
}


function generateStaticInsights(findings) {
    const insights = []
    const types = findings.map(f => f.type)
    if (types.includes("password")) insights.push("Plaintext password found in logs — immediate rotation required")
    if (types.includes("api_key")) insights.push("API key exposed — revoke and rotate immediately")
    if (types.includes("token")) insights.push("Auth token leaked — invalidate this token now")
    if (types.includes("hardcoded_secret")) insights.push("Hardcoded secret detected — move to environment variables")
    if (types.includes("stack_trace")) insights.push("Stack traces reveal internal system structure — disable verbose errors in production")
    if (types.includes("brute_force")) insights.push("Brute-force login pattern detected — consider IP blocking or rate limiting")
    if (types.includes("debug_leak")) insights.push("Debug mode enabled in production — disable immediately")
    if (types.includes("phone_number")) insights.push("Phone numbers present in logs — review PII logging policy")
    if (types.includes("email")) insights.push("User email addresses present in logs — review logging policy for PII compliance")
    if (insights.length === 0) insights.push("No critical issues detected — logs appear clean")
    return insights
}

async function generateAIInsights(findings, riskData, logSample) {
    try {
        const findingsSummary = findings.map(f =>
            `Line ${f.line || "N/A"}: [${f.type.toUpperCase()}] risk=${f.risk} — ${f.value}`
        ).join("\n")

        const completion = await groq.chat.completions.create({
            model: "llama-3.1-8b-instant",
            messages: [
                {
                    role: "system",
                    content: "You are a security analyst. Return ONLY a JSON array of strings. No markdown, no explanation, just the array."
                },
                {
                    role: "user",
                    content: `Log sample:\n${logSample.substring(0, 500)}\n\nFindings:\n${findingsSummary}\n\nOverall risk: ${riskData.level} (score: ${riskData.score})\n\nGive 3-5 specific actionable security insights referencing exact line numbers and finding types. Return ONLY a JSON array of strings.`
                }
            ],
            temperature: 0.3,
            max_tokens: 500
        })

        const text = completion.choices[0].message.content.trim()
        const cleaned = text.replace(/```json|```/g, "").trim()
        const parsed = JSON.parse(cleaned)

        if (Array.isArray(parsed) && parsed.length > 0) {
            return { insights: parsed, source: "ai" }
        }
        throw new Error("Invalid response format")

    } catch (err) {
        console.error("AI insights failed, using static fallback:", err.message)
        return { insights: generateStaticInsights(findings), source: "static" }
    }
}


function buildTimeline(content, findings) {
    const lines = content.split("\n")
    const timestampRegex = /\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}/
    const findingLines = new Set(findings.map(f => f.line).filter(Boolean))
    const timeline = []

    lines.forEach((line, index) => {
        const lineNum = index + 1
        const tsMatch = line.match(timestampRegex)
        if (tsMatch && findingLines.has(lineNum)) {
            const finding = findings.find(f => f.line === lineNum)
            timeline.push({
                timestamp: tsMatch[0],
                line: lineNum,
                event: finding ? finding.type : "unknown",
                risk: finding ? finding.risk : "low",
                raw: line.trim()
            })
        }
    })

    return timeline.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
}


async function analyzeContent(content, inputType, options) {
    const findings = detectSensitiveData(content)
    const riskData = calculateRisk(findings)
    const action = applyPolicy(findings, riskData, options)
    const timeline = buildTimeline(content, findings)

    
    const { insights, source: insightSource } = await generateAIInsights(findings, riskData, content)

    const criticalCount = findings.filter(f => f.risk === "critical").length
    const highCount = findings.filter(f => f.risk === "high").length
    const summary = findings.length === 0
        ? "No sensitive data or security issues detected."
        : `Found ${findings.length} issue(s) including ${criticalCount} critical and ${highCount} high risk. Immediate review recommended.`

    return {
        summary,
        content_type: inputType,
        findings,
        risk_score: riskData.score,
        risk_level: riskData.level,
        action,
        insights,
        insight_source: insightSource,
        timeline,
        meta: {
            total_lines: content.split("\n").length,
            total_findings: findings.length,
            analyzed_at: new Date().toISOString()
        }
    }
}


app.post("/analyze", async (req, res) => {
    const { content, input_type = "text", options = {} } = req.body
    if (!content) return res.status(400).json({ error: "No content provided" })
    const result = await analyzeContent(content, input_type, options)
    return res.json(result)
})


app.post("/analyze/file", upload.single("file"), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" })

    try {
        const content = readFileContent(req.file.path, req.file.originalname)
        let options = {}
        try {
            if (req.body.options && req.body.options !== "null" && req.body.options !== "") {
                options = JSON.parse(req.body.options)
            }
        } catch(e) { options = {} }

        const ext = path.extname(req.file.originalname).toLowerCase()
        const inputType = ext === ".log" ? "log" : "file"

        const result = await analyzeContent(content, inputType, options)
        fs.unlinkSync(req.file.path)

        return res.json({
            ...result,
            file_name: req.file.originalname,
            file_size_kb: Math.round(req.file.size / 1024)
        })
    } catch (err) {
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path)
        return res.status(500).json({ error: "Failed to process file", details: err.message })
    }
})


app.get("/health", (req, res) => {
    res.json({ status: "ok", version: "3.0.0", ai: "groq-llama3" })
})

app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError || err.message.includes("not supported")) {
        return res.status(400).json({ error: err.message })
    }
    next(err)
})

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`)
})