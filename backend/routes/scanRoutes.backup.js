import express from "express";
import jwt from "jsonwebtoken";
import Scan from "../models/Scan.js";
console.log("SCAN ROUTES FILE LOADED");
const router = express.Router();
console.log("VirusTotal key loaded:", Boolean(process.env.VT_API_KEY?.trim()));
const VT_API = "https://www.virustotal.com/api/v3";

// Verify login token
const verifyToken = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                message: "Authentication required"
            });
        }

        const token = authHeader.split(" ")[1];

        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        req.user = decoded;
        next();

    } catch (error) {
        return res.status(401).json({
            message: "Invalid or expired token"
        });
    }
};


// Detect IOC type
const detectType = (indicator) => {

    const value = indicator.trim();

    const ipRegex =
        /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;

    if (ipRegex.test(value)) return "ip";

    if (/^https?:\/\//i.test(value)) return "url";

    if (/^[a-fA-F0-9]{32}$/.test(value)) return "md5";

    if (/^[a-fA-F0-9]{40}$/.test(value)) return "sha1";

    if (/^[a-fA-F0-9]{64}$/.test(value)) return "sha256";

    return "domain";
};


// IOC Scanner API
router.post("/", verifyToken, async (req, res) => {
console.log("SCAN REQUEST REACHED AUTH MIDDLEWARE");
    try {

        const { indicator } = req.body;

        if (!indicator || !indicator.trim()) {
            return res.status(400).json({
                message: "Please enter an indicator"
            });
        }
console.log("VirusTotal key detected:", Boolean(process.env.VT_API_KEY?.trim()));
      if (!process.env.VT_API_KEY ||
            process.env.VT_API_KEY === "d0aaa120e46de11024a20feac16d2ae526d929a3f8a3305c46316dce949bfb12 ") {
            return res.status(500).json({
                message: "VirusTotal API key is not configured"
            });
}
console.log("PASSED API KEY CHECK");
        const value = indicator.trim();
        const type = detectType(value);

        let endpoint;

        if (type === "ip") {
            endpoint = `/ip_addresses/${encodeURIComponent(value)}`;
        }

        else if (type === "url") {

            const url = new URL(value);

            const urlId = Buffer
                .from(url.toString())
                .toString("base64")
                .replace(/=/g, "");

            endpoint = `/urls/${urlId}`;
        }

        else if (["md5", "sha1", "sha256"].includes(type)) {
            endpoint = `/files/${encodeURIComponent(value)}`;
        }

        else {
            endpoint = `/domains/${encodeURIComponent(value)}`;
        }

        const response = await fetch(`${VT_API}${endpoint}`, {
            method: "GET",
            headers: {
                "x-apikey": process.env.VT_API_KEY
            }
        });

        const data = await response.json();

        if (!response.ok) {
            return res.status(response.status).json({
                message: data.error?.message || "Threat intelligence lookup failed"
            });
        }

        const attributes = data.data.attributes;

        const stats = attributes.last_analysis_stats || {};

        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const harmless = stats.harmless || 0;
        const undetected = stats.undetected || 0;

        const total = malicious + suspicious + harmless + undetected;

        const riskScore = total > 0
            ? Math.round(((malicious + suspicious * 0.5) / total) * 100)
            : null;

        let severity = "Unknown";

        if (riskScore !== null) {
            if (malicious > 0 && riskScore >= 50) {
                severity = "High";
            }
            else if (malicious > 0 || suspicious > 0) {
                severity = "Medium";
            }
            else {
                severity = "Low";
            }
        }
// Save scan history in MongoDB
try {
    await Scan.create({
        userId: req.user.id,
        indicator: value,
        type,
        riskScore,
        severity,
        statistics: {
            malicious,
            suspicious,
            harmless,
            undetected
        },
        source: "VirusTotal"
    });

    console.log("Scan history saved successfully!");

} catch (historyError) {
    console.error("Scan history save failed:", historyError.message);
}
        res.json({
            success: true,
            indicator: value,
            type,
            riskScore,
            severity,
            statistics: {
                malicious,
                suspicious,
                harmless,
                undetected
            },
            reputation: attributes.reputation ?? null,
            lastAnalysisDate: attributes.last_analysis_date ?? null,
            source: "VirusTotal"
        });

    } catch (error) {

        res.status(500).json({
            message: error.message
        });

    }

});

export default router;
