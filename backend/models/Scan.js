import mongoose from "mongoose";

const scanSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
    },
    indicator: {
        type: String,
        required: true
    },
    type: {
        type: String,
        required: true
    },
    riskScore: {
        type: Number,
        default: null
    },
    severity: {
        type: String,
        default: "Unknown"
    },
    statistics: {
        malicious: Number,
        suspicious: Number,
        harmless: Number,
        undetected: Number
    },
    source: {
        type: String,
        default: "VirusTotal"
    }
}, {
    timestamps: true
});

const Scan = mongoose.model("Scan", scanSchema);

export default Scan;