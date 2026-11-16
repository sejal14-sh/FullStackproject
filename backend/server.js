import "dotenv/config";

import express from "express";
import cors from "cors";
import connectDB from "./config/db.js";
import authRoutes from "./routes/authRoutes.js";
import scanRoutes from "./routes/scanRoutes.js";

const app = express();

app.use(cors());
app.use(express.json());

app.use((req, res, next) => {
    console.log("INCOMING REQUEST:", req.method, req.originalUrl);
    next();
});

app.use("/api/auth", authRoutes);
app.use("/api/scan", scanRoutes);

app.get("/", (req, res) => {
    res.send("ThreatForge Backend is Running!");
});

const PORT = process.env.PORT || 5000;

connectDB();

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});