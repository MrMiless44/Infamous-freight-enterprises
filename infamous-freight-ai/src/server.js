require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("./middleware/rateLimit");
const { loadConfig } = require("./config");

loadConfig(process.env);

const app = express();
app.use(express.json());
app.use(helmet());
app.use(cors());
app.use(rateLimit({ points: 100, duration: 60 }));

app.use("/ai", require("./routes/ai.commands"));
app.use("/health", require("./routes/health"));

app.get("/", (req, res) => res.json({ status: "ok", version: "1.0.0" }));

module.exports = app;

if (require.main === module) {
    app.listen(process.env.PORT || 4000, () =>
        console.log("🚚 Infæmous Freight AI running")
    );
}
