require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const morgan = require("morgan");
const healthRoutes = require("./routes/health");
const aiRoutes = require("./routes/ai.commands");
const billingRoutes = require("./routes/billing");
const voiceRoutes = require("./routes/voice");
const aiSimRoutes = require("./routes/aiSim.internal");

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "12mb" }));
app.use(morgan("combined"));

// Routes
app.use("/api", healthRoutes);
app.use("/api", aiRoutes);
app.use("/api", billingRoutes);
app.use("/api", voiceRoutes);

// Internal synthetic engine simulator
app.use("/internal", aiSimRoutes);

const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`Infamous Freight API listening on ${port}`);
});
