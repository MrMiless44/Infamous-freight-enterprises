const axios = require("axios");

async function sendCommand(command, payload, context) {
    const res = await axios.post(
        process.env.AI_ENGINE_URL,
        { command, payload, context },
        { timeout: 15000 }
    );
    return res.data;
}

module.exports = { sendCommand };
