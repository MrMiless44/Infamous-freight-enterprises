// api/src/middleware/logger.js (example HTTP shipper)
const axios = require('axios');
async function shipLogToDatadog(entry) {
    await axios.post(
        'https://http-intake.logs.datadoghq.com/api/v2/logs',
        [{ ddsource: 'node', service: 'infamous-freight-api', ...entry }],
        { headers: { 'DD-API-KEY': process.env.DD_API_KEY, 'Content-Type': 'application/json' } },
    );
}