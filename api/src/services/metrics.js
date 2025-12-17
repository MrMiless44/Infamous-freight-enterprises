const StatsD = (() => {
    try {
        return require('hot-shots');
    } catch (e) {
        return null;
    }
})();

let dogstatsd = null;
if (StatsD && (process.env.DD_METRICS_ENABLED === 'true')) {
    try {
        dogstatsd = new StatsD({ host: process.env.DD_AGENT_HOST || '127.0.0.1', port: Number(process.env.DD_AGENT_PORT) || 8125 });
    } catch (e) {
        dogstatsd = null;
    }
}

module.exports = {
    shipmentCreated() {
        if (dogstatsd) dogstatsd.increment('shipment.created');
    },
    apiLatency(ms, route) {
        if (dogstatsd) dogstatsd.histogram('api.latency', ms, ['route:' + route]);
    },
};
