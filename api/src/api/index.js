/**
 * API Routes Index
 * Centralized exports for all API route handlers
 */

module.exports = {
  healthRoutes: require("./health"),
  aiRoutes: require("./ai.commands"),
  billingRoutes: require("./billing"),
  voiceRoutes: require("./voice"),
  aiSimRoutes: require("./aiSim.internal"),
  usersRoutes: require("./users"),
  shipmentsRoutes: require("./shipments"),
};
