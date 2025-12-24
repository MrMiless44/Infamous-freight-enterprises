import { calibrate } from "../../../../ai/v2";

type DispatchRoute = {
  id?: string;
  trafficRisk: number;
  delayMinutes?: number;
  etaMinutes?: number;
  customerPriority?: "standard" | "priority" | "expedite";
};

type DispatchDriver = {
  id?: string;
  name?: string;
  safetyScore?: number;
  utilization?: number;
  currentLoad?: number;
};

export type DispatchIntelResult = {
  action: "REROUTE" | "MONITOR" | "BALANCE";
  message: string;
  confidence: number;
  etaDeltaMinutes: number;
  driverImpact: string;
  recommendedNext: string[];
};

function computeDriverImpact(
  driver: DispatchDriver,
  etaDeltaMinutes: number,
): string {
  if ((driver.utilization ?? 0) > 0.9) {
    return "Driver nearing capacity—balance remaining loads.";
  }

  if (etaDeltaMinutes < 0) {
    return "Driver efficiency improves with the new route.";
  }

  if ((driver.safetyScore ?? 1) < 0.6) {
    return "Guardrails applied: monitor aggressive maneuvers.";
  }

  return "Driver impact neutral—keep monitoring.";
}

export function dispatchIntel(
  route: DispatchRoute,
  driver: DispatchDriver,
): DispatchIntelResult {
  const baseRisk = route.trafficRisk ?? 0;
  const delayMinutes = route.delayMinutes ?? 0;
  const etaMinutes = route.etaMinutes ?? 0;
  const isPriority = route.customerPriority === "priority";

  if (baseRisk > 0.7 || delayMinutes > 15) {
    const etaDeltaMinutes = delayMinutes > 0 ? -Math.min(delayMinutes, 25) : -18;
    const confidence = calibrate(0.86 + baseRisk * 0.1);
    const rerouteMessage =
      baseRisk > 0.7
        ? "Traffic detected. Rerouting to save 18 minutes."
        : "Delay detected. Rerouting to claw back time.";
    return {
      action: "REROUTE",
      message: rerouteMessage,
      confidence,
      etaDeltaMinutes,
      driverImpact: computeDriverImpact(driver, etaDeltaMinutes),
      recommendedNext: [
        "Notify customer with revised ETA",
        "Sync reroute to driver nav",
        "Capture telemetry for post-run learning",
      ],
    };
  }

  if (isPriority && etaMinutes > 60) {
    const etaDeltaMinutes = -12;
    const confidence = calibrate(0.8);
    return {
      action: "BALANCE",
      message: "Priority load detected. Rebalancing to protect SLA.",
      confidence,
      etaDeltaMinutes,
      driverImpact: computeDriverImpact(driver, etaDeltaMinutes),
      recommendedNext: [
        "Reassign nearby driver with better proximity",
        "Alert dispatcher with swap proposal",
        "Update customer SLA tracker",
      ],
    };
  }

  return {
    action: "MONITOR",
    message: "Route stable.",
    confidence: calibrate(0.68),
    etaDeltaMinutes: 0,
    driverImpact: computeDriverImpact(driver, 0),
    recommendedNext: [
      "Continue telemetry monitoring",
      "Run next checkpoint in 15 minutes",
      "Keep customer ETA steady",
    ],
  };
}
