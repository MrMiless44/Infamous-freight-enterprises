// Phase 3: Predictive Driver Availability Service
// Predicts when drivers will become available using historical patterns

import { PrismaClient, Driver, DriverSession } from "@prisma/client";

const prisma = new PrismaClient();

interface AvailabilityPrediction {
  driverId: string;
  availableIn: number; // minutes
  confidence: number; // 0-1
  factors: {
    historicalPattern: number;
    currentStatus: string;
    scheduledDeliveries: number;
    averageSessionDuration: number;
  };
  predictions: {
    time: Date;
    probability: number;
  }[];
}

interface HistoricalPattern {
  hourOfDay: number;
  dayOfWeek: number;
  averageAvailability: number;
  frequency: number;
}

/**
 * Analyze historical driver availability patterns
 */
async function analyzeHistoricalPatterns(
  driverId: string,
  daysBack: number = 60,
): Promise<HistoricalPattern[]> {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - daysBack);

  const sessions = await prisma.driverSession.findMany({
    where: {
      driverId,
      endTime: {
        gte: startDate,
      },
    },
    orderBy: { endTime: "desc" },
  });

  // Build patterns by hour and day of week
  const patterns: Map<string, HistoricalPattern> = new Map();

  sessions.forEach((session) => {
    if (!session.endTime) return;

    const endTime = new Date(session.endTime);
    const hourOfDay = endTime.getHours();
    const dayOfWeek = endTime.getDay();
    const key = `${dayOfWeek}:${hourOfDay}`;

    if (!patterns.has(key)) {
      patterns.set(key, {
        hourOfDay,
        dayOfWeek,
        averageAvailability: 0,
        frequency: 0,
      });
    }

    const pattern = patterns.get(key)!;
    pattern.frequency++;
  });

  // Calculate average availability probability (frequency / total days)
  const totalDays = daysBack;
  patterns.forEach((pattern) => {
    pattern.averageAvailability = pattern.frequency / totalDays;
  });

  return Array.from(patterns.values());
}

/**
 * Calculate availability based on current status and scheduled work
 */
async function getCurrentAvailabilityStatus(
  driver: Driver & { currentLoads: any[] },
): Promise<{
  status: string;
  estimatedAvailableIn: number;
  scheduledDeliveries: number;
}> {
  const currentLoads = driver.currentLoads || [];
  const scheduledDeliveries = currentLoads.length;

  if (scheduledDeliveries === 0) {
    return {
      status: "available",
      estimatedAvailableIn: 0,
      scheduledDeliveries: 0,
    };
  }

  // Estimate time to complete current loads
  // Average delivery time: 45 minutes
  const estimatedCompleteIn = scheduledDeliveries * 45;

  return {
    status: "busy",
    estimatedAvailableIn: estimatedCompleteIn,
    scheduledDeliveries,
  };
}

/**
 * Calculate confidence score for prediction
 */
function calculateConfidenceScore(
  patterns: HistoricalPattern[],
  currentStatus: { estimatedAvailableIn: number },
  recentVariance: number,
): number {
  let confidence = 0.5; // Base confidence

  // Increase confidence if patterns are consistent
  const avgPatternFreq =
    patterns.reduce((sum, p) => sum + p.frequency, 0) / (patterns.length || 1);
  if (avgPatternFreq > 5) {
    confidence += 0.3; // Strong patterns
  }

  // Decrease confidence if recent variance is high
  confidence -= recentVariance * 0.2;

  // Clamp between 0 and 1
  return Math.max(0, Math.min(1, confidence));
}

/**
 * Main prediction function
 */
export async function predictDriverAvailability(
  driverId: string,
  horizonMinutes: number = 120,
): Promise<AvailabilityPrediction> {
  // 1. Get driver and current status
  const driver = await prisma.driver.findUnique({
    where: { id: driverId },
    include: { currentLoads: true },
  });

  if (!driver) {
    throw new Error(`Driver not found: ${driverId}`);
  }

  // 2. Analyze historical patterns
  const patterns = await analyzeHistoricalPatterns(driverId);

  // 3. Get current availability
  const current = await getCurrentAvailabilityStatus(driver);

  // 4. Calculate average session duration
  const sessions = await prisma.driverSession.findMany({
    where: { driverId },
    take: 30,
    orderBy: { endTime: "desc" },
  });

  const avgSessionDuration =
    sessions.reduce((sum, s) => {
      if (s.startTime && s.endTime) {
        return (
          sum + (s.endTime.getTime() - s.startTime.getTime()) / (1000 * 60)
        );
      }
      return sum;
    }, 0) / (sessions.length || 1);

  // 5. Calculate current time patterns
  const now = new Date();
  const currentHour = now.getHours();
  const currentDay = now.getDay();
  const patternKey = `${currentDay}:${currentHour}`;

  const currentPattern = patterns.find(
    (p) => p.hourOfDay === currentHour && p.dayOfWeek === currentDay,
  );
  const patternAvailability = currentPattern?.averageAvailability || 0.5;

  // 6. Calculate variance for confidence
  const recentVariance = calculateRecencyWeightedVariance(sessions);

  // 7. Make prediction
  const confidence = calculateConfidenceScore(
    patterns,
    current,
    recentVariance,
  );

  // 8. Generate probability distribution for next 2 hours
  const predictions = generateProbabilityDistribution(
    current.estimatedAvailableIn,
    horizonMinutes,
    patternAvailability,
    confidence,
  );

  return {
    driverId,
    availableIn: current.estimatedAvailableIn,
    confidence,
    factors: {
      historicalPattern: patternAvailability,
      currentStatus: current.status,
      scheduledDeliveries: current.scheduledDeliveries,
      averageSessionDuration: Math.round(avgSessionDuration),
    },
    predictions,
  };
}

/**
 * Calculate variance in recent session durations
 */
function calculateRecencyWeightedVariance(sessions: DriverSession[]): number {
  if (sessions.length < 2) return 0.5; // High uncertainty for new drivers

  const durations = sessions
    .filter((s) => s.startTime && s.endTime)
    .map((s) => (s.endTime!.getTime() - s.startTime!.getTime()) / (1000 * 60));

  const mean = durations.reduce((a, b) => a + b, 0) / durations.length;
  const variance =
    durations.reduce((sum, d) => sum + Math.pow(d - mean, 2), 0) /
    durations.length;

  // Normalize variance (0 = consistent, 1 = highly variable)
  return Math.min(1, variance / mean / 2);
}

/**
 * Generate probability distribution for availability
 */
function generateProbabilityDistribution(
  estimatedAvailableIn: number,
  horizonMinutes: number,
  patternAvailability: number,
  confidence: number,
): { time: Date; probability: number }[] {
  const predictions: { time: Date; probability: number }[] = [];
  const now = new Date();

  for (let i = 0; i <= horizonMinutes; i += 15) {
    const time = new Date(now.getTime() + i * 60 * 1000);

    // Probability increases as we approach estimated available time
    let probability = 0;

    if (i < estimatedAvailableIn) {
      // Before estimated time: low probability
      probability = (i / estimatedAvailableIn) * 0.2;
    } else {
      // After estimated time: high probability
      probability =
        0.5 + patternAvailability * confidence + Math.random() * 0.2;
      probability = Math.min(1, probability);
    }

    predictions.push({ time, probability });
  }

  return predictions;
}

/**
 * Get top N most likely available drivers for a specific time
 */
export async function findAvailableDrivers(
  availableAfterMinutes: number,
  count: number = 5,
): Promise<
  (AvailabilityPrediction & { driverId: string; availableScore: number })[]
> {
  const drivers = await prisma.driver.findMany({
    where: { isActive: true },
    take: 100, // Analyze top 100 drivers
  });

  const predictions = await Promise.all(
    drivers.map((d) => predictDriverAvailability(d.id)),
  );

  // Score and sort by availability match
  const scored = predictions
    .map((p) => ({
      ...p,
      availableScore:
        Math.max(0, 1 - Math.abs(p.availableIn - availableAfterMinutes) / 120) *
        p.confidence,
    }))
    .sort((a, b) => b.availableScore - a.availableScore)
    .slice(0, count);

  return scored;
}

/**
 * Log prediction for analytics
 */
export async function logPrediction(
  driverId: string,
  prediction: AvailabilityPrediction,
  actualAvailableIn: number,
): Promise<void> {
  const error = Math.abs(prediction.availableIn - actualAvailableIn);
  const accuracy = Math.max(0, 1 - error / 120); // Normalize to 120-min horizon

  console.log(
    `[Prediction] Driver: ${driverId}, Predicted: ${prediction.availableIn}min, Actual: ${actualAvailableIn}min, Accuracy: ${(accuracy * 100).toFixed(1)}%, Confidence: ${(prediction.confidence * 100).toFixed(0)}%`,
  );
}

export default {
  predictDriverAvailability,
  findAvailableDrivers,
  logPrediction,
};
