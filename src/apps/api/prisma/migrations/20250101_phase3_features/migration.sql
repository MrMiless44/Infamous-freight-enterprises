-- Phase 3 Feature 1: Predictive Driver Availability
CREATE TABLE "DriverPrediction" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "driverId" TEXT NOT NULL,
    "availabilityScore" DOUBLE PRECISION NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "factors" JSONB NOT NULL,
    "recommendation" TEXT NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "DriverPrediction_driverId_fkey" FOREIGN KEY ("driverId") REFERENCES "Driver" ("id") ON DELETE CASCADE
);

CREATE INDEX "DriverPrediction_driverId_idx" ON "DriverPrediction"("driverId");
CREATE INDEX "DriverPrediction_createdAt_idx" ON "DriverPrediction"("createdAt" DESC);
CREATE INDEX "DriverPrediction_recommendation_idx" ON "DriverPrediction"("recommendation");

-- Phase 3 Feature 2: Route Optimization
CREATE TABLE "RouteOptimization" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "waypoints" JSONB NOT NULL,
    "optimizedPath" JSONB NOT NULL,
    "totalDistance" DOUBLE PRECISION NOT NULL,
    "estimatedTime" INTEGER NOT NULL,
    "efficiency" DOUBLE PRECISION NOT NULL,
    "fuelEstimate" DOUBLE PRECISION NOT NULL,
    "costEstimate" DOUBLE PRECISION NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX "RouteOptimization_createdAt_idx" ON "RouteOptimization"("createdAt" DESC);

-- Phase 3 Feature 3: Real-time GPS Tracking
CREATE TABLE "LocationHistory" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "driverId" TEXT NOT NULL,
    "latitude" DOUBLE PRECISION NOT NULL,
    "longitude" DOUBLE PRECISION NOT NULL,
    "speed" DOUBLE PRECISION NOT NULL,
    "heading" DOUBLE PRECISION NOT NULL,
    "accuracy" DOUBLE PRECISION NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "LocationHistory_driverId_fkey" FOREIGN KEY ("driverId") REFERENCES "Driver" ("id") ON DELETE CASCADE
);

CREATE INDEX "LocationHistory_driverId_idx" ON "LocationHistory"("driverId");
CREATE INDEX "LocationHistory_timestamp_idx" ON "LocationHistory"("timestamp" DESC);
CREATE INDEX "LocationHistory_driverId_timestamp_idx" ON "LocationHistory"("driverId", "timestamp");

-- Phase 3 Feature 3: Geofencing
CREATE TABLE "Geofence" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "latitude" DOUBLE PRECISION NOT NULL,
    "longitude" DOUBLE PRECISION NOT NULL,
    "radiusMeters" DOUBLE PRECISION NOT NULL,
    "alertOnEntry" BOOLEAN NOT NULL DEFAULT true,
    "alertOnExit" BOOLEAN NOT NULL DEFAULT true,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL
);

CREATE INDEX "Geofence_organizationId_idx" ON "Geofence"("organizationId");
CREATE INDEX "Geofence_type_idx" ON "Geofence"("type");

-- Phase 3 Feature 4: Gamification System - Points
CREATE TABLE "GamificationPoints" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "driverId" TEXT NOT NULL,
    "points" INTEGER NOT NULL,
    "category" TEXT NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "GamificationPoints_driverId_fkey" FOREIGN KEY ("driverId") REFERENCES "Driver" ("id") ON DELETE CASCADE
);

CREATE INDEX "GamificationPoints_driverId_idx" ON "GamificationPoints"("driverId");
CREATE INDEX "GamificationPoints_category_idx" ON "GamificationPoints"("category");

-- Phase 3 Feature 4: Gamification System - Badges
CREATE TABLE "Badge" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "driverId" TEXT NOT NULL,
    "badgeType" TEXT NOT NULL,
    "earnedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "metadata" JSONB,
    CONSTRAINT "Badge_driverId_fkey" FOREIGN KEY ("driverId") REFERENCES "Driver" ("id") ON DELETE CASCADE
);

CREATE INDEX "Badge_driverId_idx" ON "Badge"("driverId");
CREATE INDEX "Badge_badgeType_idx" ON "Badge"("badgeType");

-- Phase 3 Feature 4: Gamification System - Leaderboard
CREATE TABLE "Leaderboard" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "driverId" TEXT NOT NULL,
    "totalPoints" INTEGER NOT NULL DEFAULT 0,
    "rank" INTEGER NOT NULL,
    "period" TEXT NOT NULL,
    "lastUpdated" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Leaderboard_driverId_fkey" FOREIGN KEY ("driverId") REFERENCES "Driver" ("id") ON DELETE CASCADE
);

CREATE INDEX "Leaderboard_driverId_idx" ON "Leaderboard"("driverId");
CREATE INDEX "Leaderboard_rank_idx" ON "Leaderboard"("rank");
CREATE INDEX "Leaderboard_period_idx" ON "Leaderboard"("period");

-- Phase 3 Feature 6: Business Metrics Dashboard
CREATE TABLE "BusinessMetric" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organizationId" TEXT NOT NULL,
    "metricType" TEXT NOT NULL,
    "value" DOUBLE PRECISION NOT NULL,
    "previousValue" DOUBLE PRECISION,
    "changePercent" DOUBLE PRECISION,
    "period" TEXT NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX "BusinessMetric_organizationId_idx" ON "BusinessMetric"("organizationId");
CREATE INDEX "BusinessMetric_metricType_idx" ON "BusinessMetric"("metricType");
CREATE INDEX "BusinessMetric_period_idx" ON "BusinessMetric"("period");
