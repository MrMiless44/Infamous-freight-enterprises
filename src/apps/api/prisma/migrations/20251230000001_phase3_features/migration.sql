-- CreateTable
CREATE TABLE "DriverPrediction" (
    "id" TEXT NOT NULL,
    "driverId" TEXT NOT NULL,
    "availabilityScore" DOUBLE PRECISION NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "factors" JSONB NOT NULL,
    "recommendation" TEXT NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DriverPrediction_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RouteOptimization" (
    "id" TEXT NOT NULL,
    "waypoints" JSONB NOT NULL,
    "optimizedPath" JSONB NOT NULL,
    "totalDistance" DOUBLE PRECISION NOT NULL,
    "estimatedTime" INTEGER NOT NULL,
    "efficiency" DOUBLE PRECISION NOT NULL,
    "fuelEstimate" DOUBLE PRECISION NOT NULL,
    "costEstimate" DOUBLE PRECISION NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RouteOptimization_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "LocationHistory" (
    "id" TEXT NOT NULL,
    "driverId" TEXT NOT NULL,
    "latitude" DOUBLE PRECISION NOT NULL,
    "longitude" DOUBLE PRECISION NOT NULL,
    "speed" DOUBLE PRECISION NOT NULL,
    "heading" DOUBLE PRECISION NOT NULL,
    "accuracy" DOUBLE PRECISION NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "LocationHistory_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Geofence" (
    "id" TEXT NOT NULL,
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
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Geofence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GamificationPoints" (
    "id" TEXT NOT NULL,
    "driverId" TEXT NOT NULL,
    "points" INTEGER NOT NULL,
    "category" TEXT NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "GamificationPoints_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Badge" (
    "id" TEXT NOT NULL,
    "driverId" TEXT NOT NULL,
    "badgeType" TEXT NOT NULL,
    "earnedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "metadata" JSONB,

    CONSTRAINT "Badge_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Leaderboard" (
    "id" TEXT NOT NULL,
    "driverId" TEXT NOT NULL,
    "totalPoints" INTEGER NOT NULL DEFAULT 0,
    "rank" INTEGER NOT NULL,
    "period" TEXT NOT NULL,
    "lastUpdated" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Leaderboard_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BusinessMetric" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "metricType" TEXT NOT NULL,
    "value" DOUBLE PRECISION NOT NULL,
    "previousValue" DOUBLE PRECISION,
    "changePercent" DOUBLE PRECISION,
    "period" TEXT NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BusinessMetric_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "DriverPrediction_driverId_idx" ON "DriverPrediction"("driverId");
CREATE INDEX "DriverPrediction_createdAt_idx" ON "DriverPrediction"("createdAt" DESC);
CREATE INDEX "DriverPrediction_recommendation_idx" ON "DriverPrediction"("recommendation");

-- CreateIndex
CREATE INDEX "RouteOptimization_createdAt_idx" ON "RouteOptimization"("createdAt" DESC);

-- CreateIndex
CREATE INDEX "LocationHistory_driverId_idx" ON "LocationHistory"("driverId");
CREATE INDEX "LocationHistory_timestamp_idx" ON "LocationHistory"("timestamp" DESC);
CREATE INDEX "LocationHistory_driverId_timestamp_idx" ON "LocationHistory"("driverId", "timestamp");

-- CreateIndex
CREATE INDEX "Geofence_organizationId_idx" ON "Geofence"("organizationId");
CREATE INDEX "Geofence_type_idx" ON "Geofence"("type");

-- CreateIndex
CREATE INDEX "GamificationPoints_driverId_idx" ON "GamificationPoints"("driverId");
CREATE INDEX "GamificationPoints_category_idx" ON "GamificationPoints"("category");

-- CreateIndex
CREATE INDEX "Badge_driverId_idx" ON "Badge"("driverId");
CREATE INDEX "Badge_badgeType_idx" ON "Badge"("badgeType");

-- CreateIndex
CREATE INDEX "Leaderboard_driverId_idx" ON "Leaderboard"("driverId");
CREATE INDEX "Leaderboard_rank_idx" ON "Leaderboard"("rank");
CREATE INDEX "Leaderboard_period_idx" ON "Leaderboard"("period");

-- CreateIndex
CREATE INDEX "BusinessMetric_organizationId_idx" ON "BusinessMetric"("organizationId");
CREATE INDEX "BusinessMetric_metricType_idx" ON "BusinessMetric"("metricType");
CREATE INDEX "BusinessMetric_period_idx" ON "BusinessMetric"("period");

-- CreateTable (Phase 3 Feature 7: 2FA)
CREATE TABLE "TwoFactorAuth" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "secret" TEXT NOT NULL,
    "backupCodes" JSONB NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "smsPhone" TEXT,
    "lastVerified" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "TwoFactorAuth_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "TwoFactorAuth_userId_key" ON "TwoFactorAuth"("userId");
CREATE INDEX "TwoFactorAuth_userId_idx" ON "TwoFactorAuth"("userId");
CREATE INDEX "TwoFactorAuth_enabled_idx" ON "TwoFactorAuth"("enabled");

-- AddForeignKey
ALTER TABLE "TwoFactorAuth" ADD CONSTRAINT "TwoFactorAuth_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DriverPrediction" ADD CONSTRAINT "DriverPrediction_driverId_fkey" FOREIGN KEY ("driverId") REFERENCES "Driver"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LocationHistory" ADD CONSTRAINT "LocationHistory_driverId_fkey" FOREIGN KEY ("driverId") REFERENCES "Driver"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "GamificationPoints" ADD CONSTRAINT "GamificationPoints_driverId_fkey" FOREIGN KEY ("driverId") REFERENCES "Driver"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Badge" ADD CONSTRAINT "Badge_driverId_fkey" FOREIGN KEY ("driverId") REFERENCES "Driver"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Leaderboard" ADD CONSTRAINT "Leaderboard_driverId_fkey" FOREIGN KEY ("driverId") REFERENCES "Driver"("id") ON DELETE CASCADE ON UPDATE CASCADE;
