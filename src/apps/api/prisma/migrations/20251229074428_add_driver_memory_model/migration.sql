-- CreateTable: DriverMemory
CREATE TABLE "driver_memories" (
    "id" TEXT NOT NULL,
    "driverId" TEXT NOT NULL,
    "preferences" JSONB NOT NULL,
    "drivingStyle" TEXT,
    "riskTolerance" TEXT,
    "pastRoutes" JSONB,
    "earningsPatterns" JSONB,
    "communicationTone" TEXT,
    "learnedConstraints" JSONB,
    "lastUpdated" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "driver_memories_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "driver_memories_driverId_key" ON "driver_memories"("driverId");

-- AddForeignKey
ALTER TABLE "driver_memories"
ADD CONSTRAINT "driver_memories_driverId_fkey"
FOREIGN KEY ("driverId")
REFERENCES "Driver" ("id")
ON DELETE CASCADE
ON UPDATE CASCADE;
