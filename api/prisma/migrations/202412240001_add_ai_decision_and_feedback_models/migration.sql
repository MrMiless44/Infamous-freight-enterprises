-- CreateTable: AiDecision
CREATE TABLE "AiDecision" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "invoiceId" TEXT NOT NULL,
    "agent" TEXT NOT NULL,
    "decision" TEXT NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "rationale" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AiDecision_pkey" PRIMARY KEY ("id")
);

-- CreateTable: AiFeedback
CREATE TABLE "AiFeedback" (
    "id" TEXT NOT NULL,
    "aiDecisionId" TEXT NOT NULL,
    "outcome" TEXT NOT NULL,
    "notes" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AiFeedback_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AiDecision_organizationId_agent_idx" ON "AiDecision"("organizationId", "agent");

-- CreateIndex
CREATE UNIQUE INDEX "AiFeedback_aiDecisionId_key" ON "AiFeedback"("aiDecisionId");

-- AddForeignKey
ALTER TABLE "AiFeedback"
ADD CONSTRAINT "AiFeedback_aiDecisionId_fkey"
FOREIGN KEY ("aiDecisionId")
REFERENCES "AiDecision" ("id")
ON DELETE RESTRICT
ON UPDATE CASCADE;
