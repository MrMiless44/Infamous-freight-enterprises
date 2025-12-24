-- CreateTable: Invoice
CREATE TABLE "Invoice" (
    "id" TEXT NOT NULL,
    "carrier" TEXT NOT NULL,
    "reference" TEXT NOT NULL,
    "totalAmount" DECIMAL(12,2) NOT NULL,
    "currency" TEXT NOT NULL DEFAULT 'USD',
    "auditResult" JSONB,
    "savings" DECIMAL(12,2) NOT NULL DEFAULT 0,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Invoice_pkey" PRIMARY KEY ("id")
);

-- Indexes
CREATE UNIQUE INDEX "Invoice_reference_key" ON "Invoice"("reference");
