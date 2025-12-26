import { prisma } from "../db/prisma";

export async function weeklySummary() {
  const count = await prisma.invoice.count();
  console.warn("Weekly invoices audited:", count);
}
