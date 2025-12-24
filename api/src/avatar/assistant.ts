import { prisma } from "../db/prisma";

export async function getAvatarInsights(userId: string, orgId: string) {
  const memory = await prisma.avatarMemory.findMany({
    where: { userId, organizationId: orgId },
  });

  return memory.map((m) => ({
    message: `Reminder based on ${m.key}: ${m.value}`,
  }));
}
