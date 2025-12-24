import { prisma } from "../db/prisma";

export async function getAvatarInsights(userId: string, orgId: string) {
  type AvatarMemoryRecord = Awaited<
    ReturnType<typeof prisma.avatarMemory.findMany>
  >[number];

  const memory: AvatarMemoryRecord[] = await prisma.avatarMemory.findMany({
    where: { userId, organizationId: orgId },
  });

  return memory.map((entry: AvatarMemoryRecord) => ({
    message: `Reminder based on ${entry.key}: ${entry.value}`,
  }));
}
