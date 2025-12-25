export function segmentUser(uploadCount: number) {
  if (uploadCount > 50) return "enterprise";
  if (uploadCount > 10) return "fleet";
  return "driver";
}
