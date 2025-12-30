type VoiceContext = {
  nextStop?: string;
  etaMinutes?: number;
  behindScheduleMinutes?: number;
  safetyIssues?: string[];
  dispatchNote?: string;
};

export async function handleVoiceCommand(
  command: string,
  context: VoiceContext = {},
): Promise<string> {
  const normalized = command.toLowerCase();

  if (normalized.includes("next stop")) {
    const eta = context.etaMinutes ?? 38;
    const stop = context.nextStop ?? "scheduled checkpoint";
    return `Your next stop is ${stop}. ETA ${eta} minutes.`;
  }

  if (normalized.includes("behind schedule") || normalized.includes("delay")) {
    const delay = context.behindScheduleMinutes ?? 12;
    return `You're behind by ${delay} minutes. Reduce idle time and maintain speed consistency.`;
  }

  if (normalized.includes("coach")) {
    return "Maintain speed consistency to recover 7 minutes.";
  }

  if (normalized.includes("safety")) {
    const issues = context.safetyIssues?.join(", ");
    return issues
      ? `Safety watch: ${issues}. Keep braking smooth and increase following distance.`
      : "No safety issues detected. Keep braking smooth and eyes forward.";
  }

  if (normalized.includes("dispatch")) {
    return (
      context.dispatchNote ?? "Dispatch acknowledged. Monitoring your route."
    );
  }

  return "Command acknowledged.";
}
