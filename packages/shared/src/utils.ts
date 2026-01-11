export function validateNonEmpty(value: string, field = 'value'): void {
  if (!value || !value.trim()) throw new Error(`${field} must be non-empty`);
}

export function nowIso(): string {
  return new Date().toISOString();
}
