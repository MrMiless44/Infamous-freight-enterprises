export type UUID = string;

export interface HealthStatus {
  ok: boolean;
  service: string;
  ts: string;
}
