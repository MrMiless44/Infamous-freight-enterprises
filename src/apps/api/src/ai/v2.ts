export function calibrate(conf: number, accuracy = 0.8) {
  return Math.min(0.99, conf * accuracy);
}
