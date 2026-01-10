export type ServiceType =
  | "local"
  | "regional"
  | "national"
  | "standard"
  | "express";

interface PriceInput {
  serviceType: ServiceType;
  distance: number; // miles
  weight: number; // pounds
}

export function calculateShippingPrice(input: PriceInput): number {
  const baseByService: Record<ServiceType, number> = {
    local: 40,
    regional: 120,
    national: 240,
    standard: 120,
    express: 180,
  };

  const base = baseByService[input.serviceType] ?? 100;
  const distanceSurcharge = Math.max(0, input.distance) * 0.35;
  const weightSurcharge = Math.max(0, input.weight - 500) * 0.01;

  const price = base + distanceSurcharge + weightSurcharge;
  return Math.round(price * 100) / 100;
}

type Coordinates = { lat: number; lng: number };

export function calculateDistance(a: Coordinates, b: Coordinates): number {
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const R = 3958.8; // miles
  const dLat = toRad(b.lat - a.lat);
  const dLon = toRad(b.lng - a.lng);
  const lat1 = toRad(a.lat);
  const lat2 = toRad(b.lat);

  const h =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.sin(dLon / 2) * Math.sin(dLon / 2) * Math.cos(lat1) * Math.cos(lat2);
  const c = 2 * Math.atan2(Math.sqrt(h), Math.sqrt(1 - h));
  const distance = R * c;
  return Math.round(distance * 100) / 100;
}

interface DeliveryTimeInput {
  distance: number; // miles
  serviceType: ServiceType;
}

export function calculateDeliveryTime(input: DeliveryTimeInput): number {
  const speeds: Record<ServiceType, number> = {
    local: 30, // mph
    regional: 45,
    national: 60,
    standard: 45,
    express: 65,
  };

  const speed = speeds[input.serviceType] ?? 45;
  const hours = Math.max(0, input.distance) / speed;
  const bufferMinutes = input.serviceType === "express" ? 20 : 60;
  return Math.round(hours * 60 + bufferMinutes);
}

interface Address {
  street?: string;
  city?: string;
  state?: string;
  zip?: string;
}

export function formatAddress(address: Address): string {
  const parts = [
    address.street,
    address.city,
    address.state,
    address.zip,
  ].filter(Boolean);
  return parts.join(", ");
}

export function validateEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export function validatePhone(phone: string): boolean {
  const digits = phone.replace(/\D/g, "");
  return digits.length >= 10 && digits.length <= 15;
}
