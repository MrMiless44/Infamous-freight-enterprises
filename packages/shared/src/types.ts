// Common types used across services
export interface User {
  id: string;
  email: string;
  name?: string;
  role: "admin" | "dispatcher" | "user";
  createdAt: Date;
  updatedAt: Date;
}

export interface Shipment {
  id: string;
  reference: string;
  origin: string;
  destination: string;
  status: ShipmentStatus;
  driverId?: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export type ShipmentStatus =
  | "created"
  | "in_transit"
  | "delivered"
  | "cancelled";

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface PaginationParams {
  page?: number;
  limit?: number;
  sortBy?: string;
  sortOrder?: "asc" | "desc";
}

export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  pagination: {
    currentPage: number;
    totalPages: number;
    totalItems: number;
    itemsPerPage: number;
  };
}
