/**
 * Marketplace Platform
 * Two-sided marketplace for drivers and shippers
 * Bidding system, rating system, automated matching
 */

import { PrismaClient } from "@prisma/client";
import { EventEmitter } from "events";

const prisma = new PrismaClient();

/**
 * Marketplace listing
 */
export interface MarketplaceListing {
  id: string;
  shipmentId?: string;
  origin: string;
  destination: string;
  weight: number;
  description: string;
  pickupDate: Date;
  deliveryDate: Date;
  budgetMin: number;
  budgetMax: number;
  status: "open" | "bidding" | "awarded" | "completed" | "cancelled";
  customerId: string;
  tenantId: string;
  bids: Bid[];
  createdAt: Date;
}

/**
 * Bid on marketplace listing
 */
export interface Bid {
  id: string;
  listingId: string;
  driverId: string;
  amount: number;
  estimatedPickup: Date;
  estimatedDelivery: Date;
  message?: string;
  status: "pending" | "accepted" | "rejected" | "withdrawn";
  createdAt: Date;
}

/**
 * Rating
 */
export interface Rating {
  id: string;
  fromUserId: string;
  toUserId: string;
  shipmentId: string;
  rating: number; // 1-5
  comment?: string;
  categories?: {
    communication?: number;
    timeliness?: number;
    professionalism?: number;
    condition?: number;
  };
  createdAt: Date;
}

/**
 * Marketplace manager
 */
export class MarketplaceManager extends EventEmitter {
  /**
   * Create marketplace listing
   */
  async createListing(
    data: Omit<MarketplaceListing, "id" | "bids" | "createdAt" | "status">,
  ): Promise<MarketplaceListing> {
    const listing = (await prisma.marketplaceListing.create({
      data: {
        ...data,
        status: "open",
      },
      include: {
        bids: true,
      },
    })) as any;

    // Emit event for notifications
    this.emit("listing-created", listing);

    // Auto-match drivers
    await this.autoMatchDrivers(listing.id);

    console.log(`✅ Marketplace listing created: ${listing.id}`);
    return listing;
  }

  /**
   * Place bid on listing
   */
  async placeBid(data: Omit<Bid, "id" | "createdAt" | "status">): Promise<Bid> {
    // Validate bid amount
    const listing = await prisma.marketplaceListing.findUnique({
      where: { id: data.listingId },
    });

    if (!listing) {
      throw new Error("Listing not found");
    }

    if (listing.status !== "open" && listing.status !== "bidding") {
      throw new Error("Listing is not accepting bids");
    }

    if (
      data.amount < (listing as any).budgetMin ||
      data.amount > (listing as any).budgetMax
    ) {
      throw new Error(
        `Bid must be between $${(listing as any).budgetMin} and $${(listing as any).budgetMax}`,
      );
    }

    // Check if driver already bid
    const existingBid = await prisma.marketplaceBid.findFirst({
      where: {
        listingId: data.listingId,
        driverId: data.driverId,
        status: { not: "withdrawn" },
      },
    });

    if (existingBid) {
      throw new Error("Driver already has an active bid on this listing");
    }

    // Create bid
    const bid = (await prisma.marketplaceBid.create({
      data: {
        ...data,
        status: "pending",
      },
    })) as any;

    // Update listing status
    await prisma.marketplaceListing.update({
      where: { id: data.listingId },
      data: { status: "bidding" },
    });

    // Emit event
    this.emit("bid-placed", { bid, listing });

    console.log(`✅ Bid placed: $${data.amount} by driver ${data.driverId}`);
    return bid;
  }

  /**
   * Accept bid
   */
  async acceptBid(bidId: string, customerId: string): Promise<void> {
    const bid = await prisma.marketplaceBid.findUnique({
      where: { id: bidId },
      include: { listing: true },
    });

    if (!bid) {
      throw new Error("Bid not found");
    }

    if ((bid.listing as any).customerId !== customerId) {
      throw new Error("Only the listing owner can accept bids");
    }

    // Accept bid
    await prisma.marketplaceBid.update({
      where: { id: bidId },
      data: { status: "accepted" },
    });

    // Reject other bids
    await prisma.marketplaceBid.updateMany({
      where: {
        listingId: bid.listingId,
        id: { not: bidId },
        status: "pending",
      },
      data: { status: "rejected" },
    });

    // Update listing
    await prisma.marketplaceListing.update({
      where: { id: bid.listingId },
      data: { status: "awarded" },
    });

    // Create shipment
    const shipment = await prisma.shipment.create({
      data: {
        trackingNumber: `MKT-${Date.now()}`,
        origin: (bid.listing as any).origin,
        destination: (bid.listing as any).destination,
        weight: (bid.listing as any).weight,
        customerId: (bid.listing as any).customerId,
        driverId: bid.driverId,
        status: "PENDING",
        tenantId: (bid.listing as any).tenantId,
      },
    });

    // Link shipment to listing
    await prisma.marketplaceListing.update({
      where: { id: bid.listingId },
      data: { shipmentId: shipment.id },
    });

    // Emit event
    this.emit("bid-accepted", { bid, shipment });

    console.log(`✅ Bid accepted: ${bidId} for shipment ${shipment.id}`);
  }

  /**
   * Withdraw bid
   */
  async withdrawBid(bidId: string, driverId: string): Promise<void> {
    const bid = await prisma.marketplaceBid.findUnique({
      where: { id: bidId },
    });

    if (!bid) {
      throw new Error("Bid not found");
    }

    if (bid.driverId !== driverId) {
      throw new Error("Only the bid owner can withdraw");
    }

    if (bid.status !== "pending") {
      throw new Error("Can only withdraw pending bids");
    }

    await prisma.marketplaceBid.update({
      where: { id: bidId },
      data: { status: "withdrawn" },
    });

    this.emit("bid-withdrawn", bid);

    console.log(`✅ Bid withdrawn: ${bidId}`);
  }

  /**
   * Submit rating
   */
  async submitRating(data: Omit<Rating, "id" | "createdAt">): Promise<Rating> {
    // Validate rating
    if (data.rating < 1 || data.rating > 5) {
      throw new Error("Rating must be between 1 and 5");
    }

    // Check if already rated
    const existing = await prisma.rating.findFirst({
      where: {
        fromUserId: data.fromUserId,
        toUserId: data.toUserId,
        shipmentId: data.shipmentId,
      },
    });

    if (existing) {
      throw new Error("Already rated this user for this shipment");
    }

    const rating = (await prisma.rating.create({
      data: data as any,
    })) as any;

    // Update user average rating
    await this.updateAverageRating(data.toUserId);

    this.emit("rating-submitted", rating);

    console.log(
      `✅ Rating submitted: ${data.rating} stars for user ${data.toUserId}`,
    );
    return rating;
  }

  /**
   * Get user ratings
   */
  async getUserRatings(
    userId: string,
  ): Promise<{ average: number; count: number; ratings: Rating[] }> {
    const ratings = await prisma.rating.findMany({
      where: { toUserId: userId },
      orderBy: { createdAt: "desc" },
      include: {
        fromUser: { select: { name: true } },
      },
    });

    const average =
      ratings.length > 0
        ? ratings.reduce((sum, r) => sum + (r as any).rating, 0) /
          ratings.length
        : 0;

    return {
      average: Math.round(average * 10) / 10,
      count: ratings.length,
      ratings: ratings as any,
    };
  }

  /**
   * Get marketplace listings
   */
  async getListings(filters: {
    status?: string[];
    origin?: string;
    destination?: string;
    minBudget?: number;
    maxBudget?: number;
    pickupAfter?: Date;
    pickupBefore?: Date;
    tenantId?: string;
  }): Promise<MarketplaceListing[]> {
    return prisma.marketplaceListing.findMany({
      where: {
        status: filters.status ? { in: filters.status } : undefined,
        origin: filters.origin
          ? { contains: filters.origin, mode: "insensitive" }
          : undefined,
        destination: filters.destination
          ? { contains: filters.destination, mode: "insensitive" }
          : undefined,
        budgetMin: filters.minBudget ? { gte: filters.minBudget } : undefined,
        budgetMax: filters.maxBudget ? { lte: filters.maxBudget } : undefined,
        pickupDate: {
          gte: filters.pickupAfter,
          lte: filters.pickupBefore,
        },
        tenantId: filters.tenantId,
      },
      include: {
        bids: true,
        customer: { select: { name: true, email: true } },
      },
      orderBy: { createdAt: "desc" },
    }) as any;
  }

  /**
   * Get driver bids
   */
  async getDriverBids(driverId: string): Promise<Bid[]> {
    return prisma.marketplaceBid.findMany({
      where: { driverId },
      include: {
        listing: true,
      },
      orderBy: { createdAt: "desc" },
    }) as any;
  }

  /**
   * Auto-match drivers based on criteria
   */
  private async autoMatchDrivers(listingId: string): Promise<void> {
    const listing = await prisma.marketplaceListing.findUnique({
      where: { id: listingId },
    });

    if (!listing) return;

    // Find available drivers in the area
    const drivers = await prisma.driver.findMany({
      where: {
        status: "AVAILABLE",
        tenantId: (listing as any).tenantId,
        // Add location-based filtering here
      },
      include: {
        user: true,
      },
      take: 10,
    });

    // Notify matched drivers
    for (const driver of drivers) {
      this.emit("driver-matched", { listing, driver });
    }

    console.log(
      `🎯 Auto-matched ${drivers.length} drivers for listing ${listingId}`,
    );
  }

  /**
   * Update user average rating
   */
  private async updateAverageRating(userId: string): Promise<void> {
    const { average } = await this.getUserRatings(userId);

    await prisma.user.update({
      where: { id: userId },
      data: { averageRating: average },
    });
  }
}

// Export singleton
export const marketplaceManager = new MarketplaceManager();

/**
 * Usage:
 *
 * // Create marketplace listing
 * const listing = await marketplaceManager.createListing({
 *   origin: 'New York, NY',
 *   destination: 'Los Angeles, CA',
 *   weight: 5000,
 *   description: 'Electronics shipment',
 *   pickupDate: new Date('2026-02-01'),
 *   deliveryDate: new Date('2026-02-05'),
 *   budgetMin: 1500,
 *   budgetMax: 2500,
 *   customerId: 'customer-123',
 *   tenantId: 'tenant-456',
 * });
 *
 * // Place bid
 * const bid = await marketplaceManager.placeBid({
 *   listingId: listing.id,
 *   driverId: 'driver-789',
 *   amount: 2000,
 *   estimatedPickup: new Date('2026-02-01T08:00:00'),
 *   estimatedDelivery: new Date('2026-02-05T17:00:00'),
 *   message: 'I can handle this shipment with care',
 * });
 *
 * // Accept bid
 * await marketplaceManager.acceptBid(bid.id, 'customer-123');
 *
 * // Submit rating
 * await marketplaceManager.submitRating({
 *   fromUserId: 'customer-123',
 *   toUserId: 'driver-789',
 *   shipmentId: 'shipment-abc',
 *   rating: 5,
 *   comment: 'Excellent service!',
 *   categories: {
 *     communication: 5,
 *     timeliness: 5,
 *     professionalism: 5,
 *     condition: 5,
 *   },
 * });
 *
 * // Get ratings
 * const ratings = await marketplaceManager.getUserRatings('driver-789');
 * console.log(`Average rating: ${ratings.average} (${ratings.count} reviews)`);
 *
 * Database schema:
 *
 * model MarketplaceListing {
 *   id           String   @id @default(uuid())
 *   origin       String
 *   destination  String
 *   weight       Float
 *   description  String
 *   pickupDate   DateTime
 *   deliveryDate DateTime
 *   budgetMin    Float
 *   budgetMax    Float
 *   status       String
 *   customerId   String
 *   tenantId     String
 *   shipmentId   String?
 *   bids         MarketplaceBid[]
 *   createdAt    DateTime @default(now())
 * }
 *
 * model MarketplaceBid {
 *   id                String   @id @default(uuid())
 *   listingId         String
 *   listing           MarketplaceListing @relation(fields: [listingId], references: [id])
 *   driverId          String
 *   driver            Driver   @relation(fields: [driverId], references: [id])
 *   amount            Float
 *   estimatedPickup   DateTime
 *   estimatedDelivery DateTime
 *   message           String?
 *   status            String
 *   createdAt         DateTime @default(now())
 * }
 *
 * model Rating {
 *   id         String   @id @default(uuid())
 *   fromUserId String
 *   fromUser   User     @relation("RatingsGiven", fields: [fromUserId], references: [id])
 *   toUserId   String
 *   toUser     User     @relation("RatingsReceived", fields: [toUserId], references: [id])
 *   shipmentId String
 *   rating     Int
 *   comment    String?
 *   categories Json?
 *   createdAt  DateTime @default(now())
 * }
 *
 * Benefits:
 * - Two-sided marketplace
 * - Competitive bidding
 * - Transparent pricing
 * - Rating system
 * - Auto-matching
 * - Increased driver utilization
 * - Better pricing for customers
 */
