/**
 * Unit tests for deliveryTime validation logic in dispatch routes
 * Tests the custom validation that ensures deliveryTime must be after pickupTime
 */

describe("Dispatch Routes - DeliveryTime Validation Logic", () => {
  /**
   * Test the custom validation logic that checks if deliveryTime is after pickupTime
   * This replicates the logic from dispatch.ts lines 116-132
   */
  const validateDeliveryTime = (
    deliveryTimeValue: string,
    pickupTimeValue: string | undefined,
  ): { isValid: boolean; error?: string } => {
    if (!pickupTimeValue) {
      // pickupTime is validated separately; if it's missing, let that validator handle it
      return { isValid: true };
    }

    const pickup = new Date(pickupTimeValue);
    const delivery = new Date(deliveryTimeValue);

    if (isNaN(pickup.getTime()) || isNaN(delivery.getTime())) {
      // Format errors are handled by .isISO8601(); do not duplicate here
      return { isValid: true };
    }

    if (delivery <= pickup) {
      return {
        isValid: false,
        error: "deliveryTime must be after pickupTime",
      };
    }

    return { isValid: true };
  };

  describe("Custom deliveryTime validation logic", () => {
    it("should accept deliveryTime after pickupTime", () => {
      const result = validateDeliveryTime(
        "2025-12-30T14:00:00Z",
        "2025-12-30T10:00:00Z",
      );
      expect(result.isValid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it("should reject deliveryTime before pickupTime", () => {
      const result = validateDeliveryTime(
        "2025-12-30T10:00:00Z",
        "2025-12-30T14:00:00Z",
      );
      expect(result.isValid).toBe(false);
      expect(result.error).toBe("deliveryTime must be after pickupTime");
    });

    it("should reject deliveryTime equal to pickupTime", () => {
      const result = validateDeliveryTime(
        "2025-12-30T12:00:00Z",
        "2025-12-30T12:00:00Z",
      );
      expect(result.isValid).toBe(false);
      expect(result.error).toBe("deliveryTime must be after pickupTime");
    });

    it("should accept deliveryTime 1 second after pickupTime", () => {
      const result = validateDeliveryTime(
        "2025-12-30T12:00:01Z",
        "2025-12-30T12:00:00Z",
      );
      expect(result.isValid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it("should handle timezone differences correctly", () => {
      const result = validateDeliveryTime(
        "2025-12-31T00:00:00+00:00",
        "2025-12-30T23:59:59+00:00",
      );
      expect(result.isValid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it("should return valid when pickupTime is undefined", () => {
      const result = validateDeliveryTime("2025-12-30T14:00:00Z", undefined);
      expect(result.isValid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it("should return valid when pickupTime is invalid ISO8601 format", () => {
      const result = validateDeliveryTime(
        "2025-12-30T14:00:00Z",
        "invalid-date",
      );
      expect(result.isValid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it("should return valid when deliveryTime is invalid ISO8601 format", () => {
      const result = validateDeliveryTime(
        "invalid-date",
        "2025-12-30T10:00:00Z",
      );
      expect(result.isValid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it("should handle different date formats", () => {
      const result = validateDeliveryTime(
        "2025-12-31T00:00:00.000Z",
        "2025-12-30T00:00:00.000Z",
      );
      expect(result.isValid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it("should handle dates far apart", () => {
      const result = validateDeliveryTime(
        "2026-01-15T10:00:00Z",
        "2025-12-30T10:00:00Z",
      );
      expect(result.isValid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it("should reject when delivery is 1 millisecond before pickup", () => {
      const pickup = new Date("2025-12-30T12:00:00.000Z");
      const delivery = new Date(pickup.getTime() - 1);

      const result = validateDeliveryTime(
        delivery.toISOString(),
        pickup.toISOString(),
      );
      expect(result.isValid).toBe(false);
      expect(result.error).toBe("deliveryTime must be after pickupTime");
    });
  });
});
