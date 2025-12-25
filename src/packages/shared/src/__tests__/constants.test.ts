import {
  HTTP_STATUS,
  ERROR_MESSAGES,
  SHIPMENT_STATUSES,
  USER_ROLES,
} from "../constants";

describe("HTTP_STATUS", () => {
  it("should have correct status codes", () => {
    expect(HTTP_STATUS.OK).toBe(200);
    expect(HTTP_STATUS.CREATED).toBe(201);
    expect(HTTP_STATUS.BAD_REQUEST).toBe(400);
    expect(HTTP_STATUS.UNAUTHORIZED).toBe(401);
    expect(HTTP_STATUS.FORBIDDEN).toBe(403);
    expect(HTTP_STATUS.NOT_FOUND).toBe(404);
    expect(HTTP_STATUS.INTERNAL_ERROR).toBe(500);
  });
});

describe("ERROR_MESSAGES", () => {
  it("should have standard error messages", () => {
    expect(ERROR_MESSAGES.UNAUTHORIZED).toBe("Unauthorized access");
    expect(ERROR_MESSAGES.NOT_FOUND).toBe("Resource not found");
    expect(ERROR_MESSAGES.INTERNAL_ERROR).toBe("Internal server error");
    expect(ERROR_MESSAGES.VALIDATION_ERROR).toBe("Validation error");
  });
});

describe("SHIPMENT_STATUSES", () => {
  it("should have all shipment status values", () => {
    expect(SHIPMENT_STATUSES.PENDING).toBe("pending");
    expect(SHIPMENT_STATUSES.IN_TRANSIT).toBe("in_transit");
    expect(SHIPMENT_STATUSES.DELIVERED).toBe("delivered");
    expect(SHIPMENT_STATUSES.CANCELLED).toBe("cancelled");
  });

  it("should have exactly 4 statuses", () => {
    expect(Object.keys(SHIPMENT_STATUSES)).toHaveLength(4);
  });
});

describe("USER_ROLES", () => {
  it("should have all user role values", () => {
    expect(USER_ROLES.ADMIN).toBe("admin");
    expect(USER_ROLES.DRIVER).toBe("driver");
    expect(USER_ROLES.CUSTOMER).toBe("customer");
  });

  it("should have exactly 3 roles", () => {
    expect(Object.keys(USER_ROLES)).toHaveLength(3);
  });
});
