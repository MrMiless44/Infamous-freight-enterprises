# New API Routes Documentation

This document describes the new API routes added for dispatch, driver, fleet, and customer management.

## Overview

Four new route modules have been added to the API:

1. **Dispatch** - Load management and AI-powered assignment
2. **Driver** - Driver management and performance tracking
3. **Fleet** - Vehicle management and maintenance tracking
4. **Customer** - Customer management and AI support

All routes require authentication and implement role-based access control (RBAC).

## Authentication

All routes use JWT bearer token authentication:

```
Authorization: Bearer <token>
```

The token must contain:

- `id` or `sub` - User ID
- `organizationId` - Organization ID
- `role` - User role (ADMIN, DISPATCHER, DRIVER, CUSTOMER)
- `scopes` - Array of permission scopes (optional)

## Dispatch Routes

Base path: `/api/dispatch`

### GET /loads

Get a paginated list of loads.

**Query Parameters:**

- `status` (optional) - Filter by status: PENDING, ASSIGNED, IN_TRANSIT, DELIVERED, CANCELLED
- `page` (optional) - Page number (default: 1)
- `limit` (optional) - Results per page (default: 10)

**Response:**

```json
{
  "status": "success",
  "data": {
    "loads": [...],
    "pagination": {
      "page": 1,
      "limit": 10,
      "total": 50,
      "pages": 5
    }
  }
}
```

### GET /loads/:id

Get details for a specific load.

**Parameters:**

- `id` - Load ID

**Response:**

```json
{
  "status": "success",
  "data": {
    "load": {
      "id": "...",
      "loadNumber": "LOAD-1234567890-123",
      "customer": {...},
      "driver": {...},
      "vehicle": {...},
      "aiDecisions": [...]
    }
  }
}
```

### POST /loads

Create a new load. Requires ADMIN or DISPATCHER role.

**Request Body:**

```json
{
  "customerId": "customer-uuid",
  "pickupAddress": "123 Main St, City, ST",
  "pickupLat": 40.7128,
  "pickupLng": -74.006,
  "deliveryAddress": "456 Oak Ave, City, ST",
  "deliveryLat": 41.8781,
  "deliveryLng": -87.6298,
  "pickupTime": "2024-01-15T10:00:00Z",
  "deliveryTime": "2024-01-16T14:00:00Z",
  "weight": 15000.5,
  "rate": 2500.0,
  "description": "Optional load description"
}
```

**Response:**

```json
{
  "status": "success",
  "data": {
    "load": {...}
  }
}
```

### POST /loads/:id/assign

Assign a load to a driver and vehicle. Requires ADMIN or DISPATCHER role.

**Parameters:**

- `id` - Load ID

**Request Body:**

```json
{
  "driverId": "driver-uuid (optional)",
  "vehicleId": "vehicle-uuid (optional)",
  "useAI": true
}
```

If `useAI` is true and driverId/vehicleId are not provided, the AI will recommend assignments.

**Response:**

```json
{
  "status": "success",
  "data": {
    "load": {...},
    "aiDecision": {
      "reasoning": "Driver John Doe selected with 2 active loads...",
      "confidence": 0.85
    }
  }
}
```

### POST /optimize

Get AI-powered route optimization for multiple loads. Requires ADMIN or DISPATCHER role.

**Request Body:**

```json
{
  "loadIds": ["load-uuid-1", "load-uuid-2", "load-uuid-3"]
}
```

**Response:**

```json
{
  "status": "success",
  "data": {
    "recommendations": [
      {
        "loadId": "...",
        "driverId": "...",
        "vehicleId": "...",
        "priority": 1
      }
    ],
    "reasoning": "Optimized 3 loads across 2 drivers...",
    "confidence": 0.78,
    "estimatedSavings": {
      "time": 45,
      "fuel": 7.5,
      "cost": 75
    }
  }
}
```

## Driver Routes

Base path: `/api/drivers`

### GET /

Get a list of all drivers.

**Query Parameters:**

- `isAvailable` (optional) - Filter by availability (true/false)
- `page` (optional) - Page number
- `limit` (optional) - Results per page

### GET /:id

Get details for a specific driver including active loads and coaching history.

### POST /:id/coaching

Get AI-powered coaching for a driver.

**Response:**

```json
{
  "status": "success",
  "data": {
    "coaching": {
      "feedback": "Good performance! Small improvements...",
      "metrics": {
        "onTimePerformance": 92.5,
        "averageRating": 4.7,
        "totalLoads": 156,
        "improvementAreas": ["Timing optimization"]
      },
      "suggestions": {
        "priority": "medium",
        "actions": ["Analyze past late deliveries for patterns"]
      }
    },
    "session": {...}
  }
}
```

### GET /:id/performance

Get performance metrics for a driver.

**Query Parameters:**

- `startDate` (optional) - ISO 8601 date
- `endDate` (optional) - ISO 8601 date

### PUT /:id/location

Update driver's current location. Requires DRIVER or ADMIN role.

**Request Body:**

```json
{
  "latitude": 40.7128,
  "longitude": -74.006
}
```

## Fleet Routes

Base path: `/api/fleet`

### GET /vehicles

Get a list of all vehicles.

**Query Parameters:**

- `status` (optional) - Filter by status: AVAILABLE, IN_USE, MAINTENANCE

### GET /vehicles/:id

Get details for a specific vehicle including maintenance logs and active loads.

### POST /vehicles/:id/maintenance

Log maintenance for a vehicle. Requires ADMIN or DISPATCHER role.

**Request Body:**

```json
{
  "type": "Oil Change",
  "description": "Regular oil change service",
  "cost": 75.0,
  "nextDue": "2024-03-15T00:00:00Z"
}
```

### GET /vehicles/:id/predict-maintenance

Get AI-powered maintenance predictions for a vehicle.

**Response:**

```json
{
  "status": "success",
  "data": {
    "predictions": [
      {
        "type": "Oil Change",
        "recommendedDate": "2024-02-01T00:00:00Z",
        "urgency": "medium",
        "estimatedCost": 75,
        "reasoning": "Based on mileage and time since last service..."
      }
    ],
    "overallRisk": "medium",
    "confidence": 0.82
  }
}
```

### GET /analytics

Get fleet-wide analytics.

**Response:**

```json
{
  "status": "success",
  "data": {
    "totalVehicles": 50,
    "availableVehicles": 35,
    "inUseVehicles": 12,
    "maintenanceVehicles": 3,
    "totalMileage": 2500000,
    "maintenanceCosts": 125000,
    "utilizationRate": 24
  }
}
```

## Customer Routes

Base path: `/api/customers`

### GET /

Get a list of all customers. Requires ADMIN or DISPATCHER role.

### GET /:id

Get details for a specific customer.

### GET /:id/loads

Get all loads for a specific customer.

**Query Parameters:**

- `status` (optional) - Filter by load status

### POST /support/ai

Get AI-powered customer support response.

**Request Body:**

```json
{
  "question": "Where is my shipment?",
  "customerId": "customer-uuid (optional)",
  "context": {}
}
```

**Response:**

```json
{
  "status": "success",
  "data": {
    "answer": "You can track your shipment by visiting...",
    "suggestions": ["View tracking page", "Contact your assigned driver"],
    "confidence": 0.9,
    "escalationNeeded": false
  }
}
```

## Error Responses

All routes return consistent error responses:

```json
{
  "status": "error",
  "errors": [
    {
      "msg": "Error message",
      "param": "fieldName",
      "location": "body"
    }
  ]
}
```

Common HTTP status codes:

- 400 - Bad Request (validation errors)
- 401 - Unauthorized (missing or invalid token)
- 403 - Forbidden (insufficient permissions)
- 404 - Not Found (resource doesn't exist)
- 500 - Internal Server Error

## Database Models

### Load

- Tracks shipments from pickup to delivery
- Links to Customer, Driver, and Vehicle
- Statuses: PENDING, ASSIGNED, IN_TRANSIT, DELIVERED, CANCELLED

### Driver

- Links to User account
- Tracks availability and current location
- Has many Loads and AICoachingSessions

### Vehicle

- Tracks fleet vehicles
- Has many MaintenanceLogs and Loads
- Statuses: AVAILABLE, IN_USE, MAINTENANCE

### Customer

- Links to User account
- Has many Loads

### AIDecision

- Logs AI-powered decisions for loads
- Tracks reasoning, confidence, and human approval

### AICoachingSession

- Stores driver coaching sessions
- Includes feedback, metrics, and suggestions

### MaintenanceLog

- Tracks vehicle maintenance history
- Records type, cost, and next due date

## AI Services

### aiDispatch.service

- `recommendAssignment(load)` - Recommends driver and vehicle for a load
- `optimizeRoutes(loads)` - Optimizes multiple load assignments

### aiCoach.service

- `generateCoaching(driver)` - Generates performance feedback for drivers

### aiFleet.service

- `predictMaintenance(vehicle)` - Predicts upcoming maintenance needs

### aiCustomer.service

- `getSupport(request)` - Provides AI-powered customer support responses
