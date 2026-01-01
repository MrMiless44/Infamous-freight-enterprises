/**
 * GraphQL Schema Definition
 * Modern alternative to REST API with flexible queries
 * Apollo Server v4 integration
 */

import { gql } from "apollo-server-express";

export const typeDefs = gql`
  # Scalars
  scalar DateTime
  scalar JSON

  # Enums
  enum ShipmentStatus {
    PENDING
    IN_TRANSIT
    DELIVERED
    CANCELLED
  }

  enum UserRole {
    ADMIN
    DRIVER
    CUSTOMER
  }

  enum DriverStatus {
    ACTIVE
    INACTIVE
    ON_BREAK
  }

  # Types
  type User {
    id: ID!
    email: String!
    name: String!
    role: UserRole!
    phone: String
    createdAt: DateTime!
    shipments: [Shipment!]!
  }

  type Driver {
    id: ID!
    user: User!
    licenseNumber: String!
    status: DriverStatus!
    rating: Float
    vehicleType: String
    currentLocation: Location
    assignedShipments: [Shipment!]!
    completedShipments: Int!
    totalDistance: Float!
    earnings: Float!
  }

  type Location {
    latitude: Float!
    longitude: Float!
    accuracy: Float
    timestamp: DateTime!
  }

  type Shipment {
    id: ID!
    trackingNumber: String!
    status: ShipmentStatus!
    origin: String!
    destination: String!
    weight: Float!
    dimensions: Dimensions
    customer: User!
    driver: Driver
    pickupTime: DateTime
    deliveryTime: DateTime
    estimatedDelivery: DateTime
    currentLocation: Location
    history: [ShipmentEvent!]!
    photos: [String!]
    documents: [String!]
    cost: Float!
    createdAt: DateTime!
    updatedAt: DateTime!
  }

  type Dimensions {
    length: Float!
    width: Float!
    height: Float!
    unit: String!
  }

  type ShipmentEvent {
    id: ID!
    type: String!
    description: String!
    location: Location
    timestamp: DateTime!
    metadata: JSON
  }

  type Route {
    id: ID!
    driver: Driver!
    origin: String!
    waypoints: [Waypoint!]!
    totalDistance: Float!
    totalDuration: Int!
    fuelCost: Float!
    status: String!
    createdAt: DateTime!
  }

  type Waypoint {
    order: Int!
    shipment: Shipment!
    address: String!
    arrivalTime: DateTime
    completed: Boolean!
  }

  type Analytics {
    totalShipments: Int!
    activeShipments: Int!
    completedShipments: Int!
    averageDeliveryTime: Float!
    onTimeRate: Float!
    customerSatisfaction: Float!
    revenue: Float!
    topDrivers: [Driver!]!
  }

  type Forecast {
    date: DateTime!
    predictedShipments: Int!
    confidence: Float!
    lowerBound: Int!
    upperBound: Int!
  }

  # Inputs
  input CreateShipmentInput {
    origin: String!
    destination: String!
    weight: Float!
    dimensions: DimensionsInput
    description: String
    scheduledPickup: DateTime
  }

  input DimensionsInput {
    length: Float!
    width: Float!
    height: Float!
    unit: String!
  }

  input UpdateShipmentInput {
    status: ShipmentStatus
    driverId: ID
    estimatedDelivery: DateTime
    currentLocation: LocationInput
  }

  input LocationInput {
    latitude: Float!
    longitude: Float!
    accuracy: Float
  }

  input OptimizeRouteInput {
    driverId: ID!
    origin: String!
    shipmentIds: [ID!]!
  }

  input AnalyticsFilter {
    startDate: DateTime!
    endDate: DateTime!
    driverId: ID
    customerId: ID
    status: ShipmentStatus
  }

  # Pagination
  type ShipmentConnection {
    edges: [ShipmentEdge!]!
    pageInfo: PageInfo!
    totalCount: Int!
  }

  type ShipmentEdge {
    node: Shipment!
    cursor: String!
  }

  type PageInfo {
    hasNextPage: Boolean!
    hasPreviousPage: Boolean!
    startCursor: String
    endCursor: String
  }

  # Queries
  type Query {
    # User queries
    me: User!
    user(id: ID!): User
    users(role: UserRole, first: Int, after: String): [User!]!

    # Shipment queries
    shipment(id: ID, trackingNumber: String): Shipment
    shipments(
      status: ShipmentStatus
      customerId: ID
      driverId: ID
      first: Int
      after: String
    ): ShipmentConnection!

    searchShipments(query: String!, first: Int): [Shipment!]!

    # Driver queries
    driver(id: ID!): Driver
    drivers(status: DriverStatus, first: Int): [Driver!]!
    nearbyDrivers(
      latitude: Float!
      longitude: Float!
      radius: Float!
    ): [Driver!]!

    # Route queries
    route(id: ID!): Route
    routes(driverId: ID, status: String): [Route!]!

    # Analytics queries
    analytics(filter: AnalyticsFilter!): Analytics!
    forecast(startDate: DateTime!, days: Int!): [Forecast!]!

    # Real-time queries
    liveShipment(id: ID!): Shipment!
    liveDriver(id: ID!): Driver!
  }

  # Mutations
  type Mutation {
    # Shipment mutations
    createShipment(input: CreateShipmentInput!): Shipment!
    updateShipment(id: ID!, input: UpdateShipmentInput!): Shipment!
    cancelShipment(id: ID!, reason: String): Shipment!
    assignDriver(shipmentId: ID!, driverId: ID!): Shipment!

    # Driver mutations
    updateDriverLocation(driverId: ID!, location: LocationInput!): Driver!
    updateDriverStatus(driverId: ID!, status: DriverStatus!): Driver!

    # Route mutations
    optimizeRoute(input: OptimizeRouteInput!): Route!
    completeWaypoint(routeId: ID!, waypointOrder: Int!): Route!

    # Photo/Document uploads
    uploadShipmentPhoto(shipmentId: ID!, photo: String!): Shipment!
    uploadShipmentDocument(shipmentId: ID!, document: String!): Shipment!
  }

  # Subscriptions
  type Subscription {
    # Real-time shipment updates
    shipmentUpdated(id: ID!): Shipment!
    shipmentStatusChanged(trackingNumber: String!): Shipment!

    # Real-time driver location
    driverLocationUpdated(id: ID!): Driver!

    # Real-time notifications
    notificationReceived(userId: ID!): Notification!
  }

  type Notification {
    id: ID!
    type: String!
    title: String!
    message: String!
    timestamp: DateTime!
    read: Boolean!
    metadata: JSON
  }
`;

export default typeDefs;
