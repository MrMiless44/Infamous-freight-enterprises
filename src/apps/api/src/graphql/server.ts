/**
 * GraphQL Server Setup
 * Apollo Server v4 with Express integration
 */

import { ApolloServer } from "@apollo/server";
import { expressMiddleware } from "@apollo/server/express4";
import { ApolloServerPluginDrainHttpServer } from "@apollo/server/plugin/drainHttpServer";
import { makeExecutableSchema } from "@graphql-tools/schema";
import { WebSocketServer } from "ws";
import { useServer } from "graphql-ws/lib/use/ws";
import { createServer } from "http";
import express, { Express } from "express";
import cors from "cors";
import { json } from "body-parser";
import jwt from "jsonwebtoken";

import typeDefs from "./schema";
import resolvers from "./resolvers";

const PORT = process.env.GRAPHQL_PORT || 4001;

/**
 * Create GraphQL context from request
 */
async function createContext({ req }: { req: express.Request }) {
  const token = req.headers.authorization?.replace("Bearer ", "");

  if (!token) {
    return { user: null };
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;
    return { user: decoded };
  } catch (error) {
    console.error("JWT verification failed:", error);
    return { user: null };
  }
}

/**
 * Setup Apollo Server with WebSocket subscriptions
 */
export async function createApolloServer(app: Express) {
  // Create HTTP server
  const httpServer = createServer(app);

  // Create schema
  const schema = makeExecutableSchema({ typeDefs, resolvers });

  // WebSocket server for subscriptions
  const wsServer = new WebSocketServer({
    server: httpServer,
    path: "/graphql",
  });

  // WebSocket server cleanup
  const serverCleanup = useServer(
    {
      schema,
      context: async (ctx) => {
        // Extract token from connection params
        const token = ctx.connectionParams?.authorization?.replace(
          "Bearer ",
          "",
        );

        if (!token) {
          return { user: null };
        }

        try {
          const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;
          return { user: decoded };
        } catch (error) {
          return { user: null };
        }
      },
    },
    wsServer,
  );

  // Apollo Server
  const server = new ApolloServer({
    schema,
    plugins: [
      // Proper shutdown for HTTP server
      ApolloServerPluginDrainHttpServer({ httpServer }),

      // Proper shutdown for WebSocket server
      {
        async serverWillStart() {
          return {
            async drainServer() {
              await serverCleanup.dispose();
            },
          };
        },
      },
    ],
  });

  await server.start();

  // Apply middleware
  app.use(
    "/graphql",
    cors<cors.CorsRequest>({
      origin: process.env.CORS_ORIGINS?.split(",") || "*",
      credentials: true,
    }),
    json(),
    expressMiddleware(server, {
      context: createContext,
    }),
  );

  return { server, httpServer };
}

/**
 * Start GraphQL server
 */
export async function startGraphQLServer() {
  const app = express();

  const { httpServer } = await createApolloServer(app);

  httpServer.listen(PORT, () => {
    console.log(`🚀 GraphQL server ready at http://localhost:${PORT}/graphql`);
    console.log(`🔌 Subscriptions ready at ws://localhost:${PORT}/graphql`);
  });

  return httpServer;
}

/**
 * Usage:
 *
 * // Start standalone GraphQL server
 * import { startGraphQLServer } from './graphql/server';
 * startGraphQLServer();
 *
 * // Or integrate with existing Express app
 * import { createApolloServer } from './graphql/server';
 * const app = express();
 * await createApolloServer(app);
 * app.listen(4000);
 *
 * // Query example
 * query GetShipment {
 *   shipment(trackingNumber: "INF-2024-001") {
 *     id
 *     trackingNumber
 *     status
 *     origin
 *     destination
 *     driver {
 *       user {
 *         name
 *       }
 *     }
 *     history {
 *       type
 *       description
 *       timestamp
 *     }
 *   }
 * }
 *
 * // Mutation example
 * mutation CreateShipment {
 *   createShipment(input: {
 *     origin: "New York, NY"
 *     destination: "Los Angeles, CA"
 *     weight: 500
 *     dimensions: {
 *       length: 10
 *       width: 8
 *       height: 6
 *       unit: "inches"
 *     }
 *   }) {
 *     id
 *     trackingNumber
 *     status
 *   }
 * }
 *
 * // Subscription example
 * subscription OnShipmentUpdate {
 *   shipmentUpdated(id: "123") {
 *     id
 *     status
 *     currentLocation {
 *       latitude
 *       longitude
 *     }
 *   }
 * }
 *
 * Benefits:
 * - Flexible queries (request only what you need)
 * - Strong typing with schema
 * - Real-time subscriptions
 * - Single endpoint
 * - Automatic documentation (GraphQL Playground)
 * - Reduced over-fetching
 * - Better developer experience
 */
