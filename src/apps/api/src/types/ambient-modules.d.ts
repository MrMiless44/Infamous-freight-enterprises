declare module "helmet" {
  import { RequestHandler } from "express";
  const helmet: () => RequestHandler;
  export default helmet;
}

declare module "express-rate-limit" {
  import { RequestHandler } from "express";
  interface RateLimitOptions {
    windowMs?: number;
    max?: number;
    message?: string | Record<string, unknown>;
    keyGenerator?: (req: any) => string;
    skip?: (req: any) => boolean;
    standardHeaders?: boolean;
    legacyHeaders?: boolean;
    store?: any;
  }
  const rateLimit: (options: RateLimitOptions) => RequestHandler;
  export default rateLimit;
}

declare module "rate-limit-redis" {
  import { RateLimitRequestHandler } from "express-rate-limit";
  interface RedisStoreOptions {
    sendCommand?: (...args: string[]) => Promise<unknown>;
    prefix?: string;
  }
  export default class RedisStore implements RateLimitRequestHandler {
    constructor(options: RedisStoreOptions);
  }
}
