import type { NextApiRequest, NextApiResponse } from "next";
import packageJson from "../../package.json";

export default function handler(_req: NextApiRequest, res: NextApiResponse) {
  res.status(200).json({
    status: "ok",
    service: "infamous-freight-web",
    version: packageJson.version || "2.0.0",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
  });
}
