import { Router } from "express";
import { aiDecisionV1 } from "../ai/v1";

export const ai = Router();
ai.post("/audit", (_, res) => res.json(aiDecisionV1()));
