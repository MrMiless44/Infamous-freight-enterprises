import { Router } from "express";
import { getAvatarInsights } from "../avatar/assistant";
import { requireAuth } from "../middleware/auth";

export const avatar = Router();

avatar.use(requireAuth);

avatar.get("/insights", async (req, res) => {
  const insights = await getAvatarInsights(
    req.user.id,
    req.user.organizationId,
  );
  res.json(insights);
});
