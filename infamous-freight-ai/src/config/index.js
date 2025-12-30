const { z } = require("zod");

const EnvSchema = z.object({
    NODE_ENV: z.string().default("development"),
    PORT: z.coerce.number().default(4000),

    DATABASE_URL: z.string().min(1),

    JWT_SECRET: z.string().min(16),
    AI_SYNTHETIC_API_KEY: z.string().min(8),

    AI_ENGINE_URL: z.string().url(),
    AI_SECURITY_MODE: z.string().default("strict")
});

function loadConfig(env = process.env) {
    const parsed = EnvSchema.safeParse(env);
    if (!parsed.success) {
        throw new Error(
            parsed.error.issues.map(i => `${i.path}: ${i.message}`).join("\n")
        );
    }
    return parsed.data;
}

module.exports = { loadConfig };
