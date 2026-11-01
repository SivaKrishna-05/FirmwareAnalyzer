import express, { type Express } from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import pinoHttp from "pino-http";
import router from "./routes";
import { logger } from "./lib/logger";
import { attachUser } from "./lib/auth/middleware";

const app: Express = express();

app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req) {
        return {
          id: req.id,
          method: req.method,
          url: req.url?.split("?")[0],
        };
      },
      res(res) {
        return {
          statusCode: res.statusCode,
        };
      },
    },
  }),
);
/**
 * CORS.
 *
 * Now that authentication uses cookies, a permissive `cors()` is unsafe:
 * credentialed requests require an explicit origin allowlist, and reflecting
 * an arbitrary Origin with credentials enabled would let any site call this
 * API as the signed-in user. Same-origin deployments need no entry here.
 */
const allowedOrigins = (process.env.CORS_ALLOWED_ORIGINS ?? "")
  .split(",")
  .map((origin) => origin.trim())
  .filter((origin) => origin.length > 0);

app.use(
  cors({
    origin(origin, callback) {
      // Same-origin and non-browser clients send no Origin header.
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(null, false);
    },
    credentials: true,
  }),
);

// `trust proxy` is required for req.ip to be meaningful behind Replit's
// proxy; it feeds the rate limiter key and the audit trail.
app.set("trust proxy", 1);

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Resolves the session cookie and attaches req.user when valid. It never
// rejects — individual routes decide what they require.
app.use(attachUser);

app.use("/api", router);

export default app;
