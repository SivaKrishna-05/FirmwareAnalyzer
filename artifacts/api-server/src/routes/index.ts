import { Router, type IRouter } from "express";
import healthRouter from "./health";
import authRouter from "./auth";
import adminRouter from "./admin";
import scansRouter from "./scans";

const router: IRouter = Router();

router.use(healthRouter);
// Auth routes first: /session and /auth/* must remain reachable without an
// existing session so the client can sign in.
router.use(authRouter);
router.use(adminRouter);
router.use(scansRouter);

export default router;
