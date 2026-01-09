import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { adminLogin } from '../../auth/strategies/adminAuth';
import { userLogin } from '../../auth/strategies/userAuth';
import { clientCredentials } from '../../auth/strategies/clientCredentials';
import { errors } from '../../common/errors';

const router = Router();

const limiter = rateLimit({
  windowMs: 60_000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});

router.post('/admin/login', limiter, async (req, res, next) => {
  try {
    const result = await adminLogin(req.body);
    res.json(result);
  } catch (e) { next(e); }
});

router.post('/user/login', limiter, async (req, res, next) => {
  try {
    const result = await userLogin(req.body);
    res.json(result);
  } catch (e) { next(e); }
});

router.post('/partner/token', limiter, async (req, res, next) => {
  try {
    const result = await clientCredentials(req.body, 'PARTNER');
    res.json(result);
  } catch (e) { next(e); }
});

router.post('/enterprise/token', limiter, async (req, res, next) => {
  try {
    const result = await clientCredentials(req.body, 'ENTERPRISE');
    res.json(result);
  } catch (e) { next(e); }
});

router.post('/government/token', limiter, async (req, res, next) => {
  try {
    const result = await clientCredentials(req.body, 'GOVERNMENT');
    res.json(result);
  } catch (e) { next(e); }
});

// Global error handler
router.use((err: any, _req, res, _next) => {
  const status = err.status || 500;
  const code = err.code || 'INTERNAL_ERROR';
  res.status(status).json({ code, message: err.message || 'Internal server error' });
});

export default router;