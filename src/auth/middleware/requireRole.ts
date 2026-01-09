import { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../utils/jwt';
import { errors } from '../../common/errors';

export function requireRole(roles: Array<'ADMIN' | 'USER' | 'PARTNER' | 'ENTERPRISE' | 'GOVERNMENT'>) {
  return (req: Request, res: Response, next: NextFunction) => {
    const header = req.headers.authorization;
    if (!header) return next(errors.Unauthorized('Missing Authorization header'));
    const token = header.split(' ')[1];
    try {
      const payload = verifyToken<any>(token);
      if (!roles.includes(payload.role)) return next(errors.Forbidden('Insufficient role'));
      (req as any).auth = payload;
      next();
    } catch {
      next(errors.Unauthorized('Invalid token'));
    }
  };
}