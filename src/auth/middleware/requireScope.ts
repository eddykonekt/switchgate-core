import { Request, Response, NextFunction } from 'express';
import { errors } from '../../common/errors';

export function requireScope(required: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const auth = (req as any).auth;
    if (!auth) return next(errors.Unauthorized());
    const scopes: string[] = auth.scopes || [];
    const ok = required.every(s => scopes.includes(s));
    if (!ok) return next(errors.Forbidden('Missing required scopes'));
    next();
  };
}