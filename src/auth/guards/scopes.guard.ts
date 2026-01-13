import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { SCOPES_KEY } from '../decorators/scopes.decorator';

@Injectable()
export class ScopesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredScopes = this.reflector.get<string[]>(SCOPES_KEY, context.getHandler()) || [];
    if (requiredScopes.length === 0) return true;

    const request = context.switchToHttp().getRequest();
    const user = request.user;
    const userScopes: string[] = user?.scopes ?? [];

    const hasAll = requiredScopes.every(s => userScopes.includes(s));
    if (!hasAll) throw new ForbiddenException('Insufficient scope');
    return true;
  }
}