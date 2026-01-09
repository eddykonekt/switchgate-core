export class AppError extends Error {
  status: number;
  code: string;
  constructor(code: string, message: string, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}
export const errors = {
  Unauthorized: (msg = 'Unauthorized') => new AppError('UNAUTHORIZED', msg, 401),
  Forbidden: (msg = 'Forbidden') => new AppError('FORBIDDEN', msg, 403),
  BadRequest: (msg = 'Bad request') => new AppError('BAD_REQUEST', msg, 400),
  NotFound: (msg = 'Not found') => new AppError('NOT_FOUND', msg, 404),
  Conflict: (msg = 'Conflict') => new AppError('CONFLICT', msg, 409),
};