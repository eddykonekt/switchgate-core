import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import { Express } from 'express';

const options: swaggerJsdoc.Options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'SwitchGate API',
      version: '1.0.0',
      description: 'Auth, Transfers, Utility, and Partner APIs',
    },
    servers: [
      { url: 'http://localhost:3000', description: 'Local dev server' },
    ],
  },
  apis: ['src/api-gateway/routes/*.ts'], // scan route files for JSDoc comments
};

export const swaggerSpec = swaggerJsdoc(options);

export function setupSwagger(app: Express) {
  app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
}