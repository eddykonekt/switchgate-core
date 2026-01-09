import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import authRoutes from './auth';
import { logger } from '../../common/logger';
import { setupSwagger } from '../../config/swagger';

const app = express();
app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));

app.use('/auth', authRoutes);

setupSwagger(app);

const PORT = Number(process.env.PORT || 8080);
app.listen(PORT, () => logger.info(`API Gateway listening on ${PORT}`));