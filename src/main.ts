import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as dotenv from 'dotenv';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { HttpExceptionFilter } from './common/http-exception.filter';
import { ValidationPipe } from '@nestjs/common';
import { VerifiedGuard } from './auth/guards/verified.guard';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  ); 
  //app.useGlobalGuards(new (AuthGuard('jwt'))());//
  const config = new DocumentBuilder()
    .setTitle('SwitchGate API')
    .setDescription('API Documentation for SwitchGate-Core')
    .setVersion('1.0')
    .addBearerAuth()
    .build();
    
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  const reflector = app.get('Reflector');
  app.useGlobalGuards(new VerifiedGuard(reflector));
  
  app.useGlobalFilters(new HttpExceptionFilter());
  dotenv.config();
  const port = process.env.PORT || 3000;
  await app.listen(3000);
  console.log(`SwitchGate API is running on: http://localhost:${port}`);
}
bootstrap();