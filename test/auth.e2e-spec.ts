import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '../src/app.module';

describe('Auth & Users (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  it('POST /auth/login should issue tokens', async () => {
    const res = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: 'offhicialeddy@gmail.com', password: 'Eddy111' }) // ensure a seeded user
      .expect(201);

    expect(res.body.access_token).toBeDefined();
    expect(res.body.refresh_token).toBeDefined();
  });

  it('GET /users without token should be 401', async () => {
    await request(app.getHttpServer()).get('/users').expect(401);
  });

  it('GET /users with token should be 200', async () => {
    const login = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: 'offhicialeddy@gmail.com', password: 'Eddy111' });

    const token = login.body.access_token;

    const res = await request(app.getHttpServer())
      .get('/users')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(Array.isArray(res.body)).toBe(true);
  });

  it('PATCH /users/:id as non-admin should be 403', async () => {
    const login = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: 'offhicialeddy@gmail.com', password: 'Eddy111' });
    const token = login.body.access_token;

    await request(app.getHttpServer())
      .patch('/users/some-uuid-here')
      .set('Authorization', `Bearer ${token}`)
      .send({ role: 'admin' })
      .expect(403);
  });
});