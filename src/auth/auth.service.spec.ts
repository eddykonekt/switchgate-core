import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { MailerService } from '../mailer/mailer.service';

describe('AuthService', () => {
  let service: AuthService;
  let module: TestingModule;

  beforeEach(async () => {
    module = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: UsersService,
          useValue: { findByEmail: jest.fn(), findOne: jest.fn(), update: jest.fn() },
        },
        {
          provide: JwtService,
          useValue: { sign: jest.fn(), verify: jest.fn() },
        },
        {
          provide: MailerService,
          useValue: { sendMail: jest.fn() },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should call MailerService when requesting reset', async () => {
    const mailer = module.get<MailerService>(MailerService);
    const users = module.get<UsersService>(UsersService);

    users.findByEmail = jest.fn().mockResolvedValue({ id: '123', email: 'test@example.com' });
    mailer.sendMail = jest.fn().mockResolvedValue(true);

    await service.requestPasswordReset('test@example.com');
    expect(mailer.sendMail).toHaveBeenCalled();
  });
});