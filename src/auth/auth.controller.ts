import {
  Controller,
  Post,
  Body,
  UnauthorizedException,
  Req,
  Query,
  Get,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { TokenService } from './token.service';
import { MFAService } from './mfa.service';
import { AuditService } from './audit.service';
import { AccountService } from './account.service';
import {
  AdminLoginDto,
  UserLoginDto,
  ClientCredentialsDto,
  TokenResponseDto,
  RefreshTokenDto,
  LogoutDto,
  ActivateDto,
  ChangePasswordDto,
  MfaVerifyDto,
} from './auth.dto';
import { VerifyEmailDto, RegisterDto } from './dto/register.dto';
import { Public } from './decorators/public.decorator';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly tokenService: TokenService,
    private readonly mfaService: MFAService,
    private readonly auditService: AuditService,
    private readonly accountService: AccountService,
  ) {}

  // ---------------- Basic Login ----------------
  @Post('login')
  @ApiOperation({ summary: 'Login with email and password' })
  @ApiBody({ type: AdminLoginDto })
  @ApiResponse({ status: 200, description: 'JWT access token issued', type: TokenResponseDto })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async login(@Body() body: { email: string; password: string }) {
    const user = await this.authService.validateUser(body.email, body.password);
    if (!user) throw new UnauthorizedException();
    return this.authService.login(user);
  }

  // ---------------- Admin Login ----------------
  @Post('admin/login')
  @ApiOperation({ summary: 'Admin login with email/password/OTP' })
  @ApiBody({ type: AdminLoginDto })
  @ApiResponse({ status: 200, description: 'Admin logged in', type: TokenResponseDto })
  async adminLogin(@Body() body: AdminLoginDto) {
    return this.authService.adminLogin(body.email, body.password);
  }

  // ---------------- User Login ----------------
  @Post('user/login')
  @ApiOperation({ summary: 'User login with email/password' })
  @ApiBody({ type: UserLoginDto })
  @ApiResponse({ status: 200, description: 'User logged in', type: TokenResponseDto })
  async userLogin(@Body() body: UserLoginDto, @Req() req: any) {
    // ✅ simplified to match AuthService.userLogin signature
    return this.authService.userLogin(body.email, body.password, req);
  }

  // ---------------- Client Credentials ----------------
  @Post('partner/token')
  async partnerToken(@Body() body: ClientCredentialsDto) {
    return this.authService.clientCredentials(body, 'PARTNER');
  }

  @Post('enterprise/token')
  async enterpriseToken(@Body() body: ClientCredentialsDto) {
    return this.authService.clientCredentials(body, 'ENTERPRISE');
  }

  @Post('government/token')
  async governmentToken(@Body() body: ClientCredentialsDto) {
    return this.authService.clientCredentials(body, 'GOVERNMENT');
  }

  // ---------------- Token Management ----------------
  @Post('token/refresh')
  async refresh(@Body() dto: RefreshTokenDto, @Req() req) {
    const userId = req.user?.sub;
    const newRefresh = await this.tokenService.rotateRefresh(dto.refresh_token, userId);
    const access = this.tokenService.issueAccess({
      sub: userId,
      role: req.user.role,
      scopes: req.user.scopes,
    });
    await this.auditService.record('TOKEN_REFRESH', userId, 'USER', true, req);
    return {
      access_token: access,
      token_type: 'Bearer',
      expires_in: 900,
      refresh_token: newRefresh,
    };
  }

  @Post('logout')
  async logout(@Body() dto: LogoutDto, @Req() req) {
    await this.tokenService.revokeByToken(dto.refresh_token, req.user.sub);
    await this.auditService.record('LOGOUT', req.user.sub, 'USER', true, req);
    return { message: 'Logged out' };
  }

  // ---------------- Admin MFA ----------------
  @Post('admin/mfa/setup')
  async adminMfaSetup(@Req() req) {
    const { secret, otpauth } = this.mfaService.setupTotp();
    await this.authService.saveAdminMfaSecret(req.user.sub, secret);
    return { otpauth };
  }

  @Post('admin/mfa/verify')
  async adminMfaVerify(@Body() dto: MfaVerifyDto, @Req() req) {
    const { secret } = await this.authService.getAdminMfaSecret(req.user.sub);
    this.mfaService.verifyTotp(secret, dto.code);
    return { message: 'MFA verified' };
  }

  // ---------------- Account Management ----------------
  @Public()
  @Post('register')
  @ApiOperation({ summary: 'Register a new user or client (Partner, Enterprise, Government)' })
  async register(@Body() dto: RegisterDto) {
    // ✅ delegate to AuthService.register so emails are triggered automatically
    return this.authService.register(dto);
  }

  @Post('activate')
  async activate(@Body() dto: ActivateDto) {
    return this.accountService.activate(dto.token);
  }

  @Post('change-password')
  async changePassword(@Body() dto: ChangePasswordDto, @Req() req) {
    return this.accountService.changePassword(req.user.sub, dto.currentPassword, dto.newPassword);
  }

  // ---------------- OTP ----------------
  @Post('send-otp')
  async sendOtp(@Body('email') email: string) {
    return this.authService.sendOtp(email);
  }

  @Post('verify-otp')
  async verifyOtp(@Body('email') email: string, @Body('otp') otp: string) {
    return this.authService.verifyOtp(email, otp);
  }

  @Post('request-password-reset')
  async requestPasswordReset(@Body('email') email: string) {
    // ✅ corrected method name
    return this.authService.requestPasswordReset(email);
  }

  @Post('reset-password')
  async resetPassword(@Body('token') token: string, @Body('newPassword') newPassword: string) {
    return this.authService.resetPassword(token, newPassword);
  }

  // ---------------- Email Verification ----------------
  @Public()
  @Get('verify-email')
  @ApiOperation({ summary: 'Verify user email with token' })
  @ApiResponse({ status: 200, description: 'Email verified successfully' })
  @ApiResponse({ status: 400, description: 'Invalid or expired token' })
  async verifyEmail(@Query() query: VerifyEmailDto, @Req() req: any) {
    // ✅ delegate to AuthService.verifyEmail
    return this.authService.verifyEmail(query.token, req);
  }
}