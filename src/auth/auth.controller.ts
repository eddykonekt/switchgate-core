import { Controller, Post, Body, UnauthorizedException, Req, Query, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { TokenService } from './token.service';
import { Throttle } from '@nestjs/throttler';
import { VerifyEmailDto } from './dto/register.dto';
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
  RegisterDto,
  ActivateDto,
  ChangePasswordDto,
  MfaVerifyDto,
} from './auth.dto';
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

  // ---------------- Admin/User Login ----------------
  @Post('admin/login')
  @ApiOperation({ summary: 'Admin login with email/password/OTP' })
  @ApiBody({ type: AdminLoginDto })
  @ApiResponse({ status: 200, description: 'Admin logged in', type: TokenResponseDto })
  async adminLogin(@Body() body: AdminLoginDto) {
    return this.authService.adminLogin(body.email, body.password);
  }

  @Post('user/login')
  @ApiOperation({ summary: 'User login with MSISDN, PIN, OTP, device fingerprint' })
  @ApiBody({ type: UserLoginDto })
  @ApiResponse({ status: 200, description: 'User logged in', type: TokenResponseDto })
  async userLogin(@Body() body: UserLoginDto) {
    return this.authService.userLogin(body.email, body.msisdn, body.pin, body.otp, body.deviceFingerprint);
  }

  // ---------------- Client Credentials ----------------
  @Post('partner/token')
  @ApiOperation({ summary: 'Partner OAuth2 client credentials' })
  @ApiBody({ type: ClientCredentialsDto })
  @ApiResponse({ status: 200, description: 'Partner token issued', type: TokenResponseDto })
  async partnerToken(@Body() body: ClientCredentialsDto) {
    return this.authService.clientCredentials(body, 'PARTNER');
  }

  @Post('enterprise/token')
  @ApiOperation({ summary: 'Enterprise OAuth2 client credentials' })
  @ApiBody({ type: ClientCredentialsDto })
  @ApiResponse({ status: 200, description: 'Enterprise token issued', type: TokenResponseDto })
  async enterpriseToken(@Body() body: ClientCredentialsDto) {
    return this.authService.clientCredentials(body, 'ENTERPRISE');
  }

  @Post('government/token')
  @ApiOperation({ summary: 'Government OAuth2 client credentials' })
  @ApiBody({ type: ClientCredentialsDto })
  @ApiResponse({ status: 200, description: 'Government token issued', type: TokenResponseDto })
  async governmentToken(@Body() body: ClientCredentialsDto) {
    return this.authService.clientCredentials(body, 'GOVERNMENT');
  }

  // ---------------- Token Management ----------------
  @Post('token/refresh')
  @ApiOperation({ summary: 'Rotate refresh token and issue new access token' })
  @ApiBody({ type: RefreshTokenDto })
  @ApiResponse({ status: 200, type: TokenResponseDto })
  async refresh(@Body() dto: RefreshTokenDto, @Req() req) {
    const userId = req.user?.sub;
    const newRefresh = await this.tokenService.rotateRefresh(dto.refresh_token, userId);
    const access = this.tokenService.issueAccess({ sub: userId, role: req.user.role, scopes: req.user.scopes });
    await this.auditService.record('TOKEN_REFRESH', userId, 'USER', true, req);
    return { access_token: access, token_type: 'Bearer', expires_in: 900, refresh_token: newRefresh };
  }

  @Post('logout')
  @ApiOperation({ summary: 'Revoke refresh token (logout)' })
  @ApiBody({ type: LogoutDto })
  @ApiResponse({ status: 200 })
  async logout(@Body() dto: LogoutDto, @Req() req) {
    await this.tokenService.revokeByToken(dto.refresh_token, req.user.sub);
    await this.auditService.record('LOGOUT', req.user.sub, 'USER', true, req);
    return { message: 'Logged out' };
  }

  // ---------------- Admin MFA ----------------
  @Post('admin/mfa/setup')
  @ApiOperation({ summary: 'Setup MFA for admin (TOTP)' })
  @ApiResponse({ status: 200 })
  async adminMfaSetup(@Req() req) {
    const { secret, otpauth } = this.mfaService.setupTotp();
    await this.authService.saveAdminMfaSecret(req.user.sub, secret);
    return { otpauth };
  }

  @Post('admin/mfa/verify')
  @ApiOperation({ summary: 'Verify MFA code for admin' })
  @ApiBody({ type: MfaVerifyDto })
  @ApiResponse({ status: 200 })
  async adminMfaVerify(@Body() dto: MfaVerifyDto, @Req() req) {
    const { secret } = await this.authService.getAdminMfaSecret(req.user.sub);
    this.mfaService.verifyTotp(secret, dto.code);
    return { message: 'MFA verified' };
  }

  // ---------------- Account Management ----------------
  @Public()
  @Post('register')
  @ApiOperation({ summary: 'Register a new user or client (Partner, Enterprise, Government)' })
  @ApiBody({ type: RegisterDto })
  @ApiResponse({ status: 201, description: 'Registration successful. Email sent with credentials or verification link.' })
  @ApiResponse({ status: 400, description: 'Invalid input data' })
  @ApiResponse({ status: 429, description: 'Too many requests (rate limit exceeded)' })
  async register(@Body() dto: RegisterDto) {
    return this.accountService.register(dto.email, dto.password, dto.msisdn);
  }

  @Post('activate')
  @ApiOperation({ summary: 'Activate account' })
  @ApiBody({ type: ActivateDto })
  @ApiResponse({ status: 200 })
  async activate(@Body() dto: ActivateDto) {
    return this.accountService.activate(dto.token);
  }

  @Post('change-password')
  @ApiOperation({ summary: 'Change password' })
  @ApiBody({ type: ChangePasswordDto })
  @ApiResponse({ status: 200 })
  async changePassword(@Body() dto: ChangePasswordDto, @Req() req) {
    return this.accountService.changePassword(req.user.sub, dto.currentPassword, dto.newPassword);
  }

  // ---------------- OTP ----------------
  @Post('send-otp')
  @ApiOperation({ summary: 'Send OTP to user email or MSISDN' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: { type: 'string', example: 'user@switchgate.com' },
      },
    },
  })
  @ApiResponse({ status: 200 })
  async sendOtp(@Body('email') email: string) {
    return this.authService.sendOtp(email);
  }

  @Post('verify-otp')
  @ApiOperation({ summary: 'Verify OTP submitted by user' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: { type: 'string', example: 'user@switchgate.com' },
        otp: { type: 'string', example: '123456' },
      },
    },
  })
  @ApiResponse({ status: 200 })
  async verifyOtp(@Body('email') email: string, @Body('otp') otp: string) {
    return this.authService.verifyOtp(email, otp);
  }

  @Post('request-password-reset')
  @ApiOperation({ summary: 'Request a password reset link'})
  async requestPasswordReset(@Body('email') email: string) {
    return this.authService.requestPasswordRequest(email);
  }

  @Post('reset-password')
  @ApiOperation({ summary: 'Reset password using token'})
  async resetPassword(
    @Body('token') token: string,
    @Body('newPassword') newPassword: string,
  ) {
    return this.authService.resetPassword(token, newPassword);
  }

  @Public()
  @Get('verify-email')
  @ApiOperation({ summary: 'Verify user email with token'})
  @ApiResponse({ status: 200, description: 'Email verified successfully' })
  @ApiResponse({ status: 400, description: 'Invalid or expired token' })
  async verifyEmail(@Query() query: VerifyEmailDto) {
    return this.authService.verifyEmail(query.token);
  }
}