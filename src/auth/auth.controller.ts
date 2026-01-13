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
import { MfaSetupDto } from './dto/admin-mfa-setup.dto';
import { AuditService } from './audit.service';
import { AccountService } from './account.service';
import { UserLoginDto } from './dto/user-login.dto';
import { AdminLoginDto } from './dto/admin-login.dto';
import { TokenResponseDto } from './dto/token-response.dto';
import { LogoutDto } from './dto/logout.dto';
import { MfaVerifyDto } from './dto/mfa-verify.dto';
import { ActivateDto } from './dto/activate.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { RequestPasswordResetDto } from './dto/request-reset.dto';
import { ClientCredentialsDto } from './dto/client-credentials.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { VerifyEmailDto, RegisterDto } from './dto/register.dto';
import { Public } from './decorators/public.decorator';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { SendOtpDto } from './dto/send-otp.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { Scopes } from './decorators/scopes.decorator';
import { TokenRevocationDto } from './dto/revocation-token.dto';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  sessionService: any;
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
  @Public()
  @Post('admin/login')
  @ApiOperation({ summary: 'Admin login with email/password/OTP' })
  @ApiBody({ type: AdminLoginDto })
  @ApiResponse({ status: 200, description: 'Admin logged in', type: TokenResponseDto })
  async adminLogin(@Body() body: AdminLoginDto) {
    return this.authService.adminLogin(body.email, body.password);
  }

  // ---------------- User Login ----------------
  @Public()
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
  @ApiOperation({ summary: 'Partner login with clientId and clientSecret' })
  @ApiBody({ type: ClientCredentialsDto })
  @ApiResponse({ status: 200, description: 'Partner logged in', type: TokenResponseDto })
  async partnerToken(@Body() body: ClientCredentialsDto) {
    return this.authService.clientCredentials(body, 'PARTNER');
  }

  @Post('enterprise/token')
  @ApiOperation({ summary: 'Enterprise login with clientId and clientSecret' })
  @ApiBody({ type: ClientCredentialsDto })
  @ApiResponse({ status: 200, description: 'Enterprise logged in', type: TokenResponseDto })
  async enterpriseToken(@Body() body: ClientCredentialsDto) {
    return this.authService.clientCredentials(body, 'ENTERPRISE');
  }

  @Post('government/token')
  @ApiOperation({ summary: 'Government login with clientId and clientSecret' })
  @ApiBody({ type: ClientCredentialsDto })
  @ApiResponse({ status: 200, description: 'Government logged in', type: TokenResponseDto })
  async governmentToken(@Body() body: ClientCredentialsDto) {
    return this.authService.clientCredentials(body, 'GOVERNMENT');
  }

  // ---------------- Token Management ----------------
  @Post('token/refresh')
  @ApiOperation({ summary: 'Refresh access token' })
  @ApiBody({ type: RefreshTokenDto })
  @ApiResponse({ status: 200, description: 'New access token issued', type: TokenResponseDto })
  async refresh(@Body() dto: RefreshTokenDto, @Req() req) {
    const userId = req.user?.sub;
    const newRefresh = await this.tokenService.rotateRefresh(dto.refreshToken, userId);
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

  @Post('token/revoke')
  @ApiOperation({ summary: 'Revoke a refresh token (Blacklist)' })
  @ApiBody({ type: TokenRevocationDto })
  @ApiResponse({ status: 200, description: 'Token revoked successfully' })
  async revokeToken(@Body() dto: TokenRevocationDto) {
    return this.authService.revokeToken(dto.refreshToken);
  }

  @Post('logout')
  @ApiOperation({ summary: 'Logout user by invalidating refresh token' })
  @ApiBody({ type: LogoutDto })
  @ApiResponse({ status: 200, description: 'User logged out' })
  async logout(@Body() dto: LogoutDto, @Req() req) {
    await this.tokenService.revokeByToken(dto.refreshToken, req.user.sub);
    await this.auditService.record('LOGOUT', req.user.sub, 'USER', true, req);
    return { message: 'Logged out' };
  }

  // ---------------- Admin MFA ----------------
  @Post('admin/mfa/setup')
  @ApiOperation({ summary: 'Setup MFA for admin' })
  @ApiBody({ type: MfaSetupDto })
  @ApiResponse({ status: 200, description: 'MFA setup' })
  async adminMfaSetup(@Body() dto: MfaSetupDto, @Req() req) {
    const { secret, otpauth } = this.mfaService.setupTotp();
    await this.authService.saveAdminMfaSecret(req.user.sub, secret);
    return { otpauth };
  }

  @Post('admin/mfa/verify')
  @ApiOperation({ summary: 'Verify MFA for admin' })
  @ApiBody({ type: MfaVerifyDto })
  @ApiResponse({ status: 200, description: 'MFA verified successfully' })
  async adminMfaVerify(@Body() dto: MfaVerifyDto, @Req() req) {
    const { secret } = await this.authService.getAdminMfaSecret(req.user.sub);
    this.mfaService.verifyTotp(secret, dto.otp);
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
  @ApiOperation({ summary: 'Activate user account' })
  @ApiBody({ type: ActivateDto })
  @ApiResponse({ status: 200, description: 'Account activated successfully' })
  async activate(@Body() dto: ActivateDto) {
    return this.accountService.activate(dto.userId);
  }

  @Post('change-password')
  @Scopes('update:password')
  @ApiOperation({ summary: 'Change password for a user' })
  @ApiBody({ type: ChangePasswordDto })
  @ApiResponse({ status: 200, description: 'Password changed successfully' })
  async changePassword(@Body() dto: ChangePasswordDto, @Req() req) {
    return this.accountService.changePassword(req.user.sub, dto.currentPassword, dto.newPassword);
  }

  // ---------------- OTP ----------------
  @Public()
  @Post('send-otp')
  @ApiOperation({ summary: 'Send OTP to user email' })
  @ApiBody({ type: SendOtpDto })
  async sendOtp(@Body('') dto: SendOtpDto) {
    return this.authService.sendOtp(dto.email);
  }

  @Post('verify-otp')
  @ApiOperation({ summary: 'Verify OTP for email' })
  @ApiBody({ type: VerifyOtpDto })
  async verifyOtp(@Body() dto: VerifyOtpDto) {
    return this.authService.verifyOtp(dto.email, dto.code);
  }

  @Post('request-password-reset')
  @ApiOperation({ summary: 'Request password reset link' })
  @ApiBody({ type: RequestPasswordResetDto })
  async requestPasswordReset(@Body() dto: RequestPasswordResetDto) {
    // ✅ corrected method name
    return this.authService.requestPasswordReset(dto.email);
  }

  @Post('reset-password')
  @ApiOperation({ summary: 'Reset password using token' })
  @ApiBody({ type: ResetPasswordDto })
  async resetPassword(@Body() dto: ResetPasswordDto) {
    return this.authService.resetPassword(dto.token, dto.newPassword);
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


@Post('sessions/revoke-all')
@ApiOperation({ summary: 'Revoke all sessions for current user' })
async revokeAllSessions(@Req() req) {
  await this.sessionService.revokeAllSessions(req.user.sub);
  return { message: 'All sessions revoked' };
}

@Post('sessions/rotate')
@ApiOperation({ summary: 'Rotate refresh token for current session' })
@ApiBody({ type: RefreshTokenDto })
async rotateSession(@Body() dto: RefreshTokenDto, @Req() req) {
  const { refreshToken } = await this.sessionService.rotateSession(dto.refreshToken, req.user.sub);
  const access = this.tokenService.issueAccess({
    sub: req.user.sub,
    role: req.user.role,
    scopes: req.user.scopes,
  });
  return { access_token: access, refresh_token: refreshToken, token_type: 'Bearer' };
}
}
