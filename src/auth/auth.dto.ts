import { ApiProperty } from '@nestjs/swagger';

export class AdminLoginDto {
  @ApiProperty() email: string;
  @ApiProperty() password: string;
  @ApiProperty({ required: false }) otp?: string;
}

export class UserLoginDto {
  @ApiProperty() msisdn: string;
  @ApiProperty() pin: string;
  @ApiProperty() otp: string;
  @ApiProperty() deviceFingerprint: string;
  email: string;
}

export class ClientCredentialsDto {
  @ApiProperty() client_id: string;
  @ApiProperty() client_secret: string;
  @ApiProperty({ enum: ['client_credentials'] }) grant_type: string;
  @ApiProperty({ required: false }) scope?: string;
}

export class TokenResponseDto {
  @ApiProperty() access_token: string;
  @ApiProperty() token_type: string;
  @ApiProperty() expires_in: number;
  @ApiProperty({ required: false }) scope?: string;
  @ApiProperty({ required: false }) refresh_token?: string;
}

export class RefreshTokenDto {
  @ApiProperty() refresh_token: string;
}

export class LogoutDto {
  @ApiProperty() refresh_token: string;
}

export class RegisterDto {
  @ApiProperty() email: string;
  @ApiProperty() password: string;
  @ApiProperty({ required: false }) msisdn?: string;
}

export class ActivateDto {
  @ApiProperty() token: string;
}

export class ChangePasswordDto {
  @ApiProperty() currentPassword: string;
  @ApiProperty() newPassword: string;
}

export class MfaSetupDto {
  @ApiProperty() method: 'TOTP' | 'EMAIL' | 'SMS';
}

export class MfaVerifyDto {
  @ApiProperty() code: string;
}

export class RequestPasswordResetDto {
  @ApiProperty({ example: 'user@switchgate.com' })
  email: string;
}

export class ResetPasswordDto {
  @ApiProperty({ example: 'jwt-reset-token' })
  token: string;

  @ApiProperty({ example: 'newSecurePassword123!' })
  newPassword: string;
}