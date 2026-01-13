import { ApiProperty } from '@nestjs/swagger';

export class MfaSetupDto {
  @ApiProperty({ example: 'user-id-uuid', description: 'Admin user ID' })
  adminId: string;

  @ApiProperty({ example: 'totp', description: 'MFA type (e.g. TOTP)' })
  type: string;
}
