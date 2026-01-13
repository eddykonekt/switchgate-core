import { ApiProperty } from '@nestjs/swagger/dist/decorators';
import { IsString } from 'class-validator';

export class MfaVerifyDto {
  @ApiProperty({ example: 'user-123' })
  @IsString()
  userId: string;

  @ApiProperty({ example: '123456' })
  @IsString()
  otp: string;
}