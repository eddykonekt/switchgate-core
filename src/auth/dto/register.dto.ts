import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, IsOptional, IsIn } from 'class-validator';

export class RegisterDto {
  @ApiProperty({ example: 'user@switchgate.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'StrongPass123!' })
  @IsString()
  password: string;

  @ApiProperty({ example: 'USER', enum: ['USER', 'PARTNER', 'ENTERPRISE', 'GOVERNMENT'] })
  @IsIn(['USER', 'PARTNER', 'ENTERPRISE', 'GOVERNMENT'])
  role: 'USER' | 'PARTNER' | 'ENTERPRISE' | 'GOVERNMENT';

  @ApiProperty({ example: '+2348012345678', required: false })
  @IsOptional()
  msisdn?: string;

  @ApiProperty({ example: '1234', required: false })
  @IsOptional()
  pin?: string;
}

export class VerifyEmailDto {
  @ApiProperty({ example: 'jwt-or-uuid-token' })
  @IsString()
  token: string;
}