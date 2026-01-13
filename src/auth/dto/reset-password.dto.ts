import { ApiProperty } from '@nestjs/swagger';
import { IsString, MinLength } from 'class-validator';

export class ResetPasswordDto {
  @ApiProperty({ example: 'reset-token-uuid'})
  @IsString()
  token: string;



  @ApiProperty({ example: 'new-password' })
  @IsString()
  @MinLength(6)
  newPassword: string;
}