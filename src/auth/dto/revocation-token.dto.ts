import { IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class TokenRevocationDto {
  @ApiProperty({ example: 'eyJhbGciOiJIUzI1NiIsInR5cCI...' })
  @IsString()
  refreshToken: string;
}