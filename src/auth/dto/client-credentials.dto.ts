import { ApiProperty } from '@nestjs/swagger/dist/decorators';
import { IsString } from 'class-validator';

export class ClientCredentialsDto {
  @ApiProperty({ example: 'client_123' })
  @IsString()
  client_id: string;

  @ApiProperty({ example: 'secret_abc' })
  @IsString()
  client_secret: string;

  @ApiProperty({ example: 'client_credentials' })
  @IsString()
  grant_type: string;
}