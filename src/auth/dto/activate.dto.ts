import { ApiProperty } from '@nestjs/swagger/dist/decorators/api-property.decorator';
import { IsString, IsBoolean, IsOptional } from 'class-validator';

export class ActivateDto {
  @ApiProperty({ example: 'user-1234'})
  @IsString()
  userId: string;



  @ApiProperty({ example: true, required: false })
  @IsOptional()
  @IsBoolean()
  activate?: boolean;
}