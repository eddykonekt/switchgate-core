import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class ClientRegisterDto {
  @IsString()
  @IsNotEmpty()
  name: string;

  @IsEmail()
  email: string;

  @IsString()
  @IsNotEmpty()
  clientType: string; // e.g. "Partner", "Enterprise", "Government"
}