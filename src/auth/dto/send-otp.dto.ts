import { ApiProperty } from "@nestjs/swagger";

export class SendOtpDto {
  @ApiProperty({ example: 'user@example.com', description: 'User email to send OTP' })
  email: string;
}