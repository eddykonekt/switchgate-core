export class AdminLoginDto {
  email: string;        // required
  password: string;     // required
  otp?: string;         // optional (only if admin requires OTP)
}