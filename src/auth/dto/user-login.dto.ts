export class UserLoginDto {
  msisdn: string;       // required (phone number)
  pin: string;          // required
  otp: string;          // required (always needed for user login)
}