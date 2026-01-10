export class CreateUserDto {
  email: string;            // required
  password: string;         // required
  role?: string;            // optional, defaults to 'user'
  msisdn?: string;          // optional
  pin?: string;             // optional
}