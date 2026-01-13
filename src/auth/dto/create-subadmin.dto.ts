import { ApiProperty } from "@nestjs/swagger";

export class CreateSubAdminDto {
  @ApiProperty({ example: 'subadmin@example.com' })
  email: string;

  @ApiProperty({ example: 'StrongPassword123!' })
  password: string;

  @ApiProperty({ example: 'sub-admin', description: 'Role assigned' })
  role: string;
}