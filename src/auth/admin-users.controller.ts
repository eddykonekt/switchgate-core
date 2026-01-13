import { Controller, Param, Patch, Delete, Post, Body, UseGuards } from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { AdminUsersService } from './admin-users.service';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { User } from '../users/entities/user.entity';
import { CreateSubAdminDto } from './dto/create-subadmin.dto';

@ApiTags('Admin Users')
@ApiBearerAuth()
@Controller('admin/users')
export class AdminUsersController {
  constructor(private readonly adminUsersService: AdminUsersService) {}

  @Roles('admin')
  @UseGuards(RolesGuard)
  @Patch(':id/enable')
  @ApiOperation({ summary: 'Enable a user account' })
  @ApiResponse({ status: 200, description: 'User enabled successfully', type: User })
  async enableUser(@Param('id') id: string) {
    return this.adminUsersService.enableUser(id);
  }

  @Roles('admin')
  @UseGuards(RolesGuard)
  @Patch(':id/disable')
  @ApiOperation({ summary: 'Disable a user account' })
  @ApiResponse({ status: 200, description: 'User disabled successfully', type: User })
  async disableUser(@Param('id') id: string) {
    return this.adminUsersService.disableUser(id);
  }

  @Roles('admin')
  @UseGuards(RolesGuard)
  @Delete(':id')
  @ApiOperation({ summary: 'Archive (soft delete) a user account' })
  @ApiResponse({ status: 200, description: 'User archived successfully', type: User })
  async archiveUser(@Param('id') id: string) {
    return this.adminUsersService.archiveUser(id);
  }

  @Roles('admin')
  @UseGuards(RolesGuard)
  @Post('sub-admin')
  @ApiOperation({ summary: 'Create a sub-admin (unit head)' })
  @ApiResponse({ status: 201, description: 'Sub-admin created successfully', type: User })
  @ApiBody({ type: CreateSubAdminDto})
  async createSubAdmin(@Body() dto: CreateSubAdminDto) {
    return this.adminUsersService.createSubAdmin(dto);
  }
}