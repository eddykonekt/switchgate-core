import { Controller, Param, Post, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiResponse } from '@nestjs/swagger';
import { ClientRegistryService } from './client-registry.service';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { Client } from './entities/client.entity';

@ApiTags('Admin Clients') // ✅ groups endpoints in Swagger
@ApiBearerAuth() // ✅ shows lock icon for JWT
@Controller('admin/clients')
export class AdminClientsController {
  constructor(private readonly clientRegistryService: ClientRegistryService) {}

  @Roles('admin')
  @UseGuards(RolesGuard)
  @Post(':id/approve')
  @ApiOperation({ summary: 'Approve a client and generate API key' })
  @ApiResponse({ status: 200, description: 'Client approved successfully', type: Client })
  async approveClient(@Param('id') id: string) {
    return this.clientRegistryService.approveClient(id);
  }

  @Roles('admin')
  @UseGuards(RolesGuard)
  @Post(':id/rotate-key')
  @ApiOperation({ summary: 'Rotate API key for a client' })
  @ApiResponse({ status: 200, description: 'API key rotated successfully', type: Client })
  async rotateApiKey(@Param('id') id: string) {
    return this.clientRegistryService.rotateApiKey(id);
  }
}