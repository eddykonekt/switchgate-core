import { Body, Controller, Get, Param, Post, Query, UseGuards } from '@nestjs/common';
import { ClientRegistryService } from './client-registry.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { ClientCredentialsDto } from '../auth/dto/client-credentials.dto';
import { AuthService } from '../auth/auth.service';
import { TokenResponseDto } from '../auth/dto/token-response.dto';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiParam, ApiQuery, ApiResponse, ApiTags } from '@nestjs/swagger';

@ApiTags('Clients')
@ApiBearerAuth()
@Controller('clients')
@UseGuards(JwtAuthGuard, RolesGuard)
export class ClientsController {
  authService: any;
  constructor(private readonly clientsService: ClientRegistryService) {}

  // GET /clients?page=1&limit=10
  @Get()
  @Roles('admin', 'sub-admin')
  @ApiOperation({ summary: 'Get paginated list of clients (Admin/Sub-admin only)' })
  @ApiQuery({ name: 'page', required: false, type: Number, example: '1' })
  @ApiQuery({ name: 'limit', required: false, type: Number, example: 10 })
  async getClients(@Query('page') page = 1, @Query('limit') limit = 10) {
    const [data, total] = await this.clientsService.findAllPaginated(+page, +limit);
    return { data, total, page, limit };
  }

  // GET /clients/:id
  @Get(':id')
  @Roles('admin', 'sub-admin')
  @ApiOperation({ summary: 'Get single client by ID (Admin/Sub-admin only)' })
  @ApiParam({ name: 'id', type: String })
  async getClient(@Param('id') id: string) {
    return this.clientsService.findOne(id);
  }

  @Post('credentials')
  @ApiOperation({ summary: 'Client login with clientId and clientSecret' })
  @ApiBody({ type: ClientCredentialsDto })
  @ApiResponse({ status: 200, description: 'Client logged in', type: TokenResponseDto })
  async clientLogin(@Body() body: ClientCredentialsDto) {
    return this.authService.clientCredentials(body, body.grant_type);
  }
}