import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() dto: { name: string; surname: string; phone: string; email: string; password: string }) {
    return this.authService.register(dto);
  }

  @Post('login')
  async login(@Body() dto: { phone: string; password: string }) {
    const user = await this.authService.validateUser(dto.phone, dto.password);
    return this.authService.login(user);
  }
}
