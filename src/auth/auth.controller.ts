// src/auth/auth.controller.ts
import { Controller, Post, Body, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  async login(
    @Body('identifier') identifier: string, // Either username or email
    @Body('password') password: string
  ) {

    try {
      return await this.authService.validateUser(identifier, password);
    } catch (error) {
      throw new UnauthorizedException(error.message);
    }
  }
}