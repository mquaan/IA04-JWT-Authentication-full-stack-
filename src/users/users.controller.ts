// src/users/user.controller.ts
import { Controller, Post, Body, BadRequestException, Get, UseGuards, Req } from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { Request } from 'express';

@Controller()
export class UsersController {
    constructor(private readonly userService: UsersService) { }

    @Post('register')
    async registerUser(@Body('email') email: string, @Body('username') username: string, @Body('password') password: string) {
        if (!email || !username || !password) {
            throw new BadRequestException('Email and password are required');
        }
        return this.userService.register(email, username, password);
    }
    // Protected profile route
    @UseGuards(JwtAuthGuard)
    @Get('profile')
    async getProfile(@Req() req: Request) {
        return req.user; // `user` is added to `req` by JwtAuthGuard after token validation
    }
}
