// src/auth/auth.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Users, UsersDocument } from '../users/users.schema';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(Users.name)
        private userModel: Model<UsersDocument>,
        private jwtService: JwtService
    ) {}

    async hashPassword(password: string): Promise<string> {
        return bcrypt.hash(password, 10);
    }

    async comparePasswords(password: string, hashedPassword: string): Promise<boolean> {
        return bcrypt.compare(password, hashedPassword);
    }

    async validateUser(identifier: string, password: string): Promise<any> {
        // Find user by either username or email
        const user = await this.userModel.findOne({
            $or: [{ email: identifier }, { username: identifier }],
        });

        if (!user) {
            throw new UnauthorizedException('User not found!'); // If user not found
        }

        const isMatch = await this.comparePasswords(password, user.password); // Check if passwords match
        if (!isMatch) {
            throw new UnauthorizedException('Incorrect email/username or password.'); // If password does not match
        }

        const payload = { id: user._id, email: user.email, username: user.username }; // Create JWT payload
        return {
            statusCode: 200,
            message: 'You have successfully logged in.',
            access_token: await this.jwtService.signAsync(payload),
            username: user.username,
        };
    }
}
