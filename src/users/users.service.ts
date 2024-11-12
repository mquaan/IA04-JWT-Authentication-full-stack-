import { Injectable, ConflictException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Users, UsersDocument } from './users.schema';
import { AuthService } from '../auth/auth.service';

@Injectable()
export class UsersService {
    constructor(
        @InjectModel(Users.name) private userModel: Model<UsersDocument>,
        private readonly authService: AuthService,
    ) {}

    async register(email: string, username: string, password: string): Promise<any> {
        const existingUser = await this.userModel.findOne({
            $or: [{ email }, { username }],
        });

        if (existingUser) {
            if (existingUser.email === email) {
                throw new ConflictException('Email already exists!');
            }
            if (existingUser.username === username) {
                throw new ConflictException('Username already exists!');
            }
        }

        const hashedPassword = await this.authService.hashPassword(password);
        const newUser = new this.userModel({ email, username, password: hashedPassword });
        await newUser.save();

        return {
            statusCode: 201,
            message: 'User registered successfully.'
        };
    }
}
