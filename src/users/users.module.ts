// src/users/user.module.ts
import { Module, forwardRef } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { Users, UsersSchema } from './users.schema';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { AuthModule } from 'src/auth/auth.module';

@Module({
    imports: [
        MongooseModule.forFeature([{ name: Users.name, schema: UsersSchema }]),
        forwardRef(() => AuthModule), // Import the AuthModule
    ],
    providers: [UsersService],
    controllers: [UsersController],
    exports: [UsersService, MongooseModule], // Export the MongooseModule
})
export class UsersModule { }
