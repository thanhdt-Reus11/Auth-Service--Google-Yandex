import { Body, ClassSerializerInterceptor, Controller, Delete, Get, Param, ParseUUIDPipe, Post, Put, UseInterceptors } from '@nestjs/common';
import { UserService } from './user.service';
import { CreatUserDto } from './dto/create-user.dto';
import { UserResponse } from './responses';
import { CurrentUser, Roles } from '@common/decorators';
import { JwtPayload } from '@auth/interfaces';
import { Role, User } from '@prisma/client';

@Controller('user')
export class UserController {
    constructor(
        private readonly userService: UserService
    ) {}

    @UseInterceptors(ClassSerializerInterceptor)
    @Get(':idOrEmail')
    async findOneUser(@Param('idOrEmail') idOrEmail: string) {
        const user = await this.userService.findOne(idOrEmail);
        return new UserResponse(user);
    }

    @Delete(':id')
    async deleteUser(
        @Param('id', ParseUUIDPipe) id: string,
        @CurrentUser() user: JwtPayload,
    ) {
        return await this.userService.delete(id, user);
    }

    @Roles(Role.ADMIN)
    @Get()
    me(
        @CurrentUser() user: JwtPayload
    ) {
        return user;
    }


    //Khi update user có phải update lại access token và refresh token không?
    @UseInterceptors(ClassSerializerInterceptor)
    @Put()
    async updateUser(
        @Body() body: Partial<User>
    ) {
        const user = await this.userService.save(body);
        return new UserResponse(user);
    }
}
