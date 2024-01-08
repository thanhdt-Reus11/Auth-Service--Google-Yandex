import { BadRequestException, ForbiddenException, Inject, Injectable } from '@nestjs/common';
import { PrismaService } from '@prisma/prisma.service';
import { Role, User } from '@prisma/client';
import { genSaltSync, hash } from 'bcrypt';
import { JwtPayload } from '@auth/interfaces';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { ConfigService } from '@nestjs/config';
import { convertToSecondsUtil } from '@common/utils';

@Injectable()
export class UserService {
    constructor(
        private readonly prismaService: PrismaService,
        @Inject(CACHE_MANAGER) private cacheManager: Cache,
        private readonly configService: ConfigService,
    ) {}

    async save(user: Partial<User>) {
        const hashPassword = user?.password ? await this.hashPassword(user.password) : null;
        const savedUser = await this.prismaService.user.upsert({
            where: {email: user.email},
            update: {
                password: hashPassword ?? undefined,
                provider: user?.provider ?? undefined,
                roles: user?.roles ?? undefined,
                isBlocked: user?.isBlocked ?? undefined,
            },
            create: {
                email: user.email,
                password: hashPassword,
                provider: user?.provider,
                roles: ['USER'],
            }
        });
        await this.cacheManager.set(savedUser.id, savedUser, convertToSecondsUtil(this.configService.get('CACHE_TTL')));
        await this.cacheManager.set(savedUser.email, savedUser, convertToSecondsUtil(this.configService.get('CACHE_TTL')));
        return savedUser;
    }

    async findOne(idOrEmail: string, isReset = false) {
        if(isReset) {
            await this.cacheManager.del(idOrEmail);
        }
        const user = await this.cacheManager.get<User>(idOrEmail);
        if(!user) {
            const newUser = await this.prismaService.user.findFirst({
                where: {
                    OR: [
                        { id: idOrEmail },
                        { email: idOrEmail }
                    ],
                },
            });
            if(!newUser) {
               return null;
            }
            await this.cacheManager.set(idOrEmail, newUser, convertToSecondsUtil(this.configService.get('CACHE_TTL')));
            return newUser;
        }
        return user;
    }

    async delete(id: string, user: JwtPayload) {
        if(user.id !== id && !user.roles.includes(Role.ADMIN)) {
            throw new ForbiddenException('Access denied');
        }
        const delUser = await this.prismaService.user.findFirst({
            where: {id},
        })
        if (!delUser) {
            throw new BadRequestException('Id does not exist');
        }
        await Promise.all([
            this.cacheManager.del(id),
            this.cacheManager.del(delUser.email)
        ])
        return this.prismaService.user.delete({
          where: {id}, select: {id: true},
        });
    }

    private async hashPassword(password: string) {
        return await hash(password, genSaltSync(10));
    }
}
