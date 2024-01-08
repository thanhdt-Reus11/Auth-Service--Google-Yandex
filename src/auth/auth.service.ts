import { BadRequestException, ConflictException, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { LoginDto, RegisterDto } from './dto';
import { UserService } from '@user/user.service';
import { Tokens } from './interfaces';
import { compareSync } from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { Provider, Token, User } from '@prisma/client';
import { PrismaService } from '@prisma/prisma.service';
import { v4 } from 'uuid';
import { add } from 'date-fns';

@Injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name);

    constructor(
        private readonly userService: UserService,
        private readonly jwtService: JwtService,
        private readonly prismaService: PrismaService
    ) {}

    async refreshTokens(refreshToken: string, agent: string) : Promise<Tokens> {
        const token = await this.prismaService.token.delete({
          where: {token: refreshToken}
        });
        if(!token || new Date(token.exp) < new Date()) {
            throw new UnauthorizedException();
        }
        const user = await this.userService.findOne(token.userId, true);
        return await this.generateTokens(user, agent);
    }

    async register(dto: RegisterDto) {
        const user = await this.userService.findOne(dto.email).catch(err => {
            this.logger.error(err);
            return null;
        });
        if(user) {
            throw new ConflictException(`User with email ${dto.email} already exists!`);
        }
        return this.userService.save(dto).catch(err => {
            this.logger.error(err);
            return null;
        });
    }

    async login (dto: LoginDto, agent: string): Promise<Tokens> {
        const user = await this.userService.findOne(dto.email).catch(err => {
            this.logger.error(err);
            return null;
        });
        if (!user || !compareSync(dto.password, user.password)) {
            throw new UnauthorizedException('Email or Password invalid')
        }
        await this.prismaService.token.deleteMany({
            where: {userId: user.id, userAgent: agent}
        });
        return await this.generateTokens(user, agent);
    }

    async deleteRefreshToken(token: string) {
        return this.prismaService.token.delete({
            where: {token},
        });
    }

    async getRefreshToken(userId: string, agent: string): Promise<Token> {
        const _token = await this.prismaService.token.findFirst({
            where: {
                userId,
                userAgent: agent,
            }
        });
        const token = _token?.token ?? ''
        return await this.prismaService.token.upsert({
            where: {token},
            update: {
                token: v4(),
                exp: add(new Date(), { months: 1 }),
            },
            create: {
                token: v4(),
                exp: add(new Date(), { months: 1 }),
                userId,
                userAgent: agent,
            }
        });
    }

    private async generateTokens(user: User, agent: string) {
        const accessToken = this.jwtService.sign({
            id: user.id,
            email: user.email,
            roles: user.roles
        });
        const refreshToken = await this.getRefreshToken(user.id, agent);
        return {accessToken: accessToken, refreshToken: refreshToken};
    }

    async providerAuth(email: string, agent: string, provider: Provider) {
        const userExist = await this.userService.findOne(email);
        
        // Nếu có tài khoản ròi mà đăng nhập bằng google hay
        // yandex bằng email đã tạo tài khoản đó thì sẽ như nào?
        // Xử lý??? (Không cho đăng nhập hay đăng nhập bình thường?)
        if(userExist) {
            return this.generateTokens(userExist, agent);
        }
        const user = await this.userService.save({ email: email, provider: provider }).catch(err => {
            this.logger.error(err);
            return null;
        });
        if(!user) {
            throw new BadRequestException(`Can not create user with email: ${email}`);
        }
        return this.generateTokens(user, agent);
    }
}
