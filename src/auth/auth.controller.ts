import { BadRequestException, Body, ClassSerializerInterceptor, Controller, Get, HttpStatus, Param, Post, Query, Req, Res, UnauthorizedException, UseGuards, UseInterceptors } from '@nestjs/common';
import { LoginDto, RegisterDto } from './dto';
import { AuthService } from './auth.service';
import { JwtPayload, Tokens } from './interfaces';
import { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { Cookie, CurrentUser, Public, Roles, UserAgent } from '@common/decorators';
import { UserResponse } from '@user/responses';
import { Role, Provider } from '@prisma/client';
import { GoogleAuthGuard } from './guards/google.guard';
import { HttpService } from '@nestjs/axios';
import { map, mergeMap, tap } from 'rxjs';
import { handleTimeoutAndError } from '@common/helpers';
import { YandexAuthGuard } from './guards/yandex.guard';


const REFRESH_TOKEN = "REFRESH_TOKEN";

@Public()
@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService : AuthService,
        private readonly configService: ConfigService,
        private readonly httpService: HttpService,
    ) {}

    @UseInterceptors(ClassSerializerInterceptor)
    @Post('register')
    async register(@Body() registerUser: RegisterDto){
        const user = await this.authService.register(registerUser);
        if (!user) {
            throw new BadRequestException(`Can't create user ${JSON.stringify(registerUser)}`)
        }
        return new UserResponse(user);
    }

    @Post('login')
    async login(
        @Body() loginUser: LoginDto,
        @Res() res: Response,
        @UserAgent() agent : string,
    ) {
        const tokens = await this.authService.login(loginUser, agent);
        if (!tokens) {
            throw new BadRequestException('Bad request!');
        }
        this.setRefreshTokenToCookies(tokens, res);
    }

    @Get('logout') 
    async logout (
        @Cookie(REFRESH_TOKEN) refreshToken: string,
        @Res() res: Response
    ) {
        if(!refreshToken) {
            res.sendStatus(HttpStatus.OK);
            return;
        }
        await this.authService.deleteRefreshToken(refreshToken);
        res.cookie(REFRESH_TOKEN, '', {httpOnly: true, secure: true, expires: new Date()});
        res.sendStatus(HttpStatus.OK);
    }

    @Get('refresh-tokens')
    async refreshTokens(
        @Cookie('REFRESH_TOKEN') refreshToken: string,
        @Res() res : Response,
        @UserAgent() agent : string,
    ) {
        if(!refreshToken) {
            throw new UnauthorizedException();
        }
        const tokens = await this.authService.refreshTokens(refreshToken, agent);
        if(!tokens) {
            throw new BadRequestException('Bad request!');
        }
        this.setRefreshTokenToCookies(tokens, res);
    }

    private setRefreshTokenToCookies(tokens: Tokens, res: Response) {
        if(!tokens) {
            throw new UnauthorizedException();
        }
        res.cookie(REFRESH_TOKEN, tokens.refreshToken.token, {
            httpOnly: true,
            sameSite: 'lax',
            expires: new Date(tokens.refreshToken.exp),
            secure: this.configService.get('NODE_ENV', 'development') === 'production',
            path: '/'
        });
        res.status(HttpStatus.CREATED).json({ accessToken: tokens.accessToken });
    }

    @UseGuards(GoogleAuthGuard)
    @Get('google')
    googleAuth() {}

    @UseGuards(GoogleAuthGuard)
    @Get('google/callback')
    googleAuthCallback(
        @Req() req: Request,
        @Res() res: Response,
    ) {
        const token = req.user['accessToken'];
        return res.redirect(`http://localhost:3000/api/auth/success-google?token=${token}`);
    }

    @Get('success-google')
    successGoogle(
        @Query('token') token: string,
        @UserAgent() agent: string,
        @Res() res: Response
    ){
        return this.httpService
            .get(`https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=${token}`)
            .pipe(
                mergeMap(({data: {email}}) => this.authService.providerAuth(email, agent, Provider.GOOGLE)), 
                map((data) => this.setRefreshTokenToCookies(data,res)),
                handleTimeoutAndError(),
                );
    }

    @UseGuards(YandexAuthGuard)
    @Get('yandex')
    yandexAuth() {}

    @UseGuards(YandexAuthGuard)
    @Get('yandex/callback')
    yandexAuthCallback(
        @Req() req: Request,
        @Res() res: Response,
    ) {
        const token = req.user['accessToken'];
        return res.redirect(`http://localhost:3000/api/auth/success-yandex?token=${token}`);
    }

    @Get('success-yandex')
    successYandex(
        @Query('token') token: string,
        @UserAgent() agent: string,
        @Res() res: Response
    ){
        return this.httpService
            .get(`https://login.yandex.ru/info?format=json&oauth_token=${token}`)
            .pipe(
                mergeMap(({data: {default_email}}) => this.authService.providerAuth(default_email, agent, Provider.YANDEX)), 
                map((data) => this.setRefreshTokenToCookies(data,res)),
                handleTimeoutAndError(),
                );
    }
}
