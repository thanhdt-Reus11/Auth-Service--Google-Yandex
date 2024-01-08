import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-google-oauth20';
import { config } from 'dotenv';

import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';


@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {

  constructor(
    private readonly configService: ConfigService
  ) {
    super({
      clientID: configService.get<string>('GOOGLE_CLIENT_ID'),
      clientSecret: configService.get<string>('GOOGLE_SECRET'),
      callbackURL: 'http://localhost:3000/api/auth/google/callback',
      scope: ['email', 'profile'],
    });
  }

    async validate(
        accessToken: string,
        refreshToken: string,
        profile: any, 
        done: (err: any, user: any, info?: any) => void,
    ): Promise<any> {
        const { name, emails, photos } = profile
        const user = {
            email: emails[0].value,
            firstName: name.givenName,
            lastName: name.familyName,
            picture: photos[0].value,
            accessToken
        }
        done(null, user);
    }
}