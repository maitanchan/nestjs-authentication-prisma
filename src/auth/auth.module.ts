import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule } from '@nestjs/config';
import { PassportModule } from '@nestjs/passport';
import { AccessTokenStrategy } from './strategy/access-token.strategy';
import { RefreshTokenStrategy } from './strategy/refresh-token.strategy';

@Module({

  imports: [

    PassportModule,

    ConfigModule.forRoot({

      isGlobal: true,

      envFilePath: '.env'

    }),

    JwtModule.register({})

  ],

  controllers: [AuthController],

  providers: [

    AuthService,

    AccessTokenStrategy,

    RefreshTokenStrategy

  ]

})
export class AuthModule { }
