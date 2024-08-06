import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { PrismaModule } from './prisma/prisma.module';
import { ConfigModule } from '@nestjs/config'
import { APP_GUARD } from '@nestjs/core';
import { AccessTokenGuard } from './auth/guard/access-token.guard';

@Module({

  imports: [

    ConfigModule.forRoot({

      isGlobal: true,

      envFilePath: '.env'

    }),

    AuthModule,

    PrismaModule

  ],

  providers: [

    {
      provide: APP_GUARD,
      useClass: AccessTokenGuard
    }

  ]

})
export class AppModule { }
