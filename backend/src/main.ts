import { NestFactory } from '@nestjs/core';
import { Module } from '@nestjs/common';
import { AuthController } from './auth/auth.controller';
import { AuthService } from './auth/auth.service';
import { AppModule } from './app.module';

@Module({
  controllers: [AuthController],
  providers: [AuthService],
})


async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(3000);
}
bootstrap();