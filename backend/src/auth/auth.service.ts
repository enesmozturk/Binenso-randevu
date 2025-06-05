import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { jwtConstants } from './constants';


@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async validateUser(phone: string, password: string) {
    const user = await this.prisma.user.findUnique({ where: { phone } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException('Telefon veya şifre yanlış');
    }
    return user;
  }

  async login(user: any) {
    const payload = { sub: user.id, phone: user.phone };
    const accessToken = this.jwtService.sign(payload, {
      secret: jwtConstants.secret,
      expiresIn: '15m',
    });
    const refreshToken = this.jwtService.sign(payload, {
      secret: jwtConstants.secret,
      expiresIn: '7d',
    });

    return { accessToken, refreshToken };
  }

  async register(data: { name: string; surname: string; phone: string; password: string; email: string }) {
    const hash = await bcrypt.hash(data.password, 10);
    const user = await this.prisma.user.create({
      data: {
        name: data.name,
        surname: data.surname,
        phone: data.phone,
        email: data.email,
        password: hash,
      },
    });
    return this.login(user);
  }
}

