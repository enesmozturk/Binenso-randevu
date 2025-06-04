import { Injectable } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class AuthService {
  private prisma = new PrismaClient();
  private jwtSecret = process.env.JWT_SECRET || 'secret';
  private refreshSecret = process.env.JWT_REFRESH_SECRET || 'refreshsecret';

  async register(phone: string, password: string) {
    const hashed = await bcrypt.hash(password, 10);
    const user = await this.prisma.user.create({
      data: { phone, password: hashed },
    });
    return { id: user.id, phone: user.phone };
  }

  async login(phone: string, password: string) {
    const user = await this.prisma.user.findUnique({ where: { phone } });
    if (!user) throw new Error('User not found');
    const match = await bcrypt.compare(password, user.password);
    if (!match) throw new Error('Invalid password');

    const accessToken = jwt.sign({ sub: user.id }, this.jwtSecret, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ sub: user.id }, this.refreshSecret, { expiresIn: '7d' });

    return { accessToken, refreshToken };
  }
}