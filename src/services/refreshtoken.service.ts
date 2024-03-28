import {
  RefreshTokenServiceBindings,
  TokenServiceBindings,
} from '@loopback/authentication-jwt';
import {inject} from '@loopback/core';
import {UserServiceBindings} from '../keys/jwt-key';
import {MyUserService} from './user.service';
import {TokenService} from '@loopback/authentication';
import {TokenObject} from '../keys';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import {securityId, UserProfile} from '@loopback/security';
import {repository} from '@loopback/repository';
import {HttpErrors} from '@loopback/rest';
import {RefreshToken, RefreshTokenRelations} from '../models';
import {RefreshTokenRepository} from '../repositories';
export class RefreshTokenService {

  constructor(
    @inject(RefreshTokenServiceBindings.REFRESH_SECRET) private refreshSecret: string,
    @inject(RefreshTokenServiceBindings.REFRESH_EXPIRES_IN) private refreshExpiresIn: string,
    @inject(RefreshTokenServiceBindings.REFRESH_ISSUER) private refreshIssuer: string,
    @repository(RefreshTokenRepository) public refreshTokenRepository: RefreshTokenRepository,
    @inject(UserServiceBindings.USER_SERVICE) public userService: MyUserService,
    @inject(TokenServiceBindings.TOKEN_SERVICE) public jwtService: TokenService,

  ) {
  }

  async generateToken(userProfile: UserProfile, token: string) : Promise<TokenObject>{
    const data = {
      token: uuidv4() + userProfile?.id,
    };
    const refreshToken = jwt.sign(data, this.refreshSecret, {
      expiresIn: Number(this.refreshExpiresIn),
      issuer: this.refreshIssuer,
    });
    const result = {
      accessToken: token,
      refreshToken: refreshToken,
    };
    await this.refreshTokenRepository.create({
      userId: userProfile[securityId],
      refreshToken: result.refreshToken,
    });
    return result;
  }

  async refreshToken(refreshToken: string){
    try {
      if (!refreshToken) {
        throw new HttpErrors.Unauthorized(
          `Error verifying token : 'refresh token' is null`,
        );
      }
      const userRefreshData = await this.verifyToken(refreshToken);
      const user = await this.userService.findUserById(
        userRefreshData.userId.toString(),
      );
      const userProfile: UserProfile =
        this.userService.convertToUserProfile(user);
      // create a JSON Web Token based on the user profile
      const token = await this.jwtService.generateToken(userProfile);

      return {
        accessToken: token,
      };
    }catch (error) {
      throw new HttpErrors.Unauthorized(
        `Error verifying token : ${error.message}`,
      );
    }
  }

  async verifyToken(
    refreshToken: string,
  ): Promise<RefreshToken & RefreshTokenRelations> {
    try {
      jwt.verify(refreshToken, this.refreshSecret);
      const userRefreshData = await this.refreshTokenRepository.findOne({
        where: {refreshToken: refreshToken},
      });

      if (!userRefreshData) {
        throw new HttpErrors.Unauthorized(
          `Error verifying token : Invalid Token`,
        );
      }
      return userRefreshData;
    } catch (error) {
      throw new HttpErrors.Unauthorized(
        `Error verifying token : ${error.message}`,
      );
    }
  }
  async revokeToken(refreshToken: string) {
    try {
      await this.refreshTokenRepository.delete(
        new RefreshToken({refreshToken: refreshToken}),
      );
    } catch (e) {
      // ignore
    }
  }
  async revokeAllToken(userId: string) {
    try {
      await this.refreshTokenRepository.deleteAll({userId: userId});
    } catch (e) {
      // ignore
    }
  }
}