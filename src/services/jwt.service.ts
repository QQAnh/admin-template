/* eslint-disable @typescript-eslint/no-explicit-any */
import {TokenService} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {JWTAuthenticationStrategyBindings, JwtPayload} from '../keys/jwt-key';
import {HttpErrors, RequestWithSession} from '@loopback/rest';
import {jwtDecode} from 'jwt-decode';
import NodeCache from 'node-cache';
import jwt from 'jsonwebtoken';
import {securityId, UserProfile} from '@loopback/security';
import _ from 'lodash';

const myCache = new NodeCache({ stdTTL: 0, checkperiod: 0 });

// const signAsync = promisify(jwt.sign);
export class JWTService implements TokenService {
  constructor(
    @inject(JWTAuthenticationStrategyBindings.TOKEN_SECRET) private jwtSecret: string,
    @inject(JWTAuthenticationStrategyBindings.TOKEN_EXPIRES_IN) private jwtExpiresIn: string,

  ) {}

  async verifyToken(token:string): Promise<UserProfile>{
    if (!token) {
      throw new HttpErrors.Unauthorized(
        `Error verifying token : 'token' is null`,
      );
    }
    const decoded : JwtPayload = jwtDecode(token);
    if (!decoded.sub){
      throw new HttpErrors.Unauthorized(
        `Error verifying token :'sub' is null`,
      );
    }
    const value: string[] | undefined = myCache.get(decoded?.sub);
    if (value && value.length > 0) {
      const found = value.find((element) => element === token);

      if (!found){
        throw new HttpErrors.Unauthorized(
          `Error verifying token : 'token' is invalid`,
        );
      }
    }else {
      throw new HttpErrors.Unauthorized(
        `Error verifying token : 'token' is invalid`,
      );
    }

    let userProfile: any;
    try {
      userProfile = jwt.verify(token, this.jwtSecret);
      if (!userProfile) throw new HttpErrors.Unauthorized
      if (userProfile?.exp && Date.now() >= userProfile.exp * 1000) {
        throw new HttpErrors.Unauthorized(
          `Error verifying token : 'token' is expired`,
        );
      }
      userProfile[securityId] = userProfile.id; //because [securityId] is a Symbol and couldn't be saved in the token, we need recreate it here.
    } catch (error) {
      throw new HttpErrors.Unauthorized(
        `Error verifying token : ${error.message}`,
      );
    }
    return userProfile
  }

  async generateToken(userProfile: UserProfile | undefined): Promise<string> {
    if (!userProfile) {
      throw new HttpErrors.Unauthorized(
        'Error generating token : userProfile is null',
      );
    }
    let token: string;
    try {
      token = jwt.sign(userProfile, this.jwtSecret, {
        expiresIn: Number(this.jwtExpiresIn),
      });

      const value: string[] | undefined = myCache.get(userProfile.id);
      if ( value === undefined ){
        myCache.set(userProfile.id, [token]);
      }else {
        value.push(token);
        myCache.set(userProfile.id,value);
      }
    } catch (error) {
      throw new HttpErrors.Unauthorized(`Error encoding token : ${error}`);
    }

    return token;
  }

  public extractCredentials(request: RequestWithSession): string {
    if (!request.headers.authorization) {
      throw new HttpErrors.Unauthorized(`Authorization header not found.`);
    }
    const authHeaderValue = request.headers.authorization;

    if (!authHeaderValue.startsWith('Bearer')) {
      throw new HttpErrors.Unauthorized(
        `Authorization header is not of type 'Bearer'.`,
      );
    }
    const parts = authHeaderValue.split(' ');
    if (parts.length !== 2)
      throw new HttpErrors.Unauthorized(
        `Authorization header value has too many parts. It must follow the pattern: 'Bearer xx.yy.zz' where xx.yy.zz is a valid JWT token.`,
      );
    return parts[1];
  }

  async revokeToken(token: string): Promise<boolean> {
    const decoded: any = jwtDecode(token);

    const value: string[] | undefined = myCache.get(decoded?.id);
    if (value && value?.length > 0) {
      const filtered = value.filter(elem => elem !== token);
      myCache.set(decoded.id,filtered);
    }
    return true
  }

  async revokeAllToken(req: RequestWithSession): Promise<boolean> {
    const token = this.extractCredentials(req);
    const decoded: any = jwtDecode(token);
    myCache.del(decoded?.id);
    return true
  }

  async revokeTokenInTime(currentTime: Date) {
    const mykeys = myCache.keys();
    for (const mykey of mykeys) {
      const value: string[] | undefined = myCache.get(mykey);
      const listDelete : string[] = [];
      if (value && value?.length > 0) {
        for (const valueElement of value) {
          const decoded: any = jwtDecode(valueElement);
          const tokenExp = new Date(decoded?.exp*1000);
          if (tokenExp < currentTime) {
            listDelete.push(valueElement);
          }
        }
        const difference = _.difference(value, listDelete);
        myCache.set(mykey, difference);
      }
    }
  }
}