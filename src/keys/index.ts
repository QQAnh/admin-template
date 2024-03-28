import {BindingKey} from '@loopback/core';
import {PasswordHashes} from '../services/hash.password.bcryptjs';

export type Credentials = {
  username: string;
  password: string;
  rememberMe?: boolean;
};
export type TokenObject = {
  accessToken: string;
  expiresIn?: string | undefined;
  refreshToken?: string | undefined;
};


export namespace PasswordHasherBindings {
  export const PASSWORD_HASHER =
    BindingKey.create<PasswordHashes>('services.hasher');
  export const ROUNDS = BindingKey.create<number>('services.hasher.round');
}