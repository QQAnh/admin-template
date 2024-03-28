import {HttpErrors} from '@loopback/rest';
import {KeyAndPassword} from '../models';

export function validateKeyPassword(keyAndPassword: KeyAndPassword) {
  // Validate Password Length
  if (!keyAndPassword.password || keyAndPassword.password.length < 8) {
    throw new HttpErrors.UnprocessableEntity(
      'password must be minimum 8 characters',
    );
  }

  if (keyAndPassword.password !== keyAndPassword.confirmPassword) {
    throw new HttpErrors.UnprocessableEntity(
      'password and confirmation password do not match',
    );
  }

  if (
    keyAndPassword.resetKey.length === 0 ||
    keyAndPassword.resetKey.trim() === ''
  ) {
    throw new HttpErrors.UnprocessableEntity('reset key is mandatory');
  }
}