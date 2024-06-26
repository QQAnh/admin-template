import {Entity, model, property, hasOne} from '@loopback/repository';
import {UserCredential} from './user-credential.model';

@model({settings: {strict: false}})
export class User extends Entity {
  @property({
    type: 'string',
    id: true,
    generated: true,
  })
  id?: string;

  @property({
    type: 'string',
    required: true,
  })
  username: string;

  @property({
    type: 'string',
    required: true,
  })
  email: string;

  @property({
    type: 'boolean',
    required: true,
  })
  emailVerified: boolean;

  @property({
    type: 'string',
  })
  verificationToken?: string;

  @property({
    type: 'string',
  })
  resetKey?: string;

  @property({
    type: 'number',
    default: 0
  })
  resetCount: number;

  @property({
    type: 'string',
  })
  resetTimestamp: string;

  @property({
    type: 'string',
  })
  resetKeyTimestamp: string;

  @property({
    type: 'date',
    default: () => new Date()
  })
  created?: string;

  @property({
    type: 'date',
    default: () => new Date()
  })
  modified?: string;

  @property({
    type: 'string',
  })
  roleId?: string;

  @hasOne(() => UserCredential)
  userCredential: UserCredential;
  // Define well-known properties here

  // Indexer property to allow additional data
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [prop: string]: any;

  constructor(data?: Partial<User>) {
    super(data);
  }
}

export interface UserRelations {
  // describe navigational properties here
}

export type UserWithRelations = User & UserRelations;
