import {Entity, model, property} from '@loopback/repository';

@model({settings: {strict: false}})
export class UserCredential extends Entity {
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
  password: string;

  @property({
    type: 'string',
    required: true,
    index: {
      unique: true,
    },
  })
  userId: string;

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
  constructor(data?: Partial<UserCredential>) {
    super(data);
  }
}

export interface UserCredentialRelations {
  // describe navigational properties here
}

export type UserCredentialWithRelations = UserCredential & UserCredentialRelations;
