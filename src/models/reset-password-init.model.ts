import {Entity, Model, model, property} from '@loopback/repository';

@model()
export class ResetPasswordInit extends Model {
  @property({
    type: 'string',
    required: true,
  })
  email: string;

  constructor(data?: Partial<ResetPasswordInit>) {
    super(data);
  }
}

export interface ResetPasswordInitRelations {
  // describe navigational properties here
}

export type ResetPasswordInitWithRelations = ResetPasswordInit & ResetPasswordInitRelations;
