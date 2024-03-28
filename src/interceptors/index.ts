import {Interceptor} from '@loopback/core';



export const logError: Interceptor = async (invocationCtx, next) => {
  try {
    await next();
  } catch (err) {
    console.error('[Log Error]: ' + invocationCtx.source);
    throw err;
  }
};