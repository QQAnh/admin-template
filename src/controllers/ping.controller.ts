import {composeInterceptors, inject, intercept, Interceptor} from '@loopback/core';
import {
  Request,
  RestBindings,
  get,
  response,
  ResponseObject,
} from '@loopback/rest';
// const log: Interceptor = async (invocationCtx, next) => {
//   console.log('log: before-' + invocationCtx.methodName);
//   // Wait until the interceptor/method chain returns
//   const result = await next();
//   console.log('log: after-' + invocationCtx.methodName);
//   return result;
// };
//
// const logError: Interceptor = async (invocationCtx, next) => {
//   try {
//     await next();
//   } catch (err) {
//     console.error('[Log Error]: ' + invocationCtx.source);
//     throw err;
//   }
// };
/**
 * OpenAPI response for ping()
 */
const PING_RESPONSE: ResponseObject = {
  description: 'Ping Response',
  content: {
    'application/json': {
      schema: {
        type: 'object',
        title: 'PingResponse',
        properties: {
          greeting: {type: 'string'},
          date: {type: 'string'},
          url: {type: 'string'},
          headers: {
            type: 'object',
            properties: {
              'Content-Type': {type: 'string'},
            },
            additionalProperties: true,
          },
        },
      },
    },
  },
};

/**
 * A simple controller to bounce back http requests
 */
// const interceptor = composeInterceptors(
//   log,
//   logError,
// );
// @intercept(interceptor)
export class PingController {
  constructor(@inject(RestBindings.Http.REQUEST) private req: Request) {}

  // Map to `GET /ping`
  @get('/ping')
  @response(200, PING_RESPONSE)
  ping(): Object {
    throw new Error('Not implemented')

    // Reply with a greeting, the current time, the url, and request headers
    return {
      greeting: 'Hello from LoopBack',
      date: new Date(),
      url: this.req.url,
      headers: Object.assign({}, this.req.headers),
    };
  }
}
