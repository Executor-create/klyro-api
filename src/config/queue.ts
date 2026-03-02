export const queueConfig = {
  connection: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT as string, 10) || 6379,
  },
};
