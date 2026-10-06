import { Application, Request, Response, NextFunction } from 'express';

// Setup-endpoint guard for a panel that exposes ONLY the /api prefix (no /open alias and no rewrite),
// so listing the /api spellings is a complete guard.
export function guardSetup(app: Application, isInitialized: () => Promise<boolean>) {
  app.use(async (req: Request, res: Response, next: NextFunction) => {
    if (!['/api/setup', '/api/setup/notification'].includes(req.path)) {
      return next();
    }
    if (await isInitialized()) {
      return res.send({ code: 450, message: 'unknown error' });
    }
    return next();
  });
}
