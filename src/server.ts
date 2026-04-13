import {expressMiddleware as RIdMiddleWare} from "cls-rtracer";
import config from "config";
import express, {NextFunction, Request, Response} from "express";
import expressWinston from "express-winston";
import registerRouters from "./routers/index.js";
import {moduleLogger} from "./logger.js";
import {registerSecurityMiddleware} from "./util/securityMiddleware.js";
import {getBool} from "./util/configHelpers.js";

const httpLogger = moduleLogger("HTTP");

export const expressApp = express();

const proxySetting = config.get<string | number | boolean>("server.proxy");
const trustProxy =
  proxySetting === "true" ? true : proxySetting === "false" ? false : proxySetting;
expressApp.set("trust proxy", trustProxy);

// Azure App Service / Functions writes X-Forwarded-For entries as ip:port.
// proxy-addr expects bare IPs, so strip the port from each entry.
expressApp.use((req, _res, next) => {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string") {
    req.headers["x-forwarded-for"] = xff
      .split(",")
      .map(entry => {
        const trimmed = entry.trim();
        // IPv6 entries are bracketed like [::1]:1234; bare IPv4 is 1.2.3.4:5678
        if (trimmed.startsWith("[")) {
          const end = trimmed.indexOf("]");
          return end === -1 ? trimmed : trimmed.slice(1, end);
        }
        const colon = trimmed.lastIndexOf(":");
        return colon === -1 || trimmed.indexOf(":") !== colon
          ? trimmed
          : trimmed.slice(0, colon);
      })
      .join(", ");
  }
  next();
});

expressApp.use(express.urlencoded({extended: false}));
expressApp.use(RIdMiddleWare({echoHeader: true}));
expressApp.use(
  expressWinston.logger({
    winstonInstance: httpLogger,
    metaField: "http",
    msg: "{{res.responseTime}}ms {{res.statusCode}} {{req.method}} {{req.url}}",
    meta: getBool("logging.http.meta"),
    statusLevels: {
      success: config.get<string>("logging.http.level"),
      warn: "warning",
      error: "error",
    },
  }),
);

registerSecurityMiddleware(expressApp);
registerRouters(expressApp);

expressApp.use(
  expressWinston.errorLogger({
    winstonInstance: httpLogger,
    msg: "{{req.method}} {{req.url}} {{err}}",
    blacklistedMetaFields: ["exception", "trace", "date", "os"],
    metaField: null,
    dynamicMeta: (req, res, err) => {
      return {
        error: err,
      };
    },
  }),
);

// eslint-disable-next-line @typescript-eslint/no-unused-vars
expressApp.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (!res.writableEnded) {
    res.status(500).send("Error occured in application. Contact application owner.").end();
  }
});

export function registerServer() {
  return new Promise((resolve, reject) => {
    let string_port: string | undefined = config.get<string>("server.port");
    // Test for alphanumericity by checking if the string -> int -> string conversion is lossless
    if (String(parseInt(string_port)) !== string_port) {
      string_port = process.env[string_port];
    }

    if (string_port == null) {
      httpLogger.error(`Unable to use ${string_port} from environment variable`);
      reject("Unable to listen");
      return;
    }

    const port = parseInt(string_port);

    const expressServer = expressApp.listen(port, config.get<string>("server.host"), () => {
      httpLogger.info(`Listening on ${port}`);
      resolve(port);
    });
    expressServer.on("error", e => {
      httpLogger.error(`Unable to listen on ${port}:`, e);
      reject(e);
    });

    process.on("SIGTERM", () => {
      httpLogger.info("Received stop signal. Goodbye.");
      expressServer.close();
    });
  });
}
