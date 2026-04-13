import {IncomingMessage, ServerResponse} from "http";
import {Socket} from "net";
import {URL} from "url";
import {
  app,
  HttpRequest,
  HttpResponseInit,
  InvocationContext,
} from "@azure/functions";
import {connectDb} from "../db/index.js";
import {expressApp} from "../server.js";

const ready = connectDb();

async function handler(
  request: HttpRequest,
  _ctx: InvocationContext,
): Promise<HttpResponseInit> {
  await ready;

  const bodyBuf = Buffer.from(await request.arrayBuffer());

  const socket = new Socket();
  const req = new IncomingMessage(socket);
  req.method = request.method;
  const u = new URL(request.url);
  req.url = u.pathname + u.search;
  for (const [k, v] of request.headers.entries()) {
    req.headers[k.toLowerCase()] = v;
  }
  // The client IP is forwarded by the Functions host. `trust proxy` in express
  // picks it up from x-forwarded-for.
  req.push(bodyBuf.length ? bodyBuf : null);
  req.push(null);

  const res = new ServerResponse(req);
  const chunks: Buffer[] = [];
  const origWrite = res.write.bind(res);
  const origEnd = res.end.bind(res);

  res.write = ((chunk: unknown, ...rest: unknown[]) => {
    if (chunk) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string));
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (origWrite as any)(chunk, ...rest);
  }) as typeof res.write;

  return new Promise<HttpResponseInit>((resolve, reject) => {
    res.end = ((chunk: unknown, ...rest: unknown[]) => {
      if (chunk && typeof chunk !== "function") {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string));
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const result = (origEnd as any)(chunk, ...rest);

      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(res.getHeaders())) {
        if (v === undefined) continue;
        headers[k] = Array.isArray(v) ? v.join(",") : String(v);
      }
      resolve({
        status: res.statusCode,
        headers,
        body: Buffer.concat(chunks),
      });
      return result;
    }) as typeof res.end;

    res.on("error", reject);
    expressApp(req, res);
  });
}

app.http("bab", {
  route: "{*path}",
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
  authLevel: "anonymous",
  handler,
});
