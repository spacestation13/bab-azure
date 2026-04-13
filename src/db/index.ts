import config from "config";
import {MongoClient, Collection, Db} from "mongodb";
import {moduleLogger} from "../logger.js";
import type {
  AuthorizationDoc,
  ByondCertDoc,
  ClientDoc,
  SigningKeyDoc,
  UserDataDoc,
} from "./types.js";

const dbLogger = moduleLogger("Database");

const client = new MongoClient(config.get<string>("database.connectionString"));

let db: Db;

export let clients: Collection<ClientDoc>;
export let authorizations: Collection<AuthorizationDoc>;
export let userData: Collection<UserDataDoc>;
export let byondCerts: Collection<ByondCertDoc>;
export let signingKeys: Collection<SigningKeyDoc>;

export async function connectDb() {
  await client.connect();
  db = client.db();

  clients = db.collection<ClientDoc>("clients");
  authorizations = db.collection<AuthorizationDoc>("authorizations");
  userData = db.collection<UserDataDoc>("userData");
  byondCerts = db.collection<ByondCertDoc>("byondCerts");
  signingKeys = db.collection<SigningKeyDoc>("signingKeys");

  await Promise.all([
    authorizations.createIndex({byondState: 1}, {unique: true}),
    authorizations.createIndex(
      {code: 1},
      {unique: true, partialFilterExpression: {code: {$type: "string"}}},
    ),
    byondCerts.createIndex({byondState: 1, byondCert: 1}, {unique: true}),
    byondCerts.createIndex({createdTime: 1}, {expireAfterSeconds: 15 * 60}),
    signingKeys.createIndex(
      {active: 1},
      {unique: true, partialFilterExpression: {active: true}},
    ),
    signingKeys.createIndex({createdTime: 1}, {expireAfterSeconds: 30 * 24 * 60 * 60}),
  ]);

  dbLogger.info("Connected to MongoDB");
}

process.on("SIGTERM", () => {
  client.close().catch(e => dbLogger.error("Error closing mongo client", {e}));
});
