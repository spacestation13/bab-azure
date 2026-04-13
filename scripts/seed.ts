import config from "config";
import {MongoClient} from "mongodb";
import {ClientType, type ClientDoc} from "../src/db/types.js";

const client = new MongoClient(config.get<string>("database.connectionString"));

async function main() {
  await client.connect();
  const db = client.db();
  const clients = db.collection<ClientDoc>("clients");

  const docs: ClientDoc[] = [
    {
      _id: "testing_public",
      contactInfo: "Application Owner",
      desc: "Public testing client",
      redirectUris: [
        "http://localhost:80",
        "https://localhost:80",
        "http://localhost:8080",
        "https://localhost:8080",
      ],
      type: ClientType.Public,
      clientSecret: null,
      allowedTokenGrant: false,
      expiry: 10080,
      disabled: null,
    },
    {
      _id: "testing",
      clientSecret: "testing_secret",
      contactInfo: "Application Owner",
      desc: "Confidential testing client",
      redirectUris: [
        "http://localhost:80",
        "https://localhost:80",
        "http://localhost:8080",
        "https://localhost:8080",
      ],
      type: ClientType.Confidential,
      allowedTokenGrant: false,
      expiry: 10080,
      disabled: null,
    },
  ];

  for (const doc of docs) {
    await clients.updateOne({_id: doc._id}, {$setOnInsert: doc}, {upsert: true});
  }
}

main()
  .catch(e => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await client.close();
  });
