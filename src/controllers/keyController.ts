import {calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, JWK, CryptoKey} from "jose";
import {signingKeys} from "../db/index.js";
import {moduleLogger} from "../logger.js";
import type {SigningKeyDoc} from "../db/types.js";

const keyController = moduleLogger("KeyController");

async function generateNewKey(): Promise<SigningKeyDoc> {
  await signingKeys.updateMany(
    {active: true},
    {$set: {active: null, private: {}}},
  );

  const {publicKey: _publicKey, privateKey: _privateKey} = await generateKeyPair("RS256", {
    extractable: true,
  });
  const publicKey = await exportJWK(_publicKey);
  const privateKey = await exportJWK(_privateKey);
  publicKey.alg = "RS256";
  publicKey.use = "sig";
  const kid = await calculateJwkThumbprint(publicKey);
  publicKey.kid = kid;
  privateKey.kid = kid;

  const doc: SigningKeyDoc = {
    _id: kid,
    active: true,
    private: privateKey,
    public: publicKey,
    createdTime: new Date(),
  };
  await signingKeys.insertOne(doc);
  return doc;
}

export type SigningKey = SigningKeyDoc & {
  importedPrivate: CryptoKey | Uint8Array;
  importedPublic: CryptoKey | Uint8Array;
};

async function getActiveKey(): Promise<SigningKey> {
  const time3daysago = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000);
  let key = await signingKeys.findOne({active: true, createdTime: {$gte: time3daysago}});
  if (key === null) {
    keyController.info("There are no valid keys. Generating new signing key");
    key = await generateNewKey();
  }
  const transformedKey = key as SigningKey;
  transformedKey.importedPublic = await importJWK(transformedKey.public as JWK, "RS256");
  transformedKey.importedPrivate = await importJWK(transformedKey.private as JWK, "RS256");
  return transformedKey;
}

export {generateNewKey, getActiveKey};
