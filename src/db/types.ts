import type {JWK} from "jose";
import type {ObjectId} from "mongodb";

export const ClientType = {
  Public: "Public",
  Confidential: "Confidential",
} as const;
export type ClientType = (typeof ClientType)[keyof typeof ClientType];

export const ResponseMode = {
  query: "query",
  fragment: "fragment",
} as const;
export type ResponseMode = (typeof ResponseMode)[keyof typeof ResponseMode];

export const ResponseTypes = {
  code: "code",
  id_token: "id_token",
  none: "none",
} as const;
export type ResponseTypes = (typeof ResponseTypes)[keyof typeof ResponseTypes];

export const AuthorizationStatus = {
  Created: "Created",
  CodeIssued: "CodeIssued",
  Completed: "Completed",
} as const;
export type AuthorizationStatus =
  (typeof AuthorizationStatus)[keyof typeof AuthorizationStatus];

export interface ClientDoc {
  _id: string;
  redirectUris: string[];
  contactInfo: string;
  desc: string;
  type: ClientType;
  clientSecret: string | null;
  allowedTokenGrant: boolean;
  expiry: number;
  disabled: string | null;
}

export interface AuthorizationDoc {
  _id?: ObjectId;
  status: AuthorizationStatus;
  startDate: Date;
  endDate: Date | null;
  clientId: string;
  redirectUri: string;
  state: string | null;
  responseMode: ResponseMode;
  responseTypes: ResponseTypes[];
  scopes: string[];
  nonce: string | null;
  subClaim: string | null;
  userIp: string;
  byondState: string;
  ckey: string | null;
  code: string | null;
}

export interface UserDataDoc {
  _id: string;
  gender: string;
}

export interface ByondCertDoc {
  _id: string;
  byondState: string;
  byondCert: string;
  clientIp: string;
  createdTime: Date;
}

export interface SigningKeyDoc {
  _id: string;
  private: JWK | Record<string, never>;
  public: JWK;
  active: boolean | null;
  createdTime: Date;
}
