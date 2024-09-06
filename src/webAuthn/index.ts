import { p256 } from "@noble/curves/p256";
import {
  startAuthentication,
  startRegistration,
  browserSupportsWebAuthn,
} from "@simplewebauthn/browser";
import {
  convertCOSEtoPKCS,
  decodeAttestationObject,
  decodeClientDataJSON,
  decodeCredentialPublicKey,
  generateChallenge,
  isoBase64URL,
  isoUint8Array,
  parseAuthenticatorData,
  convertAAGUIDToString,
  cose,
  isoCBOR,
} from "@simplewebauthn/server/helpers";
import type {
  AttestationConveyancePreference,
  COSEAlgorithmIdentifier,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialDescriptorJSON,
  PublicKeyCredentialRequestOptionsJSON,
  PublicKeyCredentialType,
  UserVerificationRequirement,
} from "@simplewebauthn/types";
import type {
  WebAuthnAuthentication,
  WebAuthnCreation,
  WebAuthnRegistration,
  WebAuthnRequest,
} from "@/webAuthn/typing";
import json from "@/util/json";

import type { B64UrlString } from "@/util/typing";

export const createWebAuthn = async (
  params?: WebAuthnCreation
): Promise<WebAuthnRegistration> => {
  const challengeBase64Url =
    params && params.challenge && isoBase64URL.isBase64(params.challenge)
      ? params.challenge
      : isoBase64URL.fromBuffer(await generateChallenge());
  const userDisplayName =
    params && params.user ? decodeURI(params.user) : "User Name";

  const name = userDisplayName.toLowerCase().replace(/[^\w]/g, "");
  const id = new Date()
    .toISOString()
    .slice(0, 23)
    .replace("T", "_")
    .replace(".", "_");

  const userId = `${name}_${id}`;
  const userIdBase64URL = isoBase64URL.fromUTF8String(`${name}_${id}`);
  const userName = `${userId}@${defaultWebAuthn.rpName}`;

  console.log(`[ttt] browserSupportsWebAuthn: ${browserSupportsWebAuthn()}`);

  // Create WebAuthn
  const regResJSON = await startRegistration({
    rp: {
      name: defaultWebAuthn.rpName,
    },
    user: {
      id: userIdBase64URL,
      name: userName,
      displayName: userDisplayName,
    },
    challenge: challengeBase64Url,
    pubKeyCredParams: [
      {
        alg: defaultWebAuthn.pubKeyCredAlgEdDsa,
        type: defaultWebAuthn.pubKeyCredType,
      },
      {
        alg: defaultWebAuthn.pubKeyCredAlgEs256,
        type: defaultWebAuthn.pubKeyCredType,
      },
      {
        alg: defaultWebAuthn.pubKeyCredAlgRs256,
        type: defaultWebAuthn.pubKeyCredType,
      },
      {
        alg: defaultWebAuthn.pubKeyCredAlgEs384,
        type: defaultWebAuthn.pubKeyCredType,
      },
      {
        alg: defaultWebAuthn.pubKeyCredAlgEs512,
        type: defaultWebAuthn.pubKeyCredType,
      },
    ],
    timeout: defaultWebAuthn.timeout,
    authenticatorSelection: {
      requireResidentKey: defaultWebAuthn.requireResidentKey,
      residentKey: defaultWebAuthn.residentKeyRequirement,
      userVerification: defaultWebAuthn.userVerificationRequirement,
    },
    attestation: defaultWebAuthn.attestationConveyancePreference,
    extensions: defaultWebAuthn.extensions,
  } as PublicKeyCredentialCreationOptionsJSON);

  //   console.log(`[ttt] regResJSON: ${JSON.stringify(regResJSON, null, 2)}`);

  const credIdBase64Url = regResJSON.id;
  console.log(`[ttt] credIdBase64Url: ${credIdBase64Url}`);
  const clientDataJsonBase64Url = regResJSON.response.clientDataJSON;
  const decodedClientData = decodeClientDataJSON(clientDataJsonBase64Url);
  const origin = decodedClientData.origin;

  const attestObjBase64Url = regResJSON.response.attestationObject;
  const attestObjUint8Arr = isoBase64URL.toBuffer(attestObjBase64Url);
  const decodedAttObj = decodeAttestationObject(attestObjUint8Arr);
  console.log(
    `[ttt] decodedAttObj.get("attStmt"): ${JSON.stringify(
      decodedAttObj.get("attStmt"),
      null,
      2
    )}`
  );
  console.log(
    `[ttt] decodedAttObj.get("fmt"): ${JSON.stringify(
      decodedAttObj.get("fmt"),
      null,
      2
    )}`
  );
  const authData = parseAuthenticatorData(decodedAttObj.get("authData"));
  //   authData.
  //   console.log(`[ttt] authData: ${JSON.stringify(authData, null, 2)}`);
  if (authData.aaguid) {
    const aaguidUint8Arr = authData.aaguid;
    const aaguid = convertAAGUIDToString(aaguidUint8Arr);
    console.log(`[ttt] aaguid: ${aaguid}`);
  }

  const credPubKeyUint8Arr = authData.credentialPublicKey!;
  // Refer: node_modules/@simplewebauthn/server/esm/helpers/convertCOSEtoPKCS.js
  const pubKeyStruct =
    isoCBOR.decodeFirst<cose.COSEPublicKey>(credPubKeyUint8Arr);
  const pubKeyKty = pubKeyStruct.get(cose.COSEKEYS.kty);
  const pubKeyAlg = pubKeyStruct.get(cose.COSEKEYS.alg);
  console.log(
    `[ttt][COSEPublicKey] pubKeyKty: ${pubKeyKty}\npubKeyAlg: ${pubKeyAlg}`
  );

  // EdDSA, e.g.: Ed25519
  if (cose.isCOSEPublicKeyOKP(pubKeyStruct)) {
    const pubKeyCrv = pubKeyStruct.get(cose.COSEKEYS.crv);
    const pubKeyXUint8Arr = pubKeyStruct.get(cose.COSEKEYS.x);
    if (pubKeyXUint8Arr) {
      // x: 密鑰對的公鑰。它不是橢圓曲線的 x 坐標，而是密鑰對的公鑰表示方式。
      const pubKeyXHex = `0x${isoUint8Array.toHex(pubKeyXUint8Arr)}`;
      const pubKeyXBigInt = BigInt(pubKeyXHex);
      console.log(
        `[ttt][COSEPublicKeyOKP] pubKeyCrv: ${pubKeyCrv}\npubKeyXHex: ${pubKeyXHex}\npubKeyXBigInt${pubKeyXBigInt}`
      );
    }
  }

  // ECDSA, e.g.: ES256, ES384, ES512
  if (cose.isCOSEPublicKeyEC2(pubKeyStruct)) {
    const pubKeyCrv = pubKeyStruct.get(cose.COSEKEYS.crv);
    const pubKeyXUint8Arr = pubKeyStruct.get(cose.COSEKEYS.x);
    const pubKeyYUint8Arr = pubKeyStruct.get(cose.COSEKEYS.y);
    if (pubKeyXUint8Arr && pubKeyYUint8Arr) {
      // x: 橢圓曲線上的 x 坐標。
      // y: 橢圓曲線上的 y 坐標。
      const pubKeyXHex = `0x${isoUint8Array.toHex(pubKeyXUint8Arr)}`;
      const pubKeyYHex = `0x${isoUint8Array.toHex(pubKeyYUint8Arr)}`;
      const pubKeyXBigInt = BigInt(pubKeyXHex);
      const pubKeyYBigInt = BigInt(pubKeyYHex);
      console.log(
        `[ttt][COSEPublicKeyEC2] pubKeyCrv: ${pubKeyCrv}\npubKeyXHex: ${pubKeyXHex}\npubKeyYHex: ${pubKeyYHex}\npubKeyXBigInt: ${pubKeyXBigInt}\npubKeyYBigInt: ${pubKeyYBigInt}`
      );
    }
  }

  // RS256
  if (cose.isCOSEPublicKeyRSA(pubKeyStruct)) {
    const pubKeyNUint8Arr = pubKeyStruct.get(cose.COSEKEYS.n);
    const pubKeyEUint8Arr = pubKeyStruct.get(cose.COSEKEYS.e);
    if (pubKeyNUint8Arr && pubKeyEUint8Arr) {
      // e: 公鑰指數（exponent），通常稱為加密指數或公開指數。它是用於加密和驗證簽名的數字。
      // n: 模數（modulus），它是由兩個大質數的乘積構成，並且用於加密和簽名驗證的基礎數字。
      const pubKeyNHex = `0x${isoUint8Array.toHex(pubKeyNUint8Arr)}`;
      const pubKeyEHex = `0x${isoUint8Array.toHex(pubKeyEUint8Arr)}`;
      const pubKeyNBigInt = BigInt(pubKeyNHex);
      const pubKeyEBigInt = BigInt(pubKeyEHex);
      console.log(
        `[ttt][COSEPublicKeyRSA] pubKeyNHex: ${pubKeyNHex}\npubKeyEHex: ${pubKeyEHex}\npubKeyNBigInt: ${pubKeyNBigInt}\npubKeyEBigInt:${pubKeyEBigInt}`
      );
    }
  }

  const credPubKeyObjUint8Arr = convertCOSEtoPKCS(credPubKeyUint8Arr);
  const credPubKeyXLen = (credPubKeyObjUint8Arr.length - 1) / 2; // tag length = 1

  const credPubKeyXUint8Arr = credPubKeyObjUint8Arr.subarray(
    1,
    1 + credPubKeyXLen
  );
  const credPubKeyXHex = `0x${isoUint8Array.toHex(credPubKeyXUint8Arr)}`;
  const credPubKeyXUint256 = BigInt(credPubKeyXHex);
  const credPubKeyYUint8Arr = credPubKeyObjUint8Arr.subarray(
    1 + credPubKeyXLen
  );
  const credPubKeyYHex = `0x${isoUint8Array.toHex(credPubKeyYUint8Arr)}`;
  const credPubKeyYUint256 = BigInt(credPubKeyYHex);
  console.log(
    `[webAuthn][debug]\nuserDisplayName: ${userDisplayName}\nchallengeBase64Url: ${challengeBase64Url}\ncredPubKeyXHex: ${credPubKeyXHex}\ncredPubKeyYHex: ${credPubKeyYHex}`
  );
  return {
    origin: origin,
    credentialId: credIdBase64Url,
    publicKey: {
      x: credPubKeyXUint256,
      y: credPubKeyYUint256,
    },
  };
};

export const requestWebAuthn = async (
  params: WebAuthnRequest
): Promise<WebAuthnAuthentication> => {
  const authResJson = await startAuthentication({
    ...(params.credentialId
      ? {
          allowCredentials: [
            { id: params.credentialId, type: defaultWebAuthn.pubKeyCredType },
          ] as PublicKeyCredentialDescriptorJSON[],
        }
      : {}),
    userVerification: defaultWebAuthn.userVerificationRequirement,
    challenge: params.challenge,
  } as PublicKeyCredentialRequestOptionsJSON);

  const authDataUrlB64 = authResJson.response.authenticatorData;
  const authDataHex = `0x${isoUint8Array.toHex(
    isoBase64URL.toBuffer(authDataUrlB64)
  )}`;
  const clientDataJsonUrlB64 = authResJson.response.clientDataJSON;
  const clientDataJsonUtf8 = isoBase64URL.toUTF8String(clientDataJsonUrlB64);
  const sigUrlB64 = authResJson.response.signature;
  console.log(`[ttt] sigUrlB64: ${sigUrlB64}`);

  const sigUint8Arr = isoBase64URL.toBuffer(sigUrlB64);
  const sigPubKey = decodeCredentialPublicKey(sigUint8Arr);
  console.log(`[ttt] sigPubKey: ${json.stringify(sigPubKey, null, 2)}`);
  const sigKty = sigPubKey.get(cose.COSEKEYS.kty);
  const sigAlg = sigPubKey.get(cose.COSEKEYS.alg);
  console.log(`[ttt][COSEPublicKey] sigKty: ${sigKty}\nsigAlg: ${sigAlg}`);

  if (cose.isCOSEPublicKeyOKP(sigPubKey)) {
    const sigCrv = sigPubKey.get(cose.COSEKEYS.crv);
    const sigXUint8Arr = sigPubKey.get(cose.COSEKEYS.x);
    if (sigXUint8Arr) {
      const sigX = isoUint8Array.toHex(sigXUint8Arr);
      console.log(`[ttt][COSEPublicKeyOKP] sigCrv: ${sigCrv}\nsigX: ${sigX}`);
    }
  }

  if (cose.isCOSEPublicKeyEC2(sigPubKey)) {
    const sigCrv = sigPubKey.get(cose.COSEKEYS.crv);
    const sigXUint8Arr = sigPubKey.get(cose.COSEKEYS.x);
    const sigYUint8Arr = sigPubKey.get(cose.COSEKEYS.y);
    if (sigXUint8Arr && sigYUint8Arr) {
      const sigX = isoUint8Array.toHex(sigXUint8Arr);
      const sigY = isoUint8Array.toHex(sigYUint8Arr);
      console.log(
        `[ttt][COSEPublicKeyEC2] sigCrv: ${sigCrv}\nsigX: ${sigX}\nsigY: ${sigY}`
      );
    }
  }

  if (cose.isCOSEPublicKeyRSA(sigPubKey)) {
    const sigNUint8Arr = sigPubKey.get(cose.COSEKEYS.n);
    const sigEUint8Arr = sigPubKey.get(cose.COSEKEYS.e);
    if (sigNUint8Arr && sigEUint8Arr) {
      const sigN = isoUint8Array.toHex(sigNUint8Arr);
      const sigE = isoUint8Array.toHex(sigEUint8Arr);
      console.log(`[ttt][COSEPublicKeyRSA] sigN: ${sigN}\nsigE: ${sigE}`);
    }
  }

  const [sigRUint, sigSUint] = parseSignature(sigUrlB64);
  console.log(`[ttt] sigRUint: ${sigRUint}\nsigUrlB64: ${sigUrlB64}`);

  return {
    authenticatorData: authDataHex,
    clientDataJson: clientDataJsonUtf8,
    signature: {
      r: sigRUint,
      s: sigSUint,
    },
  };
};

export const defaultWebAuthn = {
  attestationConveyancePreference: "none" as AttestationConveyancePreference,
  // This Relying Party will accept either an ES256 or RS256 credential, but prefers an ES256 credential.
  // Refer: https://www.iana.org/assignments/cose/cose.xhtml
  pubKeyCredAlgEs256: -7 as COSEAlgorithmIdentifier, // ES256 (WebAuthn's default algorithm)
  pubKeyCredAlgRs256: -257 as COSEAlgorithmIdentifier, // RS256 (for Windows Hello and others)
  pubKeyCredAlgEs384: -35 as COSEAlgorithmIdentifier, // ES384
  pubKeyCredAlgEs512: -36 as COSEAlgorithmIdentifier, // ES512
  pubKeyCredAlgEdDsa: -8 as COSEAlgorithmIdentifier, // EdDSA
  // Try to use UV if possible. This is also the default.
  pubKeyCredType: "public-key" as PublicKeyCredentialType,
  residentKeyRequirement: "required" as ResidentKeyRequirement,
  userVerificationRequirement: "required" as UserVerificationRequirement,
  timeout: 300000, // 5 minutes
  // Relying Party
  rpName: "Waallet Extension",
  extensions: {
    largeBlob: {
      support: "preferred", // "required", "preferred"
    },
  },
  requireResidentKey: true,
};

const parseSignature = (signature: B64UrlString): [bigint, bigint] => {
  if (!isoBase64URL.isBase64URL(signature)) {
    console.log(`${signature} is not Base64Url`);
    return [BigInt(0), BigInt(0)];
  }
  const p256Sig = p256.Signature.fromDER(
    isoUint8Array.toHex(isoBase64URL.toBuffer(signature))
  );
  // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
  const p256SigS =
    p256Sig.s > p256.CURVE.n / 2n ? p256.CURVE.n - p256Sig.s : p256Sig.s;

  return [p256Sig.r, p256SigS];
};
