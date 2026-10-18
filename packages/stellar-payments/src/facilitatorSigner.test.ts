import { Keypair } from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";

import { loadConfig } from "@lumenbazaar/shared";

import {
  assertRuntimeSignerReady,
  createRuntimeFacilitatorSignerProvider,
  EnvironmentFacilitatorSignerProvider
} from "./facilitatorSigner.js";

describe("facilitator signer provider", () => {
  it("loads an official signer without exposing secret material", async () => {
    const keypair = Keypair.random();
    const secret = keypair.secret();
    const provider = providerFor(keypair, () => ({ secret, version: "key-v1" }));

    await expect(provider.getStatus()).resolves.toEqual({
      address: keypair.publicKey(),
      keyVersion: "key-v1",
      network: "stellar:testnet",
      provider: "environment"
    });
    const signer = await provider.getSigner();
    expect(signer.address).toBe(keypair.publicKey());
    expect(JSON.stringify(signer)).not.toContain(secret);
  });

  it("fails closed when the signer is unavailable or has the wrong address", async () => {
    const expected = Keypair.random();
    const wrong = Keypair.random();
    const wrongSecret = wrong.secret();
    const unavailable = providerFor(expected, () => {
      throw new Error("provider internals must stay private");
    });
    const wrongAddress = providerFor(expected, () => ({
      secret: wrongSecret,
      version: "key-v1"
    }));

    await expect(unavailable.assertReady()).rejects.toMatchObject({
      code: "SETTLEMENT_FAILED",
      message: "Facilitator signing material is unavailable."
    });
    await expect(wrongAddress.assertReady()).rejects.toMatchObject({
      code: "SETTLEMENT_FAILED",
      message: "Facilitator signer address does not match configuration."
    });
    await wrongAddress.assertReady().catch((error: unknown) => {
      expect(JSON.stringify(error)).not.toContain(wrongSecret);
      expect(String(error)).not.toContain(wrongSecret);
    });
  });

  it("refreshes rotated key versions and enforces revocation", async () => {
    const keypair = Keypair.random();
    const snapshot = { secret: keypair.secret(), version: "key-v1" };
    const provider = providerFor(keypair, () => snapshot);
    const first = await provider.getSigner();

    snapshot.version = "key-v2";
    provider.rotate();
    const rotated = await provider.getSigner();
    expect(rotated).not.toBe(first);
    await expect(provider.getStatus()).resolves.toMatchObject({ keyVersion: "key-v2" });

    provider.revoke();
    await expect(provider.getSigner()).rejects.toMatchObject({
      code: "SETTLEMENT_FAILED",
      message: "Facilitator signer has been revoked."
    });

    provider.restore();
    await expect(provider.getSigner()).resolves.toMatchObject({ address: keypair.publicKey() });
  });

  it("validates runtime network, address, and key availability at startup", async () => {
    const keypair = Keypair.random();
    const config = loadConfig({
      FACILITATOR_ACCOUNT: keypair.publicKey(),
      FACILITATOR_SIGNER_PROVIDER: "environment",
      FACILITATOR_SIGNER_NETWORK: "stellar:testnet",
      FACILITATOR_SIGNING_KEY_VERSION: "key-v1"
    });
    const runtime = createRuntimeFacilitatorSignerProvider(config, {
      FACILITATOR_SIGNING_KEY: keypair.secret(),
      FACILITATOR_SIGNING_KEY_VERSION: "key-v1"
    });

    await expect(assertRuntimeSignerReady(runtime)).resolves.toBeUndefined();
    await expect(
      assertRuntimeSignerReady(
        createRuntimeFacilitatorSignerProvider(config, {
          FACILITATOR_SIGNING_KEY_VERSION: "key-v1"
        })
      )
    ).rejects.toMatchObject({ code: "SETTLEMENT_FAILED" });

    expect(() =>
      createRuntimeFacilitatorSignerProvider(
        {
          ...config,
          signer: { ...config.signer, network: "stellar:pubnet" }
        },
        {}
      )
    ).toThrow("does not match the active network");
  });
});

function providerFor(keypair: Keypair, readSecret: () => { secret: string; version: string }) {
  return new EnvironmentFacilitatorSignerProvider({
    expectedAddress: keypair.publicKey(),
    network: "stellar:testnet",
    readSecret
  });
}
