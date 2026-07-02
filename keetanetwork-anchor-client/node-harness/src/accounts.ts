/*
 * Shared account derivation for harnesses that name curves
 */

import type * as KeetaNetModule from '@keetanetwork/keetanet-client';

import { referenceResolver } from './core.js';

const KeetaNet = referenceResolver().client<typeof KeetaNetModule>();
const Account = KeetaNet.lib.Account;
const KeyAlgorithm = Account.AccountKeyAlgorithm;

export type SigningAccount = ReturnType<typeof Account.fromSeed>;

function keyAlgorithm(name: string | undefined): number | undefined {
	if (name === undefined) {
		return(undefined);
	}

	switch (name) {
		case 'secp256k1': return(KeyAlgorithm.ECDSA_SECP256K1);
		case 'ed25519': return(KeyAlgorithm.ED25519);
		case 'secp256r1': return(KeyAlgorithm.ECDSA_SECP256R1);
		default: throw(new Error(`unsupported key algorithm: ${name}`));
	}
}

export function accountFromSeed(seed: string, algorithm: string | undefined): SigningAccount {
	const algorithmId = keyAlgorithm(algorithm);
	if (algorithmId === undefined) {
		return(Account.fromSeed(seed, 0));
	}

	return(Account.fromSeed(seed, 0, algorithmId));
}
