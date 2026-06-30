/*
 * EncryptedContainer interop harness.
 *
 * Drives the reference `EncryptedContainer` over the JSON-lines protocol so the
 * Rust core can prove it encodes blobs the reference can open (and verify) and
 * decodes blobs the reference produced.
 */

import type * as EncryptedContainerModule from '@keetanetwork/anchor/lib/encrypted-container.js';
import type * as KeetaNetModule from '@keetanetwork/keetanet-client';

import type { HarnessResponse } from './core.js';
import { referenceResolver, runHarness } from './core.js';

const refs = referenceResolver();
const containerModule = await refs.anchor<typeof EncryptedContainerModule>('lib/encrypted-container.js');
const KeetaNet = refs.client<typeof KeetaNetModule>();

const EncryptedContainer = containerModule.EncryptedContainer;
const Account = KeetaNet.lib.Account;
const KeyAlgorithm = Account.AccountKeyAlgorithm;

type SigningAccount = ReturnType<typeof Account.fromSeed>;

interface EncodePlaintextRequest {
	cmd: 'encodePlaintext';
	plaintext: string;
	signerSeed?: string;
	signerAlgorithm?: string;
}

interface EncodeEncryptedRequest {
	cmd: 'encodeEncrypted';
	plaintext: string;
	principalSeeds: string[];
	principalAlgorithm?: string;
	signerSeed?: string;
	signerAlgorithm?: string;
}

interface DecodeRequest {
	cmd: 'decode';
	encoded: string;
	principalSeeds?: string[];
	principalAlgorithm?: string;
}

interface ShutdownRequest {
	cmd: 'shutdown';
}

type ContainerRequest =
	EncodePlaintextRequest |
	EncodeEncryptedRequest |
	DecodeRequest |
	ShutdownRequest;

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

function accountFromSeed(seed: string, algorithm: string | undefined): SigningAccount {
	const algorithmId = keyAlgorithm(algorithm);
	if (algorithmId === undefined) {
		return(Account.fromSeed(seed, 0));
	}

	return(Account.fromSeed(seed, 0, algorithmId));
}

function accountsFromSeeds(seeds: string[], algorithm: string | undefined): SigningAccount[] {
	return(seeds.map(seed => accountFromSeed(seed, algorithm)));
}

function signerFromSeed(seed: string | undefined, algorithm: string | undefined): SigningAccount | undefined {
	if (seed === undefined) {
		return(undefined);
	}

	return(accountFromSeed(seed, algorithm));
}

async function encodeContainer(container: InstanceType<typeof EncryptedContainer>): Promise<string> {
	const encoded = await container.getEncodedBuffer();
	return(Buffer.from(encoded).toString('base64'));
}

async function handleEncodePlaintext(request: EncodePlaintextRequest): Promise<HarnessResponse> {
	const plaintext = Buffer.from(request.plaintext, 'base64');
	const signer = signerFromSeed(request.signerSeed, request.signerAlgorithm);
	const container = EncryptedContainer.fromPlaintext(plaintext, null, { locked: false, signer });

	const encoded = await encodeContainer(container);
	return({ event: 'encoded', encoded });
}

async function handleEncodeEncrypted(request: EncodeEncryptedRequest): Promise<HarnessResponse> {
	const plaintext = Buffer.from(request.plaintext, 'base64');
	const principals = accountsFromSeeds(request.principalSeeds, request.principalAlgorithm);
	const signer = signerFromSeed(request.signerSeed, request.signerAlgorithm);
	const container = EncryptedContainer.fromPlaintext(plaintext, principals, { locked: false, signer });

	const encoded = await encodeContainer(container);
	return({ event: 'encoded', encoded });
}

async function handleDecode(request: DecodeRequest): Promise<HarnessResponse> {
	const encoded = Buffer.from(request.encoded, 'base64');
	const principals = request.principalSeeds === undefined ? null : accountsFromSeeds(request.principalSeeds, request.principalAlgorithm);
	const container = EncryptedContainer.fromEncodedBuffer(encoded, principals);

	const plaintext = Buffer.from(await container.getPlaintext()).toString('base64');
	const isSigned = container.isSigned;
	let signatureValid: boolean | null = null;
	let signerPublicKey: string | null = null;
	if (isSigned) {
		signatureValid = await container.verifySignature();
		const signingAccount = container.getSigningAccount();
		if (signingAccount !== undefined) {
			signerPublicKey = Buffer.from(signingAccount.publicKeyAndType).toString('hex');
		}
	}

	return({ event: 'decoded', plaintext, encrypted: container.encrypted, isSigned, signatureValid, signerPublicKey });
}

async function handle(request: ContainerRequest): Promise<HarnessResponse> {
	switch (request.cmd) {
		case 'encodePlaintext': return(await handleEncodePlaintext(request));
		case 'encodeEncrypted': return(await handleEncodeEncrypted(request));
		case 'decode': return(await handleDecode(request));
		case 'shutdown': return({ event: 'shutdown' });
	}
}

runHarness<ContainerRequest>({ event: 'ready' }, handle);
