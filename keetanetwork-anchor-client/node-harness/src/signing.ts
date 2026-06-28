/*
 * Signing interop harness.
 *
 * Wraps the anchor signing and HTTP-auth primitives so the Rust client can be
 * tested against them: signing, verification, URL/body auth, and the canonical
 * `objectToSignable` projection.
 */

import type * as SigningModule from '@keetanetwork/anchor/lib/utils/signing.js';
import type * as CommonModule from '@keetanetwork/anchor/lib/http-server/common.js';
import type * as KeetaNetModule from '@keetanetwork/keetanet-client';

import type { HarnessResponse } from './core.js';
import { referenceResolver, runHarness } from './core.js';

const refs = referenceResolver();
const signing = await refs.anchor<typeof SigningModule>('lib/utils/signing.js');
const common = await refs.anchor<typeof CommonModule>('lib/http-server/common.js');
const KeetaNet = refs.client<typeof KeetaNetModule>();
const Account = KeetaNet.lib.Account;
const Helper = KeetaNet.lib.Utils.Helper;

const signer = Account.fromSeed(Account.generateRandomSeed(), 0);
const secondary = Account.fromSeed(Account.generateRandomSeed(), 0);

/* A signable element of the harness protocol: a string, an integer, or the
 * harness's secondary account. */
interface Part {
	t: 's' | 'i' | 'a';
	v?: string | number;
}

interface SignRequest {
	cmd: 'sign';
	nonce?: string;
	timestamp?: string;
	data?: Part[];
}

interface VerifyRequest {
	cmd: 'verify';
	publicKeyAndType: string;
	nonce: string;
	timestamp: string;
	signature: string;
	data?: Part[];
}

interface ObjectToSignableRequest {
	cmd: 'objectToSignable';
	value: SigningModule.SignableInput;
}

interface AddSignatureToURLRequest {
	cmd: 'addSignatureToURL';
	baseUrl: string;
	account: string;
	nonce: string;
	timestamp: string;
	signature: string;
}

interface VerifyURLAuthRequest {
	cmd: 'verifyURLAuth';
	url: string;
	data?: Part[];
}

interface VerifyBodyAuthRequest {
	cmd: 'verifyBodyAuth';
	account: string;
	nonce: string;
	timestamp: string;
	signature: string;
	data?: Part[];
}

interface ShutdownRequest {
	cmd: 'shutdown';
}

type SigningRequest =
	SignRequest |
	VerifyRequest |
	ObjectToSignableRequest |
	AddSignatureToURLRequest |
	VerifyURLAuthRequest |
	VerifyBodyAuthRequest |
	ShutdownRequest;

function buildData(parts: Part[]): SigningModule.Signable {
	return(parts.map(function(part): string | number | typeof secondary {
		if (part.t === 's') {
			return(String(part.v));
		}
		if (part.t === 'i') {
			return(Number(part.v));
		}
		if (part.t === 'a') {
			return(secondary);
		}

		throw(new Error(`unknown signable part type: ${JSON.stringify(part)}`));
	}));
}

async function handleSign(request: SignRequest): Promise<HarnessResponse> {
	const data = buildData(request.data ?? []);
	const formatted = signing.FormatData(signer, data, request.nonce, request.timestamp);
	const signature = await signer.sign(Helper.bufferToArrayBuffer(formatted.verificationData));

	return({
		event: 'signed',
		nonce: formatted.nonce,
		timestamp: formatted.timestamp,
		verificationData: Buffer.from(formatted.verificationData).toString('hex'),
		signature: signature.getBuffer().toString('base64')
	});
}

async function handleVerify(request: VerifyRequest): Promise<HarnessResponse> {
	const data = buildData(request.data ?? []);
	const account = Account.fromPublicKeyAndType(Buffer.from(request.publicKeyAndType, 'hex'));
	const signed = { nonce: request.nonce, timestamp: request.timestamp, signature: request.signature };
	const valid = await signing.VerifySignedData(account, data, signed, { maxSkewMs: Number.MAX_SAFE_INTEGER });

	return({ event: 'verified', valid: valid });
}

function handleObjectToSignable(request: ObjectToSignableRequest): HarnessResponse {
	const signable = signing.objectToSignable(request.value);
	return({ event: 'object-to-signable', signable: signable });
}

function handleAddSignatureToURL(request: AddSignatureToURLRequest): HarnessResponse {
	const account = Account.fromPublicKeyString(request.account).assertAccount();
	const signedField = { nonce: request.nonce, timestamp: request.timestamp, signature: request.signature };
	const url = common.addSignatureToURL(request.baseUrl, { signedField, account });

	return({ event: 'signature-added', url: url.href });
}

async function handleVerifyURLAuth(request: VerifyURLAuthRequest): Promise<HarnessResponse> {
	const data = buildData(request.data ?? []);
	try {
		const account = await common.verifyURLAuth(request.url, function() { return(data); });
		return({ event: 'url-verified', valid: true, account: account.publicKeyString.get() });
	} catch {
		return({ event: 'url-verified', valid: false });
	}
}

async function handleVerifyBodyAuth(request: VerifyBodyAuthRequest): Promise<HarnessResponse> {
	const data = buildData(request.data ?? []);
	const body = {
		account: request.account,
		signed: { nonce: request.nonce, timestamp: request.timestamp, signature: request.signature }
	};

	try {
		const account = await common.verifyBodyAuth(body, function() { return(data); });
		return({ event: 'body-verified', valid: true, account: account.publicKeyString.get() });
	} catch {
		return({ event: 'body-verified', valid: false });
	}
}

async function handle(request: SigningRequest): Promise<HarnessResponse> {
	switch (request.cmd) {
		case 'sign': return(await handleSign(request));
		case 'verify': return(await handleVerify(request));
		case 'objectToSignable': return(handleObjectToSignable(request));
		case 'addSignatureToURL': return(handleAddSignatureToURL(request));
		case 'verifyURLAuth': return(await handleVerifyURLAuth(request));
		case 'verifyBodyAuth': return(await handleVerifyBodyAuth(request));
		case 'shutdown': return({ event: 'shutdown' });
	}
}

runHarness<SigningRequest>({
	event: 'ready',
	keyType: 'ECDSA_SECP256K1',
	signerPublicKeyAndType: signer.publicKeyAndType.toString('hex'),
	signerPublicKeyString: signer.publicKeyString.get(),
	secondaryPublicKeyAndType: secondary.publicKeyAndType.toString('hex')
}, handle);
