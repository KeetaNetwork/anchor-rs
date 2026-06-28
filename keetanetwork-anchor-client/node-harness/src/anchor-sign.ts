/*
 * Signing parity harness.
 *
 * Wraps the TypeScript anchor signing implementation so the Rust client
 * can be tested against it at runtime.
 */

import * as readline from 'node:readline';
import * as path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

/* eslint-disable @typescript-eslint/no-explicit-any */

interface Part {
	t: 's' | 'i' | 'a';
	v?: string | number;
}

interface References {
	signing: any;
	common: any;
	KeetaNetLib: any;
}

async function loadReferences(): Promise<References> {
	const dist = process.env.KEETANET_ANCHOR_DIST;
	if (dist !== undefined && dist !== '') {
		const signingHref = pathToFileURL(path.join(dist, 'lib/utils/signing.js')).href;
		const commonHref = pathToFileURL(path.join(dist, 'lib/http-server/common.js')).href;
		const requireFromDist = createRequire(signingHref);
		return {
			signing: await import(signingHref),
			common: await import(commonHref),
			KeetaNetLib: requireFromDist('@keetanetwork/keetanet-client').lib
		};
	}

	const requireFromHere = createRequire(import.meta.url);
	return {
		signing: await import('@keetanetwork/anchor/lib/utils/signing.js'),
		common: await import('@keetanetwork/anchor/lib/http-server/common.js'),
		KeetaNetLib: requireFromHere('@keetanetwork/keetanet-client').lib
	};
}

const { signing, common, KeetaNetLib } = await loadReferences();
const Account = KeetaNetLib.Account;
const Helper = KeetaNetLib.Utils.Helper;

const signer = Account.fromSeed(Account.generateRandomSeed(), 0);
const secondary = Account.fromSeed(Account.generateRandomSeed(), 0);

function buildData(parts: Part[]): unknown[] {
	return parts.map(function (part) {
		if (part.t === 's') {
			return part.v;
		}
		if (part.t === 'i') {
			return part.v;
		}
		if (part.t === 'a') {
			return secondary;
		}

		throw new Error(`unknown signable part type: ${JSON.stringify(part)}`);
	});
}

async function handleSign(request: any): Promise<{ [key: string]: unknown }> {
	const data = buildData(request.data ?? []);
	const formatted = signing.FormatData(signer, data, request.nonce, request.timestamp);
	const signature = await signer.sign(Helper.bufferToArrayBuffer(formatted.verificationData));

	return {
		event: 'signed',
		nonce: formatted.nonce,
		timestamp: formatted.timestamp,
		verificationData: Buffer.from(formatted.verificationData).toString('hex'),
		signature: signature.getBuffer().toString('base64')
	};
}

async function handleVerify(request: any): Promise<{ [key: string]: unknown }> {
	const data = buildData(request.data ?? []);
	const account = Account.fromPublicKeyAndType(Buffer.from(request.publicKeyAndType, 'hex'));
	const signed = { nonce: request.nonce, timestamp: request.timestamp, signature: request.signature };
	const valid = await signing.VerifySignedData(account, data, signed, { maxSkewMs: Number.MAX_SAFE_INTEGER });

	return { event: 'verified', valid: valid };
}

function handleObjectToSignable(request: any): { [key: string]: unknown } {
	const signable = signing.objectToSignable(request.value);
	return { event: 'object-to-signable', signable: signable };
}

function handleAddSignatureToURL(request: any): { [key: string]: unknown } {
	const account = Account.fromPublicKeyString(request.account).assertAccount();
	const signedField = { nonce: request.nonce, timestamp: request.timestamp, signature: request.signature };
	const url = common.addSignatureToURL(request.baseUrl, { signedField, account });

	return { event: 'signature-added', url: url.href };
}

async function handleVerifyURLAuth(request: any): Promise<{ [key: string]: unknown }> {
	const data = buildData(request.data ?? []);
	try {
		const account = await common.verifyURLAuth(request.url, function () { return data; });
		return { event: 'url-verified', valid: true, account: account.publicKeyString.get() };
	} catch {
		return { event: 'url-verified', valid: false };
	}
}

async function handleVerifyBodyAuth(request: any): Promise<{ [key: string]: unknown }> {
	const data = buildData(request.data ?? []);
	const body = {
		account: request.account,
		signed: { nonce: request.nonce, timestamp: request.timestamp, signature: request.signature }
	};

	try {
		const account = await common.verifyBodyAuth(body, function () { return data; });
		return { event: 'body-verified', valid: true, account: account.publicKeyString.get() };
	} catch {
		return { event: 'body-verified', valid: false };
	}
}

async function handleRequest(request: any): Promise<{ [key: string]: unknown }> {
	switch (request.cmd) {
		case 'sign': return (handleSign(request));
		case 'verify': return (handleVerify(request));
		case 'objectToSignable': return (Promise.resolve(handleObjectToSignable(request)));
		case 'addSignatureToURL': return (Promise.resolve(handleAddSignatureToURL(request)));
		case 'verifyURLAuth': return (handleVerifyURLAuth(request));
		case 'verifyBodyAuth': return (handleVerifyBodyAuth(request));
		case 'shutdown': return (Promise.resolve({ event: 'shutdown' }));
		default: throw (new Error(`unknown command: ${JSON.stringify(request)}`));
	}
}

console.log(JSON.stringify({
	event: 'ready',
	keyType: 'ECDSA_SECP256K1',
	signerPublicKeyAndType: signer.publicKeyAndType.toString('hex'),
	signerPublicKeyString: signer.publicKeyString.get(),
	secondaryPublicKeyAndType: secondary.publicKeyAndType.toString('hex')
}));

const rl = readline.createInterface({ input: process.stdin, terminal: false });

/* Serialize command handling: one response line per request line. */
let queue = Promise.resolve();
rl.on('line', function (line) {
	const trimmed = line.trim();
	if (trimmed === '') {
		return;
	}

	queue = queue.then(async function () {
		try {
			const request = JSON.parse(trimmed);
			const response = await handleRequest(request);
			console.log(JSON.stringify(response));
			if (request.cmd === 'shutdown') {
				process.exit(0);
			}
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			console.log(JSON.stringify({ error: message }));
		}
	});
});
