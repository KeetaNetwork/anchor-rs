/*
 * SharableCertificateAttributes interop harness.
 */

import type * as CertificatesModule from '@keetanetwork/anchor/lib/certificates.js';
import type * as KeetaNetModule from '@keetanetwork/keetanet-client';

import type { HarnessResponse } from './core.js';
import { accountFromSeed } from './accounts.js';
import { referenceResolver, runHarness } from './core.js';
import { reviveValue } from './values.js';

const refs = referenceResolver();
const certificates = await refs.anchor<typeof CertificatesModule>('lib/certificates.js');
const KeetaNet = refs.client<typeof KeetaNetModule>();

const Account = KeetaNet.lib.Account;
const SharableCertificateAttributes = certificates.SharableCertificateAttributes;

type BaseCertificate = InstanceType<typeof KeetaNet.lib.Utils.Certificate.Certificate>;

/**
 * A single attribute to embed in the issued leaf: its friendly `name`, whether
 * it is `sensitive` (encrypted and proven) or plain, and its `value`.
 */
interface SharableAttribute {
	name: string;
	sensitive: boolean;
	value: unknown;
}

/**
 * Build a leaf for `subjectSeed`, wrap the named attributes in a sharable
 * bundle, and grant `recipientSeed` access. `algorithm` names the curve both
 * sides derive the subject and recipient accounts on.
 */
interface BuildSharableRequest {
	cmd: 'buildSharable';
	subjectSeed: string;
	recipientSeed: string;
	attributes: SharableAttribute[];
	algorithm?: string;
}

/**
 * Open a sharable bundle the Rust core exported, reading each named attribute
 * back through the reference so both sides can compare buffers.
 */
interface ReadSharableRequest {
	cmd: 'readSharable';
	pem: string;
	recipientSeed: string;
	names: string[];
	algorithm?: string;
}

interface ShutdownRequest {
	cmd: 'shutdown';
}

type SharableRequest =
	BuildSharableRequest |
	ReadSharableRequest |
	ShutdownRequest;

/**
 * Read each named attribute buffer back through a populated bundle, encoding it
 * as base64 so the Rust side can compare byte-for-byte.
 */
async function readBuffers(
	sharable: InstanceType<typeof SharableCertificateAttributes>,
	names: string[]
): Promise<{ [name: string]: string | null }> {
	const buffers: { [name: string]: string | null } = {};
	for (const name of names) {
		const buffer = await sharable.getAttributeBuffer(name);
		if (buffer === undefined) {
			buffers[name] = null;
		} else {
			buffers[name] = Buffer.from(buffer).toString('base64');
		}
	}

	return(buffers);
}

/**
 * Issue a leaf carrying the requested attributes, wrap the named ones in a
 * sharable bundle for the recipient, and return the exported PEM alongside the
 * reference's own view of each disclosed buffer.
 */
async function handleBuildSharable(request: BuildSharableRequest): Promise<HarnessResponse> {
	const subjectAccount = accountFromSeed(request.subjectSeed, request.algorithm);
	const publicKeyString = subjectAccount.publicKeyString.get();
	const subjectNoPrivate = Account.fromPublicKeyString(publicKeyString);
	const seed = Account.generateRandomSeed();
	const issuer = Account.fromSeed(seed, 0);

	const builder = new certificates.CertificateBuilder({
		issuer,
		subject: subjectNoPrivate,
		validFrom: new Date(Date.now() - 30_000),
		validTo: new Date(Date.now() + (60 * 60 * 1000))
	});

	for (const attribute of request.attributes) {
		// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
		const name = attribute.name as CertificatesModule.CertificateAttributeNames;
		// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
		builder.setAttribute(name, attribute.sensitive, reviveValue(attribute.value) as never);
	}

	const leaf = await builder.build({ serial: 4 });
	const reader = new certificates.Certificate(leaf, { subjectKey: subjectAccount, moment: null });

	const names = request.attributes.map(function(attribute) {
		return(attribute.name);
	});
	// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
	const attributeNames = names as CertificatesModule.CertificateAttributeNames[];
	const intermediates = new Set<BaseCertificate>();
	const sharable = await SharableCertificateAttributes.fromCertificate(reader, intermediates, attributeNames);

	const recipient = accountFromSeed(request.recipientSeed, request.algorithm);
	await sharable.grantAccess(recipient);

	const pem = await sharable.export({ format: 'string' });
	const buffers = await readBuffers(sharable, names);

	return({ event: 'sharable-built', pem, buffers });
}

/**
 * Open a Rust-exported bundle with the recipient key and read the named
 * attribute buffers back through the reference.
 */
async function handleReadSharable(request: ReadSharableRequest): Promise<HarnessResponse> {
	const recipient = accountFromSeed(request.recipientSeed, request.algorithm);
	const sharable = new SharableCertificateAttributes(request.pem, { principals: recipient });

	const buffers = await readBuffers(sharable, request.names);
	return({ event: 'sharable-read', buffers });
}

async function handle(request: SharableRequest): Promise<HarnessResponse> {
	switch (request.cmd) {
		case 'buildSharable': return(await handleBuildSharable(request));
		case 'readSharable': return(await handleReadSharable(request));
		case 'shutdown': return({ event: 'shutdown' });
	}
}

runHarness<SharableRequest>({ event: 'ready' }, handle);
