/*
 * KYC interop harness.
 *
 * Runs a live KYC anchor server (the production `KeetaNetKYCAnchorHTTPServer`)
 * backed by an in-memory reference node with an initialized chain. Service
 * metadata is published on-chain to a root account, so the Rust resolver reads
 * it through the real node API (`keetanet://<root>/metadata`) the same way the
 * reference client does.
 */

import * as http from 'node:http';

import type * as ResolverModule from '@keetanetwork/anchor/lib/resolver.js';
import type * as KycServerModule from '@keetanetwork/anchor/services/kyc/server.js';
import type * as KycCommonModule from '@keetanetwork/anchor/services/kyc/common.js';
import type * as KycStatusModule from '@keetanetwork/anchor/services/kyc/status.js';
import type * as CertificatesModule from '@keetanetwork/anchor/lib/certificates.js';
import type * as KeetaNetModule from '@keetanetwork/keetanet-client';

import type { ChainNode, ServiceMetadata } from './chain.js';
import type { HarnessResponse } from './core.js';
import { referenceResolver, runHarness } from './core.js';
import { bootChainNode } from './chain.js';
import { reviveValue } from './values.js';

const refs = referenceResolver();
const resolver = await refs.anchor<typeof ResolverModule>('lib/resolver.js');
const kycServer = await refs.anchor<typeof KycServerModule>('services/kyc/server.js');
const kycCommon = await refs.anchor<typeof KycCommonModule>('services/kyc/common.js');
const kycStatus = await refs.anchor<typeof KycStatusModule>('services/kyc/status.js');
const certificates = await refs.anchor<typeof CertificatesModule>('lib/certificates.js');
const KeetaNet = refs.client<typeof KeetaNetModule>();

const KeetaNetLib = KeetaNet.lib;
const Account = KeetaNetLib.Account;
const Metadata = resolver.default.Metadata;

const metadataSigner = Account.fromSeed(Account.generateRandomSeed(), 0);

type CertificateAuthority = Awaited<ReturnType<InstanceType<typeof KeetaNetLib.Utils.Certificate.CertificateBuilder>['build']>>;
type SigningAccount = ReturnType<typeof KeetaNetLib.Account.fromSeed>;
type KycServerConfig = ConstructorParameters<typeof kycServer.KeetaNetKYCAnchorHTTPServer>[0];
type KycServerInstance = InstanceType<typeof kycServer.KeetaNetKYCAnchorHTTPServer>;

/**
 * A self-signed CA together with the account that owns its signing key, so the
 * harness can issue leaf certificates that chain to it.
 */
interface CertificateAuthorityWithKey {
	ca: CertificateAuthority;
	account: SigningAccount;
}

/**
 * A booted chain node plus the live KYC anchor server it backs. `issued` maps a
 * verification id to the PEM chain (`[leaf, ca]`) the anchor serves back through
 * `getCertificates`, so a binding can fetch a populated leaf over the network.
 */
let kycAnchor: {
	server: KycServerInstance;
	chain: ChainNode;
	ca: CertificateAuthority;
	caAccount: SigningAccount;
	issued: Map<string, string[]>;
} | undefined;

interface StartKycAnchorRequest {
	cmd: 'startKycAnchor';
	sign?: boolean;
	countryCodes?: string[];
	providerId?: string;
}

interface StopKycAnchorRequest {
	cmd: 'stopKycAnchor';
}

interface BuildMetadataRequest {
	cmd: 'buildMetadata';
	metadata: ServiceMetadata;
}

interface PublishMetadataRequest {
	cmd: 'publishMetadata';
	metadata: ServiceMetadata;
}

/**
 * Publish a certificate chain on-chain for a fresh holder account: one record
 * carrying the CA as its intermediate bundle, and one recorded without
 * intermediates, so a ledger read exercises both shapes.
 */
interface PublishCertificateChainRequest {
	cmd: 'publishCertificateChain';
}

interface ShutdownRequest {
	cmd: 'shutdown';
}

/**
 * A single KYC attribute to embed in an issued leaf. `value` is plain JSON; an
 * object of the form `{ "__date": "<ISO>" }` (at any depth) is revived to a
 * `Date` so date attributes encode as the reference implementation does.
 */
interface IssueAttribute {
	name: string;
	sensitive: boolean;
	value: unknown;
}

interface IssueCertificateRequest {
	cmd: 'issueCertificate';
	attributes: IssueAttribute[];
	subjectSeed?: string;
	verificationID?: string;
}

/**
 * Serve a stored blob over HTTP for reference-fetch tests. `data` is the
 * base64 stored bytes; `wrap` serves them inside the storage-service
 * `{ data, mimeType }` JSON convention instead of raw.
 */
interface ServeBlobRequest {
	cmd: 'serveBlob';
	data: string;
	mimeType: string;
	wrap?: boolean;
}

/**
 * Open a sharable bundle PEM with the reference reader, decode the named
 * attributes, and resolve every `$blob` reference on them to its verified
 * bytes (the reference reader throws on an access-time digest mismatch).
 */
interface OpenSharableRequest {
	cmd: 'openSharable';
	pem: string;
	recipientSeed: string;
	attributes: string[];
}

/**
 * Decode an externally issued leaf with the reference reader. `leaf` is the
 * PEM-encoded certificate, `subjectSeed` the seed whose key decrypts sensitive
 * attributes, and `attributes` the names to read back as reference values.
 */
interface DecodeCertificateRequest {
	cmd: 'decodeCertificate';
	leaf: string;
	subjectSeed: string;
	attributes: string[];
}

/** The reference `SensitiveAttribute` and the proof shape its `getProof` emits. */
type SensitiveAttribute = InstanceType<typeof certificates.SensitiveAttribute>;
type AttributeProof = Awaited<ReturnType<SensitiveAttribute['getProof']>>;

/**
 * Generate a proof for the sensitive attribute `name` on an externally issued
 * `leaf`, decrypting with `subjectSeed`. The proof validates against the same
 * leaf without the subject's private key.
 */
interface ProveAttributeRequest {
	cmd: 'proveAttribute';
	leaf: string;
	subjectSeed: string;
	name: string;
}

/**
 * Validate `proof` for the sensitive attribute `name` against an externally
 * issued `leaf`, using the subject public key derived from `subjectSeed`.
 */
interface ValidateProofRequest {
	cmd: 'validateProof';
	leaf: string;
	subjectSeed: string;
	name: string;
	proof: AttributeProof;
}

type KycRequest =
	StartKycAnchorRequest |
	StopKycAnchorRequest |
	BuildMetadataRequest |
	PublishMetadataRequest |
	PublishCertificateChainRequest |
	IssueCertificateRequest |
	ServeBlobRequest |
	OpenSharableRequest |
	DecodeCertificateRequest |
	ProveAttributeRequest |
	ValidateProofRequest |
	ShutdownRequest;

/**
 * Mint a self-signed CA the anchor issues KYC certificates under.
 */
async function buildCertificateAuthority(): Promise<CertificateAuthorityWithKey> {
	const caAccount = Account.fromSeed(Account.generateRandomSeed(), 0);
	const builder = new KeetaNetLib.Utils.Certificate.CertificateBuilder({
		subjectPublicKey: caAccount,
		issuer: caAccount,
		serial: 1,
		validFrom: new Date(Date.now() - 30_000),
		validTo: new Date(Date.now() + (60 * 60 * 1000))
	});

	return({ ca: await builder.build(), account: caAccount });
}

function kycCallbacks(
	ca: CertificateAuthority,
	issued: Map<string, string[]>,
	countryCodes: string[] | undefined
): KycServerConfig['kyc'] {
	const kyc: KycServerConfig['kyc'] = {
		getCertificates: async function(verificationID: string) {
			/*
			 * A leaf issued for this verification is served as a full `[leaf, ca]`
			 * chain so a binding can resolve and trust it over the network.
			 */
			const chain = issued.get(verificationID);
			if (chain !== undefined) {
				return(await Promise.resolve(chain.map(certificate => ({ certificate }))));
			}

			/*
			 * A verification still in progress reports as not-yet-issued; any
			 * other id yields the issued CA certificate.
			 */
			if (verificationID === 'pending') {
				throw(new kycCommon.Errors.CertificateNotFound());
			}

			return(await Promise.resolve([{ certificate: ca.toPEM() }]));
		},
		getVerificationStatus: async function() {
			/*
			 * The manual-review flag exercises the optional
			 * `requiresManualVerification` response field end to end.
			 */
			return(await Promise.resolve({
				status: kycStatus.KYCVerificationStatus.PENDING,
				requiresManualVerification: true
			}));
		}
	};

	if (countryCodes !== undefined) {
		// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
		kyc.countryCodes = countryCodes as NonNullable<KycServerConfig['kyc']['countryCodes']>;
	}

	return(kyc);
}

async function stopKycAnchor(): Promise<void> {
	const current = kycAnchor;
	if (current === undefined) {
		return;
	}

	kycAnchor = undefined;
	await current.server.stop();
	await current.chain.node.stop();
}

async function handleStartKycAnchor(request: StartKycAnchorRequest): Promise<HarnessResponse> {
	await stopKycAnchor();

	const providerId = request.providerId ?? 'kyc_test';
	const countryCodes = request.countryCodes;
	const sign = request.sign !== false;

	const chain = await bootChainNode();
	const { ca, account: caAccount } = await buildCertificateAuthority();
	const issued = new Map<string, string[]>();
	const certificateSigner = Account.fromSeed(Account.generateRandomSeed(), 0);

	const server: KycServerInstance = new kycServer.KeetaNetKYCAnchorHTTPServer({
		signer: certificateSigner,
		ca,
		client: chain.repClient,
		metadataSigner: sign ? metadataSigner : undefined,
		kycProviderURL: function(verificationID: string): string {
			return(`${server.url}verify/${encodeURIComponent(verificationID)}`);
		},
		kyc: kycCallbacks(ca, issued, countryCodes)
	});

	await server.start();
	kycAnchor = { server, chain, ca, caAccount, issued };

	const entry = await server.serviceMetadata();
	const metadata = { version: 1, currencyMap: {}, services: { kyc: { [providerId]: entry }}};
	const blob = Metadata.formatMetadata(metadata);
	const root = await chain.publish(metadata);

	return({
		event: 'kyc-anchor-started',
		url: server.url,
		api: chain.api,
		root,
		ca: ca.toPEM(),
		providerId,
		countryCodes: countryCodes ?? null,
		signer: sign ? metadataSigner.publicKeyString.get() : null,
		blob
	});
}

async function handleStopKycAnchor(): Promise<HarnessResponse> {
	await stopKycAnchor();
	return({ event: 'kyc-anchor-stopped' });
}

function handleBuildMetadata(request: BuildMetadataRequest): HarnessResponse {
	const blob = Metadata.formatMetadata(request.metadata);
	return({ event: 'metadata-built', blob });
}

/**
 * Publish arbitrary metadata on-chain to a fresh root account on the running
 * node, so resolver tests can exercise documents the anchor would not produce
 * (tampered, worldwide, unsigned). Requires a running anchor for the node.
 */
async function handlePublishMetadata(request: PublishMetadataRequest): Promise<HarnessResponse> {
	const current = kycAnchor;
	if (current === undefined) {
		throw(new Error('no running anchor: start the KYC anchor before publishing metadata'));
	}

	const root = await current.chain.publish(request.metadata);
	return({ event: 'metadata-published', api: current.chain.api, root });
}

/**
 * Publish two certificate records on-chain for a fresh funded holder: a leaf
 * issued by the running anchor's CA with the CA recorded as its intermediate
 * bundle, and a second leaf recorded without intermediates. The Rust client
 * reads both back through the node API.
 */
async function handlePublishCertificateChain(): Promise<HarnessResponse> {
	const current = kycAnchor;
	if (current === undefined) {
		throw(new Error('no running anchor: start the KYC anchor before publishing certificates'));
	}

	const holder = Account.fromSeed(Account.generateRandomSeed(), 0);
	await current.chain.give(holder, 1_000n);

	const buildLeaf = async function(serial: number): Promise<CertificateAuthority> {
		const builder = new KeetaNetLib.Utils.Certificate.CertificateBuilder({
			subjectPublicKey: holder,
			issuer: current.caAccount,
			serial,
			validFrom: new Date(Date.now() - 30_000),
			validTo: new Date(Date.now() + (60 * 60 * 1000))
		});

		return(await builder.build());
	};

	const leaf = await buildLeaf(2);
	const bare = await buildLeaf(3);

	const holderClient = current.chain.clientFor(holder);
	const intermediates = new KeetaNetLib.Utils.Certificate.CertificateBundle([current.ca]);
	await holderClient.modifyCertificate(KeetaNetLib.Block.AdjustMethod.ADD, leaf, intermediates);
	await holderClient.modifyCertificate(KeetaNetLib.Block.AdjustMethod.ADD, bare, null);

	return({
		event: 'certificate-chain-published',
		api: current.chain.api,
		account: holder.publicKeyString.get(),
		leaf: leaf.toPEM(),
		bare: bare.toPEM(),
		ca: current.ca.toPEM()
	});
}

/**
 * Issue a populated KYC leaf for a subject under the running anchor's CA, then
 * read every attribute back through the reference `Certificate` to produce the
 * `getValue()` reference values.
 */
async function handleIssueCertificate(request: IssueCertificateRequest): Promise<HarnessResponse> {
	const current = kycAnchor;
	if (current === undefined) {
		throw(new Error('no running anchor: start the KYC anchor before issuing certificates'));
	}

	const subjectSeed = request.subjectSeed ?? Account.generateRandomSeed({ asString: true });
	const subjectAccount = Account.fromSeed(subjectSeed, 0);
	const subjectNoPrivate = Account.fromPublicKeyString(subjectAccount.publicKeyString.get());

	const builder = new certificates.CertificateBuilder({
		issuer: current.caAccount,
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
	const leafPEM = leaf.toPEM();
	const caPEM = current.ca.toPEM();

	const reader = new certificates.Certificate(leaf, { subjectKey: subjectAccount, moment: null });
	const attributes: { [name: string]: unknown } = {};
	for (const attribute of request.attributes) {
		// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
		const name = attribute.name as CertificatesModule.CertificateAttributeNames;
		/*
		 * The response line is JSON-serialized as a whole, which already turns
		 * each value into the exact form a binding compares against (e.g.
		 * `Date` becomes its ISO string, `Buffer` its `{ type, data }` form).
		 */
		attributes[attribute.name] = await reader.getAttributeValue(name);
	}

	const verificationID = request.verificationID ?? subjectAccount.publicKeyString.get();
	current.issued.set(verificationID, [leafPEM, caPEM]);

	return({
		event: 'certificate-issued',
		verificationID,
		subjectSeed,
		subject: subjectAccount.publicKeyString.get(),
		leaf: leafPEM,
		ca: caPEM,
		attributes
	});
}

/**
 * A single-process HTTP blob store for reference-fetch tests: each served blob
 * gets a unique path on one listener.
 */
let blobServer: {
	server: http.Server;
	url: string;
	blobs: Map<string, { body: Buffer; contentType: string }>;
} | undefined;

/**
 * Start the blob listener on a random loopback port on first use and reuse it
 * for every later blob.
 */
async function ensureBlobServer(): Promise<NonNullable<typeof blobServer>> {
	const current = blobServer;
	if (current !== undefined) {
		return(current);
	}

	const blobs = new Map<string, { body: Buffer; contentType: string }>();
	const server = http.createServer(function(request, response) {
		const key = (request.url ?? '').replace(/^\//, '');
		const entry = blobs.get(key);
		if (entry === undefined) {
			response.writeHead(404);
			response.end();
			return;
		}

		response.writeHead(200, { 'content-type': entry.contentType });
		response.end(entry.body);
	});

	await new Promise<void>(function(resolve) {
		server.listen(0, '127.0.0.1', resolve);
	});

	const address = server.address();
	if (address === null || typeof address === 'string') {
		throw(new Error('blob server did not report a bound port'));
	}

	const started = { server, url: `http://127.0.0.1:${address.port}/`, blobs };
	blobServer = started;
	return(started);
}

/**
 * Close the blob listener if one is running, so the harness process can exit.
 */
async function stopBlobServer(): Promise<void> {
	const current = blobServer;
	if (current === undefined) {
		return;
	}

	blobServer = undefined;
	await new Promise<void>(function(resolve) {
		current.server.close(() => { resolve(); });
	});
}

/**
 * Serve the request's bytes over HTTP and return the URL. With `wrap`, the
 * bytes are served in the storage-service `{data, mimeType}` JSON convention
 * instead of raw.
 */
async function handleServeBlob(request: ServeBlobRequest): Promise<HarnessResponse> {
	const store = await ensureBlobServer();
	const raw = Buffer.from(request.data, 'base64');

	let body = raw;
	let contentType = request.mimeType;
	if (request.wrap === true) {
		body = Buffer.from(JSON.stringify({ data: raw.toString('base64'), mimeType: request.mimeType }));
		contentType = 'application/json';
	}

	const key = `blob-${store.blobs.size}`;
	store.blobs.set(key, { body, contentType });
	return({ event: 'blob-served', url: `${store.url}${key}` });
}

/**
 * Resolve every `$blob` closure in a decoded attribute `value`.
 */
async function resolveBlobReferences(
	value: unknown,
	resolved: { [id: string]: { data: string; type: string }}
): Promise<void> {
	const pending: unknown[] = [value];
	while (pending.length > 0) {
		const node = pending.pop();
		if (Array.isArray(node)) {
			const items: unknown[] = node;
			pending.push(...items);
			continue;
		}
		if (node === null || typeof node !== 'object' || Buffer.isBuffer(node)) {
			continue;
		}

		// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
		const record = node as { [key: string]: unknown };
		const blobFunction = record['$blob'];
		if (typeof blobFunction !== 'function') {
			pending.push(...Object.values(record));
			continue;
		}

		const digestInfo = record['digest'];
		if (digestInfo === null || typeof digestInfo !== 'object' || !('digest' in digestInfo) || !Buffer.isBuffer(digestInfo.digest)) {
			throw(new Error('$blob node does not carry a Buffer digest'));
		}

		const id = digestInfo.digest.toString('hex').toUpperCase();
		// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
		const resolve = blobFunction as () => Promise<Blob>;
		const blob = await resolve();
		const bytes = Buffer.from(await blob.arrayBuffer());
		resolved[id] = { data: bytes.toString('base64'), type: blob.type };
		delete record['$blob'];
	}
}

/**
 * Open a sharable bundle PEM with the reference `SharableCertificateAttributes`
 * reader and return the decoded attribute values alongside every resolved,
 * digest-verified `$blob` payload, keyed by attribute name then reference id.
 */
async function handleOpenSharable(request: OpenSharableRequest): Promise<HarnessResponse> {
	const recipient = Account.fromSeed(request.recipientSeed, 0);
	const sharable = new certificates.SharableCertificateAttributes(request.pem, { principals: recipient });

	const attributes: { [name: string]: unknown } = {};
	const blobs: { [name: string]: { [id: string]: { data: string; type: string }}} = {};
	for (const name of request.attributes) {
		// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
		const attributeName = name as CertificatesModule.CertificateAttributeNames;
		const value = await sharable.getAttribute(attributeName);
		const resolved: { [id: string]: { data: string; type: string }} = {};

		await resolveBlobReferences(value, resolved);

		attributes[name] = value;
		blobs[name] = resolved;
	}

	return({ event: 'sharable-opened', attributes, blobs });
}

/**
 * Read the named attributes from a leaf issued elsewhere (e.g. by the Rust core)
 * through the reference `Certificate`. No running anchor is required: the subject
 * key alone decrypts the sensitive attributes.
 */
async function handleDecodeCertificate(request: DecodeCertificateRequest): Promise<HarnessResponse> {
	const subjectAccount = Account.fromSeed(request.subjectSeed, 0);
	const reader = new certificates.Certificate(request.leaf, { subjectKey: subjectAccount, moment: null });
	const attributes: { [name: string]: unknown } = {};
	for (const name of request.attributes) {
		// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
		const attributeName = name as CertificatesModule.CertificateAttributeNames;

		attributes[name] = await reader.getAttributeValue(attributeName);
	}

	return({ event: 'certificate-decoded', attributes });
}

/**
 * Resolve the live `SensitiveAttribute` for `name` on an externally issued
 * `leaf`, constructed with the subject key derived from `subjectSeed` so it can
 * decrypt and prove. Throws if the attribute is absent or not sensitive.
 */
function sensitiveAttribute(leaf: string, subjectSeed: string, name: string): SensitiveAttribute {
	const subjectAccount = Account.fromSeed(subjectSeed, 0);
	const reader = new certificates.Certificate(leaf, { subjectKey: subjectAccount, moment: null });

	// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
	const entry = reader.attributes[name as CertificatesModule.CertificateAttributeNames];
	if (!entry?.sensitive) {
		throw(new Error(`attribute ${name} is not a sensitive attribute on the certificate`));
	}

	return(entry.value);
}

/**
 * Prove the sensitive attribute `name` on an externally issued leaf, producing
 * the proof a third party validates with `validateProof`.
 */
async function handleProveAttribute(request: ProveAttributeRequest): Promise<HarnessResponse> {
	const attribute = sensitiveAttribute(request.leaf, request.subjectSeed, request.name);
	const proof = await attribute.getProof();
	return({ event: 'attribute-proved', proof });
}

/**
 * Validate a proof for the sensitive attribute `name` against an externally
 * issued leaf using the reference reader.
 */
async function handleValidateProof(request: ValidateProofRequest): Promise<HarnessResponse> {
	const attribute = sensitiveAttribute(request.leaf, request.subjectSeed, request.name);
	const valid = await attribute.validateProof(request.proof);
	return({ event: 'proof-validated', valid });
}

async function handle(request: KycRequest): Promise<HarnessResponse> {
	switch (request.cmd) {
		case 'startKycAnchor': return(await handleStartKycAnchor(request));
		case 'stopKycAnchor': return(await handleStopKycAnchor());
		case 'buildMetadata': return(handleBuildMetadata(request));
		case 'publishMetadata': return(await handlePublishMetadata(request));
		case 'publishCertificateChain': return(await handlePublishCertificateChain());
		case 'issueCertificate': return(await handleIssueCertificate(request));
		case 'serveBlob': return(await handleServeBlob(request));
		case 'openSharable': return(await handleOpenSharable(request));
		case 'decodeCertificate': return(await handleDecodeCertificate(request));
		case 'proveAttribute': return(await handleProveAttribute(request));
		case 'validateProof': return(await handleValidateProof(request));
		case 'shutdown': return({ event: 'shutdown' });
	}
}

runHarness<KycRequest>({ event: 'ready' }, handle, async function() {
	await stopBlobServer();
	await stopKycAnchor();
});
