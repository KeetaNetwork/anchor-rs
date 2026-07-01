/*
 * KYC interop harness.
 *
 * Runs a live KYC anchor server (the production `KeetaNetKYCAnchorHTTPServer`)
 * backed by an in-memory reference node with an initialized chain. Service
 * metadata is published on-chain to a root account, so the Rust resolver reads
 * it through the real node API (`keetanet://<root>/metadata`) the same way the
 * reference client does.
 */

import type * as ResolverModule from '@keetanetwork/anchor/lib/resolver.js';
import type * as KycServerModule from '@keetanetwork/anchor/services/kyc/server.js';
import type * as KycCommonModule from '@keetanetwork/anchor/services/kyc/common.js';
import type * as KycStatusModule from '@keetanetwork/anchor/services/kyc/status.js';
import type * as CertificatesModule from '@keetanetwork/anchor/lib/certificates.js';
import type * as KeetaNetModule from '@keetanetwork/keetanet-client';
import type * as NodeClientModule from '@keetanetwork/keetanet-node/dist/client';
import type * as NodeTestingModule from '@keetanetwork/keetanet-node/dist/lib/utils/helper_testing.js';

import type { HarnessResponse } from './core.js';
import { referenceResolver, runHarness } from './core.js';

const refs = referenceResolver();
const resolver = await refs.anchor<typeof ResolverModule>('lib/resolver.js');
const kycServer = await refs.anchor<typeof KycServerModule>('services/kyc/server.js');
const kycCommon = await refs.anchor<typeof KycCommonModule>('services/kyc/common.js');
const kycStatus = await refs.anchor<typeof KycStatusModule>('services/kyc/status.js');
const certificates = await refs.anchor<typeof CertificatesModule>('lib/certificates.js');
const KeetaNet = refs.client<typeof KeetaNetModule>();
const NodeClient = refs.node<typeof NodeClientModule>('@keetanetwork/keetanet-node/dist/client');
const nodeTesting = refs.node<typeof NodeTestingModule>('@keetanetwork/keetanet-node/dist/lib/utils/helper_testing.js');

const KeetaNetLib = KeetaNet.lib;
const Account = KeetaNetLib.Account;
const Permissions = KeetaNetLib.Permissions;
const Metadata = resolver.default.Metadata;

const metadataSigner = Account.fromSeed(Account.generateRandomSeed(), 0);

type CertificateAuthority = Awaited<ReturnType<InstanceType<typeof KeetaNetLib.Utils.Certificate.CertificateBuilder>['build']>>;
type ReferenceNode = Awaited<ReturnType<typeof nodeTesting.createTestNode>>;
type UserClient = InstanceType<typeof KeetaNet.UserClient>;
type GenericAccount = InstanceType<typeof KeetaNetLib.Account>;
type SigningAccount = ReturnType<typeof KeetaNetLib.Account.fromSeed>;
type KycServerConfig = ConstructorParameters<typeof kycServer.KeetaNetKYCAnchorHTTPServer>[0];
type KycServerInstance = InstanceType<typeof kycServer.KeetaNetKYCAnchorHTTPServer>;
type ServiceMetadata = Parameters<typeof Metadata.formatMetadata>[0];

/**
 * A reference node with an initialized chain, plus the helpers needed to fund
 * accounts and publish service metadata on-chain.
 */
interface ChainNode {
	node: ReferenceNode;
	/* The node API base URL, e.g. `http://127.0.0.1:<port>`. */
	api: string;
	/* A UserClient for the funded representative account. */
	repClient: UserClient;
	/* Send `amount` of the base token to `account`. */
	give(account: GenericAccount, amount: bigint): Promise<void>;
	/* Publish `metadata` on-chain to a fresh funded account; return its key. */
	publish(metadata: ServiceMetadata): Promise<string>;
}

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
	IssueCertificateRequest |
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

/**
 * Boot an in-memory reference node and initialize its chain (base token, supply,
 * delegation) so accounts can publish on-chain metadata. The resolver reads that
 * metadata back through the node API, exactly as the reference client does.
 */
async function bootChainNode(): Promise<ChainNode> {
	const seed = Account.generateRandomSeed({ asString: true });
	const repNodeAccount = NodeClient.lib.Account.fromSeed(seed, 0);
	const repClientAccount = Account.fromSeed(seed, 0);

	/* Fees start disabled so the network can be initialized for free. */
	const feeFreeAccounts = new Set<string>();
	let feesEnabled = false;

	const node = await nodeTesting.createTestNode(repNodeAccount, {
		createInitialVoteStaple: false,
		nodeConfig: { nodeAlias: 'TEST' },
		ledger: {
			computeFeeFromBlocks: function(_ignore_ledger, blocks, _ignore_effects) {
				if (!feesEnabled) {
					return(null);
				}
				for (const block of blocks) {
					if (feeFreeAccounts.has(block.account.publicKeyString.get())) {
						return(null);
					}
				}

				return({ amount: 1n });
			}
		}
	});

	const endpoints = node.config.endpoints;
	if (endpoints?.api === undefined || endpoints.p2p === undefined) {
		throw(new Error('reference node did not expose its API and P2P endpoints'));
	}

	const client = new KeetaNet.Client([{ endpoints: { api: endpoints.api, p2p: endpoints.p2p }, key: repClientAccount }]);
	const repClient = new KeetaNet.UserClient({
		client,
		network: node.config.network,
		networkAlias: node.config.networkAlias,
		signer: repClientAccount,
		usePublishAid: false
	});

	/*
	 * Manually initialize the chain: mint the base token, add supply, and
	 * delegate voting weight to the representative.
	 */
	const { networkAddress } = Account.generateBaseAddresses(node.config.network);
	await repClient.initializeNetwork({
		addSupplyAmount: 10_000_000_000_000n,
		delegateTo: repClientAccount,
		voteSerial: BigInt('999999999999999999'),
		baseTokenInfo: { name: 'KeetaNet Test Token', currencyCode: 'KTA', decimalPlaces: 9 }
	}, { account: repClientAccount, usePublishAid: false });
	await repClient.setInfo({
		name: 'KEETANET',
		description: 'Network Address For KeetaNet',
		metadata: '',
		defaultPermission: new Permissions(['TOKEN_ADMIN_CREATE', 'STORAGE_CREATE', 'ACCESS'])
	}, { account: networkAddress });

	feesEnabled = true;

	const give = async function(account: GenericAccount, amount: bigint): Promise<void> {
		await repClient.send(account, amount, repClient.baseToken, undefined, { account: repClientAccount });
	};

	const publish = async function(metadata: ServiceMetadata): Promise<string> {
		const rootAccount = Account.fromSeed(Account.generateRandomSeed(), 0);
		await give(rootAccount, 1_000n);

		const rootClient = new KeetaNet.UserClient({
			client,
			network: node.config.network,
			networkAlias: node.config.networkAlias,
			signer: rootAccount,
			usePublishAid: false
		});
		await rootClient.setInfo({ name: '', description: '', metadata: Metadata.formatMetadata(metadata) });

		return(rootAccount.publicKeyString.get());
	};

	return({ node, api: endpoints.api, repClient, give, publish });
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
			return(await Promise.resolve({ status: kycStatus.KYCVerificationStatus.PENDING }));
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
 * Recursively revive a JSON request value into the shape the reference builder
 * expects: an object `{ "__date": "<ISO>" }` becomes a `Date` (at any depth),
 * everything else passes through unchanged.
 */
function reviveValue(value: unknown): unknown {
	if (Array.isArray(value)) {
		return(value.map(reviveValue));
	}

	if (value !== null && typeof value === 'object') {
		const entries = Object.entries(value);
		const dateEntry = entries.find(([key]) => key === '__date');
		if (dateEntry !== undefined && typeof dateEntry[1] === 'string') {
			return(new Date(dateEntry[1]));
		}

		// A Node `Buffer` JSON form (`{ type: 'Buffer', data: [..] }`) revives to a
		// Buffer so an OCTET STRING (e.g. a document reference digest) encodes as
		// the reference implementation expects.
		const typeEntry = entries.find(([key]) => key === 'type');
		const dataEntry = entries.find(([key]) => key === 'data');
		if (typeEntry !== undefined && typeEntry[1] === 'Buffer' && dataEntry !== undefined && Array.isArray(dataEntry[1])) {
			return(Buffer.from(dataEntry[1] as number[]));
		}

		const revived: { [key: string]: unknown } = {};
		for (const [key, nested] of entries) {
			revived[key] = reviveValue(nested);
		}

		return(revived);
	}

	return(value);
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
		const value = await reader.getAttributeValue(name);
		/*
		 * Round-trip through JSON so each value is the exact form a binding
		 * compares against (e.g. `Date` becomes its ISO string).
		 */
		attributes[attribute.name] = JSON.parse(JSON.stringify(value));
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
		const value = await reader.getAttributeValue(attributeName);

		/* Round-trip through JSON so a `Date` becomes its ISO string, etc. */
		attributes[name] = JSON.parse(JSON.stringify(value));
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
		case 'issueCertificate': return(await handleIssueCertificate(request));
		case 'decodeCertificate': return(await handleDecodeCertificate(request));
		case 'proveAttribute': return(await handleProveAttribute(request));
		case 'validateProof': return(await handleValidateProof(request));
		case 'shutdown': return({ event: 'shutdown' });
	}
}

runHarness<KycRequest>({ event: 'ready' }, handle, stopKycAnchor);
