/*
 * KYC interop harness.
 *
 * Runs a live KYC anchor server (the production `KeetaNetKYCAnchorHTTPServer`)
 * backed by an in-memory reference node, plus the metadata blob a root account
 * would publish, so the Rust client exercises the real endpoints.
 */

import type * as ResolverModule from '@keetanetwork/anchor/lib/resolver.js';
import type * as KycServerModule from '@keetanetwork/anchor/services/kyc/server.js';
import type * as KycCommonModule from '@keetanetwork/anchor/services/kyc/common.js';
import type * as KycStatusModule from '@keetanetwork/anchor/services/kyc/status.js';
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
const KeetaNet = refs.client<typeof KeetaNetModule>();
const NodeClient = refs.node<typeof NodeClientModule>('@keetanetwork/keetanet-node/dist/client');
const nodeTesting = refs.node<typeof NodeTestingModule>('@keetanetwork/keetanet-node/dist/lib/utils/helper_testing.js');

const KeetaNetLib = KeetaNet.lib;
const Account = KeetaNetLib.Account;
const Metadata = resolver.default.Metadata;

const metadataSigner = Account.fromSeed(Account.generateRandomSeed(), 0);

type CertificateAuthority = Awaited<ReturnType<InstanceType<typeof KeetaNetLib.Utils.Certificate.CertificateBuilder>['build']>>;
type ReferenceNode = Awaited<ReturnType<typeof nodeTesting.createTestNode>>;
type KycServerConfig = ConstructorParameters<typeof kycServer.KeetaNetKYCAnchorHTTPServer>[0];
type KycServerInstance = InstanceType<typeof kycServer.KeetaNetKYCAnchorHTTPServer>;

/* A booted reference node plus the live KYC anchor server it backs. */
let kycAnchor: { server: KycServerInstance; node: ReferenceNode } | undefined;

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
	metadata: Parameters<typeof Metadata.formatMetadata>[0];
}

interface ShutdownRequest {
	cmd: 'shutdown';
}

type KycRequest =
	StartKycAnchorRequest |
	StopKycAnchorRequest |
	BuildMetadataRequest |
	ShutdownRequest;

/* Mint a self-signed CA the anchor issues KYC certificates under. */
async function buildCertificateAuthority(): Promise<CertificateAuthority> {
	const caAccount = Account.fromSeed(Account.generateRandomSeed(), 0);
	const builder = new KeetaNetLib.Utils.Certificate.CertificateBuilder({
		subjectPublicKey: caAccount,
		issuer: caAccount,
		serial: 1,
		validFrom: new Date(Date.now() - 30_000),
		validTo: new Date(Date.now() + (60 * 60 * 1000))
	});

	return(await builder.build());
}

/* Boot an in-memory reference node and a client bound to its API. The KYC
 * endpoints never touch the ledger, so the chain is left uninitialized. */
async function bootReferenceNode(): Promise<{ node: ReferenceNode; client: KeetaNetModule.UserClient }> {
	const seed = Account.generateRandomSeed({ asString: true });
	const repNodeAccount = NodeClient.lib.Account.fromSeed(seed, 0);
	const repClientAccount = Account.fromSeed(seed, 0);

	const node = await nodeTesting.createTestNode(repNodeAccount, {
		createInitialVoteStaple: false,
		nodeConfig: { nodeAlias: 'TEST' }
	});

	const endpoints = node.config.endpoints;
	if (endpoints?.api === undefined || endpoints.p2p === undefined) {
		throw(new Error('reference node did not expose its API and P2P endpoints'));
	}

	const client = new KeetaNet.Client([{ endpoints: { api: endpoints.api, p2p: endpoints.p2p }, key: repClientAccount }]);
	const userClient = new KeetaNet.UserClient({
		client,
		network: node.config.network,
		networkAlias: node.config.networkAlias,
		signer: repClientAccount,
		usePublishAid: false
	});

	return({ node, client: userClient });
}

function kycCallbacks(ca: CertificateAuthority, countryCodes: string[] | undefined): KycServerConfig['kyc'] {
	const kyc: KycServerConfig['kyc'] = {
		getCertificates: async function(verificationID: string) {
			/* A verification still in progress reports as not-yet-issued; any
			 * other id yields the issued CA certificate. */
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
	await current.node.stop();
}

async function handleStartKycAnchor(request: StartKycAnchorRequest): Promise<HarnessResponse> {
	await stopKycAnchor();

	const providerId = request.providerId ?? 'kyc_test';
	const countryCodes = request.countryCodes;
	const sign = request.sign !== false;

	const reference = await bootReferenceNode();
	const ca = await buildCertificateAuthority();
	const certificateSigner = Account.fromSeed(Account.generateRandomSeed(), 0);

	const server: KycServerInstance = new kycServer.KeetaNetKYCAnchorHTTPServer({
		signer: certificateSigner,
		ca,
		client: reference.client,
		metadataSigner: sign ? metadataSigner : undefined,
		kycProviderURL: function(verificationID: string): string {
			return(`${server.url}verify/${encodeURIComponent(verificationID)}`);
		},
		kyc: kycCallbacks(ca, countryCodes)
	});

	await server.start();
	kycAnchor = { server, node: reference.node };

	const entry = await server.serviceMetadata();
	const metadata = { version: 1, currencyMap: {}, services: { kyc: { [providerId]: entry }}};
	const blob = Metadata.formatMetadata(metadata);

	return({
		event: 'kyc-anchor-started',
		url: server.url,
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

async function handle(request: KycRequest): Promise<HarnessResponse> {
	switch (request.cmd) {
		case 'startKycAnchor': return(await handleStartKycAnchor(request));
		case 'stopKycAnchor': return(await handleStopKycAnchor());
		case 'buildMetadata': return(handleBuildMetadata(request));
		case 'shutdown': return({ event: 'shutdown' });
	}
}

runHarness<KycRequest>({ event: 'ready' }, handle, stopKycAnchor);
