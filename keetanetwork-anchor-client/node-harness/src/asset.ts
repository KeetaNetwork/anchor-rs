/*
 * Asset-movement interop harness.
 *
 * Runs the production `KeetaNetAssetMovementAnchorHTTPServer` backed by an
 * in-memory reference node with an initialized chain. Service metadata is
 * published on-chain to a root account, so the Rust resolver reads it through
 * the real node API (`keetanet://<root>/metadata`).
 */

import type * as ResolverModule from '@keetanetwork/anchor/lib/resolver.js';
import type * as AssetServerModule from '@keetanetwork/anchor/services/asset-movement/server.js';
import type { KeetaAssetMovementTransaction } from '@keetanetwork/anchor/services/asset-movement/common.js';
import type * as KeetaNetModule from '@keetanetwork/keetanet-client';

import type { ChainNode, GenericAccount, UserClient } from './chain.js';
import type { HarnessResponse } from './core.js';
import { bootChainNode } from './chain.js';
import { referenceResolver, runHarness } from './core.js';

const refs = referenceResolver();
const resolver = await refs.anchor<typeof ResolverModule>('lib/resolver.js');
const assetServer = await refs.anchor<typeof AssetServerModule>('services/asset-movement/server.js');
const KeetaNet = refs.client<typeof KeetaNetModule>();

const KeetaNetLib = KeetaNet.lib;
const Account = KeetaNetLib.Account;
const Metadata = resolver.default.Metadata;

const metadataSigner = Account.fromSeed(Account.generateRandomSeed(), 0);

type TokenAccount = UserClient['baseToken'];
type AssetServerInstance = InstanceType<typeof assetServer.KeetaNetAssetMovementAnchorHTTPServer>;
type AssetServerConfig = ConstructorParameters<typeof assetServer.KeetaNetAssetMovementAnchorHTTPServer>[0];
type AssetMovementConfig = AssetServerConfig['assetMovement'];
type SimulateRequest = Parameters<NonNullable<AssetMovementConfig['simulateTransfer']>>[0];
type InitiateRequest = Parameters<NonNullable<AssetMovementConfig['initiateTransfer']>>[0];
type SimulateResponse = Awaited<ReturnType<NonNullable<AssetMovementConfig['simulateTransfer']>>>;
type InitiateResponse = Awaited<ReturnType<NonNullable<AssetMovementConfig['initiateTransfer']>>>;

/** The running asset-movement anchor together with the node it is backed by. */
let assetAnchor: {
	server: AssetServerInstance;
	chain: ChainNode;
} | undefined;

interface StartAssetAnchorRequest {
	cmd: 'startAssetAnchor';
	sign?: boolean;
	providerId?: string;
}

interface StopAssetAnchorRequest {
	cmd: 'stopAssetAnchor';
}

interface ShutdownRequest {
	cmd: 'shutdown';
}

type AssetRequest =
	StartAssetAnchorRequest |
	StopAssetAnchorRequest |
	ShutdownRequest;

/**
 * The full asset-movement callback surface, exercising every operation a binding
 * can drive. `authenticationRequired` forces a signature on every operation
 * except `simulateTransfer` (which the server publishes unauthenticated), so the
 * signed/unsigned split matches the Rust client.
 */
function assetCallbacks(baseTokenAccount: TokenAccount, sendToAccount: GenericAccount, moment: string): AssetMovementConfig {
	const baseToken = baseTokenAccount.publicKeyString.get();
	const sendToAddress = sendToAccount.publicKeyString.get();

	/*
	 * The shared simulate/initiate handler: a fiat pull (`ACH_DEBIT`) when the
	 * source is a persistent-address reference at the bank location, otherwise a
	 * crypto push (`KEETA_SEND`) to the resolved recipient. A simulated push
	 * omits `sendToAddress`, matching `SimulatedAssetTransferInstructions`.
	 */
	function transferHandler(simulate: true, request: SimulateRequest): SimulateResponse;
	function transferHandler(simulate: false, request: InitiateRequest): InitiateResponse;
	function transferHandler(simulate: boolean, request: SimulateRequest | InitiateRequest): SimulateResponse | InitiateResponse {
		if (request.from.location === 'bank-account:us') {
			const source = request.from.source;
			if (!source || typeof source !== 'object' || !('type' in source)) {
				throw(new TypeError('from.source must be a persistent address reference'));
			}
			if (source.type !== 'persistent-address' && source.type !== 'persistent-address-template') {
				throw(new TypeError('from.source must reference a persistent address or template'));
			}

			return({
				...(simulate ? {} : { id: '123' }),
				instructionChoices: [{
					type: 'ACH_DEBIT',
					pullFrom: source,
					assetFee: '0'
				}]
			});
		}

		if (typeof request.to.recipient !== 'string') {
			throw(new TypeError('recipient must be a string'));
		}

		return({
			...(simulate ? {} : { id: '123' }),
			instructionChoices: [{
				type: 'KEETA_SEND',
				location: request.from.location,
				...(simulate ? {} : { sendToAddress }),
				value: String(request.value),
				tokenAddress: baseToken,
				external: `123:${request.to.recipient}`,
				assetFee: '10'
			}]
		});
	}

	/*
	 * The canonical transaction the status/list/execute operations report.
	 */
	const transaction = (): KeetaAssetMovementTransaction => ({
		id: '123',
		status: 'COMPLETED',
		asset: baseToken,
		from: {
			location: 'chain:evm:100',
			value: '100',
			transactions: {
				persistentForwarding: null,
				deposit: null,
				finalization: null
			}
		},
		to: {
			location: 'chain:keeta:100',
			value: '100',
			transactions: {
				withdraw: null
			}
		},
		fee: null,
		additionalTransferDetails: { type: 'markdown', content: 'Custom Transaction Details' },
		createdAt: moment,
		updatedAt: moment
	});

	return({
		authenticationRequired: true,

		supportedAssets: [
			{
				asset: baseToken,
				paths: [
					{
						pair: [
							{ id: 'evm:0xc0634090F2Fe6c6d75e61Be2b949464aBB498973', location: 'chain:evm:100', rails: { inbound: [ 'KEETA_SEND' ] }},
							{ id: baseToken, location: 'chain:keeta:100', rails: { outbound: [ 'KEETA_SEND' ] }}
						]
					}
				]
			},
			{
				asset: [ baseToken, 'USD' ],
				paths: [
					{
						pair: [
							{ id: 'USD', location: 'bank-account:us', rails: { inbound: [ 'ACH_DEBIT' ] }},
							{ id: baseToken, location: 'chain:keeta:100', rails: { outbound: [ 'KEETA_SEND' ] }}
						]
					}
				]
			}
		],

		simulateTransfer: async function(request) {
			return(await Promise.resolve(transferHandler(true, request)));
		},

		initiateTransfer: async function(request) {
			return(await Promise.resolve(transferHandler(false, request)));
		},

		executeTransfer: async function(request) {
			if (!request.account) {
				throw(new Error('missing account authentication'));
			}

			return({
				transaction: {
					...transaction(),
					status: 'EXECUTED'
				}
			});
		},

		getTransferStatus: async function(_ignored_id, account) {
			if (!account) {
				throw(new Error('missing account authentication'));
			}

			return({
				transaction: transaction()
			});
		},

		getAccountStatus: async function() {
			return({ actionRequired: false });
		},

		initiatePersistentForwardingTemplate: async function() {
			return({
				id: 'test-session-id',
				expiresAt: new Date(Date.now() + (60 * 60 * 1000)).toISOString(),
				data: {
					type: 'plaid',
					plaidLinkToken: 'link-sandbox-test-token'
				}
			});
		},

		createPersistentForwardingTemplate: async function() {
			return({
				id: 'template-id',
				asset: baseToken,
				location: 'chain:evm:100',
				address: sendToAddress
			});
		},

		listPersistentForwardingTemplate: async function() {
			return({
				templates: [
					{
						id: 'template-id',
						asset: baseToken,
						location: 'chain:evm:100',
						address: sendToAddress
					}
				],
				total: '1'
			});
		},

		createPersistentForwarding: async function() {
			return({
				address: sendToAddress,
				fees: {
					lineItems: [
						{
							purpose: 'VALUE_VARIABLE',
							basisPoints: 50,
							details: { type: 'markdown', content: 'Variable fee of 50 basis points' }
						}
					],
					total: '10'
				}
			});
		},

		listPersistentForwarding: async function() {
			return({
				addresses: [
					{
						address: sendToAddress,
						asset: baseToken,
						sourceLocation: 'chain:evm:100',
						destinationLocation: 'chain:keeta:100',
						destinationAddress: sendToAddress,
						id: 'template-id'
					}
				],
				total: '1'
			});
		},

		listTransactions: async function() {
			return({
				transactions: [ transaction() ],
				total: '1'
			});
		},

		shareKYC: async function(request) {
			/*
			 * A magic attributes string exercises the pending path: the anchor
			 * reports the share pending and hands back a root-relative promise
			 * URL the client must poll to completion.
			 */
			if (request.attributes.includes('promise')) {
				return({
					isPending: true,
					promiseURL: `/_promises/${request.attributes}`
				});
			}

			return({});
		},

		deactivatePersistentForwardingTemplate: async function(id, account) {
			if (!account) {
				throw(new Error('missing account authentication'));
			}
			if (id === 'does-not-exist') {
				throw(new Error('template not found'));
			}

			return({});
		},

		deactivatePersistentForwarding: async function(id, account) {
			if (!account) {
				throw(new Error('missing account authentication'));
			}
			if (id === 'does-not-exist') {
				throw(new Error('address not found'));
			}

			return({});
		}
	});
}

async function stopAssetAnchor(): Promise<void> {
	const current = assetAnchor;
	if (current === undefined) {
		return;
	}

	assetAnchor = undefined;
	await current.server.stop();
	await current.chain.node.stop();
}

async function handleStartAssetAnchor(request: StartAssetAnchorRequest): Promise<HarnessResponse> {
	await stopAssetAnchor();

	const providerId = request.providerId ?? 'asset_test';
	const sign = request.sign !== false;

	const chain = await bootChainNode();
	const baseTokenAccount = chain.repClient.baseToken;
	const sendToAccount = Account.fromSeed(Account.generateRandomSeed(), 0);
	const moment = (new Date()).toISOString();

	/*
	 * Pending share-KYC promises, counted per promise id. The promise route
	 * reports pending (202) for the first two polls and completes (200) after.
	 */
	const promisePolling = new Map<string, number>();

	const server: AssetServerInstance = new (class extends assetServer.KeetaNetAssetMovementAnchorHTTPServer {
		protected override async initRoutes(config: AssetServerConfig) {
			const routes = await super.initRoutes(config);
			routes['GET /_promises/:promiseID'] = async function(params) {
				const promiseId = params.get('promiseID');
				if (promiseId === undefined) {
					throw(new Error('Missing promise ID'));
				}

				const polls = (promisePolling.get(promiseId) ?? 0) + 1;
				promisePolling.set(promiseId, polls);

				if (polls <= 2) {
					return({
						statusCode: 202,
						output: 'pending',
						headers: { 'Retry-After': '0.1' }
					});
				}

				return({ output: JSON.stringify({ ok: true }) });
			};

			return(routes);
		}
	})({
		metadataSigner: sign ? metadataSigner : undefined,
		assetMovement: assetCallbacks(baseTokenAccount, sendToAccount, moment)
	});

	await server.start();
	assetAnchor = { server, chain };

	/*
	 * The service-metadata entry's operation map is a mapped type the resolver's
	 * `JSONSerializable` index signature cannot structurally accept, so it crosses
	 * as an opaque JSON value exactly as the reference `client.test.ts` does.
	 */
	const metadata = {
		version: 1,
		currencyMap: {},
		services: {
			assetMovement: {
				// eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-unsafe-assignment
				[providerId]: await server.serviceMetadata() as any
			}
		}
	};
	const blob = Metadata.formatMetadata(metadata);
	const root = await chain.publish(metadata);

	const asset = baseTokenAccount.publicKeyString.get();
	const sendToAddress = sendToAccount.publicKeyString.get();

	return({
		event: 'asset-anchor-started',
		url: server.url,
		api: chain.api,
		root,
		providerId,
		signer: sign ? metadataSigner.publicKeyString.get() : null,
		asset,
		sendToAddress,
		blob
	});
}

async function handleStopAssetAnchor(): Promise<HarnessResponse> {
	await stopAssetAnchor();
	return({ event: 'asset-anchor-stopped' });
}

async function handle(request: AssetRequest): Promise<HarnessResponse> {
	switch (request.cmd) {
		case 'startAssetAnchor': return(await handleStartAssetAnchor(request));
		case 'stopAssetAnchor': return(await handleStopAssetAnchor());
		case 'shutdown': return({ event: 'shutdown' });
	}
}

runHarness<AssetRequest>({ event: 'ready' }, handle, stopAssetAnchor);
