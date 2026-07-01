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
import type * as NodeClientModule from '@keetanetwork/keetanet-node/dist/client';
import type * as NodeTestingModule from '@keetanetwork/keetanet-node/dist/lib/utils/helper_testing.js';

import type { HarnessResponse } from './core.js';
import { referenceResolver, runHarness } from './core.js';

const refs = referenceResolver();
const resolver = await refs.anchor<typeof ResolverModule>('lib/resolver.js');
const assetServer = await refs.anchor<typeof AssetServerModule>('services/asset-movement/server.js');
const KeetaNet = refs.client<typeof KeetaNetModule>();
const NodeClient = refs.node<typeof NodeClientModule>('@keetanetwork/keetanet-node/dist/client');
const nodeTesting = refs.node<typeof NodeTestingModule>('@keetanetwork/keetanet-node/dist/lib/utils/helper_testing.js');

const KeetaNetLib = KeetaNet.lib;
const Account = KeetaNetLib.Account;
const Permissions = KeetaNetLib.Permissions;
const Metadata = resolver.default.Metadata;

const metadataSigner = Account.fromSeed(Account.generateRandomSeed(), 0);

type ReferenceNode = Awaited<ReturnType<typeof nodeTesting.createTestNode>>;
type UserClient = InstanceType<typeof KeetaNet.UserClient>;
type GenericAccount = InstanceType<typeof KeetaNetLib.Account>;
type TokenAccount = UserClient['baseToken'];
type AssetServerInstance = InstanceType<typeof assetServer.KeetaNetAssetMovementAnchorHTTPServer>;
type AssetServerConfig = ConstructorParameters<typeof assetServer.KeetaNetAssetMovementAnchorHTTPServer>[0];
type AssetMovementConfig = AssetServerConfig['assetMovement'];
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

/**
 * The full asset-movement callback surface, exercising every operation a binding
 * can drive. `authenticationRequired` forces a signature on every operation
 * except `simulateTransfer` (which the server publishes unauthenticated), so the
 * signed/unsigned split matches the Rust client. `baseToken` stands in for the
 * moved asset and `sendToAddress` for a resolved KEETA_SEND recipient; both are
 * branded public-key strings so the fixtures satisfy the reference types. The
 * fixtures are ported from the reference `client.test.ts`.
 */
function assetCallbacks(baseTokenAccount: TokenAccount, sendToAccount: GenericAccount, moment: string): AssetMovementConfig {
	const baseToken = baseTokenAccount.publicKeyString.get();
	const sendToAddress = sendToAccount.publicKeyString.get();

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
			}
		],

		simulateTransfer: async function(request) {
			if (typeof request.to.recipient !== 'string') {
				throw(new Error('recipient must be a string'));
			}

			return({
				instructionChoices: [{
					type: 'KEETA_SEND',
					location: request.from.location,
					value: String(request.value),
					tokenAddress: baseToken,
					external: `123:${request.to.recipient}`,
					assetFee: '10'
				}]
			});
		},

		initiateTransfer: async function(request) {
			if (typeof request.to.recipient !== 'string') {
				throw(new Error('recipient must be a string'));
			}

			return({
				id: '123',
				instructionChoices: [{
					type: 'KEETA_SEND',
					location: request.from.location,
					sendToAddress,
					value: String(request.value),
					tokenAddress: baseToken,
					external: `123:${request.to.recipient}`,
					assetFee: '10'
				}]
			});
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
