/*
 * Shared chain-node bootstrap for the interop harnesses.
 *
 * Boots an in-memory reference node with an initialized chain (base token,
 * supply, delegation) so harness accounts can publish on-chain service
 * metadata that a resolver reads back through the real node API, exactly as
 * the reference client does.
 */

import type * as ResolverModule from '@keetanetwork/anchor/lib/resolver.js';
import type * as KeetaNetModule from '@keetanetwork/keetanet-client';
import type * as NodeClientModule from '@keetanetwork/keetanet-node/dist/client';
import type * as NodeTestingModule from '@keetanetwork/keetanet-node/dist/lib/utils/helper_testing.js';

import { referenceResolver } from './core.js';

const refs = referenceResolver();
const resolver = await refs.anchor<typeof ResolverModule>('lib/resolver.js');
const KeetaNet = refs.client<typeof KeetaNetModule>();
const NodeClient = refs.node<typeof NodeClientModule>('@keetanetwork/keetanet-node/dist/client');
const nodeTesting = refs.node<typeof NodeTestingModule>('@keetanetwork/keetanet-node/dist/lib/utils/helper_testing.js');

const KeetaNetLib = KeetaNet.lib;
const Account = KeetaNetLib.Account;
const Permissions = KeetaNetLib.Permissions;
const Metadata = resolver.default.Metadata;

type ReferenceNode = Awaited<ReturnType<typeof nodeTesting.createTestNode>>;

export type UserClient = InstanceType<typeof KeetaNet.UserClient>;
export type GenericAccount = InstanceType<typeof KeetaNetLib.Account>;
export type ServiceMetadata = Parameters<typeof Metadata.formatMetadata>[0];

/**
 * A reference node with an initialized chain, plus the helpers needed to fund
 * accounts and publish service metadata on-chain.
 */
export interface ChainNode {
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
 * Boot an in-memory reference node and initialize its chain (base token, supply,
 * delegation) so accounts can publish on-chain metadata. The resolver reads that
 * metadata back through the node API, exactly as the reference client does.
 */
export async function bootChainNode(): Promise<ChainNode> {
	const seed = Account.generateRandomSeed({ asString: true });
	const repNodeAccount = NodeClient.lib.Account.fromSeed(seed, 0);
	const repClientAccount = Account.fromSeed(seed, 0);

	/* Fees start disabled so the network can be initialized for free. */
	let feesEnabled = false;

	const node = await nodeTesting.createTestNode(repNodeAccount, {
		createInitialVoteStaple: false,
		nodeConfig: { nodeAlias: 'TEST' },
		ledger: {
			computeFeeFromBlocks: function(_ignore_ledger, _ignore_blocks, _ignore_effects) {
				if (!feesEnabled) {
					return(null);
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
