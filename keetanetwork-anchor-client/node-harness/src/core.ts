/*
 * Shared harness core.
 *
 * Resolves the reference modules and drives a harness over the JSON-lines
 * protocol: one request object per stdin line, one response object per
 * stdout line. Each domain harness composes this with its own command set.
 */

import * as readline from 'node:readline';
import * as path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

export type HarnessResponse = { [key: string]: unknown };

/*
 * The reference modules resolve at runtime, so these two helpers are the one
 * place a typed assertion bridges the dynamic `import`/`require` to the
 * declared module surface.
 */
async function importTyped<T>(specifier: string): Promise<T> {
	// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
	return(await import(specifier) as T);
}

function requireTyped<T>(requireFn: NodeRequire, specifier: string): T {
	// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
	return(requireFn(specifier) as T);
}

/**
 * Loads reference modules by their role, hiding whether they come from the
 * installed packages or a local anchor `dist`.
 */
export interface ReferenceResolver {
	/** An `@keetanetwork/anchor` sub-module, by its `dist`-relative path. */
	anchor<T>(relative: string): Promise<T>;
	/** The `@keetanetwork/keetanet-client` module. */
	client<T>(): T;
	/** A `@keetanetwork/keetanet-node` sub-module, by its full specifier. */
	node<T>(specifier: string): T;
}

export function referenceResolver(): ReferenceResolver {
	const requireFromHere = createRequire(import.meta.url);
	const dist = process.env.KEETANET_ANCHOR_DIST;
	if (dist !== undefined && dist !== '') {
		const href = (relative: string): string => pathToFileURL(path.join(dist, relative)).href;
		const requireFromDist = createRequire(href('lib/utils/signing.js'));
		return({
			anchor: <T>(relative: string): Promise<T> => importTyped<T>(href(relative)),
			client: <T>(): T => requireTyped<T>(requireFromDist, '@keetanetwork/keetanet-client'),
			node: <T>(specifier: string): T => requireTyped<T>(requireFromHere, specifier)
		});
	}

	return({
		anchor: <T>(relative: string): Promise<T> => importTyped<T>(`@keetanetwork/anchor/${relative}`),
		client: <T>(): T => requireTyped<T>(requireFromHere, '@keetanetwork/keetanet-client'),
		node: <T>(specifier: string): T => requireTyped<T>(requireFromHere, specifier)
	});
}

/**
 * Print the ready line, then serialize handling of each request line so the
 * harness emits exactly one response line per request. `onShutdown` runs after
 * the `shutdown` command's response, before the process exits.
 */
export function runHarness<Request extends { cmd: string }>(
	ready: HarnessResponse,
	handle: (request: Request) => HarnessResponse | Promise<HarnessResponse>,
	onShutdown?: () => Promise<void>
): void {
	console.log(JSON.stringify(ready));

	const rl = readline.createInterface({ input: process.stdin, terminal: false });

	let queue = Promise.resolve();

	rl.on('line', function(line) {
		const trimmed = line.trim();
		if (trimmed === '') {
			return;
		}

		queue = queue.then(async function() {
			// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
			const request = JSON.parse(trimmed) as Request;
			try {
				const response = await handle(request);
				console.log(JSON.stringify(response));
				if (request.cmd === 'shutdown') {
					if (onShutdown !== undefined) {
						await onShutdown();
					}

					process.exit(0);
				}
			} catch (error) {
				const message = error instanceof Error ? error.message : String(error);
				console.log(JSON.stringify({ error: message }));
			}
		});
	});
}
