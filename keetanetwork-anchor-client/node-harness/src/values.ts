/*
 * Shared request-value revival for harness commands that embed reference
 * builder values in JSON.
 */

/**
 * A traversable JSON container: an array or a plain object.
 */
type Container = { [key: string]: unknown } | unknown[];

/**
 * The revived form of a marker object.
 */
function reviveMarker(value: object): Date | Buffer | undefined {
	const entries = Object.entries(value);
	const dateEntry = entries.find(([key]) => key === '__date');
	if (dateEntry !== undefined && typeof dateEntry[1] === 'string') {
		return(new Date(dateEntry[1]));
	}

	const typeEntry = entries.find(([key]) => key === 'type');
	const dataEntry = entries.find(([key]) => key === 'data');
	const data: unknown = dataEntry?.[1];
	const isByte = (byte: unknown): byte is number => Number.isInteger(byte) && typeof byte === 'number' && byte >= 0 && byte <= 255;
	if (typeEntry?.[1] === 'Buffer' && Array.isArray(data) && data.every(isByte)) {
		return(Buffer.from(data));
	}

	return(undefined);
}

/**
 * Write `value` at `key` on either container shape.
 */
function setEntry(container: Container, key: string | number, value: unknown): void {
	if (Array.isArray(container)) {
		container[Number(key)] = value;
	} else {
		container[String(key)] = value;
	}
}

/**
 * Revive one container entry: replace a marker child in place, queue a nested
 * container for the walk, leave primitives and Buffers untouched.
 */
function reviveChild(container: Container, key: string | number, child: unknown, pending: Container[]): void {
	if (child === null || typeof child !== 'object' || Buffer.isBuffer(child)) {
		return;
	}

	if (Array.isArray(child)) {
		pending.push(child);
		return;
	}

	const revived = reviveMarker(child);
	if (revived === undefined) {
		// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
		pending.push(child as { [key: string]: unknown });
		return;
	}

	setEntry(container, key, revived);
}

/**
 * Revive a JSON request value into the shape the reference builder expects,
 * replacing marker objects in place throughout the tree.
 */
export function reviveValue(value: unknown): unknown {
	const holder: unknown[] = [value];
	const pending: Container[] = [holder];
	while (pending.length > 0) {
		const container = pending.pop();
		if (container === undefined) {
			continue;
		}

		if (Array.isArray(container)) {
			for (const [index, child] of container.entries()) {
				reviveChild(container, index, child, pending);
			}

			continue;
		}

		for (const [key, child] of Object.entries(container)) {
			reviveChild(container, key, child, pending);
		}
	}

	return(holder[0]);
}
