const SESSION_HEADER = "x-odoo-v3-broker-session";
const SESSION_HANDLE = /^[A-Za-z0-9._~-]{32,512}$/;
const LOOPBACK_ADDRESSES = new Set([
	"127.0.0.1",
	"::1",
	"::ffff:127.0.0.1",
]);

export function resolveAuthenticatedSession(request) {
	if (
		request?.method !== "POST"
		|| request?.url !== "/chat"
		|| !LOOPBACK_ADDRESSES.has(request?.remoteAddress)
	) {
		return null;
	}
	const value = request?.headers?.[SESSION_HEADER];
	if (typeof value !== "string" || !SESSION_HANDLE.test(value)) {
		return null;
	}
	return Object.freeze({ brokerSessionHandle: value });
}
