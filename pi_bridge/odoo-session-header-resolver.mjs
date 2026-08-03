const SESSION_HEADER = "x-odoo-v3-broker-session";
const RESULT_DELIVERY_SESSION_HEADER =
	"x-odoo-v3-result-delivery-session";
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
	const resultDeliveryValue =
		request?.headers?.[RESULT_DELIVERY_SESSION_HEADER];
	if (
		typeof value !== "string"
		|| !SESSION_HANDLE.test(value)
		|| typeof resultDeliveryValue !== "string"
		|| !SESSION_HANDLE.test(resultDeliveryValue)
		|| value === resultDeliveryValue
	) {
		return null;
	}
	return Object.freeze({
		brokerSessionHandle: value,
		resultDeliverySessionHandle: resultDeliveryValue,
	});
}
