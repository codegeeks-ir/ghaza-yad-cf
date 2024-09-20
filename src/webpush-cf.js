// src/utils.ts
var stringFromArrayBuffer = (s) => {
	let result = '';
	for (const code of new Uint8Array(s)) result += String.fromCharCode(code);
	return result;
};
var base64UrlEncode = (s) => {
	const text = typeof s === 'string' ? s : stringFromArrayBuffer(s);
	return btoa(text).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
};
var base64UrlDecodeString = (s) => s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
var base64UrlDecode = (s) =>
	new Uint8Array(
		atob(base64UrlDecodeString(s))
			.split('')
			.map((char) => char.charCodeAt(0))
	).buffer;
var concatTypedArrays = (arrays) => {
	const length = arrays.reduce((accumulator, current) => accumulator + current.byteLength, 0);
	let index = 0;
	const targetArray = new Uint8Array(length);
	for (const array of arrays) {
		targetArray.set(array, index);
		index += array.byteLength;
	}
	return targetArray;
};
var getPublicKeyFromJwk = (jwk) => base64UrlEncode('' + atob(base64UrlDecodeString(jwk.x)) + atob(base64UrlDecodeString(jwk.y)));

// src/jwt.ts
var createJwt = async (jwk, jwtData) => {
	const jwtInfo = {
		typ: 'JWT',
		alg: 'ES256',
	};
	const base64JwtInfo = base64UrlEncode(JSON.stringify(jwtInfo));
	const base64JwtData = base64UrlEncode(JSON.stringify(jwtData));
	const unsignedToken = `${base64JwtInfo}.${base64JwtData}`;
	const privateKey = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
	const signature = await crypto.subtle
		.sign({ name: 'ECDSA', hash: { name: 'SHA-256' } }, privateKey, new TextEncoder().encode(unsignedToken))
		.then((token) => base64UrlEncode(token));
	return `${base64JwtInfo}.${base64JwtData}.${signature}`;
};

// src/index.ts
var importClientKeys = async (keys) => {
	const auth = base64UrlDecode(keys.auth);
	if (auth.byteLength !== 16) {
		throw new Error(`incorrect auth length, expected 16 bytes got ${auth.byteLength}`);
	}
	const key = atob(base64UrlDecodeString(keys.p256dh));
	const p256 = await crypto.subtle.importKey(
		'jwk',
		{
			kty: 'EC',
			crv: 'P-256',
			x: base64UrlEncode(key.slice(1, 33)),
			y: base64UrlEncode(key.slice(33, 65)),
			ext: true,
		},
		{
			name: 'ECDH',
			namedCurve: 'P-256',
		},
		true,
		[]
	);
	return { auth, p256 };
};
var deriveSharedSecret = async (clientPublicKey, localPrivateKey) => {
	const sharedSecretBytes = await crypto.subtle.deriveBits(
		// @ts-expect-error typescript says it should be $public, but it doesn't work
		{ name: 'ECDH', public: clientPublicKey },
		localPrivateKey,
		256
	);
	return crypto.subtle.importKey('raw', sharedSecretBytes, { name: 'HKDF' }, false, ['deriveBits', 'deriveKey']);
};
var derivePsuedoRandomKey = async (auth, sharedSecret) => {
	const pseudoRandomKeyBytes = await crypto.subtle.deriveBits(
		{
			name: 'HKDF',
			hash: 'SHA-256',
			salt: auth,
			// Adding Content-Encoding data info here is required by the Web
			// Push API
			info: new TextEncoder().encode('Content-Encoding: auth\0'),
		},
		sharedSecret,
		256
	);
	return crypto.subtle.importKey('raw', pseudoRandomKeyBytes, 'HKDF', false, ['deriveBits']);
};
var createContext = async (clientPublicKey, localPublicKey) => {
	const [clientKeyBytes, localKeyBytes] = await Promise.all([
		crypto.subtle.exportKey('raw', clientPublicKey),
		crypto.subtle.exportKey('raw', localPublicKey),
	]);
	return concatTypedArrays([
		new TextEncoder().encode('P-256\0'),
		new Uint8Array([0, clientKeyBytes.byteLength]),
		new Uint8Array(clientKeyBytes),
		new Uint8Array([0, localKeyBytes.byteLength]),
		new Uint8Array(localKeyBytes),
	]);
};
var deriveNonce = async (pseudoRandomKey, salt, context) => {
	const nonceInfo = concatTypedArrays([new TextEncoder().encode('Content-Encoding: nonce\0'), context]);
	return crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: nonceInfo }, pseudoRandomKey, 12 * 8);
};
var deriveContentEncryptionKey = async (pseudoRandomKey, salt, context) => {
	const cekInfo = concatTypedArrays([new TextEncoder().encode('Content-Encoding: aesgcm\0'), context]);
	const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: cekInfo }, pseudoRandomKey, 16 * 8);
	return crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['encrypt']);
};
var padPayload = (payload) => {
	const MAX_PAYLOAD_SIZE = 4078;
	let paddingSize = Math.round(Math.random() * 100);
	const payloadSizeWithPadding = payload.byteLength + 2 + paddingSize;
	if (payloadSizeWithPadding > MAX_PAYLOAD_SIZE) {
		paddingSize -= payloadSizeWithPadding - MAX_PAYLOAD_SIZE;
	}
	const paddingArray = new ArrayBuffer(2 + paddingSize);
	new DataView(paddingArray).setUint16(0, paddingSize);
	return concatTypedArrays([new Uint8Array(paddingArray), payload]);
};
var encryptPayload = async (localKeys, salt, payload, target) => {
	const clientKeys = await importClientKeys(target.keys);
	const sharedSecret = await deriveSharedSecret(clientKeys.p256, localKeys.privateKey);
	const pseudoRandomKey = await derivePsuedoRandomKey(clientKeys.auth, sharedSecret);
	const context = await createContext(clientKeys.p256, localKeys.publicKey);
	const nonce = await deriveNonce(pseudoRandomKey, salt, context);
	const contentEncryptionKey = await deriveContentEncryptionKey(pseudoRandomKey, salt, context);
	const encodedPayload = new TextEncoder().encode(payload);
	const paddedPayload = padPayload(encodedPayload);
	return crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, contentEncryptionKey, paddedPayload);
};
var buildHeaders = async (options, payloadLength, salt, localPublicKey) => {
	const localPublicKeyBase64 = await crypto.subtle.exportKey('raw', localPublicKey).then((bytes) => base64UrlEncode(bytes));
	const serverPublicKey = getPublicKeyFromJwk(options.jwk);
	const jwt = await createJwt(options.jwk, options.jwt);
	const headers = new Headers({
		Encryption: `salt=${base64UrlEncode(salt)}`,
		'Crypto-Key': `dh=${localPublicKeyBase64}`,
		'Content-Length': payloadLength.toString(),
		'Content-Type': 'application/octet-stream',
		'Content-Encoding': 'aesgcm',
		Authorization: `vapid t=${jwt}, k=${serverPublicKey}`,
	});
	if (options.ttl !== void 0) headers.append('TTL', options.ttl.toString());
	if (options.topic !== void 0) headers.append('Topic', options.topic);
	if (options.urgency !== void 0) headers.append('Urgency', options.urgency);
	return headers;
};
var buildRequest = async (options, target) => {
	const salt = crypto.getRandomValues(new Uint8Array(16));
	const localKeys = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
	const encryptedPayload = await encryptPayload(localKeys, salt, options.payload, target);
	const headers = await buildHeaders(options, encryptedPayload.byteLength, salt, localKeys.publicKey);
	return new Request(target.endpoint, {
		body: encryptedPayload,
		headers,
		method: 'POST',
	});
};
export { buildRequest, getPublicKeyFromJwk };
