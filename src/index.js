/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */
import { buildRequest } from './webpush-cf';

export default {
	async scheduled(event, env, ctx) {
		const payload = JSON.stringify({
			title: 'یادآوری رزرو غذا',
			body: 'رزرو غذا یادت نره! از همین پایین وارد سایت شو و غذات رو رزرو کن',
			url: 'https://food.uut.ac.ir',
		});
		ctx.waitUntil(BroadcastMessage(payload, env));
	},
	async fetch(request, env, ctx) {
		return handleRequest(request, env);
	},
};

async function handleRequest(request, env) {
	const url = new URL(request.url);

	if (request.method === 'OPTIONS') {
		return handleOptions(request, env);
	}

	if (request.method === 'POST') {
		if (url.pathname === '/subscribe') {
			return handleSubscribe(request, env);
		} else if (url.pathname === '/unsubscribe') {
			return handleUnsubscribe(request, env);
		} else if (url.pathname === '/test-notification') {
			const payload = JSON.stringify({
				title: 'این یک پیام آزمایشی است',
				body: 'در صورت دریافت این نوتیفیکیشن فرایند فعال سازی با موفقیت انجام شده',
			});
			console.log(JSON.stringify(request));
			const subscription = await request.json();
			if (!subscription.endpoint) {
				return new Response('Invalid subscription', {
					status: 400,
					headers: corsHeaders(),
				});
			}
			return sendPushNotification(payload, subscription, env);
		}
	}

	return new Response('404 page not found', { status: 404 });
}

// Handle CORS preflight requests
function handleOptions(request, env) {
	const headers = {
		'Access-Control-Allow-Origin': 'https://ghaza-yad.pages.dev',
		'Access-Control-Allow-Methods': 'POST, OPTIONS',
		'Access-Control-Allow-Headers': 'Content-Type',
		'Access-Control-Max-Age': '86400',
	};

	return new Response(null, { status: 204, headers });
}

// Handle subscription requests
async function handleSubscribe(request, env) {
	try {
		const subscription = await request.json();
		if (!subscription.endpoint) {
			return new Response('Invalid subscription', {
				status: 400,
				headers: corsHeaders(),
			});
		}

		const key = subscription.endpoint;
		await env.SUBSCRIPTIONS.put(key, JSON.stringify(subscription));

		return new Response('Subscribed successfully', {
			status: 201,
			headers: corsHeaders(),
		});
	} catch (error) {
		console.error('Error handling subscribe:', error);
		return new Response('Failed to subscribe', {
			status: 500,
			headers: corsHeaders(),
		});
	}
}

// Handle unsubscription requests
async function handleUnsubscribe(request, env) {
	try {
		const subscription = await request.json();
		if (!subscription.endpoint) {
			return new Response('Invalid subscription', {
				status: 400,
				headers: corsHeaders(),
			});
		}

		const key = subscription.endpoint;
		await env.SUBSCRIPTIONS.delete(key);

		return new Response('Unsubscribed successfully', {
			status: 200,
			headers: corsHeaders(),
		});
	} catch (error) {
		console.error('Error handling unsubscribe:', error);
		return new Response('Failed to unsubscribe', {
			status: 500,
			headers: corsHeaders(),
		});
	}
}

// Broadcast Message
async function BroadcastMessage(payload, env) {
	try {
		const subscriptionsList = await env.SUBSCRIPTIONS.list();

		for (const key of subscriptionsList.keys) {
			const subscriptionJSON = await env.SUBSCRIPTIONS.get(key.name);
			if (!subscriptionJSON) continue;

			const subscription = JSON.parse(subscriptionJSON);
			await sendPushNotification(payload, subscription, env);
		}
	} catch (error) {
		console.error('Error sending test notifications:', error);
	}
}

// Helper function to set CORS headers
function corsHeaders() {
	return {
		'Access-Control-Allow-Origin': 'https://ghaza-yad.pages.dev',
		'Access-Control-Allow-Methods': 'POST, OPTIONS',
		'Access-Control-Allow-Headers': 'Content-Type',
	};
}

async function sendPushNotification(payload, subscription, env) {
	const aud = new URL(subscription.endpoint).origin;

	const jwk = JSON.parse(env.VAPID_PRIVATE_KEY);
	console.log('subscription: ' + JSON.stringify(jwk));
	const ttl = 20 * 60 * 60; // 20 hours
	const host = new URL(subscription.endpoint).origin;
	const pushRequest = await buildRequest(
		{
			jwk,
			ttl,
			jwt: {
				aud: host,
				exp: Math.floor(Date.now() / 1000) + ttl,
				sub: 'ceit.uut@gmail.com',
			},
			payload,
		},
		subscription
	);

	const response = await fetch(pushRequest);
	if (!response.ok) {
	}

	if (!response.ok) {
		const text = await response.text(); // Log response body for better debugging
		console.error('Failed to send push notification:', response.status, response.statusText, text);
		return Error('received http code ' + response.status);
	} else {
		console.log('Push notification sent successfully!');
		return new Response('Subscribed successfully', {
			status: 201,
			headers: corsHeaders(),
		});
	}
}
