/**
 * DingTalk Webhook Server
 * 
 * Provides HTTP POST webhook endpoint for receiving DingTalk messages
 * as an alternative to Stream mode (WebSocket).
 */

import * as http from 'node:http';
import { URL } from 'node:url';
import type { 
  DingTalkConfig, 
  Logger 
} from './types';

import type { OpenClawConfig } from 'openclaw/plugin-sdk';

interface MessageData {
  type: string;
  content: string;
}

export interface WebhookServerOptions {
  config: DingTalkConfig;
  cfg: OpenClawConfig;
  log?: Logger;
  onMessage: (data: MessageData) => Promise<void>;
}

export interface WebhookServerResult {
  server: http.Server;
  port: number;
}

/**
 * Create and start HTTP webhook server for receiving DingTalk POST requests
 * 
 * @param options - Configuration options
 * @returns Server instance and port information
 * @throws Error if server fails to start
 */
export async function createWebhookServer(options: WebhookServerOptions): Promise<WebhookServerResult> {
  const { config, log, onMessage } = options;
  
  const webhookAuthToken = config.webhookAuthToken || '';
  const webhookPort = config.webhookPort || 20123;
  const webhookPath = '/webhook/dingtalk';

  const server = http.createServer((req: http.IncomingMessage, res: http.ServerResponse) => {
    // Only handle POST requests
    if (req.method !== 'POST') {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
      return;
    }

    // Validate request path
    const url = new URL(req.url || '', `http://${req.headers.host || 'localhost'}`);
    if (url.pathname !== webhookPath) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
      return;
    }

    // Validate Authorization header
    const authHeader = req.headers['authorization'] || '';
    
    const expectedAuth = `Bearer ${webhookAuthToken}`;
    if (authHeader !== expectedAuth) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized', message: 'Invalid or missing Authorization token' }));
      return;
    }

    // Check Content-Type - only accept application/json
    const contentType = req.headers['content-type'] || '';
    const isJson = contentType.includes('application/json');

    if (!isJson) {
      log?.warn?.(`[DingTalk][Webhook] Only application/json is supported, got: ${contentType}`);
      res.writeHead(415, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unsupported Media Type', expected: 'application/json' }));
      return;
    }

    // Parse request body
    const chunks: Buffer[] = [];
    let totalLength = 0;
    const MAX_SIZE = 10 * 1024 * 1024; // 10MB limit for file uploads

    req.on('data', (chunk: Buffer) => {
      totalLength += chunk.length;
      // Prevent excessively large payloads
      if (totalLength > MAX_SIZE) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Payload too large' }));
        req.socket.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', async () => {
      try {
        const body = Buffer.concat(chunks);

        // Parse JSON body
        const jsonString = body.toString('utf-8');
        const data = JSON.parse(jsonString) as MessageData;
        log?.debug?.(`[DingTalk][Webhook] Parsed JSON data`);

        // Send response immediately to acknowledge webhook
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));

        // Process message asynchronously
        await onMessage(data);
      } catch (error: unknown) {
        if (log?.error) {
          log.error(`[DingTalk][Webhook] Error processing POST message: ${String(error)}`);
        }
        
        // Try to send error response if not already sent
        if (!res.headersSent) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Bad Request', message: String(error) }));
        }
      }
    });

    req.on('error', (error: Error) => {
      if (log?.error) {
        log.error(`[DingTalk][Webhook] Request error: ${error.message}`);
      }
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal Server Error' }));
      }
    });
  });

  // Start listening on specified port
  await new Promise<void>((resolve, reject) => {
    server.listen(webhookPort, () => {
      if (log?.info) {
        log.info(
          `DingTalk Webhook server listening on port ${webhookPort}`
        );
      }
      resolve();
    });
    server.on('error', (err: Error) => reject(err));
  });

  return { server, port: webhookPort };
}

/**
 * Gracefully close webhook server
 * 
 * @param server - HTTP server instance to close
 * @param log - Optional logger for status messages
 */
export function closeWebhookServer(
  server: http.Server, 
  log?: Logger
): void {
  server.close(() => {
    if (log?.info) {
      log.info('DingTalk Webhook server closed');
    }
  });
}
