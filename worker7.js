//nat64\u81ea\u52a8\u586b\u5145proxyip\uff0c\u65e0\u9700\u4e14\u4e0d\u652f\u6301proxyip\u8bbe\u7f6e
// nat64 auto-fills proxyip, no proxyip setting needed or supported.
import { connect } from "cloudflare:sockets";
const WS_READY_STATE_OPEN = 1;
let userID = "86c50e3a-5b87-49dd-bd20-03c7f2735e40";
const cn_hostnames = [''];
let CDNIP = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0073\u0067'
// http_ip
let IP1 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP2 = '\u0063\u0069\u0073\u002e\u0076\u0069\u0073\\u0061\u002e\u0063\u006f\u006d'
let IP3 = '\u0061\u0066\u0072\u0069\u0063\\u0061\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP4 = '\u0077\u0077\u0077\u002e\u0076\u0069\\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0073\u0067'
let IP5 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0061\u0074'
let IP6 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u006d\u0074'
let IP7 = '\u0071\u0061\u002e\u0076\u0069\u0073\u0061\u006d\u0069\u0064\u0064\u006c\u0065\u0065\u0061\u0073\u0074\u002e\u0063\u006f\u006d'

// https_ip
let IP8 = '\u0075\u0073\u0061\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP9 = '\u006d\u0079\u0061\u006e\u006d\u0061\u0072\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP10 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0074\u0077'
let IP11 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0063\u0068'
let IP12 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0062\u0072'
let IP13 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0073\u006f\u0075\u0074\u0068\u0065\u0061\u0073\u0074\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0063\u006f\u006d'

// http_port
let PT1 = '80'
let PT2 = '8080'
let PT3 = '8880'
let PT4 = '2052'
let PT5 = '2082'
let PT6 = '2086'
let PT7 = '2095'

// https_port
let PT8 = '443'
let PT9 = '8443'
let PT10 = '2053'
let PT11 = '2083'
let PT12 = '2087'
let PT13 = '2096'

export default {
  /**
   * @param {any} request
   * @param {{uuid: string, proxyip: string, cdnip: string, ip1: string, ip2: string, ip3: string, ip4: string, ip5: string, ip6: string, ip7: string, ip8: string, ip9: string, ip10: string, ip11: string, ip12: string, ip13: string, pt1: string, pt2: string, pt3: string, pt4: string, pt5: string, pt6: string, pt7: string, pt8: string, pt9: string, pt10: string, pt11: string, pt12: string, pt13: string}} env
   * @param {any} ctx
   * @returns {Promise<Response>}
   */
  async fetch(request, env, ctx) {
    try {
      userID = env.uuid || userID;
      CDNIP = env.cdnip || CDNIP;
	  IP1 = env.ip1 || IP1;
	  IP2 = env.ip2 || IP2;
	  IP3 = env.ip3 || IP3;
	  IP4 = env.ip4 || IP4;
	  IP5 = env.ip5 || IP5;
	  IP6 = env.ip6 || IP6;
	  IP7 = env.ip7 || IP7;
	  IP8 = env.ip8 || IP8;
	  IP9 = env.ip9 || IP9;
	  IP10 = env.ip10 || IP10;
	  IP11 = env.ip11 || IP11;
	  IP12 = env.ip12 || IP12;
	  IP13 = env.ip13 || IP13;
	  PT1 = env.pt1 || PT1;
	  PT2 = env.pt2 || PT2;
	  PT3 = env.pt3 || PT3;
	  PT4 = env.pt4 || PT4;
	  PT5 = env.pt5 || PT5;
	  PT6 = env.pt6 || PT6;
	  PT7 = env.pt7 || PT7;
	  PT8 = env.pt8 || PT8;
	  PT9 = env.pt9 || PT9;
	  PT10 = env.pt10 || PT10;
	  PT11 = env.pt11 || PT11;
	  PT12 = env.pt12 || PT12;
	  PT13 = env.pt13 || PT13;
      const upgradeHeader = request.headers.get("Upgrade");
      const url = new URL(request.url);
      if (!upgradeHeader || upgradeHeader !== "websocket") {
        const url = new URL(request.url);
        switch (url.pathname) {
          case `/${userID}`: {
            const \u0076\u006c\u0065\u0073\u0073Config = get\u0076\u006c\u0065\u0073\u0073Config(userID, request.headers.get("Host"));
            return new Response(`${\u0076\u006c\u0065\u0073\u0073Config}`, {
              status: 200,
              headers: {
                "Content-Type": "text/html;charset=utf-8",
              },
            });
          }
		  case `/${userID}/ty`: {
			const tyConfig = gettyConfig(userID, request.headers.get('Host'));
			return new Response(`${tyConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "text/plain;charset=utf-8",
				}
			});
		}
		case `/${userID}/cl`: {
			const clConfig = getclConfig(userID, request.headers.get('Host'));
			return new Response(`${clConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "text/plain;charset=utf-8",
				}
			});
		}
		case `/${userID}/sb`: {
			const sbConfig = getsbConfig(userID, request.headers.get('Host'));
			return new Response(`${sbConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "application/json;charset=utf-8",
				}
			});
		}
		case `/${userID}/pty`: {
			const ptyConfig = getptyConfig(userID, request.headers.get('Host'));
			return new Response(`${ptyConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "text/plain;charset=utf-8",
				}
			});
		}
		case `/${userID}/pcl`: {
			const pclConfig = getpclConfig(userID, request.headers.get('Host'));
			return new Response(`${pclConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "text/plain;charset=utf-8",
				}
			});
		}
		case `/${userID}/psb`: {
			const psbConfig = getpsbConfig(userID, request.headers.get('Host'));
			return new Response(`${psbConfig}`, {
				status: 200,
				headers: {
					"Content-Type": "application/json;charset=utf-8",
				}
			});
		}
          default:
            // return new Response('Not found', { status: 404 });
            // For any other path, reverse proxy to 'ramdom website' and return the original response, caching it in the process
            if (cn_hostnames.includes('')) {
            return new Response(JSON.stringify(request.cf, null, 4), {
              status: 200,
              headers: {
                "Content-Type": "application/json;charset=utf-8",
              },
            });
            }
            const randomHostname = cn_hostnames[Math.floor(Math.random() * cn_hostnames.length)];
            const newHeaders = new Headers(request.headers);
            newHeaders.set("cf-connecting-ip", "1.2.3.4");
            newHeaders.set("x-forwarded-for", "1.2.3.4");
            newHeaders.set("x-real-ip", "1.2.3.4");
            newHeaders.set("referer", "https://www.google.com/search?q=edtunnel");
            // Use fetch to proxy the request to 15 different domains
            const proxyUrl = "https://" + randomHostname + url.pathname + url.search;
            let modifiedRequest = new Request(proxyUrl, {
              method: request.method,
              headers: newHeaders,
              body: request.body,
              redirect: "manual",
            });
            const proxyResponse = await fetch(modifiedRequest, { redirect: "manual" });
            // Check for 302 or 301 redirect status and return an error response
            if ([301, 302].includes(proxyResponse.status)) {
              return new Response(`Redirects to ${randomHostname} are not allowed.`, {
                status: 403,
                statusText: "Forbidden",
              });
            }
            // Return the response from the proxy server
            return proxyResponse;
        }
      }
      return await handle\u0076\u006c\u0065\u0073\u0073WebSocket(request);
    } catch (err) {
      /** @type {Error} */ let e = err;
      return new Response(e.toString());
    }
  },
};

async function handle\u0076\u006c\u0065\u0073\u0073WebSocket(request) {
  const wsPair = new WebSocketPair();
  const [clientWS, serverWS] = Object.values(wsPair);

  serverWS.accept();

  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const wsReadable = createWebSocketReadableStream(serverWS, earlyDataHeader);
  let remoteSocket = null;

  let udpStreamWrite = null;
  let isDns = false;
  
  wsReadable.pipeTo(new WritableStream({
    async write(chunk) {

      if (isDns && udpStreamWrite) {
        return udpStreamWrite(chunk);
      }
      
      if (remoteSocket) {
        const writer = remoteSocket.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      const result = parse\u0076\u006c\u0065\u0073\u0073Header(chunk, userID);
      if (result.hasError) {
        throw new Error(result.message);
      }

      const \u0076\u006c\u0065\u0073\u0073RespHeader = new Uint8Array([result.\u0076\u006c\u0065\u0073\u0073Version[0], 0]);
      const rawClientData = chunk.slice(result.rawDataIndex);
      
      if (result.isUDP) {
        if (result.portRemote === 53) {
          isDns = true;
          const { write } = await handleUDPOutBound(serverWS, \u0076\u006c\u0065\u0073\u0073RespHeader);
          udpStreamWrite = write;
          udpStreamWrite(rawClientData);
          return;
        } else {
          throw new Error('UDP proxy only supports DNS (port 53)'); // Translated
        }
      }

      async function connectAndWrite(address, port) {
        const tcpSocket = await connect({
          hostname: address,
          port: port
        });
        remoteSocket = tcpSocket;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
      }

      function convertToNAT64IPv6(ipv4Address) {
        const parts = ipv4Address.split('.');
        if (parts.length !== 4) {
          throw new Error('Invalid IPv4 address'); // Translated
        }
        
        const hex = parts.map(part => {
          const num = parseInt(part, 10);
          if (num < 0 || num > 255) {
            throw new Error('Invalid IPv4 address segment'); // Translated
          }
          return num.toString(16).padStart(2, '0');
        });
        const prefixes = ['2001:67c:2960:6464::'];
        const chosenPrefix = prefixes[Math.floor(Math.random() * prefixes.length)];
        return `[${chosenPrefix}${hex[0]}${hex[1]}:${hex[2]}${hex[3]}]`;
      }

      async function getIPv6ProxyAddress(domain) {
        try {
          const dnsQuery = await fetch(`https://1.1.1.1/dns-query?name=${domain}&type=A`, {
            headers: {
              'Accept': 'application/dns-json'
            }
          });
          
          const dnsResult = await dnsQuery.json();
          if (dnsResult.Answer && dnsResult.Answer.length > 0) {
            const aRecord = dnsResult.Answer.find(record => record.type === 1);
            if (aRecord) {
              const ipv4Address = aRecord.data;
              return convertToNAT64IPv6(ipv4Address);
            }
          }
          throw new Error('Unable to resolve IPv4 address for domain'); // Translated
        } catch (err) {
          throw new Error(`DNS resolution failed: ${err.message}`); // Translated
        }
      }

      async function retry() {
        try {
          const proxyIP = await getIPv6ProxyAddress(result.addressRemote);
          console.log(`Attempting to connect via NAT64 IPv6 address ${proxyIP}...`); // Translated
          const tcpSocket = await connect({
            hostname: proxyIP,
            port: result.portRemote
          });
          remoteSocket = tcpSocket;
          const writer = tcpSocket.writable.getWriter();
          await writer.write(rawClientData);
          writer.releaseLock();

          tcpSocket.closed.catch(error => {
            console.error('NAT64 IPv6 connection closed error:', error); // Translated
          }).finally(() => {
            if (serverWS.readyState === WS_READY_STATE_OPEN) {
              serverWS.close(1000, 'Connection closed'); // Translated
            }
          });
          
          pipeRemoteToWebSocket(tcpSocket, serverWS, \u0076\u006c\u0065\u0073\u0073RespHeader, null);
        } catch (err) {
          console.error('NAT64 IPv6 connection failed:', err); // Translated
          serverWS.close(1011, 'NAT64 IPv6 connection failed: ' + err.message); // Translated
        }
      }

      try {
        const tcpSocket = await connectAndWrite(result.addressRemote, result.portRemote);
        pipeRemoteToWebSocket(tcpSocket, serverWS, \u0076\u006c\u0065\u0073\u0073RespHeader, retry);
      } catch (err) {
        console.error('Connection failed:', err); // Translated
        serverWS.close(1011, 'Connection failed'); // Translated
      }
    },
    close() {
      if (remoteSocket) {
        closeSocket(remoteSocket);
      }
    }
  })).catch(err => {
    console.error('WebSocket Error:', err); // Translated
    closeSocket(remoteSocket);
    serverWS.close(1011, 'Internal Error'); // Translated
  });

  return new Response(null, {
    status: 101,
    webSocket: clientWS,
  });
}

function createWebSocketReadableStream(ws, earlyDataHeader) {
  return new ReadableStream({
    start(controller) {
      ws.addEventListener('message', event => {
        controller.enqueue(event.data);
      });
      
      ws.addEventListener('close', () => {
        controller.close();
      });
      
      ws.addEventListener('error', err => {
        controller.error(err);
      });
      
      if (earlyDataHeader) {
        try {
          const decoded = atob(earlyDataHeader.replace(/-/g, '+').replace(/_/g, '/'));
          const data = Uint8Array.from(decoded, c => c.charCodeAt(0));
          controller.enqueue(data.buffer);
        } catch (e) {
        }
      }
    }
  });
}

function parse\u0076\u006c\u0065\u0073\u0073Header(buffer, userID) {
  if (buffer.byteLength < 24) {
    return { hasError: true, message: 'Invalid header length' }; // Translated
  }
  
  const view = new DataView(buffer);
  const version = new Uint8Array(buffer.slice(0, 1));
  
  const uuid = formatUUID(new Uint8Array(buffer.slice(1, 17)));
  if (uuid !== userID) {
    return { hasError: true, message: 'Invalid user' }; // Translated
  }
  
  const optionsLength = view.getUint8(17);
  const command = view.getUint8(18 + optionsLength);

  let isUDP = false;
  if (command === 1) {

  } else if (command === 2) {

    isUDP = true;
  } else {
    return { hasError: true, message: 'Unsupported command, only TCP(01) and UDP(02) are supported' }; // Translated
  }
  
  let offset = 19 + optionsLength;
  const port = view.getUint16(offset);
  offset += 2;
  
  const addressType = view.getUint8(offset++);
  let address = '';
  
  switch (addressType) {
    case 1: // IPv4
      address = Array.from(new Uint8Array(buffer.slice(offset, offset + 4))).join('.');
      offset += 4;
      break;
      
    case 2: // Domain
      const domainLength = view.getUint8(offset++);
      address = new TextDecoder().decode(buffer.slice(offset, offset + domainLength));
      offset += domainLength;
      break;
      
    case 3: // IPv6
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(view.getUint16(offset).toString(16).padStart(4, '0'));
        offset += 2;
      }
      address = ipv6.join(':').replace(/(^|:)0+(\w)/g, '$1$2');
      break;
      
    default:
      return { hasError: true, message: 'Unsupported address type' }; // Translated
  }
  
  return {
    hasError: false,
    addressRemote: address,
    portRemote: port,
    rawDataIndex: offset,
    \u0076\u006c\u0065\u0073\u0073Version: version,
    isUDP
  };
}

function pipeRemoteToWebSocket(remoteSocket, ws, \u0076\u006c\u0065\u0073\u0073Header, retry = null) {
  let headerSent = false;
  let hasIncomingData = false;
  
  remoteSocket.readable.pipeTo(new WritableStream({
    write(chunk) {
      hasIncomingData = true;
      if (ws.readyState === WS_READY_STATE_OPEN) {
        if (!headerSent) {
          const combined = new Uint8Array(\u0076\u006c\u0065\u0073\u0073Header.byteLength + chunk.byteLength);
          combined.set(new Uint8Array(\u0076\u006c\u0065\u0073\u0073Header), 0);
          combined.set(new Uint8Array(chunk), \u0076\u006c\u0065\u0073\u0073Header.byteLength);
          ws.send(combined.buffer);
          headerSent = true;
        } else {
          ws.send(chunk);
        }
      }
    },
    close() {
      if (!hasIncomingData && retry) {
        retry();
        return;
      }
      if (ws.readyState === WS_READY_STATE_OPEN) {
        ws.close(1000, 'Normal closure'); // Translated
      }
    },
    abort() {
      closeSocket(remoteSocket);
    }
  })).catch(err => {
    console.error('Data forwarding error:', err); // Translated
    closeSocket(remoteSocket);
    if (ws.readyState === WS_READY_STATE_OPEN) {
      ws.close(1011, 'Data transfer error'); // Translated
    }
  });
}

function closeSocket(socket) {
  if (socket) {
    try {
      socket.close();
    } catch (e) {
    }
  }
}

function formatUUID(bytes) {
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

async function handleUDPOutBound(webSocket, \u0076\u006c\u0065\u0073\u0073ResponseHeader) {
  let is\u0076\u006c\u0065\u0073\u0073HeaderSent = false;
  const transformStream = new TransformStream({
    start(controller) {
    },
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength;) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(
          chunk.slice(index + 2, index + 2 + udpPacketLength)
        );
        index = index + 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    },
    flush(controller) {
    }
  });

  transformStream.readable.pipeTo(new WritableStream({
    async write(chunk) {
      const resp = await fetch('https://1.1.1.1/dns-query',
        {
          method: 'POST',
          headers: {
            'content-type': 'application/dns-message',
          },
          body: chunk,
        })
      const dnsQueryResult = await resp.arrayBuffer();
      const udpSize = dnsQueryResult.byteLength;
      const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
      
      if (webSocket.readyState === WS_READY_STATE_OPEN) {
        console.log(`DNS query successful, DNS message length is ${udpSize}`); // Translated
        if (is\u0076\u006c\u0065\u0073\u0073HeaderSent) {
          webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
        } else {
          webSocket.send(await new Blob([\u0076\u006c\u0065\u0073\u0073ResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
          is\u0076\u006c\u0065\u0073\u0073HeaderSent = true;
        }
      }
    }
  })).catch((error) => {
    console.error('DNS UDP processing error:', error); // Translated
  });

  const writer = transformStream.writable.getWriter();

  return {
    write(chunk) {
      writer.write(chunk);
    }
  };
}
/**
 *
 * @param {string} userID
 * @param {string | null} hostName
 * @returns {string}
 */
function get\u0076\u006c\u0065\u0073\u0073Config(userID, hostName) {
  const w\u0076\u006c\u0065\u0073\u0073ws = `\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${CDNIP}:8880?encryption=none&security=none&type=ws&host=${hostName}&path=%2F%3Fed%3D68#${hostName}`;
  const p\u0076\u006c\u0065\u0073\u0073wstls = `\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${CDNIP}:8443?encryption=none&security=tls&type=ws&host=${hostName}&sni=${hostName}&fp=random&path=%2F%3Ded%3D68#${hostName}`;
  
  // تغییرات برای ایموجی و کادربندی
  const note = `
    <div class="panel-68-container">
        <span class="panel-68-emoji">💪6️⃣8️⃣</span>
    </div>
  `;
  
  const ty = `https://${hostName}/${userID}/ty`
  const cl = `https://${hostName}/${userID}/cl`
  const sb = `https://${hostName}/${userID}/sb`
  const pty = `https://${hostName}/${userID}/pty`
  const pcl = `https://${hostName}/${userID}/pcl`
  const psb = `https://${hostName}/${userID}/psb`

  const wk\u0076\u006c\u0065\u0073\u0073share = btoa(`\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP1}:${PT1}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Ded%3D68#CF_V1_${IP1}_${PT1}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP2}:${PT2}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Ded%3D68#CF_V2_${IP2}_${PT2}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP3}:${PT3}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Ded%3D68#CF_V3_${IP3}_${PT3}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP4}:${PT4}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Ded%3D68#CF_V4_${IP4}_${PT4}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP5}:${PT5}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Ded%3D68#CF_V5_${IP5}_${PT5}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP6}:${PT6}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Ded%3D68#CF_V6_${IP6}_${PT6}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP7}:${PT7}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Ded%3D68#CF_V7_${IP7}_${PT7}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Ded%3D68#CF_V8_${IP8}_${PT8}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Ded%3D68#CF_V9_${IP9}_${PT9}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Ded%3D68#CF_V10_${IP10}_${PT10}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Ded%3D68#CF_V11_${IP11}_${PT11}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Ded%3D68#CF_V12_${IP12}_${PT12}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Ded%3D68#CF_V13_${IP13}_${PT13}`);


  const pg\u0076\u006c\u0065\u0073\u0073share = btoa(`\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Ded%3D68#CF_V8_${IP8}_${PT8}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Ded%3D68#CF_V9_${IP9}_${PT9}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Ded%3D68#CF_V10_${IP10}_${PT10}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Ded%3D68#CF_V11_${IP11}_${PT11}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Ded%3D68#CF_V12_${IP12}_${PT12}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Ded%3D68#CF_V13_${IP13}_${PT13}`);	

	
  const noteshow = note.replace(/\n/g, '<br>');
  const displayHtml = `
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VLESS Proxy Configuration</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
<style>
/* Keyframes for blinking effect */
@keyframes blink-border {
    0% { border-color: #4CAF50; } /* Green */
    25% { border-color: #2196F3; } /* Blue */
    50% { border-color: #FFC107; } /* Amber */
    75% { border-color: #F44336; } /* Red */
    100% { border-color: #4CAF50; } /* Back to Green */
}

body {
    background-color: #1c1c2e; /* Deep dark blue */
    color: #e6e6fa; /* Lavender blush for text */
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    padding: 10px; /* Reduced padding for smaller screens */
    line-height: 1.6;
}
.container {
    background-color: #2a2a4a; /* Darker slate blue for container */
    border-radius: 15px;
    padding: 20px; /* Adjusted padding for responsiveness */
    box-shadow: 0 0 25px rgba(0, 0, 0, 0.6);
    margin-top: 20px;
    margin-bottom: 20px;
}
h1, h3 {
    color: #8aff8a; /* Bright green for headings */
    text-align: center;
    margin-bottom: 25px;
    font-weight: 700;
}
hr {
    border-top: 2px solid #5a5a8a; /* Subtle separator */
    margin-top: 20px;
    margin-bottom: 20px;
}

/* Panel 68 specific styling */
.panel-68-container {
    text-align: center; /* Center the content horizontally */
    margin: 30px auto; /* Center the div itself */
    padding: 15px 25px;
    border: 5px solid; /* Border for animation */
    border-image: linear-gradient(to right, #4CAF50, #2196F3) 1; /* Initial gradient */
    border-radius: 12px;
    width: fit-content; /* Make container fit content for better centering with auto margins */
    max-width: 90%; /* Ensure it doesn't overflow on small screens */
    animation: blink-border 4s infinite linear; /* Blinking animation */
    box-shadow: 0 0 15px rgba(138, 255, 138, 0.7); /* Green glow */
    display: flex; /* Use flexbox for vertical centering if needed */
    align-items: center; /* Center vertically if flex container */
    justify-content: center; /* Center horizontally if flex container */
    background-color: #3b3b5b; /* Changed to match other panels */
    /* Adjust margin-top to make it more in line with other panels if needed */
    margin-top: 15px; /* Example adjustment */
    margin-bottom: 25px; /* Example adjustment */
}
.panel-68-emoji {
    font-size: 5em; /* Very large font size for emojis */
    line-height: 1; /* Adjust line height to prevent extra space */
    font-family: "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji", sans-serif; /* Ensure emoji font is used */
    /* Remove transparent and text-shadow for emojis to display correctly */
    /* color: transparent; /* Make text invisible */
    /* text-shadow: 0 0 0 #FFF; /* Use text-shadow to color the emojis white */ */
    color: #e6e6fa; /* Set color for the numbers if they are text */
    display: block; /* Take full width of parent */
    width: 100%; /* Ensure it takes full width of its flex container */
    overflow-wrap: break-word; /* Ensure emojis wrap if too long, though unlikely */
    word-break: break-all; /* For very long strings, though not applicable to emojis */
}


.table {
    background-color: #3b3b5b; /* Darker purple for table background */
    border-radius: 10px;
    overflow: hidden; /* Ensures rounded corners apply to content */
    margin-bottom: 30px;
    width: 100%; /* Ensure table takes full width */
    max-width: 100%; /* Prevent overflow on small screens */
}
.table th, .table td {
    border-color: #5a5a8a; /* Matching border color */
    color: #e6e6fa;
    padding: 12px 15px;
    vertical-align: middle;
    font-size: 0.95em; /* Slightly smaller font for tables */
}
.table thead th {
    background-color: #4a4a70; /* Even darker purple for table header */
    color: #ffffff;
    font-weight: bold;
}
.table tbody tr:nth-child(even) {
    background-color: #404060; /* Alternate row color */
}
.limited-width {
    max-width: 300px; /* Increased width for better readability on larger screens */
    overflow-wrap: break-word; /* Use overflow-wrap for better word breaking */
    word-break: break-all; /* Break long strings */
    font-size: 0.85em; /* Smaller font to fit content */
}
.btn-primary {
    background-color: #4a4a70; /* Changed background color to match site */
    border-color: #4a4a70; /* Changed border color to match site */
    color: #e6e6fa; /* Set text color for readability */
    transition: background-color 0.3s ease, transform 0.2s ease, box-shadow 0.3s ease;
    padding: 10px 20px;
    border-radius: 8px;
    font-weight: bold;
}
.btn-primary:hover {
    background-color: #5a5a8a; /* Darker shade for hover effect */
    border-color: #5a5a8a; /* Darker shade for hover effect */
    transform: translateY(-2px); /* Slight lift effect */
    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.4); /* Darker glow on hover */
}
ul {
    list-style-type: none;
    padding-left: 0;
}
ul li {
    background-color: #3b3b5b;
    margin-bottom: 8px;
    padding: 10px 15px;
    border-radius: 8px;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2);
    font-size: 0.9em;
}

/* Footer message styling */
.footer-message {
    text-align: center;
    font-size: 1.5em; /* Large font for the message */
    margin-top: 40px; /* Space from the last element */
    margin-bottom: 20px; /* Space at the bottom */
    color: #8aff8a; /* Bright green, similar to headings */
    font-weight: bold;
}


/* Responsive adjustments */
@media (max-width: 768px) {
    .container {
        padding: 15px;
    }
    h1 {
        font-size: 1.8em;
    }
    h3 {
        font-size: 1.4em;
    }
    .panel-68-emoji {
        font-size: 3.5em; /* Smaller on mobile */
    }
    .panel-68-container {
        padding: 10px 15px;
        border-width: 3px;
    }
    .table th, .table td {
        padding: 8px 10px;
        font-size: 0.8em; /* Smaller table font */
    }
    .limited-width {
        max-width: 100%; /* Allow full width on small screens */
        font-size: 0.75em;
    }
    .btn-primary {
        padding: 8px 15px;
        font-size: 0.9em;
    }
    ul li {
        font-size: 0.85em;
    }
    .footer-message {
        font-size: 1.2em;
    }
}

@media (max-width: 576px) {
    body {
        padding: 5px;
    }
    .container {
        border-radius: 10px;
        padding: 10px;
    }
    h1 {
        font-size: 1.5em;
    }
    h3 {
        font-size: 1.2em;
    }
    .panel-68-emoji {
        font-size: 2.5em; /* Even smaller on very small screens */
    }
    .panel-68-container {
        margin: 20px auto;
        padding: 8px 10px;
        border-width: 2px;
    }
    .table th, .table td {
        display: block; /* Stack table cells */
        width: 100%;
        text-align: left !important;
        border-bottom: 1px solid #5a5a8a;
    }
    .table thead {
        display: none; /* Hide table header on very small screens */
    }
    .table tbody tr {
        margin-bottom: 15px;
        display: block;
        border: 1px solid #5a5a8a;
        border-radius: 10px;
    }
    .table tbody tr td:last-child {
        border-bottom: none;
    }
    .limited-width {
        font-size: 0.8em;
    }
    .btn-primary {
        width: 100%;
        margin-top: 10px;
    }
    .footer-message {
        font-size: 1em;
    }
}
</style>
</head>
<script>
function copyToClipboard(text) {
  const input = document.createElement('textarea');
  input.style.position = 'fixed';
  input.style.opacity = 0;
  input.value = text;
  document.body.appendChild(input);
  input.select();
  document.execCommand('Copy');
  document.body.removeChild(input);
  alert('لینک با موفقیت کپی شد!'); // Translated to Persian
}
</script>
`;
if (hostName.includes("workers.dev")) {
return `
<br>
<br>
${displayHtml}
<body>
<div class="container">
    <div class="row">
        <div class="col-md-12">
            <h1>Cloudflare-workers/pages-VLESS Proxy Script V25.5.27</h1>
	    <hr>
            ${noteshow}
            <hr>
	    <hr>
	    <hr>
            <br>
            <br>
            <h3>1: CF-workers-VLESS+WS Node</h3>
			<table class="table">
				<thead>
					<tr>
						<th>ویژگی‌های نود:</th>
						<th>لینک نود تک:</th>
						<th>کپی لینک</th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td class="limited-width">رمزگذاری TLS غیرفعال است، مسدودسازی دامنه را نادیده می‌گیرد</td>
						<td class="limited-width">${w\u0076\u006c\u0065\u0073\u0073ws}</td>
						<td><button class="btn btn-primary" onclick="copyToClipboard('${w\u0076\u006c\u0065\u0073\u0073ws}')">برای کپی لینک کلیک کنید</button></td>
					</tr>
				</tbody>
			</table>
            <h5>پارامترهای کلاینت:</h5>
            <ul>
                <li>آدرس کلاینت (address): دامنه سفارشی یا دامنه بهینه یا IP بهینه یا IP پروکسی معکوس</li>
                <li>پورت (port): 7 پورت HTTP قابل انتخاب (80, 8080, 8880, 2052, 2082, 2086, 2095)، یا پورت متناظر IP پروکسی معکوس</li>
                <li>شناسه کاربری (uuid): ${userID}</li>
                <li>پروتکل انتقال (network): ws یا websocket</li>
                <li>دامنه جعلی (host): ${hostName}</li>
                <li>مسیر (path): /?ed=68</li>
                <li>امنیت انتقال (TLS): غیرفعال</li>
            </ul>
            <hr>
            <hr>
            <hr>
            <br>
            <br>
            <h3>2: CF-workers-VLESS+WS+TLS Node</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>ویژگی‌های نود:</th>
                        <th>لینک نود تک:</th>
                        <th>کپی لینک</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">رمزگذاری TLS فعال است،<br>اگر کلاینت از تکه‌تکه شدن پشتیبانی می‌کند، توصیه می‌شود برای جلوگیری از مسدود شدن دامنه آن را فعال کنید.</td>
                        <td class="limited-width">${p\u0076\u006c\u0065\u0073\u0073wstls}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${p\u0076\u006c\u0065\u0073\u0073wstls}')">برای کپی لینک کلیک کنید</button></td>
                    </tr>
                </tbody>
            </table>
            <h5>پارامترهای کلاینت:</h5>
            <ul>
                <li>آدرس کلاینت (address): دامنه سفارشی یا دامنه بهینه یا IP بهینه یا IP پروکسی معکوس</li>
                <li>پورت (port): 6 پورت HTTPS قابل انتخاب (443, 8443, 2053, 2083, 2087, 2096)، یا پورت متناظر IP پروکسی معکوس</li>
                <li>شناسه کاربری (uuid): ${userID}</li>
                <li>پروتکل انتقال (network): ws یا websocket</li>
                <li>دامنه جعلی (host): ${hostName}</li>
                <li>مسیر (path): /?ed=68</li>
                <li>امنیت انتقال (TLS): فعال</li>
                <li>نادیده گرفتن تأیید گواهی (allowInsecure): false</li>
            </ul>
            <hr>
            <hr>
            <hr>
            <br>
            <br>
            <h3>3: جمع‌آوری لینک‌های اشتراک عمومی، Clash-meta، Sing-box:</h3>
            <hr>
            <p>توجه:<br>1. هر لینک اشتراک به طور پیش‌فرض شامل 13 نود پورت (TLS + غیر TLS) است.<br>2. دامنه کارگران فعلی به عنوان یک لینک اشتراک نیاز به به‌روزرسانی از طریق پروکسی دارد.<br>3. اگر کلاینت مورد استفاده از تکه‌تکه شدن پشتیبانی نمی‌کند، نودهای TLS ممکن است در دسترس نباشند.</p>
            <hr>
            <table class="table">
                <thead>
                    <tr>
                        <th>لینک اشتراک‌گذاری عمومی (قابل ایمپورت مستقیم در کلاینت):</th>
                        <th>کپی لینک</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${wk\u0076\u006c\u0065\u0073\u0073share}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${wk\u0076\u006c\u0065\u0073\u0073share}')">برای کپی لینک کلیک کنید</button></td>
                    </tr>
                </tbody>
            </table>
            <table class="table">
                <thead>
                    <tr>
                        <th>لینک اشتراک عمومی:</th>
                        <th>کپی لینک</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${ty}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${ty}')">برای کپی لینک کلیک کنید</button></td>
                    </tr>
                </tbody>
            </table>
            <table class="table">
                <thead>
                    <tr>
                        <th>لینک اشتراک Clash-meta:</th>
                        <th>کپی لینک</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${cl}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${cl}')">برای کپی لینک کلیک کنید</button></td>
                    </tr>
                </tbody>
            </table>
            <table class="table">
                <thead>
                    <tr>
                        <th>لینک اشتراک Sing-box:</th>
                        <th>کپی لینک</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${sb}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${sb}')">برای کپی لینک کلیک کنید</button></td>
                    </tr>
                </tbody>
            </table>
            <br>
            <br>
        </div>
    </div>
</div>
<div class="footer-message">
    برو حالشو ببر 😉
</div>
</body>
`;
} else {
return `
<br>
<br>
${displayHtml}
<body>
<div class="container">
    <div class="row">
        <div class="col-md-12">
            <h1>Cloudflare-workers/pages-VLESS Proxy Script V25.5.27</h1>
            <hr>
            ${noteshow}
            <hr>
            <hr>
            <hr>
            <br>
            <br>
            <h3>1: CF-pages/workers/Custom Domain-VLESS+WS Node</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>ویژگی‌های نود:</th>
                        <th>لینک نود تک:</th>
                        <th>کپی لینک</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">رمزگذاری TLS غیرفعال است، مسدودسازی دامنه را نادیده می‌گیرد</td>
                        <td class="limited-width">${w\u0076\u006c\u0065\u0073\u0073ws}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${w\u0076\u006c\u0065\u0073\u0073ws}')">برای کپی لینک کلیک کنید</button></td>
                    </tr>
                </tbody>
            </table>
            <h5>پارامترهای کلاینت:</h5>
            <ul>
                <li>آدرس کلاینت (address): دامنه سفارشی یا دامنه بهینه یا IP بهینه یا IP پروکسی معکوس</li>
                <li>پورت (port): 7 پورت HTTP قابل انتخاب (80, 8080, 8880, 2052, 2082, 2086, 2095)، یا پورت متناظر IP پروکسی معکوس</li>
                <li>شناسه کاربری (uuid): ${userID}</li>
                <li>پروتکل انتقال (network): ws یا websocket</li>
                <li>دامنه جعلی (host): ${hostName}</li>
                <li>مسیر (path): /?ed=68</li>
                <li>امنیت انتقال (TLS): غیرفعال</li>
            </ul>
            <hr>
            <hr>
            <hr>
            <br>
            <br>
            <h3>2: CF-pages/workers/Custom Domain-VLESS+WS+TLS Node</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>ویژگی‌های نود:</th>
                        <th>لینک نود تک:</th>
                        <th>کپی لینک</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">رمزگذاری TLS فعال است،<br>اگر کلاینت از تکه‌تکه شدن پشتیبانی می‌کند، توصیه می‌شود برای جلوگیری از مسدود شدن دامنه آن را فعال کنید.</td>
                        <td class="limited-width">${p\u0076\u006c\u0065\u0073\u0073wstls}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${p\u0076\u006c\u0065\u0073\u0073wstls}')">برای کپی لینک کلیک کنید</button></td>
                    </tr>
                </tbody>
            </table>
            <h5>پارامترهای کلاینت:</h5>
            <ul>
                <li>آدرس کلاینت (address): دامنه سفارشی یا دامنه بهینه یا IP بهینه یا IP پروکسی معکوس</li>
                <li>پورت (port): 6 پورت HTTPS قابل انتخاب (443, 8443, 2053, 2083, 2087, 2096)، یا پورت متناظر IP پروکسی معکوس</li>
                <li>شناسه کاربری (uuid): ${userID}</li>
                <li>پروتکل انتقال (network): ws یا websocket</li>
                <li>دامنه جعلی (host): ${hostName}</li>
                <li>مسیر (path): /?ed=68</li>
                <li>امنیت انتقال (TLS): فعال</li>
                <li>نادیده گرفتن تأیید گواهی (allowInsecure): false</li>
            </ul>
            <hr>
            <hr>
            <hr>
            <br>
            <br>
            <h3>3: جمع‌آوری لینک‌های اشتراک عمومی، Clash-meta، Sing-box:</h3>
            <hr>
            <p>توجه:<br>1. هر لینک اشتراک به طور پیش‌فرض شامل 13 نود پورت (TLS + غیر TLS) است.<br>2. دامنه کارگران فعلی به عنوان یک لینک اشتراک نیاز به به‌روزرسانی از طریق پروکسی دارد.<br>3. اگر کلاینت مورد استفاده از تکه‌تکه شدن پشتیبانی نمی‌کند، نودهای TLS ممکن است در دسترس نباشند.</p>
            <hr>
            <table class="table">
                <thead>
                    <tr>
                        <th>لینک اشتراک‌گذاری پورت‌های HTTP (قابل ایمپورت مستقیم در کلاینت):</th>
                        <th>کپی لینک</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${wk\u0076\u006c\u0065\u0073\u0073share}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${wk\u0076\u006c\u0065\u0073\u0073share}')">برای کپی لینک کلیک کنید</button></td>
                    </tr>
                </tbody>
            </table>
            <table class="table">
                <thead>
                    <tr>
                        <th>لینک اشتراک‌گذاری پورت‌های HTTPS (قابل ایمپورت مستقیم در کلاینت):</th>
                        <th>کپی لینک</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${pg\u0076\u006c\u0065\u0073\u0073share}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${pg\u0076\u006c\u0065\u0073\u0073share}')">برای کپی لینک کلیک کنید</button></td>
                    </tr>
                </tbody>
            </table>
            <table class="table">
                <thead>
                    <tr>
                        <th>لینک اشتراک عمومی:</th>
                        <th>کپی لینک</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${ty}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${ty}')">برای کپی لینک کلیک کنید</button></td>
                    </tr>
                </tbody>
            </table>
            <table class="table">
                <thead>
                    <tr>
                        <th>لینک اشتراک Clash-meta:</th>
                        <th>کپی لینک</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${cl}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${cl}')">برای کپی لینک کلیک کنید</button></td>
                    </tr>
                </tbody>
            </table>
            <table class="table">
                <thead>
                    <tr>
                        <th>لینک اشتراک Sing-box:</th>
                        <th>کپی لینک</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${sb}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${sb}')">برای کپی لینک کلیک کنید</button></td>
                    </tr>
                </tbody>
            </table>
            <br>
            <br>
            <h3>4: جمع‌آوری لینک‌های اشتراک عمومی، Clash-meta، Sing-box از طریق پروکسی:</h3>
            <hr>
            <p>توجه:<br>1. هر لینک اشتراک به طور پیش‌فرض شامل 13 نود پورت (TLS + غیر TLS) است.<br>2. دامنه کارگران فعلی به عنوان یک لینک اشتراک نیاز به به‌روزرسانی از طریق پروکسی دارد.<br>3. اگر کلاینت مورد استفاده از تکه‌تکه شدن پشتیبانی نمی‌کند، نودهای TLS ممکن است در دسترس نباشند.</p>
            <hr>
            <table class="table">
                <thead>
                    <tr>
                        <th>لینک اشتراک عمومی از طریق پروکسی:</th>
                        <th>کپی لینک</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${pty}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${pty}')">برای کپی لینک کلیک کنید</button></td>
                    </tr>
                </tbody>
            </table>
            <table class="table">
                <thead>
                    <tr>
                        <th>لینک اشتراک Clash-meta از طریق پروکسی:</th>
                        <th>کپی لینک</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${pcl}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${pcl}')">برای کپی لینک کلیک کنید</button></td>
                    </tr>
                </tbody>
            </table>
            <table class="table">
                <thead>
                    <tr>
                        <th>لینک اشتراک Sing-box از طریق پروکسی:</th>
                        <th>کپی لینک</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${psb}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${psb}')">برای کپی لینک کلیک کنید</button></td>
                    </tr>
                </tbody>
            </table>
            <br>
            <br>
        </div>
    </div>
</div>
<div class="footer-message">
    برو حالشو ببر 😉
</div>
</body>
`;
}
}
