//nat64\u81ea\u52a8\u586b\u5145proxyip\uff0c\u65e0\u9700\u4e14\u4e0d\u652f\u6301proxyip\u8bbe\u7f6e
// nat64 auto-fills proxyip, no proxyip setting needed or supported.
import { connect } from "cloudflare:sockets";
const WS_READY_STATE_OPEN = 1;
let userID = "86c50e3a-5b87-49dd-bd20-03c7f2735e40";
const cn_hostnames = [''];
let CDNIP = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0073\u0067'
// http_ip
let IP1 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP2 = '\u0063\u0069\u0073\u002e\u0076\u0069\u0073\u0061\\u002e\\u0063\\u006f\\u006d'
// ws_ip
let IP3 = '\u0077\u0077\u0077\\u002e\\u0076\\u0069\\u0073\\u0061\\u002e\\u0063\\u006f\\u006d\\u002e\\u0073\\u0067'
let IP4 = '\u0063\\u0069\\u0073\\u002e\\u0076\\u0069\\u0073\\u0061\\u002e\\u0063\\u006f\\u006d'

let VLESS_TCP_PORT = 443;
let VLESS_WS_PORT = 8443;
let current_proxy_ip = CDNIP;
if (cn_hostnames.includes(CDNIP)) {
    current_proxy_ip = IP2;
}
let current_proxy_ws_ip = IP3;
if (cn_hostnames.includes(IP3)) {
    current_proxy_ws_ip = IP4;
}

const vless_id_url = (uuid, host, port, path, security, type, flow) => {
    let url = `${type}://${uuid}@${host}:${port}?encryption=none&security=${security}&type=${type}&host=${host}&path=${path}`;
    if (flow) {
        url += `&flow=${flow}`;
    }
    return url;
};

const sub_links_generate = (userID, hostName, VLESS_TCP_PORT, VLESS_WS_PORT) => {
    const vless_ws = `vless://${userID}@${hostName}:${VLESS_WS_PORT}?encryption=none&security=tls&type=ws&host=${hostName}&path=/vless?ed=2048#CDN-%E2%9C%A8VLESS-WS`;
    const vless_tcp = `vless://${userID}@${hostName}:${VLESS_TCP_PORT}?encryption=none&security=tls&type=tcp&host=${hostName}&flow=xtls-rprx-vision#CDN-%E2%9C%A8VLESS-TCP`;
    const vless_grpc = `vless://${userID}@${hostName}:${VLESS_TCP_PORT}?encryption=none&security=tls&type=grpc&host=${hostName}&serviceName=vless-grpc#CDN-%E2%9C%A8VLESS-GRPC`;
    const vless_ws_proxy = `vless://${userID}@${current_proxy_ws_ip}:${VLESS_WS_PORT}?encryption=none&security=tls&type=ws&host=${hostName}&path=/vless?ed=2048#PROX-VLESS-WS`;
    const vless_tcp_proxy = `vless://${userID}@${current_proxy_ip}:${VLESS_TCP_PORT}?encryption=none&security=tls&type=tcp&host=${hostName}&flow=xtls-rprx-vision#PROX-VLESS-TCP`;
    const vless_grpc_proxy = `vless://${userID}@${current_proxy_ip}:${VLESS_TCP_PORT}?encryption=none&security=tls&type=grpc&host=${hostName}&serviceName=vless-grpc#PROX-VLESS-GRPC`;
    return { vless_ws, vless_tcp, vless_grpc, vless_ws_proxy, vless_tcp_proxy, vless_grpc_proxy };
};

const subscription_link = (userID, hostName, VLESS_TCP_PORT, VLESS_WS_PORT) => {
    const { vless_ws, vless_tcp, vless_grpc, vless_ws_proxy, vless_tcp_proxy, vless_grpc_proxy } = sub_links_generate(userID, hostName, VLESS_TCP_PORT, VLESS_WS_PORT);

    const subscription = btoa([vless_ws, vless_tcp, vless_grpc, vless_ws_proxy, vless_tcp_proxy, vless_grpc_proxy].join('\n'));
    const subscription_proxy = btoa([vless_ws_proxy, vless_tcp_proxy, vless_grpc_proxy].join('\n'));

    return { subscription, subscription_proxy };
};

addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
    const url = new URL(request.url);

    if (url.pathname === '/sub') {
        const { subscription } = subscription_link(userID, url.hostname, VLESS_TCP_PORT, VLESS_WS_PORT);
        return new Response(subscription, { headers: { 'Content-Type': 'text/plain;charset=utf-8' } });
    }
    if (url.pathname === '/sub_proxy') {
        const { subscription_proxy } = subscription_link(userID, url.hostname, VLESS_TCP_PORT, VLESS_WS_PORT);
        return new Response(subscription_proxy, { headers: { 'Content-Type': 'text/plain;charset=utf-8' } });
    }

    if (url.pathname === '/') {
        const html = getvlessConfig(userID, url.hostname);
        return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
    }

    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
        return new Response('Expected Upgrade: websocket', { status: 426 });
    }

    const clientIP = request.headers.get('CF-Connecting-IP');
    let targetHost = CDNIP;
    if (cn_hostnames.includes(url.hostname)) {
        targetHost = IP1;
    }

    const webSocketPair = new WebSocketPair();
    const [client, worker] = Object.values(webSocketPair);

    worker.addEventListener('message', async event => {
        const vlessConfig = JSON.parse(event.data);
        const address = vlessConfig.address || targetHost;
        const port = vlessConfig.port || 443;
        const rawSocket = await connect(`${address}:${port}`, { security: 'tls' });
        const vless = new VlessWebsocket(rawSocket, userID);

        worker.addEventListener('message', event => {
            try {
                vless.handleMessage(event.data);
            } catch (err) {
                console.error('Error handling message from client:', err);
                worker.close(1011, err.message);
            }
        });

        worker.addEventListener('close', event => {
            vless.close();
            console.log('Client WebSocket closed:', event.code, event.reason);
        });

        vless.onClose = (code, reason) => {
            worker.close(code, reason);
        };

        vless.onError = err => {
            worker.close(1011, err.message);
        };

        vless.start();
    });

    worker.accept();
    return new Response(null, { status: 101, webSocket: client });
}

class VlessWebsocket {
    constructor(socket, uuid) {
        this.socket = socket;
        this.uuid = uuid;
        this.onClose = null;
        this.onError = null;
        this.closed = false;
        this.remoteSocketClosed = false;
        this.onMessage = null;
    }

    start() {
        this.socket.readable.pipeTo(new WritableStream({
            write: chunk => {
                if (this.onMessage) {
                    this.onMessage(chunk);
                }
            },
            close: () => {
                this.remoteSocketClosed = true;
                if (!this.closed && this.onClose) {
                    this.onClose(1000, 'Remote socket closed');
                }
            },
            abort: err => {
                if (this.onError) {
                    this.onError(err);
                }
                if (!this.closed && this.onClose) {
                    this.onClose(1011, err.message);
                }
            }
        }));
    }

    handleMessage(data) {
        if (this.closed) return;

        if (typeof data === 'string') {
            const vlessRequest = JSON.parse(data);
            if (vlessRequest.uuid !== this.uuid) {
                this.onError(new Error('Invalid UUID'));
                return;
            }
            // Further handle VLESS protocol handshake
        } else {
            this.socket.writable.write(data).catch(err => {
                if (this.onError) {
                    this.onError(err);
                }
            });
        }
    }

    close(code, reason) {
        if (this.closed) return;
        this.closed = true;
        this.socket.close();
        if (this.onClose) {
            this.onClose(code, reason);
        }
    }
}

function getvlessConfig(userID, hostName) {
  const note = `
<div class="note">
    <h3>
        <p dir="rtl">نکته مهم: برای استفاده از این کانفیگ ها در اپلیکیشن ها، لطفا حتماً موارد زیر را رعایت کنید:</p>
    </h3>
    <ul dir="rtl">
        <li>مطمئن شوید که برنامه شما (مثلاً V2RayNG، Streisand، NekoBox و غیره) به روز است.</li>
        <li>از آخرین نسخه برنامه استفاده کنید تا از سازگاری کامل با پروتکل VLESS اطمینان حاصل شود.</li>
        <li>در برخی برنامه‌ها، ممکن است نیاز به فعال‌سازی گزینه XTLS یا Vision باشد.</li>
        <li>برای لینک‌های پروکسی، مطمئن شوید که پروکسی داخلی برنامه به درستی تنظیم شده باشد.</li>
        <li>در صورت بروز مشکل، کش برنامه را پاک کرده و دوباره امتحان کنید.</li>
        <li>همچنین می‌توانید از ابزارهای تست پینگ داخل برنامه برای بررسی اتصال استفاده کنید.</li>
    </ul>
    <h3><p dir="rtl">ممنون از توجه شما!</p></h3>
</div>
    `;

    const { vless_ws, vless_tcp, vless_grpc, vless_ws_proxy, vless_tcp_proxy, vless_grpc_proxy } = sub_links_generate(userID, hostName, VLESS_TCP_PORT, VLESS_WS_PORT);
    const { subscription, subscription_proxy } = subscription_link(userID, hostName, VLESS_TCP_PORT, VLESS_WS_PORT);

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
    text-align: center;
    margin: 30px auto;
    padding: 15px 25px;
    border: 5px solid;
    border-image: linear-gradient(to right, #4CAF50, #2196F3) 1;
    border-radius: 12px;
    width: fit-content;
    max-width: 90%;
    animation: blink-border 4s infinite linear;
    box-shadow: 0 0 15px rgba(138, 255, 138, 0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    background-color: #3b3b5b; /* این رنگ را اینجا حفظ کنید */
    margin-top: 15px;
    margin-bottom: 25px;
}
.panel-68-emoji {
    font-size: 5em;
    line-height: 1;
    font-family: "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji", sans-serif;
    /* خط زیر را برای دیده شدن متن روی پس‌زمینه سفید تغییر می‌دهیم */
    color: #333333; /* رنگ خاکستری تیره */
    display: block;
    width: 100%;
    overflow-wrap: break-word;
    word-break: break-all;
}

/* Common styling for table and links */
.table {
    width: 100%;
    margin-top: 20px;
    border-collapse: collapse;
    color: #e6e6fa; /* Lavender blush for table text */
}
.table th, .table td {
    padding: 12px 15px;
    border: 1px solid #5a5a8a; /* Subtle border for table cells */
    text-align: left;
}
.table th {
    background-color: #3a3a5a; /* Slightly lighter dark blue for table headers */
    color: #8aff8a; /* Bright green for table headers */
    font-weight: bold;
}
.table td {
    background-color: #2f2f4f; /* Darker background for table data */
    word-break: break-all; /* Ensure long links wrap */
}
.btn-primary {
    background-color: #007bff;
    border-color: #007bff;
    transition: all 0.3s ease;
}
.btn-primary:hover {
    background-color: #0056b3;
    border-color: #004085;
    transform: translateY(-2px);
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
}
.copy-btn {
    display: block;
    width: 100%;
    text-align: center;
}
.limited-width {
    max-width: 250px; /* Adjust as needed */
    overflow-wrap: break-word;
    word-break: break-all;
}

/* Custom styling for the note */
.note {
    background-color: #3a3a5a; /* Darker slate blue */
    border-left: 5px solid #8aff8a; /* Bright green border */
    padding: 15px;
    margin-top: 20px;
    margin-bottom: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.4);
}
.note h3 {
    color: #8aff8a; /* Bright green for note headings */
    margin-top: 0;
    margin-bottom: 10px;
    font-size: 1.4em;
}
.note ul {
    list-style: none; /* Remove default bullet points */
    padding-left: 0; /* Remove default padding */
}
.note ul li {
    margin-bottom: 8px;
    position: relative;
    padding-left: 25px; /* Space for custom bullet */
}
.note ul li::before {
    content: "•"; /* Custom bullet point */
    color: #8aff8a; /* Green bullet point */
    font-weight: bold;
    display: inline-block;
    width: 1em;
    margin-left: -1em;
    position: absolute;
    left: 0;
}
.footer-message {
    text-align: center;
    color: #8aff8a; /* Bright green for footer message */
    font-size: 1.2em;
    margin-top: 30px;
    margin-bottom: 20px;
    font-weight: bold;
}

/* Responsive adjustments */
@media (max-width: 768px) {
    .container {
        padding: 15px;
    }
    .table th, .table td {
        padding: 8px 10px;
        font-size: 0.9em;
    }
    .panel-68-emoji {
        font-size: 3em; /* Smaller emoji on smaller screens */
    }
}
@media (max-width: 480px) {
    .container {
        padding: 10px;
    }
    .table th, .table td {
        font-size: 0.8em;
    }
    .panel-68-container {
        padding: 10px 15px;
    }
}
</style>
</head>
<body>
<div class="container">
    <h1>
        <p dir="rtl">
            خوش آمدید! در اینجا می‌توانید لینک‌های کانفیگ VLESS خود را مشاهده و کپی کنید.
        </p>
    </h1>
    <hr>
    <h3><p dir="rtl">لینک‌های سابسکریپشن:</p></h3>
    <table class="table">
        <thead>
            <tr>
                <th>لینک سابسکریپشن از طریق CDN:</th>
                <th>کپی لینک</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td class="limited-width">${subscription}</td>
                <td><button class="btn btn-primary" onclick="copyToClipboard('${subscription}')">برای کپی لینک کلیک کنید</button></td>
            </tr>
        </tbody>
    </table>
    <table class="table">
        <thead>
            <tr>
                <th>لینک سابسکریپشن از طریق پروکسی:</th>
                <th>کپی لینک</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td class="limited-width">${subscription_proxy}</td>
                <td><button class="btn btn-primary" onclick="copyToClipboard('${subscription_proxy}')">برای کپی لینک کلیک کنید</button></td>
            </tr>
        </tbody>
    </table>
    <hr>
    <h3><p dir="rtl">کانفیگ‌های VLESS مستقیم:</p></h3>
    <table class="table">
        <thead>
            <tr>
                <th>کانفیگ VLESS-WS از طریق CDN:</th>
                <th>کپی لینک</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td class="limited-width">${vless_ws}</td>
                <td><button class="btn btn-primary" onclick="copyToClipboard('${vless_ws}')">برای کپی لینک کلیک کنید</button></td>
            </tr>
        </tbody>
    </table>
    <table class="table">
        <thead>
            <tr>
                <th>کانفیگ VLESS-TCP از طریق CDN:</th>
                <th>کپی لینک</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td class="limited-width">${vless_tcp}</td>
                <td><button class="btn btn-primary" onclick="copyToClipboard('${vless_tcp}')">برای کپی لینک کلیک کنید</button></td>
            </tr>
        </tbody>
    </table>
    <table class="table">
        <thead>
            <tr>
                <th>کانفیگ VLESS-GRPC از طریق CDN:</th>
                <th>کپی لینک</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td class="limited-width">${vless_grpc}</td>
                <td><button class="btn btn-primary" onclick="copyToClipboard('${vless_grpc}')">برای کپی لینک کلیک کنید</button></td>
            </tr>
        </tbody>
    </table>
    <hr>
    <h3><p dir="rtl">کانفیگ‌های VLESS از طریق پروکسی:</p></h3>
    <table class="table">
        <thead>
            <tr>
                <th>کانفیگ VLESS-WS از طریق پروکسی:</th>
                <th>کپی لینک</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td class="limited-width">${vless_ws_proxy}</td>
                <td><button class="btn btn-primary" onclick="copyToClipboard('${vless_ws_proxy}')">برای کپی لینک کلیک کنید</button></td>
            </tr>
        </tbody>
    </table>
    <table class="table">
        <thead>
            <tr>
                <th>کانفیگ VLESS-TCP از طریق پروکسی:</th>
                <th>کپی لینک</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td class="limited-width">${vless_tcp_proxy}</td>
                <td><button class="btn btn-primary" onclick="copyToClipboard('${vless_tcp_proxy}')">برای کپی لینک کلیک کنید</button></td>
            </tr>
        </tbody>
    </table>
    <table class="table">
        <thead>
            <tr>
                <th>کانفیگ VLESS-GRPC از طریق پروکسی:</th>
                <th>کپی لینک</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td class="limited-width">${vless_grpc_proxy}</td>
                <td><button class="btn btn-primary" onclick="copyToClipboard('${vless_grpc_proxy}')">برای کپی لینک کلیک کنید</button></td>
            </tr>
        </tbody>
    </table>
    <hr>
    <div class="panel-68-container">
        <span class="panel-68-emoji">💪6️⃣8️⃣</span>
    </div>
    <div class="note-container">
        <div class="note">
            <h3><p dir="rtl">نکات مهم:</p></h3>
            <p dir="rtl">
                <ul>
                    <li>${noteshow}</li>
                </ul>
            </p>
            <br>
        </div>
        <div class="table-responsive">
            <table class="table">
                <thead>
                    <tr>
                        <th>لینک اشتراک V2rayNG از طریق پروکسی:</th>
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
    return displayHtml;
}
