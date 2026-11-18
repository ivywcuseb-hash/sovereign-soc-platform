import * as dns from 'node:dns/promises';
import * as net from 'node:net';
import * as tls from 'node:tls';

function isPrivateOrReservedIp(ip: string): boolean {
  const clean = ip.replace(/^::ffff:/i, '');
  if (!net.isIP(clean)) return true;
  if (clean === '::1' || clean === '::' || clean.startsWith('fe80:') || clean.startsWith('fc') || clean.startsWith('fd')) {
    return true;
  }
  const parts = clean.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false;
  const [a, b] = parts;
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

function parseHostname(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error('يرجى إدخال رابط موقع أو اسم نطاق صالح.');
  let host = trimmed;
  if (/^https?:\/\//i.test(host)) {
    host = new URL(host).hostname;
  } else {
    host = host.split('/')[0].split(':')[0];
  }
  host = host.toLowerCase().replace(/^\.+|\.+$/g, '');
  if (
    !host ||
    host === 'localhost' ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host)
  ) {
    throw new Error('النطاق غير صالح أو محظور أمنياً (SSRF Protection).');
  }
  return host;
}

export default async function handler(req: any, res: any) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  try {
    const bodyObj = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body || {};
    const hostname = parseHostname(String(bodyObj.target || ''));

    const resolved = await dns.lookup(hostname, { all: true });
    const publicIp = resolved.find((r) => !isPrivateOrReservedIp(r.address))?.address;
    if (!publicIp) {
      return res.status(400).json({ error: 'تعذر حل النطاق إلى عنوان IP عام آمن (SSRF Protection).' });
    }

    const sslResult = await new Promise<any>((resolve, reject) => {
      let done = false;
      const finish = (err: Error | null, val?: any) => {
        if (done) return;
        done = true;
        if (err) reject(err);
        else resolve(val);
      };

      const socket = tls.connect(
        {
          host: publicIp,
          port: 443,
          servername: hostname,
          rejectUnauthorized: false,
        },
        () => {
          try {
            const cert = socket.getPeerCertificate(true);
            const protocol = socket.getProtocol() || 'TLS';
            const cipher = socket.getCipher();
            const authorized = socket.authorized;
            const authError = socket.authorizationError ? String(socket.authorizationError) : null;
            socket.end();

            if (!cert || !Object.keys(cert).length) {
              return finish(new Error('لم يُرجع الخادم شهادة SSL/TLS صالحة.'));
            }

            const chain: Array<{
              subjectCN: string;
              issuerCN: string;
              issuerO: string;
              validFrom: string;
              validTo: string;
              fingerprint256: string;
            }> = [];

            let cur: any = cert;
            const seen = new Set<string>();
            while (cur && chain.length < 6) {
              const fp = String(cur.fingerprint256 || cur.serialNumber || chain.length);
              if (seen.has(fp)) break;
              seen.add(fp);
              chain.push({
                subjectCN: String(cur.subject?.CN || cur.subject?.O || hostname),
                issuerCN: String(cur.issuer?.CN || '—'),
                issuerO: String(cur.issuer?.O || '—'),
                validFrom: String(cur.valid_from || ''),
                validTo: String(cur.valid_to || ''),
                fingerprint256: String(cur.fingerprint256 || ''),
              });
              if (!cur.issuerCertificate || cur.issuerCertificate === cur) break;
              cur = cur.issuerCertificate;
            }

            const validToMs = cert.valid_to ? new Date(cert.valid_to).getTime() : NaN;
            const validFromMs = cert.valid_from ? new Date(cert.valid_from).getTime() : NaN;
            const nowMs = Date.now();
            const daysRemaining = Number.isFinite(validToMs)
              ? Math.floor((validToMs - nowMs) / (1000 * 60 * 60 * 24))
              : null;
            const isExpired = Number.isFinite(validToMs) ? validToMs < nowMs : false;
            const isNotYetValid = Number.isFinite(validFromMs) ? validFromMs > nowMs : false;

            const sanList = String(cert.subjectaltname || '')
              .split(',')
              .map((s) => s.trim().replace(/^DNS:/i, ''))
              .filter(Boolean)
              .slice(0, 20);

            const bits = cert.bits ? Number(cert.bits) : null;
            const keyType = cert.asn1Curve ? `ECDSA (${cert.asn1Curve})` : bits ? `RSA ${bits}-bit` : 'Asymmetric Key';

            finish(null, {
              hostname,
              resolvedIp: publicIp,
              authorized,
              authorizationError: authError,
              protocol,
              cipherName: cipher?.name || 'Unknown',
              cipherStandardName: cipher?.standardName || cipher?.name || 'Unknown',
              subjectCN: String(cert.subject?.CN || hostname),
              subjectO: String(cert.subject?.O || '—'),
              issuerCN: String(cert.issuer?.CN || '—'),
              issuerO: String(cert.issuer?.O || '—'),
              issuerC: String(cert.issuer?.C || '—'),
              validFrom: String(cert.valid_from || ''),
              validTo: String(cert.valid_to || ''),
              daysRemaining,
              isExpired,
              isNotYetValid,
              keyBits: bits,
              keyType,
              serialNumber: String(cert.serialNumber || ''),
              fingerprint256: String(cert.fingerprint256 || ''),
              fingerprintSha1: String(cert.fingerprint || ''),
              sanList,
              chain,
              inspectedAt: new Date().toISOString(),
            });
          } catch (err: any) {
            finish(err instanceof Error ? err : new Error('فشل قراءة الشهادة.'));
          }
        }
      );

      socket.setTimeout(5000, () => {
        socket.destroy();
        finish(new Error('انتهت مهلة الاتصال بمنفذ 443 للخادم المستهدف.'));
      });
      socket.on('error', (err) => finish(err));
    });

    return res.status(200).json({ success: true, certificate: sslResult });
  } catch (err: any) {
    return res.status(400).json({ error: err?.message || 'تعذر فحص شهادة SSL/TLS للموقع.' });
  }
}
