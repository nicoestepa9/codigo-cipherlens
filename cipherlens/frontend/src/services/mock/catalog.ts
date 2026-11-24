export interface IssuerDef {
  cn: string;
  o: string;
  c: string;
}

export const ISSUERS: IssuerDef[] = [
  { cn: "DigiCert Global CA G2", o: "DigiCert Inc", c: "US" },
  { cn: "Let's Encrypt Authority X3", o: "Let's Encrypt", c: "US" },
  { cn: "Google Trust Services WE1", o: "Google Trust Services LLC", c: "US" },
  { cn: "GlobalSign Organization Validation CA - G2", o: "GlobalSign nv-sa", c: "BE" },
  { cn: "Sectigo RSA Domain Validation Secure Server CA", o: "Sectigo Limited", c: "GB" },
  { cn: "Amazon RSA 2048 M02", o: "Amazon", c: "US" },
  { cn: "Microsoft RSA TLS CA 02", o: "Microsoft Corporation", c: "US" },
  { cn: "QuoVadis Root CA 3 G3", o: "QuoVadis Limited", c: "BM" },
];

export const INTERNAL_DOMAINS = [
  "api.internal.company.com",
  "app.internal.company.com",
  "admin.internal.company.com",
  "db-primary.internal.company.com",
  "db-replica.internal.company.com",
  "git.internal.company.com",
  "ci.internal.company.com",
  "registry.internal.company.com",
  "auth.internal.company.com",
  "mail.internal.company.com",
  "wiki.internal.company.com",
  "monitoring.internal.company.com",
  "kafka-broker-01.internal.company.com",
  "kafka-broker-02.internal.company.com",
  "elasticsearch.internal.company.com",
  "vault.internal.company.com",
  "jenkins.internal.company.com",
  "nexus.internal.company.com",
  "grafana.internal.company.com",
  "prometheus.internal.company.com",
  "storage-01.internal.company.com",
  "storage-02.internal.company.com",
  "erp.internal.company.com",
  "crm.internal.company.com",
  "billing.internal.company.com",
  "payments.internal.company.com",
  "identity.internal.company.com",
  "proxy-eu.internal.company.com",
  "proxy-us.internal.company.com",
  "chat.internal.company.com",
];

export const EXTERNAL_DOMAINS = [
  "www.company.com",
  "company.com",
  "shop.company.com",
  "api.company.com",
  "payments.company.com",
  "portal.company.com",
  "login.company.com",
  "cdn.company.com",
  "status.company.com",
  "blog.company.com",
  "support.company.com",
  "docs.company.com",
  "corporate.company.com",
  "careers.company.com",
  "investor.company.com",
  "m.company.com",
  "mail.company.com",
  "vpn.company.com",
  "partner.company.com",
  "dev.company.com",
];

export const SERVICES = [
  "HTTPS Web Server",
  "API Gateway",
  "Database",
  "Message Broker",
  "Kubernetes API",
  "Load Balancer",
  "Mail Server",
  "Identity Provider",
  "CI/CD",
  "Container Registry",
  "Monitoring",
  "Storage",
  "ERP",
  "CRM",
  "Payment Gateway",
  "VPN Gateway",
  "Reverse Proxy",
  "Search Engine",
  "Authentication Service",
  "Object Storage",
];

export const KEY_TYPES = [
  { keyType: "RSA", keySize: 2048, alg: "sha256WithRSAEncryption" },
  { keyType: "RSA", keySize: 4096, alg: "sha384WithRSAEncryption" },
  { keyType: "EC (secp256r1)", keySize: 256, alg: "ecdsa-with-SHA256" },
  { keyType: "EC (secp384r1)", keySize: 384, alg: "ecdsa-with-SHA384" },
];

export const TLS_CONFIGS = [
  {
    protocol: "TLS 1.3",
    cipher: "TLS_AES_256_GCM_SHA384",
    keyExchange: "X25519",
    signature: "RSA-PSS-SHA256",
    status: "secure",
  },
  {
    protocol: "TLS 1.2",
    cipher: "ECDHE-RSA-AES256-GCM-SHA384",
    keyExchange: "ECDHE",
    signature: "RSA-PSS-SHA256",
    status: "secure",
  },
  {
    protocol: "TLS 1.2",
    cipher: "ECDHE-RSA-AES128-GCM-SHA256",
    keyExchange: "ECDHE",
    signature: "SHA256-RSA",
    status: "secure",
  },
  {
    protocol: "TLS 1.2",
    cipher: "ECDHE-RSA-AES128-SHA256",
    keyExchange: "ECDHE",
    signature: "SHA256-RSA",
    status: "warning",
  },
  {
    protocol: "TLS 1.1",
    cipher: "ECDHE-RSA-AES256-CBC-SHA",
    keyExchange: "ECDHE",
    signature: "SHA1-RSA",
    status: "critical",
  },
  {
    protocol: "TLS 1.0",
    cipher: "TLS_RSA_WITH_AES_128_CBC_SHA",
    keyExchange: "RSA",
    signature: "SHA1-RSA",
    status: "critical",
  },
  {
    protocol: "TLS 1.2",
    cipher: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    keyExchange: "RSA",
    signature: "SHA1-RSA",
    status: "critical",
  },
];

export const OS_FINGERPRINTS = [
  "Linux (Ubuntu 22.04) — nginx/1.24",
  "Linux (Debian 12) — Apache/2.4.57",
  "Linux (RHEL 9) — haproxy",
  "Linux (Alpine 3.19) — CloudFront",
  "FreeBSD 13 — OpenSSH_9.3",
  "Linux (Amazon Linux 2) — nginx/1.22",
  "Windows Server 2022 — IIS 10.0",
  "Windows Server 2019 — IIS 10.0",
  "Linux (CentOS 7) — Apache/2.4.6",
  "Ubuntu 20.04 — Node.js (Express)",
];

export const DEPARTMENTS = ["Engineering", "IT Security", "Platform", "Fintech", "DevOps", "Data"];

export const OWNERS = [
  "M. Fernández",
  "L. Rodríguez",
  "A. Gómez",
  "S. Pérez",
  "D. Martínez",
  "C. López",
  "R. Sánchez",
  "J. Torres",
  "K. Ramírez",
  "P. Díaz",
];
