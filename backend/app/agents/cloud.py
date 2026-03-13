"""
Recon Sentinel — Cloud Asset Discovery Agent
Sources: DNS CNAME analysis, S3 bucket brute, Azure/GCP storage checks, cloud IP range matching
MITRE: T1580 (Cloud Infrastructure Discovery), T1530 (Data from Cloud Storage Object)

Discovers:
  - S3 buckets (name patterns from target domain + common prefixes)
  - Azure Blob Storage containers
  - GCP Storage buckets
  - Cloud services identified via CNAME records (Heroku, Netlify, etc.)
  - Dangling cloud resources (subdomain takeover candidates)
"""

import asyncio
import hashlib
import logging

import httpx

from app.agents.base import BaseAgent
from app.core.celery_app import celery_app
from app.core.database import AsyncSessionLocal
from app.models.enums import FindingSeverity, FindingType, ScanPhase
from app.models.models import Finding

logger = logging.getLogger(__name__)

# Cloud service fingerprints in CNAME records
CLOUD_CNAME_SIGNATURES = {
    ".s3.amazonaws.com": "AWS S3",
    ".s3-website": "AWS S3 Website",
    ".cloudfront.net": "AWS CloudFront",
    ".elasticbeanstalk.com": "AWS Elastic Beanstalk",
    ".elb.amazonaws.com": "AWS ELB",
    ".amazonaws.com": "AWS (generic)",
    ".blob.core.windows.net": "Azure Blob Storage",
    ".azurewebsites.net": "Azure App Service",
    ".azureedge.net": "Azure CDN",
    ".cloudapp.azure.com": "Azure VM",
    ".trafficmanager.net": "Azure Traffic Manager",
    ".storage.googleapis.com": "GCP Storage",
    ".appspot.com": "GCP App Engine",
    ".cloudfunctions.net": "GCP Cloud Functions",
    ".run.app": "GCP Cloud Run",
    ".firebaseapp.com": "Firebase",
    ".herokuapp.com": "Heroku",
    ".netlify.app": "Netlify",
    ".vercel.app": "Vercel",
    ".pages.dev": "Cloudflare Pages",
    ".workers.dev": "Cloudflare Workers",
    ".fly.dev": "Fly.io",
    ".render.com": "Render",
    ".railway.app": "Railway",
}

# Common bucket name patterns
BUCKET_PREFIXES = [
    "", "www-", "assets-", "static-", "media-", "backup-", "backups-",
    "data-", "dev-", "staging-", "prod-", "test-", "logs-", "uploads-",
    "cdn-", "img-", "images-", "files-", "docs-", "internal-", "private-",
]

BUCKET_SUFFIXES = [
    "", "-assets", "-static", "-media", "-backup", "-backups",
    "-data", "-dev", "-staging", "-prod", "-test", "-logs", "-uploads",
    "-cdn", "-public", "-private", "-internal", "-web", "-app",
]


class CloudAssetAgent(BaseAgent):
    agent_type = "cloud"
    agent_name = "Cloud Asset Discovery Agent"
    phase = ScanPhase.ACTIVE
    mitre_tags = ["T1580", "T1530"]

    async def execute(self) -> list[dict]:
        domain = self.target_value
        findings = []

        # ─── Phase 1: CNAME cloud fingerprinting ─────────────
        await self.report_progress(10, "Checking DNS CNAMEs for cloud services...")
        cname_findings = await self._check_cnames_for_cloud(domain)
        findings.extend(cname_findings)

        # ─── Phase 2: S3 bucket enumeration ───────────────────
        await self.report_progress(30, "Enumerating S3 buckets...")
        s3_findings = await self._enumerate_s3(domain)
        findings.extend(s3_findings)

        # ─── Phase 3: Azure blob checks ───────────────────────
        await self.report_progress(60, "Checking Azure Blob Storage...")
        azure_findings = await self._check_azure_blobs(domain)
        findings.extend(azure_findings)

        # ─── Phase 4: GCP storage checks ─────────────────────
        await self.report_progress(80, "Checking GCP Storage...")
        gcp_findings = await self._check_gcp_storage(domain)
        findings.extend(gcp_findings)

        return findings

    # ─── CNAME Cloud Detection ────────────────────────────────

    async def _check_cnames_for_cloud(self, domain: str) -> list[dict]:
        """Check discovered subdomains for cloud CNAMEs."""
        findings = []

        # Get subdomains from earlier phase
        import uuid
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            result = await db.execute(
                select(Finding.value)
                .where(Finding.scan_id == uuid.UUID(self.scan_id))
                .where(Finding.finding_type == FindingType.SUBDOMAIN)
            )
            subdomains = [r[0] for r in result.all()]

        # Add the base domain
        subdomains = list(set(subdomains + [domain]))

        for sub in subdomains[:50]:  # Cap to avoid excessive DNS lookups
            cname = await self._get_cname(sub)
            if not cname:
                continue

            for signature, service in CLOUD_CNAME_SIGNATURES.items():
                if signature in cname.lower():
                    severity = FindingSeverity.INFO
                    tags = ["cloud_service"]

                    # Check for potential takeover (NXDOMAIN on cloud CNAME)
                    is_dangling = await self._check_dangling(cname)
                    if is_dangling:
                        severity = FindingSeverity.HIGH
                        tags.append("potential_takeover")

                    findings.append({
                        "finding_type": FindingType.CLOUD_ASSET,
                        "severity": severity,
                        "value": f"{sub} → {service}",
                        "detail": (
                            f"CNAME points to {service}: {cname}."
                            + (" DANGLING — potential subdomain takeover!" if is_dangling else "")
                        ),
                        "mitre_technique_ids": ["T1580"] + (["T1584"] if is_dangling else []),
                        "fingerprint": hashlib.sha256(f"cloud:{sub}:{cname}".encode()).hexdigest()[:32],
                        "tags": tags,
                        "raw_data": {
                            "subdomain": sub,
                            "cname": cname,
                            "cloud_service": service,
                            "is_dangling": is_dangling,
                        },
                    })
                    break

        return findings

    # ─── S3 Bucket Enumeration ────────────────────────────────

    async def _enumerate_s3(self, domain: str) -> list[dict]:
        """Brute-force S3 bucket names based on domain patterns."""
        findings = []
        base = domain.replace(".", "-").split(".")[0] if "." in domain else domain

        bucket_names = set()
        for prefix in BUCKET_PREFIXES:
            for suffix in BUCKET_SUFFIXES:
                name = f"{prefix}{base}{suffix}".strip("-")
                if name and len(name) >= 3:
                    bucket_names.add(name)

        # Check buckets concurrently (limit to 20 at a time)
        sem = asyncio.Semaphore(20)

        async def check_bucket(name: str) -> dict | None:
            async with sem:
                return await self._check_s3_bucket(name)

        tasks = [check_bucket(name) for name in sorted(bucket_names)[:100]]  # Cap at 100
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, dict) and r:
                findings.append(r)

        return findings

    async def _check_s3_bucket(self, bucket_name: str) -> dict | None:
        """Check if an S3 bucket exists and its permissions."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                # Check via HTTP
                url = f"https://{bucket_name}.s3.amazonaws.com"
                resp = await client.get(url)

                if resp.status_code == 200:
                    # Public bucket — listable
                    return {
                        "finding_type": FindingType.CLOUD_ASSET,
                        "severity": FindingSeverity.CRITICAL,
                        "value": f"s3://{bucket_name} (PUBLIC — listable)",
                        "detail": f"S3 bucket '{bucket_name}' is publicly listable. This may expose sensitive data.",
                        "mitre_technique_ids": ["T1530"],
                        "fingerprint": hashlib.sha256(f"s3:{bucket_name}".encode()).hexdigest()[:32],
                        "tags": ["s3_public", "data_exposure"],
                        "raw_data": {"bucket": bucket_name, "status": resp.status_code, "public": True},
                    }
                elif resp.status_code == 403:
                    # Exists but not public
                    return {
                        "finding_type": FindingType.CLOUD_ASSET,
                        "severity": FindingSeverity.INFO,
                        "value": f"s3://{bucket_name} (exists, private)",
                        "detail": f"S3 bucket '{bucket_name}' exists but is not publicly accessible.",
                        "mitre_technique_ids": ["T1580"],
                        "fingerprint": hashlib.sha256(f"s3:{bucket_name}".encode()).hexdigest()[:32],
                        "tags": ["s3_private"],
                        "raw_data": {"bucket": bucket_name, "status": 403, "public": False},
                    }
                # 404 = doesn't exist, skip
        except Exception:
            pass
        return None

    # ─── Azure Blob Storage ───────────────────────────────────

    async def _check_azure_blobs(self, domain: str) -> list[dict]:
        """Check Azure Blob Storage containers."""
        findings = []
        base = domain.replace(".", "").split(".")[0] if "." in domain else domain

        storage_accounts = [base, f"{base}storage", f"{base}data", f"{base}assets"]

        for account in storage_accounts:
            try:
                async with httpx.AsyncClient(timeout=5) as client:
                    url = f"https://{account}.blob.core.windows.net/?comp=list"
                    resp = await client.get(url)

                    if resp.status_code == 200 and "EnumerationResults" in resp.text:
                        findings.append({
                            "finding_type": FindingType.CLOUD_ASSET,
                            "severity": FindingSeverity.HIGH,
                            "value": f"Azure: {account}.blob.core.windows.net (public listing)",
                            "detail": f"Azure storage account '{account}' allows public container listing.",
                            "mitre_technique_ids": ["T1530"],
                            "fingerprint": hashlib.sha256(f"azure:{account}".encode()).hexdigest()[:32],
                            "tags": ["azure_public", "data_exposure"],
                            "raw_data": {"account": account, "status": resp.status_code},
                        })
                    elif resp.status_code != 404:
                        findings.append({
                            "finding_type": FindingType.CLOUD_ASSET,
                            "severity": FindingSeverity.INFO,
                            "value": f"Azure: {account}.blob.core.windows.net (exists)",
                            "detail": f"Azure storage account '{account}' exists.",
                            "mitre_technique_ids": ["T1580"],
                            "fingerprint": hashlib.sha256(f"azure:{account}".encode()).hexdigest()[:32],
                            "tags": ["azure_storage"],
                            "raw_data": {"account": account, "status": resp.status_code},
                        })
            except Exception:
                pass

        return findings

    # ─── GCP Storage ──────────────────────────────────────────

    async def _check_gcp_storage(self, domain: str) -> list[dict]:
        """Check GCP Storage buckets."""
        findings = []
        base = domain.replace(".", "-").split(".")[0] if "." in domain else domain

        bucket_names = [base, f"{base}-public", f"{base}-assets", f"{base}-backup"]

        for name in bucket_names:
            try:
                async with httpx.AsyncClient(timeout=5) as client:
                    url = f"https://storage.googleapis.com/{name}"
                    resp = await client.get(url)

                    if resp.status_code == 200:
                        findings.append({
                            "finding_type": FindingType.CLOUD_ASSET,
                            "severity": FindingSeverity.HIGH,
                            "value": f"gs://{name} (PUBLIC)",
                            "detail": f"GCP bucket '{name}' is publicly accessible.",
                            "mitre_technique_ids": ["T1530"],
                            "fingerprint": hashlib.sha256(f"gcp:{name}".encode()).hexdigest()[:32],
                            "tags": ["gcp_public", "data_exposure"],
                            "raw_data": {"bucket": name, "status": resp.status_code},
                        })
            except Exception:
                pass

        return findings

    # ─── DNS Helpers ──────────────────────────────────────────

    async def _get_cname(self, hostname: str) -> str | None:
        try:
            result = await self.run_command(["dig", "+short", hostname, "CNAME"], timeout=5, silent=True)
            if result["returncode"] == 0 and result["stdout"].strip():
                return result["stdout"].strip().rstrip(".")
        except Exception:
            pass
        return None

    async def _check_dangling(self, cname: str) -> bool:
        """Check if a CNAME target is dangling (NXDOMAIN)."""
        try:
            result = await self.run_command(["dig", "+short", cname, "A"], timeout=5, silent=True)
            return result["returncode"] == 0 and not result["stdout"].strip()
        except Exception:
            return False


@celery_app.task(name="app.agents.cloud.run_cloud_agent", bind=True)
def run_cloud_agent(self, scan_id: str, target_value: str, project_id: str, config: dict | None = None):
    import asyncio
    return asyncio.run(CloudAssetAgent(scan_id, target_value, project_id, config).run())
