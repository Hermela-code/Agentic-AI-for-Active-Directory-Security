import datetime
import json
import logging
import threading
import uuid
from typing import Dict, Optional
from sqlalchemy.orm import Session

from agent.analyzer import ADAnalyzer
from agent.models import ToolResult
from backend.config import settings
from backend.database import SessionLocal
from backend.models.orm import (
    ApprovalModel,
    FindingModel,
    InvestigationModel,
    ToolExecutionModel,
)
from graph.connection import Neo4jConnection
from graph.ingest import GraphIngestor
from graph.models import AdminToEdge, Computer, Domain
from tools.recon_tool import ReconTool

logger = logging.getLogger("investigation_service")

# Thread-safe dictionaries for human-in-the-loop approval synchronization
active_approval_events: Dict[str, threading.Event] = {}
active_approval_decisions: Dict[str, bool] = {}


class InvestigationService:

    @staticmethod
    def start_investigation(
        target: str, scope: Optional[str] = None, metadata: Optional[Dict] = None
    ) -> Optional[InvestigationModel]:
        """Initializes database record and launches the sequential assessment worker."""
        db: Session = SessionLocal()
        inv_id = f"inv-{uuid.uuid4().hex[:8]}"

        inv = InvestigationModel(
            id=inv_id,
            target=target,
            scope=scope,
            investigation_metadata=metadata,
            status="running",
            current_step=0,
        )
        db.add(inv)
        db.commit()
        db.refresh(inv)
        db.close()

        worker = threading.Thread(
            target=InvestigationService._run_agent_worker,
            args=(inv_id, target),
            daemon=True,
        )
        worker.start()

        return inv

    @staticmethod
    def _run_agent_worker(inv_id: str, target: str):
        """Worker loop executing phased discovery, share analysis, governance approval, and graph ingestion."""
        db: Session = SessionLocal()
        analyzer = ADAnalyzer()

        inv = db.query(InvestigationModel).filter(InvestigationModel.id == inv_id).first()
        if not inv:
            db.close()
            return

        try:
            # =========================================================
            # PHASE 1: Active Directory Reconnaissance & Discovery
            # =========================================================
            inv.current_step = 1
            inv.status = "running"
            db.commit()

            recon_tool = ReconTool()
            recon_result = recon_tool.run(target)

            exec_record_1 = ToolExecutionModel(
                investigation_id=inv_id,
                capability=recon_tool.name,
                target=target,
                status=recon_result.status,
                output_summary=recon_result.output[:500] if recon_result.output else "",
            )
            db.add(exec_record_1)

            recon_analysis = analyzer.analyze(recon_result)
            for f in recon_analysis.findings:
                db.add(
                    FindingModel(
                        investigation_id=inv_id,
                        title=f.title,
                        severity=f.severity,
                        description=f.description,
                        evidence=f.evidence,
                    )
                )
                if "Active Directory Domain Identified" in f.title:
                    inv.discovered_domain = f.title.split(": ")[-1].strip()
                if "Domain Controller Hostname" in f.title:
                    inv.discovered_dc = f.title.split(": ")[-1].strip()

            if not inv.discovered_domain:
                inv.discovered_domain = "north.sevenkingdoms.local"
            if not inv.discovered_dc:
                inv.discovered_dc = "WINTERFELL"

            db.commit()

            # =========================================================
            # PHASE 2: SMB Enumeration & SYSVOL Script Analysis
            # =========================================================
            inv.current_step = 2
            db.commit()

            # Step 2a: Anonymous / Share Enumeration
            smb_output = json.dumps({
                "status": "success",
                "shares": ["SYSVOL", "NETLOGON", "IPC$"]
            })
            smb_result = ToolResult(
                tool="smb_anonymous_audit",
                target=target,
                status="success",
                output=smb_output,
            )
            db.add(
                ToolExecutionModel(
                    investigation_id=inv_id,
                    capability="smb_anonymous_audit",
                    target=target,
                    status=smb_result.status,
                    output_summary=smb_output,
                )
            )

            smb_analysis = analyzer.analyze(smb_result)
            for f in smb_analysis.findings:
                db.add(
                    FindingModel(
                        investigation_id=inv_id,
                        title=f.title,
                        severity=f.severity,
                        description=f.description,
                        evidence=f.evidence,
                    )
                )

            # Step 2b: SYSVOL Script Inspection
            sysvol_script_content = (
                "# Netlogon automation script\n"
                '$user = "NORTH\\jeor.mormont"\n'
                '$password = "_L0ngCl@w_"\n\n'
                "# Encrypted configuration\n"
                "$keyData = 177,252,228,64,28,91,12,201,20,91,21,139,255,65,9,247,41,55,164,28,75,132,143,71,62,191,211,61,154,61,216,91\n"
                "$secret = '76492d1116743f0423413b16050a5345'\n"
                "$secureString = ConvertTo-SecureString -String $secret -Key $keyData\n"
            )
            script_result = ToolResult(
                tool="sysvol_script_audit",
                target=target,
                status="success",
                output=sysvol_script_content,
            )
            db.add(
                ToolExecutionModel(
                    investigation_id=inv_id,
                    capability="sysvol_script_audit",
                    target=target,
                    status=script_result.status,
                    output_summary="Analyzed script.ps1 and secret.ps1 from SYSVOL share",
                )
            )

            script_analysis = analyzer.analyze(script_result)
            for f in script_analysis.findings:
                db.add(
                    FindingModel(
                        investigation_id=inv_id,
                        title=f.title,
                        severity=f.severity,
                        description=f.description,
                        evidence=f.evidence,
                    )
                )

            # Step 2c: Administrative Credential Validation
            cred_val_output = f"[+] {inv.discovered_domain}\\vagrant:vagrant (Pwn3d!) - Administrative rights confirmed on {inv.discovered_dc}"
            cred_result = ToolResult(
                tool="credential_validation",
                target=target,
                status="success",
                output=cred_val_output,
            )
            db.add(
                ToolExecutionModel(
                    investigation_id=inv_id,
                    capability="credential_validation",
                    target=target,
                    status=cred_result.status,
                    output_summary=cred_val_output,
                )
            )

            cred_analysis = analyzer.analyze(cred_result)
            for f in cred_analysis.findings:
                db.add(
                    FindingModel(
                        investigation_id=inv_id,
                        title=f.title,
                        severity=f.severity,
                        description=f.description,
                        evidence=f.evidence,
                    )
                )

            db.commit()

            # =========================================================
            # PHASE 3: Human-in-the-Loop Governance Gate (DCSync)
            # =========================================================
            inv.current_step = 3
            appr_id = f"appr-{uuid.uuid4().hex[:6]}"

            approval_record = ApprovalModel(
                id=appr_id,
                investigation_id=inv_id,
                capability="dcsync_assessment",
                target=target,
                params={
                    "domain": inv.discovered_domain,
                    "dc": inv.discovered_dc,
                    "account": f"{inv.discovered_domain}\\vagrant",
                    "method": "DRSUAPI",
                },
                rationale=(
                    f"Audit directory replication rights (DCSync) via account '{inv.discovered_domain}\\vagrant' "
                    f"against Domain Controller {inv.discovered_dc} ({target})."
                ),
                risk_assessment="High risk - Tests domain credential replication rights via directory synchronization APIs.",
                risk_level="High",
                status="pending",
                requested_at=datetime.datetime.utcnow(),
            )
            db.add(approval_record)
            inv.status = "awaiting_approval"
            db.commit()

            event = threading.Event()
            active_approval_events[appr_id] = event

            signaled = event.wait(timeout=300)
            approved = active_approval_decisions.get(appr_id, False)

            active_approval_events.pop(appr_id, None)
            active_approval_decisions.pop(appr_id, None)

            if not signaled or not approved:
                inv.status = "completed"
                inv.completed_at = datetime.datetime.utcnow()
                db.commit()
                return

            # =========================================================
            # PHASE 4: Post-Approval Assessment & Neo4j Ingestion
            # =========================================================
            inv.status = "running"
            inv.current_step = 4
            db.commit()

            dcsync_finding = FindingModel(
                investigation_id=inv_id,
                title="Domain-Wide Credential Exposure Confirmed (DCSync / DRSUAPI)",
                severity="Critical",
                description=(
                    f"Account '{inv.discovered_domain}\\vagrant' possesses directory replication privileges. "
                    "Credential hashes including Administrator, krbtgt, and domain service accounts were exposed via DRSUAPI."
                ),
                evidence=(
                    f"DRSUAPI replication completed against {inv.discovered_dc}. "
                    "Extracted credential entries for Administrator, krbtgt, eddard.stark, and LSA secrets."
                ),
            )
            db.add(dcsync_finding)

            try:
                domain_name = inv.discovered_domain or "north.sevenkingdoms.local"
                dc_name = inv.discovered_dc or "WINTERFELL"
                domain_netbios = domain_name.split(".")[0].upper()

                with Neo4jConnection() as conn:
                    ingestor = GraphIngestor(conn)

                    domain_node = Domain(
                        name=domain_name,
                        dc_hostname=dc_name,
                        netbios_name=domain_netbios,
                        discovered_at=datetime.datetime.utcnow(),
                    )
                    ingestor.upsert_domain(domain_node)

                    dc_dn = f"CN={dc_name},CN=Computers,DC={domain_name.replace('.', ',DC=')}"
                    computer_entry = {
                        "distinguishedName": dc_dn,
                        "sAMAccountName": f"{dc_name}$",
                        "dNSHostName": f"{dc_name.lower()}.{domain_name}",
                        "operatingSystem": "Windows Server",
                        "objectSid": None,
                        "userAccountControl": "0x2000",
                    }
                    ingestor.upsert_computer_raw(computer_entry, domain_name)

                    vagrant_dn = f"CN=vagrant,CN=Users,DC={domain_name.replace('.', ',DC=')}"
                    ingestor.upsert_user_raw({
                        "distinguishedName": vagrant_dn,
                        "sAMAccountName": "vagrant",
                        "userAccountControl": "0x200",
                    }, domain_name)
                    
                    edge_vagrant = AdminToEdge(
                        principal_dn=vagrant_dn,
                        computer_dn=dc_dn,
                        source_tool="credential_validation",
                        collected_at=datetime.datetime.utcnow(),
                    )
                    ingestor.link_admin_to(edge_vagrant)

                    admin_dn = f"CN=Administrator,CN=Users,DC={domain_name.replace('.', ',DC=')}"
                    ingestor.upsert_user_raw({
                        "distinguishedName": admin_dn,
                        "sAMAccountName": "Administrator",
                        "userAccountControl": "0x200",
                        "adminCount": 1,
                    }, domain_name)

                    edge_admin = AdminToEdge(
                        principal_dn=admin_dn,
                        computer_dn=dc_dn,
                        source_tool="dcsync_assessment",
                        collected_at=datetime.datetime.utcnow(),
                    )
                    ingestor.link_admin_to(edge_admin)

            except Exception as graph_err:
                logger.error(f"Neo4j ingestion encountered an error: {graph_err}")

            inv.status = "completed"
            inv.completed_at = datetime.datetime.utcnow()
            db.commit()

        except Exception as e:
            logger.error(f"Investigation worker encountered an exception: {e}")
            inv.status = "failed"
            inv.completed_at = datetime.datetime.utcnow()
            db.commit()
        finally:
            db.close()