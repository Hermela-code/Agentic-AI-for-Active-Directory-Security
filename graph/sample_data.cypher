// ============================================================
// Sample data — modeled loosely on GOAD-Light
// Run AFTER schema.cypher.
// ============================================================

MERGE (d:Domain {name: 'sevenkingdoms.local'}) SET d.sid = 'S-1-5-21-1111111111';

MERGE (u1:User {samAccountName: 'arya.stark'})
  SET u1.displayName = 'Arya Stark', u1.enabled = true, u1.description = 'Standard user';
MERGE (u2:User {samAccountName: 'sql_svc'})
  SET u2.displayName = 'SQL Service Account', u2.enabled = true,
      u2.description = 'Service account running MSSQL';
MERGE (u3:User {samAccountName: 'ned.stark'})
  SET u3.displayName = 'Ned Stark', u3.enabled = true, u3.description = 'IT admin';

MERGE (g1:Group {sid: 'S-1-5-21-1111111111-512'}) SET g1.name = 'Domain Admins';
MERGE (g2:Group {sid: 'S-1-5-21-1111111111-1001'}) SET g2.name = 'IT Support';

MERGE (c1:Computer {hostname: 'WINTERFELL-DC01'})
  SET c1.os = 'Windows Server 2019', c1.ipAddress = '10.0.0.10';
MERGE (c2:Computer {hostname: 'KINGSLANDING-SQL01'})
  SET c2.os = 'Windows Server 2016', c2.ipAddress = '10.0.0.20';

MERGE (svc1:Service {spn: 'MSSQLSvc/kingslanding-sql01.sevenkingdoms.local:1433'})
  SET svc1.name = 'MSSQL';

// --- relationships ---

MATCH (u1:User {samAccountName: 'arya.stark'}), (d:Domain {name: 'sevenkingdoms.local'})
MERGE (u1)-[:BELONGS_TO]->(d);
MATCH (u2:User {samAccountName: 'sql_svc'}), (d:Domain {name: 'sevenkingdoms.local'})
MERGE (u2)-[:BELONGS_TO]->(d);
MATCH (u3:User {samAccountName: 'ned.stark'}), (d:Domain {name: 'sevenkingdoms.local'})
MERGE (u3)-[:BELONGS_TO]->(d);

MATCH (u3:User {samAccountName: 'ned.stark'}), (g1:Group {name: 'Domain Admins'})
MERGE (u3)-[:MEMBER_OF]->(g1);
MATCH (u1:User {samAccountName: 'arya.stark'}), (g2:Group {name: 'IT Support'})
MERGE (u1)-[:MEMBER_OF]->(g2);

MATCH (u2:User {samAccountName: 'sql_svc'}), (svc1:Service)
MERGE (u2)-[:HAS_SPN]->(svc1);

MATCH (c2:Computer {hostname: 'KINGSLANDING-SQL01'}), (svc1:Service)
MERGE (c2)-[:RUNS_SERVICE]->(svc1);

MATCH (g1:Group {name: 'Domain Admins'}), (c1:Computer {hostname: 'WINTERFELL-DC01'})
MERGE (g1)-[:ADMIN_TO {source: 'bloodhound'}]->(c1);

MATCH (g2:Group {name: 'IT Support'}), (c2:Computer {hostname: 'KINGSLANDING-SQL01'})
MERGE (g2)-[:CAN_ACCESS {type: 'GenericAll'}]->(c2);

MERGE (f1:Finding {id: 'finding-001'})
  SET f1.title = 'Kerberoastable service account: sql_svc',
      f1.severity = 'Medium',
      f1.description = 'Account sql_svc has a registered SPN and can be targeted for Kerberoasting.',
      f1.evidence = 'SPN: MSSQLSvc/kingslanding-sql01.sevenkingdoms.local:1433',
      f1.createdAt = datetime();

MATCH (f1:Finding {id: 'finding-001'}), (u2:User {samAccountName: 'sql_svc'})
MERGE (f1)-[:INVOLVES]->(u2);
