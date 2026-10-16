// ============================================================
// Attack-path and finding-detection queries
// Run these ONE AT A TIME in Neo4j Browser (not all at once)
// ============================================================

// 1. Find all Kerberoastable accounts
MATCH (u:User)-[:HAS_SPN]->(s:Service)
RETURN u.samAccountName AS account, s.spn AS spn, s.name AS serviceName;

// 2. Find all users/groups with direct admin rights on a computer
MATCH (principal)-[r:ADMIN_TO]->(c:Computer)
RETURN principal.samAccountName AS principalName,
       labels(principal) AS principalType,
       c.hostname AS computer,
       r.source AS evidenceSource;

// 3. Shortest attack path from a given starting user to Domain Admins
// (replace 'arya.stark' with whichever user you want to test)
MATCH (start:User {samAccountName: 'arya.stark'}),
      (da:Group {name: 'Domain Admins'}),
      path = shortestPath((start)-[:MEMBER_OF|ADMIN_TO|CAN_ACCESS*1..6]->(da))
RETURN path;

// 4. All findings with their linked evidence nodes
MATCH (f:Finding)-[:INVOLVES]->(evidence)
RETURN f.id AS findingId, f.title AS title, f.severity AS severity,
       f.description AS description, f.evidence AS evidenceText,
       collect(DISTINCT evidence.samAccountName) AS involvedAccounts,
       f.createdAt AS createdAt
ORDER BY f.createdAt DESC;

// 5. Users in a privileged group who are still enabled
MATCH (u:User {enabled: true})-[:MEMBER_OF]->(g:Group {name: 'Domain Admins'})
RETURN u.samAccountName AS account, g.name AS group;

// 6. Lateral-movement candidates
MATCH (g:Group)-[r:CAN_ACCESS]->(c:Computer)-[:RUNS_SERVICE]->(svc:Service)
RETURN g.name AS group, r.type AS accessType, c.hostname AS computer,
       svc.name AS exposedService;
