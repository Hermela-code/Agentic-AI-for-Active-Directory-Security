// ============================================================
// Active Directory Knowledge Graph — Schema
// ============================================================

CREATE CONSTRAINT domain_name IF NOT EXISTS
FOR (d:Domain) REQUIRE d.name IS UNIQUE;

CREATE CONSTRAINT user_sam IF NOT EXISTS
FOR (u:User) REQUIRE u.samAccountName IS UNIQUE;

CREATE CONSTRAINT group_sid IF NOT EXISTS
FOR (g:Group) REQUIRE g.sid IS UNIQUE;

CREATE CONSTRAINT computer_hostname IF NOT EXISTS
FOR (c:Computer) REQUIRE c.hostname IS UNIQUE;

CREATE CONSTRAINT service_key IF NOT EXISTS
FOR (s:Service) REQUIRE s.spn IS UNIQUE;

CREATE CONSTRAINT finding_id IF NOT EXISTS
FOR (f:Finding) REQUIRE f.id IS UNIQUE;

CREATE INDEX user_enabled IF NOT EXISTS FOR (u:User) ON (u.enabled);
CREATE INDEX computer_os IF NOT EXISTS FOR (c:Computer) ON (c.os);
CREATE INDEX finding_severity IF NOT EXISTS FOR (f:Finding) ON (f.severity);
