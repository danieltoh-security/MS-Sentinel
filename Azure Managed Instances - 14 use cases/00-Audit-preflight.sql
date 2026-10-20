/*
READ ONLY. Run as an authorized MI administrator before any numbered test.
No audit settings, server configuration, accounts, or databases are changed.
Rule tests require enabled Sentinel rules and SQLSecurityAuditEvents diagnostic
routing to the Sentinel workspace, in addition to these engine audit settings.
*/
USE [master];
SET NOCOUNT ON;
SELECT @@SERVERNAME AS InstanceName,
    CONVERT(int, SERVERPROPERTY('EngineEdition')) AS EngineEdition,
    ORIGINAL_LOGIN() AS ConnectedLogin,
    IS_SRVROLEMEMBER(N'sysadmin') AS IsSysadmin;

SELECT a.name AS AuditName, a.is_state_enabled AS AuditEnabled,
    a.type_desc AS Destination, r.status_desc AS RuntimeStatus,
    s.name AS SpecificationName, s.is_state_enabled AS SpecificationEnabled
FROM sys.server_audits AS a
LEFT JOIN sys.dm_server_audit_status AS r ON r.audit_id = a.audit_id
LEFT JOIN sys.server_audit_specifications AS s ON s.audit_guid = a.audit_guid;

SELECT s.name AS SpecificationName, d.audit_action_name AS ConfiguredAction
FROM sys.server_audit_specifications AS s
JOIN sys.server_audit_specification_details AS d
    ON d.server_specification_id = s.server_specification_id
ORDER BY s.name, d.audit_action_name;

SELECT RequiredGroup, Cases
FROM (VALUES
    (N'DATABASE_ROLE_MEMBER_CHANGE_GROUP', N'01, 12 (11 on SQL Database only)'),
    (N'FAILED_DATABASE_AUTHENTICATION_GROUP', N'02'),
    (N'DATABASE_CHANGE_GROUP', N'03; disposable database cleanup can also match'),
    (N'FAILED_LOGIN_GROUP', N'04, 05, 06'),
    (N'SERVER_PRINCIPAL_CHANGE_GROUP', N'07; setup for 04/05/06/09/10/13/14 can also match'),
    (N'SCHEMA_OBJECT_CHANGE_GROUP', N'08'),
    (N'SERVER_ROLE_MEMBER_CHANGE_GROUP', N'09, 10, 13, 14')
) AS Required(RequiredGroup, Cases);

SELECT name, value_in_use
FROM sys.configurations
WHERE name = N'contained database authentication';

SELECT name AS ExistingTestDatabase
FROM sys.databases WHERE name LIKE N'SentinelSql14[_]%';
SELECT name AS ExistingTestLogin, is_disabled
FROM sys.server_principals WHERE name LIKE N'SentinelSql14[_]%';

PRINT 'Have your DBA add missing native audit groups to the intended audit specification.';
PRINT 'BATCH_COMPLETED_GROUP is an alternative for statement rules, not real authentication events.';
PRINT 'This file does not alter audit specifications or enable contained authentication.';
