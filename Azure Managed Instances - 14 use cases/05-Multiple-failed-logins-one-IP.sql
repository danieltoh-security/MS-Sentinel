/*
Rule 05: 739531a9-91b8-4b87-a169-000000000005
SQL MI - Multiple failed logins from one source IP
Requires FAILED_LOGIN_GROUP and a valid client IPv4/IPv6 address in audit logs.
Run this WHOLE setup batch as administrator, then:
  .\Invoke-Sql14FailedAuthentication.ps1 -Server '<MI-FQDN>,1433' -Case 05
The helper creates SIX fresh attempts, within ten minutes, from one client.
Original threshold is MORE THAN five. Pooling is disabled to avoid cached failures.
A placeholder such as '<local machine>' cannot pass this rule's IP filter.
Password policy/lockout stays enabled; use only this disposable login.
Case 04 and case 06 may also match: isolation between overlapping rules is not promised.
Cleanup after the helper: DROP LOGIN [SentinelSql14_Login05] in master.
*/
USE [master];
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @AllowTest bit = 0;
IF @AllowTest <> 1 THROW 51000, 'Test not authorized. Set @AllowTest = 1.', 1;
IF @@TRANCOUNT <> 0 THROW 51000, 'Use a new session with no active transaction.', 1;
IF CONVERT(int, SERVERPROPERTY('EngineEdition')) <> 8
    THROW 51000, 'This test requires Azure SQL Managed Instance.', 1;
IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'SentinelSql14_Login05')
    THROW 51000, 'Test login already exists. Inspect it before cleanup.', 1;
BEGIN TRY
    BEGIN TRANSACTION;
    DECLARE @Password nvarchar(128) = N'Sql14!' + CONVERT(nvarchar(36), NEWID()) + N'aA9';
    DECLARE @Sql nvarchar(max) = N'CREATE LOGIN [SentinelSql14_Login05] WITH PASSWORD = ' +
        QUOTENAME(@Password, '''') + N', CHECK_POLICY = ON, CHECK_EXPIRATION = OFF;';
    EXEC sys.sp_executesql @Sql;
    COMMIT;
    SET @Password = NULL;
    SET @Sql = NULL;
    PRINT 'Setup complete. Run helper -Case 05 from one reachable client, then drop the login.';
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    THROW;
END CATCH;
