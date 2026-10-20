/*
Rule 06: 739531a9-91b8-4b87-a169-000000000006
SQL MI - Multiple failed logins for one account
Requires FAILED_LOGIN_GROUP and a POPULATED Actor in the audit records.
Run this WHOLE setup batch as administrator, then:
  .\Invoke-Sql14FailedAuthentication.ps1 -Server '<MI-FQDN>,1433' -Case 06
SIX attempts use the same existing test login within ten minutes.
MI may omit failed-login principal names; if it does, rule 06 intentionally cannot
match. Do not populate a fictitious principal merely to make the test pass.
An error 18456 alone does not prove that the account field was populated.
Case 04 and possibly case 05 can also match this workload.
Cleanup after the helper: DROP LOGIN [SentinelSql14_Login06] in master.
*/
USE [master];
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @AllowTest bit = 0;
IF @AllowTest <> 1 THROW 51000, 'Test not authorized. Set @AllowTest = 1.', 1;
IF @@TRANCOUNT <> 0 THROW 51000, 'Use a new session with no active transaction.', 1;
IF CONVERT(int, SERVERPROPERTY('EngineEdition')) <> 8
    THROW 51000, 'This test requires Azure SQL Managed Instance.', 1;
IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'SentinelSql14_Login06')
    THROW 51000, 'Test login already exists. Inspect it before cleanup.', 1;
BEGIN TRY
    BEGIN TRANSACTION;
    DECLARE @Password nvarchar(128) = N'Sql14!' + CONVERT(nvarchar(36), NEWID()) + N'aA9';
    DECLARE @Sql nvarchar(max) = N'CREATE LOGIN [SentinelSql14_Login06] WITH PASSWORD = ' +
        QUOTENAME(@Password, '''') + N', CHECK_POLICY = ON, CHECK_EXPIRATION = OFF;';
    EXEC sys.sp_executesql @Sql;
    COMMIT;
    SET @Password = NULL;
    SET @Sql = NULL;
    PRINT 'Setup complete. Run helper -Case 06, verify principal fields, then drop the login.';
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    THROW;
END CATCH;
