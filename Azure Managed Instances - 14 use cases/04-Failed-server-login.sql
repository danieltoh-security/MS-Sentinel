/*
Rule 04: 739531a9-91b8-4b87-a169-000000000004
SQL MI - Failed server login observed
Requires FAILED_LOGIN_GROUP and SQL authentication.
Run this WHOLE setup batch as administrator, then run:
  .\Invoke-Sql14FailedAuthentication.ps1 -Server '<MI-FQDN>,1433' -Case 04
The helper makes one fresh login with an incorrect randomly generated password.
T-SQL in an existing session cannot reproduce a real failed login.
The test login has only normal public membership, a random undisclosed password,
and CHECK_POLICY=ON. Do not grant it privileged roles.
Cleanup after the helper: DROP LOGIN [SentinelSql14_Login04] in master.
*/
USE [master];
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @AllowTest bit = 0;
IF @AllowTest <> 1 THROW 51000, 'Test not authorized. Set @AllowTest = 1.', 1;
IF @@TRANCOUNT <> 0 THROW 51000, 'Use a new session with no active transaction.', 1;
IF CONVERT(int, SERVERPROPERTY('EngineEdition')) <> 8
    THROW 51000, 'This test requires Azure SQL Managed Instance.', 1;
IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'SentinelSql14_Login04')
    THROW 51000, 'Test login already exists. Inspect it before cleanup.', 1;
BEGIN TRY
    BEGIN TRANSACTION;
    DECLARE @Password nvarchar(128) = N'Sql14!' + CONVERT(nvarchar(36), NEWID()) + N'aA9';
    DECLARE @Sql nvarchar(max) = N'CREATE LOGIN [SentinelSql14_Login04] WITH PASSWORD = ' +
        QUOTENAME(@Password, '''') + N', CHECK_POLICY = ON, CHECK_EXPIRATION = OFF;';
    EXEC sys.sp_executesql @Sql;
    COMMIT;
    SET @Password = NULL;
    SET @Sql = NULL;
    PRINT 'Setup complete. Run authentication helper -Case 04, then drop the test login.';
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    THROW;
END CATCH;
