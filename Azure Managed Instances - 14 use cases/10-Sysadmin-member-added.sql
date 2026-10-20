/*
Rule 10: 739531a9-91b8-4b87-a169-000000000010
SQL MI - Member added to sysadmin
Requires SERVER_ROLE_MEMBER_CHANGE_GROUP or captured BATCH_COMPLETED_GROUP.
Requires authorized sysadmin execution on a dedicated test MI.
The login is DISABLED before adding sysadmin; never enable it.
The assignment and cleanup commit together. Errors roll back all login changes.
Also produces rule 07 and rule 14 activity.
*/
USE [master];
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @AllowTest bit = 0;
IF @AllowTest <> 1 THROW 51000, 'Test not authorized. Set @AllowTest = 1.', 1;
IF @@TRANCOUNT <> 0 THROW 51000, 'Use a new session with no active transaction.', 1;
IF CONVERT(int, SERVERPROPERTY('EngineEdition')) <> 8
    THROW 51000, 'This test requires Azure SQL Managed Instance.', 1;
IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'SentinelSql14_Login10')
    THROW 51000, 'Test login already exists. Refusing to modify it.', 1;
BEGIN TRY
    BEGIN TRANSACTION;
    DECLARE @Password nvarchar(128) = N'Sql14!' + CONVERT(nvarchar(36), NEWID()) + N'aA9';
    DECLARE @Sql nvarchar(max) = N'CREATE LOGIN [SentinelSql14_Login10] WITH PASSWORD = ' +
        QUOTENAME(@Password, '''') + N', CHECK_POLICY = ON;';
    EXEC sys.sp_executesql @Sql;
    ALTER LOGIN [SentinelSql14_Login10] DISABLE;
    ALTER SERVER ROLE [sysadmin] ADD MEMBER [SentinelSql14_Login10];
    ALTER SERVER ROLE [sysadmin] DROP MEMBER [SentinelSql14_Login10];
    DROP LOGIN [SentinelSql14_Login10];
    COMMIT;
    PRINT 'Case 10 completed; disabled test login and sysadmin membership removed.';
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    THROW;
END CATCH;
