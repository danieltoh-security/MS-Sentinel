/*
Rule 09: 739531a9-91b8-4b87-a169-000000000009
SQL MI - Member added to securityadmin
Requires SERVER_ROLE_MEMBER_CHANGE_GROUP or captured BATCH_COMPLETED_GROUP.
Requires authorized sysadmin execution on a dedicated test MI.
The new random-password login is DISABLED before privilege assignment.
Membership is removed and the login dropped before commit; errors roll back.
Also produces rule 07, rule 13, and rule 14 activity as setup/cleanup.
*/
USE [master];
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @AllowTest bit = 0;
IF @AllowTest <> 1 THROW 51000, 'Test not authorized. Set @AllowTest = 1.', 1;
IF @@TRANCOUNT <> 0 THROW 51000, 'Use a new session with no active transaction.', 1;
IF CONVERT(int, SERVERPROPERTY('EngineEdition')) <> 8
    THROW 51000, 'This test requires Azure SQL Managed Instance.', 1;
IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'SentinelSql14_Login09')
    THROW 51000, 'Test login already exists. Refusing to modify it.', 1;
BEGIN TRY
    BEGIN TRANSACTION;
    DECLARE @Password nvarchar(128) = N'Sql14!' + CONVERT(nvarchar(36), NEWID()) + N'aA9';
    DECLARE @Sql nvarchar(max) = N'CREATE LOGIN [SentinelSql14_Login09] WITH PASSWORD = ' +
        QUOTENAME(@Password, '''') + N', CHECK_POLICY = ON;';
    EXEC sys.sp_executesql @Sql;
    ALTER LOGIN [SentinelSql14_Login09] DISABLE;
    ALTER SERVER ROLE [securityadmin] ADD MEMBER [SentinelSql14_Login09];
    ALTER SERVER ROLE [securityadmin] DROP MEMBER [SentinelSql14_Login09];
    DROP LOGIN [SentinelSql14_Login09];
    COMMIT;
    PRINT 'Case 09 completed; disabled test login and membership removed.';
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    THROW;
END CATCH;
