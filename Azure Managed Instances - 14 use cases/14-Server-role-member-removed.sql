/*
Rule 14: 739531a9-91b8-4b87-a169-000000000014
SQL MI - Server role member removed
Requires SERVER_ROLE_MEMBER_CHANGE_GROUP or captured BATCH_COMPLETED_GROUP.
Requires authorized sysadmin execution on a dedicated test MI.
Uses setupadmin rather than securityadmin so the REMOVE event does not match
the narrower rule 13. The new login is disabled before assignment.
Setup also produces rule 07 activity.
*/
USE [master];
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @AllowTest bit = 0;
IF @AllowTest <> 1 THROW 51000, 'Test not authorized. Set @AllowTest = 1.', 1;
IF @@TRANCOUNT <> 0 THROW 51000, 'Use a new session with no active transaction.', 1;
IF CONVERT(int, SERVERPROPERTY('EngineEdition')) <> 8
    THROW 51000, 'This test requires Azure SQL Managed Instance.', 1;
IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'SentinelSql14_Login14')
    THROW 51000, 'Test login already exists. Refusing to modify it.', 1;
BEGIN TRY
    BEGIN TRANSACTION;
    DECLARE @Password nvarchar(128) = N'Sql14!' + CONVERT(nvarchar(36), NEWID()) + N'aA9';
    DECLARE @Sql nvarchar(max) = N'CREATE LOGIN [SentinelSql14_Login14] WITH PASSWORD = ' +
        QUOTENAME(@Password, '''') + N', CHECK_POLICY = ON;';
    EXEC sys.sp_executesql @Sql;
    ALTER LOGIN [SentinelSql14_Login14] DISABLE;
    ALTER SERVER ROLE [setupadmin] ADD MEMBER [SentinelSql14_Login14];
    ALTER SERVER ROLE [setupadmin] DROP MEMBER [SentinelSql14_Login14];
    DROP LOGIN [SentinelSql14_Login14];
    COMMIT;
    PRINT 'Case 14 completed; setupadmin membership removed and login deleted.';
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    THROW;
END CATCH;
