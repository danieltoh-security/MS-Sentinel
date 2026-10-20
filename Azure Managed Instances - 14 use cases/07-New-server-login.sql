/*
Rule 07: 739531a9-91b8-4b87-a169-000000000007
SQL MI - New server login reported successful by audit
Requires SERVER_PRINCIPAL_CHANGE_GROUP or captured BATCH_COMPLETED_GROUP.
Creates a random-password login and disables and deletes it before commit.
The CREATE LOGIN audit text may contain a password; restrict audit-log access.
*/
USE [master];
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @AllowTest bit = 0;
IF @AllowTest <> 1 THROW 51000, 'Test not authorized. Set @AllowTest = 1.', 1;
IF @@TRANCOUNT <> 0 THROW 51000, 'Use a new session with no active transaction.', 1;
IF CONVERT(int, SERVERPROPERTY('EngineEdition')) <> 8
    THROW 51000, 'This test requires Azure SQL Managed Instance.', 1;
IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'SentinelSql14_Login07')
    THROW 51000, 'Test login already exists. Refusing to modify it.', 1;
BEGIN TRY
    BEGIN TRANSACTION;
    DECLARE @Password nvarchar(128) = N'Sql14!' + CONVERT(nvarchar(36), NEWID()) + N'aA9';
    DECLARE @Sql nvarchar(max) = N'CREATE LOGIN [SentinelSql14_Login07] WITH PASSWORD = ' +
        QUOTENAME(@Password, '''') + N', CHECK_POLICY = ON;';
    EXEC sys.sp_executesql @Sql;
    ALTER LOGIN [SentinelSql14_Login07] DISABLE;
    DROP LOGIN [SentinelSql14_Login07];
    COMMIT;
    PRINT 'Case 07 completed. Login was created and removed in the same transaction.';
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    THROW;
END CATCH;
