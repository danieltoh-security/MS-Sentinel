/*
Rule 12: 739531a9-91b8-4b87-a169-000000000012
SQL MI - Database role member removed (NOT DROP USER).
Requires DATABASE_ROLE_MEMBER_CHANGE_GROUP or captured BATCH_COMPLETED_GROUP.
The source use case removes ROLE membership, not a database user account.
Setup also matches rule 01. Cleanup can match rule 03.
*/
USE [master];
SET NOCOUNT ON;
DECLARE @AllowTest bit = 0;
IF @AllowTest <> 1 THROW 51000, 'Test not authorized. Set @AllowTest = 1.', 1;
IF @@TRANCOUNT <> 0 THROW 51000, 'Use a new session with no active transaction.', 1;
IF CONVERT(int, SERVERPROPERTY('EngineEdition')) <> 8
    THROW 51000, 'This test requires Azure SQL Managed Instance.', 1;
IF DB_ID(N'SentinelSql14_Case12') IS NOT NULL
    THROW 51000, 'Test database already exists. Refusing to modify it.', 1;
CREATE DATABASE [SentinelSql14_Case12];
BEGIN TRY
    EXEC [SentinelSql14_Case12].sys.sp_executesql N'
        CREATE USER [SentinelSql14_User12] WITHOUT LOGIN;
        CREATE ROLE [SentinelSql14_Role12];
        ALTER ROLE [SentinelSql14_Role12] ADD MEMBER [SentinelSql14_User12];
        ALTER ROLE [SentinelSql14_Role12] DROP MEMBER [SentinelSql14_User12];';
    DROP DATABASE [SentinelSql14_Case12];
    PRINT 'Case 12 completed. Role membership was removed; disposable database cleaned up.';
END TRY
BEGIN CATCH
    PRINT 'Case 12 failed. Inspect SentinelSql14_Case12 before cleanup.';
    THROW;
END CATCH;
