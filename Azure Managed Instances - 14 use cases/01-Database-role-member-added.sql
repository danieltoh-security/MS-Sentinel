/*
Rule 01: 739531a9-91b8-4b87-a169-000000000001
SQL MI - Database role member added
Run this whole file as an MI administrator in a dedicated test instance.
Requires DATABASE_ROLE_MEMBER_CHANGE_GROUP or captured BATCH_COMPLETED_GROUP.
Expected statement: ALTER ROLE [SentinelSql14_Role01] ADD MEMBER [SentinelSql14_User01].
Creates and deletes only a new disposable database. No login is granted access.
*/
USE [master];
SET NOCOUNT ON;
DECLARE @AllowTest bit = 0; -- Set to 1 after reviewing this file.
IF @AllowTest <> 1 THROW 51000, 'Test not authorized. Set @AllowTest = 1.', 1;
IF @@TRANCOUNT <> 0 THROW 51000, 'Use a new session with no active transaction.', 1;
IF CONVERT(int, SERVERPROPERTY('EngineEdition')) <> 8
    THROW 51000, 'This test requires Azure SQL Managed Instance.', 1;
IF DB_ID(N'SentinelSql14_Case01') IS NOT NULL
    THROW 51000, 'Test database already exists. Review it; do not overwrite it.', 1;

CREATE DATABASE [SentinelSql14_Case01];
BEGIN TRY
    EXEC [SentinelSql14_Case01].sys.sp_executesql N'
        CREATE USER [SentinelSql14_User01] WITHOUT LOGIN;
        CREATE ROLE [SentinelSql14_Role01];
        ALTER ROLE [SentinelSql14_Role01] ADD MEMBER [SentinelSql14_User01];';
    DROP DATABASE [SentinelSql14_Case01];
    PRINT 'Case 01 completed. Check audit ingestion and rule 01.';
END TRY
BEGIN CATCH
    PRINT 'Case 01 failed. Disposable database SentinelSql14_Case01 may remain; inspect before cleanup.';
    THROW;
END CATCH;
