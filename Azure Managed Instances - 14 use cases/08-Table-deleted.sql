/*
Rule 08: 739531a9-91b8-4b87-a169-000000000008
SQL MI - DROP TABLE reported successful by audit
Requires SCHEMA_OBJECT_CHANGE_GROUP or captured BATCH_COMPLETED_GROUP.
Deletes one table containing only generated test data in a NEW disposable database.
Expected: DROP TABLE [dbo].[SentinelSql14_Table08].
*/
USE [master];
SET NOCOUNT ON;
DECLARE @AllowTest bit = 0;
IF @AllowTest <> 1 THROW 51000, 'Test not authorized. Set @AllowTest = 1.', 1;
IF @@TRANCOUNT <> 0 THROW 51000, 'Use a new session with no active transaction.', 1;
IF CONVERT(int, SERVERPROPERTY('EngineEdition')) <> 8
    THROW 51000, 'This test requires Azure SQL Managed Instance.', 1;
IF DB_ID(N'SentinelSql14_Case08') IS NOT NULL
    THROW 51000, 'Test database already exists. Refusing to modify it.', 1;
CREATE DATABASE [SentinelSql14_Case08];
BEGIN TRY
    EXEC [SentinelSql14_Case08].sys.sp_executesql N'
        CREATE TABLE [dbo].[SentinelSql14_Table08] (TestId int NOT NULL);
        INSERT [dbo].[SentinelSql14_Table08] (TestId) VALUES (1);
        DROP TABLE [dbo].[SentinelSql14_Table08];';
    DROP DATABASE [SentinelSql14_Case08];
    PRINT 'Case 08 completed. The disposable table and database were removed.';
END TRY
BEGIN CATCH
    PRINT 'Case 08 failed. Inspect remaining SentinelSql14_Case08 before cleanup.';
    THROW;
END CATCH;
