/*
Rule 03: 739531a9-91b8-4b87-a169-000000000003
SQL MI - DROP DATABASE reported successful by audit
Requires DATABASE_CHANGE_GROUP or captured BATCH_COMPLETED_GROUP.
Expected statement: DROP DATABASE [SentinelSql14_Case03].
Never substitute a production database name. The collision check is mandatory.
*/
USE [master];
SET NOCOUNT ON;
DECLARE @AllowTest bit = 0;
IF @AllowTest <> 1 THROW 51000, 'Test not authorized. Set @AllowTest = 1.', 1;
IF @@TRANCOUNT <> 0 THROW 51000, 'Use a new session with no active transaction.', 1;
IF CONVERT(int, SERVERPROPERTY('EngineEdition')) <> 8
    THROW 51000, 'This test requires Azure SQL Managed Instance.', 1;
IF DB_ID(N'SentinelSql14_Case03') IS NOT NULL
    THROW 51000, 'Test database already exists. Refusing to delete it.', 1;

CREATE DATABASE [SentinelSql14_Case03];
DROP DATABASE [SentinelSql14_Case03];
PRINT 'Case 03 completed. The newly created disposable database was deleted.';
