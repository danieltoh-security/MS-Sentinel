/*
Rule 02: 739531a9-91b8-4b87-a169-000000000002
SQL MI - Database authentication failure
Requires FAILED_DATABASE_AUTHENTICATION_GROUP and contained database authentication.
This file prepares a contained SQL user. A failed login to that DATABASE, not
EXECUTE AS or RAISERROR(18456), is needed to generate a real authentication event.
Run the whole file as administrator. SQL authentication must be permitted.
After setup, run:
  .\Invoke-Sql14FailedAuthentication.ps1 -Server '<MI-FQDN>,1433' -Case 02
Cloud Shell needs network access to the MI; use port 3342 only for an already
configured MI public endpoint. The helper does NOT open any network access.
Cleanup after testing: explicitly DROP DATABASE [SentinelSql14_Case02] in master.
Never drop an existing database just to rerun this test.
*/
USE [master];
SET NOCOUNT ON;
DECLARE @AllowTest bit = 0; -- Set to 1 after review.
IF @AllowTest <> 1 THROW 51000, 'Test not authorized. Set @AllowTest = 1.', 1;
IF @@TRANCOUNT <> 0 THROW 51000, 'Use a new session with no active transaction.', 1;
IF CONVERT(int, SERVERPROPERTY('EngineEdition')) <> 8
    THROW 51000, 'This test requires Azure SQL Managed Instance.', 1;
IF NOT EXISTS (
    SELECT 1 FROM sys.configurations
    WHERE name = N'contained database authentication' AND value_in_use = 1
)
    THROW 51000, 'Contained database authentication must already be enabled by your DBA; this file does not change server configuration.', 1;
IF DB_ID(N'SentinelSql14_Case02') IS NOT NULL
    THROW 51000, 'Test database already exists. Review before cleanup.', 1;

CREATE DATABASE [SentinelSql14_Case02] CONTAINMENT = PARTIAL;
BEGIN TRY
    DECLARE @Password nvarchar(128) = N'Sql14!' + CONVERT(nvarchar(36), NEWID()) + N'aA9';
    DECLARE @Sql nvarchar(max) =
        N'CREATE USER [SentinelSql14_User02] WITH PASSWORD = ' +
        QUOTENAME(@Password, '''') + N';';
    EXEC [SentinelSql14_Case02].sys.sp_executesql @Sql;
    SET @Password = NULL;
    SET @Sql = NULL;
    PRINT 'Prepared contained user. Now run helper -Case 02 from a reachable client.';
    PRINT 'Expected database authentication failure (DBAF); verify actual MI audit output.';
END TRY
BEGIN CATCH
    PRINT 'Setup failed. Inspect SentinelSql14_Case02 before dropping the disposable database.';
    THROW;
END CATCH;
