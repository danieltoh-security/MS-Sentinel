/*
Rule 11: 739531a9-91b8-4b87-a169-000000000011
SQL Database ONLY - Member added to loginmanager or dbmanager (not MI)

THIS RULE CANNOT BE POSITIVELY TESTED ON SQL MANAGED INSTANCE.
The imported query explicitly requires ResourceType == SERVERS/DATABASES.
loginmanager/dbmanager are not MI built-in roles. Do not create fake roles on MI
or alter the rule's resource filter just to claim a successful test.

Optional genuine SQL Database test below:
1. Use a separate dedicated Azure SQL Database logical server.
2. Connect directly to that server's virtual master database as administrator.
3. Route its SQLSecurityAuditEvents into the same Sentinel workspace.
4. Capture DATABASE_ROLE_MEMBER_CHANGE_GROUP / relevant batch audit statements.
5. Set @AllowTest=1 and run the WHOLE file. The contained test user has NO LOGIN.
The user is temporarily added to loginmanager, removed, then dropped.
*/
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @AllowTest bit = 0;
IF CONVERT(int, SERVERPROPERTY('EngineEdition')) <> 5 OR DB_NAME() <> N'master'
    THROW 51000, 'Case 11 is NOT applicable to MI. Connect to Azure SQL Database virtual master for the optional positive test.', 1;
IF @AllowTest <> 1 THROW 51000, 'Test not authorized. Set @AllowTest = 1.', 1;
IF @@TRANCOUNT <> 0 THROW 51000, 'Use a new session with no active transaction.', 1;
IF DATABASE_PRINCIPAL_ID(N'SentinelSql14_User11') IS NOT NULL
    THROW 51000, 'Test user already exists. Refusing to modify it.', 1;
IF DATABASE_PRINCIPAL_ID(N'loginmanager') IS NULL
    THROW 51000, 'The expected SQL Database loginmanager role is unavailable.', 1;
BEGIN TRY
    BEGIN TRANSACTION;
    CREATE USER [SentinelSql14_User11] WITHOUT LOGIN;
    ALTER ROLE [loginmanager] ADD MEMBER [SentinelSql14_User11];
    ALTER ROLE [loginmanager] DROP MEMBER [SentinelSql14_User11];
    DROP USER [SentinelSql14_User11];
    COMMIT;
    PRINT 'Optional SQL Database case 11 completed. This is NOT an MI test.';
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK;
    THROW;
END CATCH;
