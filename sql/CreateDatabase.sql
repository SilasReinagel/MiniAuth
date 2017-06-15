CREATE SCHEMA Auth 
GO

IF EXISTS(SELECT * FROM Auth.Accounts) 
    DROP TABLE Auth.Accounts
GO

CREATE TABLE Auth.Accounts (
    UserId char(36) NOT NULL PRIMARY KEY,
    Username varchar(256) NOT NULL,
    Password varchar(128) NOT NULL,
	Salt varchar(128) NOT NULL,
    IsDisabled BIT DEFAULT 0
) 
GO

IF EXISTS(SELECT * FROM Auth.Apps) 
    DROP TABLE Auth.Apps
GO

CREATE TABLE Auth.Apps (
    Name varchar(256) NOT NULL PRIMARY KEY,
	Secret varchar(512) NOT NULL
)
GO