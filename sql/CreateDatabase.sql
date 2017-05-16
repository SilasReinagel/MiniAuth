CREATE SCHEMA Auth 
GO;

CREATE TABLE Auth.Accounts (
    UserId char(36) NOT NULL PRIMARY KEY,
    Username varchar(256) NOT NULL,
    Password varchar(128) NOT NULL,
    IsDisabled BIT DEFAULT 0
) 
GO;