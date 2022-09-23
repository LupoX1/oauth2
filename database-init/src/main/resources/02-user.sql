USE mysql;
CREATE USER 'test_user'@'%' IDENTIFIED BY 'test_password';
GRANT ALL PRIVILEGES ON `oauth2`.* TO 'test_user'@'%';
FLUSH PRIVILEGES;