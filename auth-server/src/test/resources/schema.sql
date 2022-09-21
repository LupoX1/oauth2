CREATE TABLE  IF NOT EXISTS `oauth2`.`users` (
  `username` VARCHAR(50) NOT NULL,
  `password` VARCHAR(500) NOT NULL,
  `enabled` TINYINT NOT NULL,
  PRIMARY KEY (`username`));

CREATE TABLE  IF NOT EXISTS `oauth2`.`authorities` (
  `username` VARCHAR(50) NOT NULL,
  `authority` VARCHAR(50) NOT NULL,
  INDEX `fk_authorities_users_idx` (`username` ASC) INVISIBLE,
  UNIQUE INDEX `ix_auth_username` (`username` ASC, `authority` ASC) VISIBLE,
  CONSTRAINT `fk_authorities_users`
    FOREIGN KEY (`username`)
    REFERENCES `oauth2`.`users` (`username`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION);