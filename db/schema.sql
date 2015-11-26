-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL,ALLOW_INVALID_DATES';

-- -----------------------------------------------------
-- Schema vxvault
-- -----------------------------------------------------

-- -----------------------------------------------------
-- Schema vxvault
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `vxvault` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci ;
USE `vxvault` ;

-- -----------------------------------------------------
-- Table `vxvault`.`Archives`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `vxvault`.`Archives` ;

CREATE TABLE IF NOT EXISTS `vxvault`.`Archives` (
  `archive_id` INT ZEROFILL UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '',
  `file` VARCHAR(512) NOT NULL COMMENT '',
  `password` VARCHAR(64) NOT NULL COMMENT '',
  PRIMARY KEY (`archive_id`)  COMMENT '',
  UNIQUE INDEX `file_UNIQUE` (`file` ASC)  COMMENT '')
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `vxvault`.`Files`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `vxvault`.`Files` ;

CREATE TABLE IF NOT EXISTS `vxvault`.`Files` (
  `file_id` INT UNSIGNED ZEROFILL NOT NULL AUTO_INCREMENT COMMENT '',
  `filename` VARCHAR(128) NOT NULL COMMENT '',
  `md5` CHAR(32) NOT NULL COMMENT '',
  `sha1` CHAR(60) NOT NULL COMMENT '',
  `archive_id` INT UNSIGNED NOT NULL COMMENT '',
  PRIMARY KEY (`file_id`)  COMMENT '',
  INDEX `fk_archive_idx` (`archive_id` ASC)  COMMENT '',
  CONSTRAINT `fk_archive`
    FOREIGN KEY (`archive_id`)
    REFERENCES `vxvault`.`Archives` (`archive_id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `vxvault`.`AVs`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `vxvault`.`AVs` ;

CREATE TABLE IF NOT EXISTS `vxvault`.`AVs` (
  `av_id` INT UNSIGNED ZEROFILL NOT NULL AUTO_INCREMENT COMMENT '',
  `name` VARCHAR(64) NOT NULL COMMENT '',
  PRIMARY KEY (`av_id`)  COMMENT '',
  UNIQUE INDEX `name_UNIQUE` (`name` ASC)  COMMENT '')
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `vxvault`.`Idents`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `vxvault`.`Idents` ;

CREATE TABLE IF NOT EXISTS `vxvault`.`Idents` (
  `file_id` INT UNSIGNED NOT NULL COMMENT '',
  `av_id` INT UNSIGNED NOT NULL COMMENT '',
  `name` VARCHAR(128) NOT NULL COMMENT '',
  PRIMARY KEY (`file_id`, `av_id`)  COMMENT '',
  INDEX `fk_ident_avid_idx` (`av_id` ASC)  COMMENT '',
  CONSTRAINT `fk_ident_fileid`
    FOREIGN KEY (`file_id`)
    REFERENCES `vxvault`.`Files` (`file_id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_ident_avid`
    FOREIGN KEY (`av_id`)
    REFERENCES `vxvault`.`AVs` (`av_id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;
