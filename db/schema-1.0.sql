
-- -----------------------------------------------------
-- Table Archives
-- -----------------------------------------------------
DROP TABLE IF EXISTS Archives ;

CREATE TABLE IF NOT EXISTS Archives (
  archive_id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename VARCHAR(512) NOT NULL,
  password VARCHAR(64) NOT NULL
 );

CREATE INDEX filename_UNIQUE ON Archives(filename);
  
-- -----------------------------------------------------
-- Table Files
-- -----------------------------------------------------
DROP TABLE IF EXISTS Files;

CREATE TABLE IF NOT EXISTS Files (
  file_id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename VARCHAR(128) NOT NULL,
  md5 CHAR(32) NOT NULL,
  sha1 CHAR(60) NOT NULL,
  archive_id INTEGER UNSIGNED NOT NULL,
    FOREIGN KEY (archive_id)
    REFERENCES Archives (archive_id)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION
);

CREATE INDEX archive_id_INDEX ON Files(archive_id);
-- -----------------------------------------------------
-- Table AVs
-- -----------------------------------------------------
DROP TABLE IF EXISTS AVs ;

CREATE TABLE IF NOT EXISTS AVs (
  av_id INTEGER PRIMARY KEY AUTOINCREMENT,
  name VARCHAR(64) NOT NULL
);

CREATE INDEX name_UNIQUE on AVs(name);

-- -----------------------------------------------------
-- Table Idents
-- -----------------------------------------------------
DROP TABLE IF EXISTS Idents ;

CREATE TABLE IF NOT EXISTS Idents (
  file_id INT UNSIGNED NOT NULL,
  av_id INT UNSIGNED NOT NULL,
  name VARCHAR(128) NOT NULL,
  PRIMARY KEY (file_id, av_id),
  FOREIGN KEY (file_id)
    REFERENCES Files(file_id)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  FOREIGN KEY (av_id)
    REFERENCES AVs(av_id)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION);

CREATE INDEX ident_avid_INDEX on Idents(av_id);
	
-- -----------------------------------------------------
-- Data for table AVs
-- -----------------------------------------------------
BEGIN TRANSACTION;
INSERT INTO AVs (name) VALUES ('ALYac');
INSERT INTO AVs (name) VALUES ('AVG');
INSERT INTO AVs (name) VALUES ('AVware');
INSERT INTO AVs (name) VALUES ('Ad-Aware');
INSERT INTO AVs (name) VALUES ('Agnitum');
INSERT INTO AVs (name) VALUES ('AhnLab-V3');
INSERT INTO AVs (name) VALUES ('Antiy-AVL');
INSERT INTO AVs (name) VALUES ('Arcabit');
INSERT INTO AVs (name) VALUES ('Avast');
INSERT INTO AVs (name) VALUES ('Avira');
INSERT INTO AVs (name) VALUES ('Baidu-International');
INSERT INTO AVs (name) VALUES ('BitDefender');
INSERT INTO AVs (name) VALUES ('CAT-QuickHeal');
INSERT INTO AVs (name) VALUES ('Comodo');
INSERT INTO AVs (name) VALUES ('Cyren');
INSERT INTO AVs (name) VALUES ('ESET-NOD32');
INSERT INTO AVs (name) VALUES ('Emsisoft');
INSERT INTO AVs (name) VALUES ('F-Secure');
INSERT INTO AVs (name) VALUES ('Fortinet');
INSERT INTO AVs (name) VALUES ('GData');
INSERT INTO AVs (name) VALUES ('Ikarus');
INSERT INTO AVs (name) VALUES ('K7AntiVirus');
INSERT INTO AVs (name) VALUES ('K7GW');
INSERT INTO AVs (name) VALUES ('Kaspersky');
INSERT INTO AVs (name) VALUES ('Kaspersky');
INSERT INTO AVs (name) VALUES ('McAfee');
INSERT INTO AVs (name) VALUES ('Microsoft');
INSERT INTO AVs (name) VALUES ('NANO-Antivirus');
INSERT INTO AVs (name) VALUES ('Panda');
INSERT INTO AVs (name) VALUES ('Qihoo-360');
INSERT INTO AVs (name) VALUES ('Sophos');
INSERT INTO AVs (name) VALUES ('Symantec');
INSERT INTO AVs (name) VALUES ('TrendMicro');
INSERT INTO AVs (name) VALUES ('VBA32');
INSERT INTO AVs (name) VALUES ('VIPRE');
INSERT INTO AVs (name) VALUES ('Zillya');
INSERT INTO AVs (name) VALUES ('AegisLab');
INSERT INTO AVs (name) VALUES ('Alibaba');
INSERT INTO AVs (name) VALUES ('Bkav');
INSERT INTO AVs (name) VALUES ('ByteHero');
INSERT INTO AVs (name) VALUES ('CMC');
INSERT INTO AVs (name) VALUES ('ClamAV');
INSERT INTO AVs (name) VALUES ('DrWeb');
INSERT INTO AVs (name) VALUES ('F-Prot');
INSERT INTO AVs (name) VALUES ('Jiangmin');
INSERT INTO AVs (name) VALUES ('Kingsoft');
INSERT INTO AVs (name) VALUES ('Rising');
INSERT INTO AVs (name) VALUES ('SUPERAntiSpyware');
INSERT INTO AVs (name) VALUES ('Tencent');
INSERT INTO AVs (name) VALUES ('TheHacker');
INSERT INTO AVs (name) VALUES ('TotalDefense');
INSERT INTO AVs (name) VALUES ('ViRobot');
INSERT INTO AVs (name) VALUES ('Zoner');
INSERT INTO AVs (name) VALUES ('nProtect');

COMMIT;

