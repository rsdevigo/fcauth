CREATE TABLE users (
    id INT NOT NULL AUTO_INCREMENT,
    uuid VARCHAR(512) NOT NULL UNIQUE,
    phone VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(512) NOT NULL,
    PRIMARY KEY (id)
);