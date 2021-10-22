CREATE DATABASE mushroomkingdom;
\c mushroomkingdom
CREATE TABLE  if not exists sensordata (
                                time BIGINT NOT NULL,
                                chamberid INT NOT NULL,
                                humidity  INT NOT NULL,
                                temperature INT NOT NULL
                                );