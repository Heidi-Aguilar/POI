DROP DATABASE IF EXISTS bd_poi;
CREATE DATABASE bd_poi;
USE bd_poi;

SET SQL_SAFE_UPDATES = 0;

CREATE TABLE Usuario (
    id_usuario INT PRIMARY KEY AUTO_INCREMENT,
    rol TINYINT NOT NULL DEFAULT 0, -- 0 = cliente, 1 = admin
    nombres VARCHAR(100) NOT NULL,
    apellidos VARCHAR(100) NOT NULL,
    fechaNacimiento DATE,
    correo VARCHAR(100) UNIQUE NOT NULL,
    usuario VARCHAR(100) UNIQUE NOT NULL, -- Agregué UNIQUE para asegurar nombres de usuario únicos
    contrasena VARCHAR(255) NOT NULL,
    foto LONGBLOB NULL, -- Puede ser nulo
    -- 'activo' se usa para el estado de sesión (0 = Activo/Loggeado, 1 = Inactivo/Desloggeado)
    activo BOOLEAN NOT NULL DEFAULT TRUE 
);

CREATE TABLE TipoChat (
    id_tipo_chat INT PRIMARY KEY AUTO_INCREMENT,
    nombre VARCHAR(50) NOT NULL UNIQUE
);

CREATE TABLE Chat (
    id_chat INT PRIMARY KEY AUTO_INCREMENT,
    id_tipo_chat INT NOT NULL,
    nombre VARCHAR(100) NULL, -- Solo necesario para chats tipo 'General' o 'Grupo'
    descripcion VARCHAR(255) NULL,
    fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
    creado_por INT NULL, -- Puede ser NULL si es un chat general predefinido
    FOREIGN KEY (id_tipo_chat) REFERENCES TipoChat(id_tipo_chat),
    FOREIGN KEY (creado_por) REFERENCES Usuario(id_usuario)
);

CREATE TABLE ChatUsuario (
    id_chat INT NOT NULL,
    id_usuario INT NOT NULL,
    es_admin BOOLEAN DEFAULT FALSE, 
    fecha_union DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id_chat, id_usuario),
    FOREIGN KEY (id_chat) REFERENCES Chat(id_chat) ON DELETE CASCADE,
    FOREIGN KEY (id_usuario) REFERENCES Usuario(id_usuario) ON DELETE CASCADE
);

CREATE TABLE Mensaje (
    id_mensaje INT PRIMARY KEY AUTO_INCREMENT,
    id_chat INT NOT NULL,
    id_usuario INT NOT NULL, -- quién envió el mensaje
    contenido TEXT NOT NULL, 
    fecha_envio DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_chat) REFERENCES Chat(id_chat) ON DELETE CASCADE,
    FOREIGN KEY (id_usuario) REFERENCES Usuario(id_usuario) ON DELETE CASCADE
);
ALTER TABLE Mensaje ADD COLUMN encriptado BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE Archivo (
    id_archivo INT PRIMARY KEY AUTO_INCREMENT,
    id_mensaje INT NOT NULL,
    tipo ENUM('imagen', 'video', 'audio', 'otro') NOT NULL,
    nombre_original VARCHAR(255),
    ruta_archivo VARCHAR(255),
    tamaño BIGINT,
    FOREIGN KEY (id_mensaje) REFERENCES Mensaje(id_mensaje) ON DELETE CASCADE
);

INSERT INTO TipoChat (id_tipo_chat, nombre) VALUES (1, 'General');
INSERT INTO TipoChat (id_tipo_chat, nombre) VALUES (2, 'Privado');
INSERT INTO TipoChat (id_tipo_chat, nombre) VALUES (3, 'Grupo');

-- La contraseña aquí es '123456
INSERT INTO Usuario (id_usuario, rol, nombres, apellidos, correo, usuario, contrasena, activo)
VALUES (1, 1, 'Sistema', 'Admin', 'admin@chat.com', 'AdminUser', '$2a$10$tW0C.F3s5S7v0QJk8Q5.p.Kj0oYqA7Z1R1yM6Ie7U4m8X2zS0XvW2', 1);


-- Chat General
-- El servidor usa esta ID fija para mensajes públicos
INSERT INTO Chat (id_chat, id_tipo_chat, nombre, descripcion, creado_por)
VALUES (1, 1, 'Chat General', 'Chat público para todos los usuarios conectados.', 1);


-- Asignar al usuario inicial al chat general
INSERT INTO ChatUsuario (id_chat, id_usuario)
VALUES (1, 1);