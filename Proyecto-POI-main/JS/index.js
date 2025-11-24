import express from 'express';
import logger from 'morgan';
import bodyParser from 'body-parser';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import { Server } from 'socket.io';
import { createServer } from 'node:http';
import connection from './db.js'; // tu conexión a MySQL
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';


// ---------------- CONFIGURACIÓN DE RUTAS Y MÓDULOS ES ----------------
// Definiciones necesarias para usar __dirname en ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// ---------------------------------------------------------------------


// ---------------- CONFIGURACIÓN GENERAL DE EXPRESS Y SERVIDOR ----------------
const port = process.env.PORT || 3000;
const app = express();
const server = createServer(app);

app.use(cors());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));


// ---------------- CONFIGURACIÓN DE ENCRIPTACIÓN AES ----------------
const ENCRYPTION_KEY = crypto.scryptSync('mi-clave-ultra-secreta-32-chars', 'salt', 32); // Clave de 32 bytes (AES-256)
const IV_LENGTH = 16; // AES requiere un IV de 16 bytes (128 bits)

function encrypt(text) {
    if (!text) return null;
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
    if (!text || text.indexOf(':') === -1) return text;
    try {
        const parts = text.split(':');
        const iv = Buffer.from(parts.shift(), 'hex');
        const encryptedText = parts.join(':');
        const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (e) {
        return text;
    }
}
// ---------------- FIN CONFIGURACIÓN DE ENCRIPTACIÓN ----------------


// ---------------- CONFIGURACIÓN DE CARGA DE ARCHIVOS (MULTER) ----------------
const UPLOADS_DIR = path.join(__dirname, '../uploads');
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

// Crear el directorio de subidas si no existe
if (!fs.existsSync(UPLOADS_DIR)) {
    console.log(`📂 Creando directorio: ${UPLOADS_DIR}`);
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOADS_DIR);
    },
    filename: (req, file, cb) => {
        const extension = path.extname(file.originalname);
        const uniqueFilename = uuidv4() + extension;
        cb(null, uniqueFilename);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: MAX_FILE_SIZE },
    fileFilter: (req, file, cb) => {
        cb(null, true);
    }
});
// ---------------- FIN CONFIGURACIÓN DE MULTER ----------------


// ---------------- SERVICIO DE ARCHIVOS ESTÁTICOS ----------------
app.use('/HTML', express.static(path.join(__dirname, '../HTML')));
app.use('/CSS', express.static(path.join(__dirname, '../CSS')));
app.use('/JS', express.static(path.join(__dirname, '../JS')));
app.use('/Resources', express.static(path.join(__dirname, '../Resources')));
// Servir el directorio de subidas de archivos
app.use('/uploads', express.static(UPLOADS_DIR));


// ID predefinido para el chat general y tipo de chat
const ID_CHAT_GENERAL = 1;
const ID_TIPO_CHAT_PRIVADO = 2;

// ---------------- ALMACENAMIENTO DE SOCKETS ----------------
// userSocketMap solo contiene a los usuarios marcados como "Activos" (activo=0 en DB)
const userSocketMap = {};
const socketUserMap = {};

// ---------------- SOCKET.IO ----------------
const io = new Server(server, {
    cors: {
        origin: [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://172.20.10.2:3000"
        ],
        methods: ["GET", "POST"]
    }
});

const users = {};

io.on('connection', (socket) => {
    console.log('🟢 Nuevo cliente conectado:', socket.id);

    // --- 1. Evento para asociar el usuario autenticado con su socket (ACTIVO)
    socket.on('user connected', (id_usuario) => {
        if (id_usuario) {
            userSocketMap[id_usuario] = socket.id;
            socketUserMap[socket.id] = id_usuario;
            console.log(`👤 Usuario ${id_usuario} asociado a socket ${socket.id} (ACTIVO)`);

            // Marcar como activo (0) en la base de datos
            connection.query('UPDATE Usuario SET activo = 0 WHERE id_usuario = ?', [id_usuario], (err) => {
                if (err) console.error("❌ Error al actualizar 'activo' a 0:", err);
            });

            io.emit('online users', Object.keys(userSocketMap));
        }
    });

    // --- NUEVO: Desconexión manual (INACTIVO/Stealth) ---
    socket.on('manual disconnect', (id_usuario) => {
        if (id_usuario) {
            // 1. Eliminar el socket mapping (lo hace "invisible" a otros usuarios)
            delete userSocketMap[id_usuario];
            delete socketUserMap[socket.id];
            console.log(`⚫ Usuario ${id_usuario} se puso INACTIVO manualmente.`);

            // 2. Marcar como inactivo en la base de datos (activo = 1)
            connection.query('UPDATE Usuario SET activo = 1 WHERE id_usuario = ?', [id_usuario], (err) => {
                if (err) console.error("❌ Error al actualizar 'activo' a 1:", err);
            });

            // 3. Notificar a todos para que la bolita desaparezca
            io.emit('online users', Object.keys(userSocketMap));
        }
    });


    socket.on('disconnect', () => {
        console.log('🔴 Cliente desconectado (físicamente):', socket.id);
        const id_usuario = socketUserMap[socket.id];

        if (id_usuario) {

            // Si el usuario aún estaba en el mapa (no se desconectó manualmente), lo marcamos inactivo.
            if (userSocketMap[id_usuario]) {
                connection.query('UPDATE Usuario SET activo = 1 WHERE id_usuario = ?', [id_usuario], (err) => {
                    if (err) console.error("❌ Error al actualizar 'activo' en logout:", err);
                });
            }

            // Limpieza final de mapas
            delete userSocketMap[id_usuario];
            delete socketUserMap[socket.id];

            io.emit('online users', Object.keys(userSocketMap));
        }
    });

    // --- 2. Mensaje de Chat General
    socket.on('general message', (data) => {
        const { id_usuario, usuario, mensaje, isEncrypted } = data;

        const mensajeParaBD = mensaje.startsWith('[UBICACIÓN:') ? mensaje : (isEncrypted ? encrypt(mensaje) : mensaje);

        const sql = "INSERT INTO Mensaje (id_chat, id_usuario, contenido, encriptado) VALUES (?, ?, ?, ?)";
        connection.query(sql, [ID_CHAT_GENERAL, id_usuario, mensajeParaBD, isEncrypted], (err, resultMensaje) => {
            if (err) {
                console.error("❌ Error al guardar mensaje general:", err);
                return;
            }
            console.log(`💬 Mensaje general guardado de ${usuario}. Encriptado: ${isEncrypted}`);

            // Enviar mensaje a todos los clientes (incluido el remitente)
            io.emit('general message', {
                usuario,
                mensaje: mensaje,
                id_usuario,
                fecha_envio: new Date().toISOString(),
                id_mensaje: resultMensaje.insertId
            });
        });
    });

    // --- 3. Mensaje Privado
    socket.on('private message', (data) => {
        const { id_chat, id_remitente, usuario_remitente, mensaje, id_destinatario, isEncrypted } = data;

        const mensajeParaBD = mensaje.startsWith('[UBICACIÓN:') ? mensaje : (isEncrypted ? encrypt(mensaje) : mensaje);

        // A. Guardar en la base de datos
        const sql = "INSERT INTO Mensaje (id_chat, id_usuario, contenido, encriptado) VALUES (?, ?, ?, ?)";
        connection.query(sql, [id_chat, id_remitente, mensajeParaBD, isEncrypted], (err, resultMensaje) => {
            if (err) {
                console.error("❌ Error al guardar mensaje privado:", err);
                return;
            }
            console.log(`💬 Mensaje privado guardado en chat ${id_chat}. Encriptado: ${isEncrypted}`);

            const messageData = {
                id_chat,
                usuario: usuario_remitente,
                mensaje: mensaje,
                id_usuario: id_remitente,
                fecha_envio: new Date().toISOString(),
                id_mensaje: resultMensaje.insertId
            };

            // B. Enviar mensaje de vuelta al remitente (usando su socket ID)
            io.to(socket.id).emit('private message', messageData);

            // C. Enviar al destinatario si está conectado
            const destinatarioSocketId = userSocketMap[id_destinatario];
            if (destinatarioSocketId) {
                if (destinatarioSocketId !== socket.id) {
                    io.to(destinatarioSocketId).emit('private message', messageData);
                }
            }
        });
    });

    // --- EVENTOS PARA VIDEOLLAMADAS ---
    socket.on('call:user', ({ to, from, fromName }) => {
        const targetSocket = userSocketMap[to];
        if (targetSocket) {
            io.to(targetSocket).emit('call:incoming', {
                from,
                fromName
            });
        }
    });

    socket.on('call:accepted', (data) => {
        const targetSocket = userSocketMap[data.from];
        if (targetSocket) {
            io.to(targetSocket).emit('call:accepted', data);
        }
    });

    socket.on('call:rejected', (data) => {
        const targetSocket = userSocketMap[data.from];
        if (targetSocket) {
            io.to(targetSocket).emit('call:rejected', data);
        }
    });

    // ---------------- WEBRTC SEÑALIZACIÓN ----------------

    // Cuando un usuario envía una oferta (offer)
    socket.on('call:offer', ({ to, offer }) => {
        const targetSocketId = userSocketMap[to];
        if (targetSocketId) {
            io.to(targetSocketId).emit('call:offer', {
                from: socketUserMap[socket.id],
                offer
            });
        }
    });

    socket.on('call:answer', ({ to, answer }) => {
        const targetSocketId = userSocketMap[to];
        if (targetSocketId) {
            io.to(targetSocketId).emit('call:answer', {
                from: socketUserMap[socket.id],
                answer
            });
        }
    });

    socket.on('call:ice-candidate', ({ to, candidate }) => {
        const targetSocketId = userSocketMap[to];
        if (targetSocketId) {
            io.to(targetSocketId).emit('call:ice-candidate', {
                from: socketUserMap[socket.id],
                candidate
            });
        }
    });



});


// ---------------- RUTAS HTML ----------------
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../HTML/inicio.html'));
});

app.get('/index', (req, res) => { // Para la ruta explícita /inicio.html
    res.sendFile(path.join(__dirname, '../HTML/index.html'));
});

app.get('/chat', (req, res) => {
    res.sendFile(path.join(__dirname, '../HTML/chatsito.html'));
});

app.get('/videollamada', (req, res) => {
    // Agrega la nueva ruta para el HTML de la videollamada
    res.sendFile(path.join(__dirname, '../HTML/videollamada.html')); 
});

// RUTAS NUEVAS O FALTANTES:
app.get('/QuinielaZo.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../HTML/QuinielaZo.html'));
});

app.get('/recompensas.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../HTML/recompensas.html'));
});

app.get('/Novedades.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../HTML/Novedades.html'));
});

app.get('/perfil.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../HTML/perfil.html'));
});

// ---------------- RUTAS API (MySQL) Y ARCHIVOS ----------------

// RUTA POST para Subida de Archivos
app.post('/upload', upload.single('archivo'), async (req, res) => {
    const { id_chat, id_usuario, usuario, tipo_chat, id_destinatario, isEncrypted } = req.body;
    const archivo = req.file;

    if (!archivo) {
        return res.status(400).json({ message: 'No se ha subido ningún archivo.' });
    }

    const tipoArchivo = archivo.mimetype.startsWith('image/') ? 'imagen' : 'otro';
    const contenidoMensaje = `[ARCHIVO:${tipoArchivo}:${archivo.filename}]`;

    const mensajeParaBD = isEncrypted === 'true' ? encrypt(contenidoMensaje) : contenidoMensaje;

    const sqlMensaje = "INSERT INTO Mensaje (id_chat, id_usuario, contenido, encriptado) VALUES (?, ?, ?, ?)";

    connection.query(sqlMensaje, [id_chat, id_usuario, mensajeParaBD, isEncrypted === 'true'], (err, resultMensaje) => {
        if (err) {
            console.error("❌ Error al guardar mensaje con archivo:", err);
            return res.status(500).json({ message: err.message });
        }

        const id_mensaje = resultMensaje.insertId;

        // Insertar en la tabla Archivo
        const sqlArchivo = "INSERT INTO Archivo (id_mensaje, tipo, nombre_original, ruta_archivo, tamaño) VALUES (?, ?, ?, ?, ?)";
        const rutaRelativa = `/uploads/${archivo.filename}`;

        connection.query(sqlArchivo, [id_mensaje, tipoArchivo, archivo.originalname, rutaRelativa, archivo.size], (err) => {
            if (err) {
                console.error("❌ Error al guardar en tabla Archivo:", err);
                return res.status(500).json({ message: err.message });
            }

            // Notificar a los clientes por Socket.IO
            const messageData = {
                id_chat: parseInt(id_chat),
                usuario: usuario,
                mensaje: contenidoMensaje,
                id_usuario: parseInt(id_usuario),
                fecha_envio: new Date().toISOString(),
                id_mensaje: id_mensaje
            };

            if (tipo_chat === 'general') {
                io.emit('general message', messageData);
            } else if (tipo_chat === 'private') {
                const remitenteSocketId = userSocketMap[id_usuario];
                if (remitenteSocketId) io.to(remitenteSocketId).emit('private message', messageData);

                const destinatarioSocketId = userSocketMap[id_destinatario];
                if (destinatarioSocketId) io.to(destinatarioSocketId).emit('private message', messageData);
            }

            res.json({ message: 'Archivo subido y notificado correctamente' });
        });
    });
});

// RUTA GET para obtener metadata del archivo
app.get('/archivo/:id_mensaje', (req, res) => {
    const { id_mensaje } = req.params;
    const sql = 'SELECT nombre_original, ruta_archivo, tipo FROM Archivo WHERE id_mensaje = ?';

    connection.query(sql, [id_mensaje], (err, results) => {
        if (err) return res.status(500).json({ message: err.message });
        if (results.length === 0) return res.status(404).json({ message: 'Archivo no encontrado' });

        res.json(results[0]);
    });
});

// --- REGISTRO ---
app.post('/register', async (req, res) => {
    const { nombre, apellido, fecha, email, usuario, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = `INSERT INTO Usuario (rol, nombres, apellidos, fechaNacimiento, correo, usuario, contrasena)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`;

    connection.query(sql, [0, nombre, apellido, fecha, email, usuario, hashedPassword], (err) => {
        if (err) {
            if (err.code === 'ER_DUP_ENTRY')
                return res.status(400).json({ message: 'Correo o usuario ya registrado' });
            return res.status(500).json({ message: err.message });
        }
        res.status(201).json({ message: 'Registro exitoso' });
    });
});

// --- LOGIN (MODIFICADO PARA DIAGNÓSTICO) ---
app.post('/login', (req, res) => {
    const { correo, password } = req.body;
    
    console.log("🔍 Intentando login con correo:", correo);

    // IMPORTANTE: Asegúrate de incluir 'rol' en el SELECT
    const sql = 'SELECT id_usuario, usuario, contrasena, activo, rol FROM Usuario WHERE correo = ?';

    connection.query(sql, [correo], async (err, results) => {
        if (err) {
            console.error("❌ Error de Base de Datos:", err);
            return res.status(500).json({ message: err.message });
        }

        // CASO 1: El correo no existe
        if (results.length === 0) {
            console.log("⚠️ Correo no encontrado en la BD.");
            return res.status(401).json({ message: 'ERROR: El correo no existe' });
        }

        const user = results[0];
        console.log("✅ Usuario encontrado:", user.usuario, "| Rol:", user.rol);

        // CASO 2: La contraseña no coincide
        const validPassword = await bcrypt.compare(password, user.contrasena);
        if (!validPassword) {
            console.log("❌ La contraseña no coincide con el hash.");
            return res.status(401).json({ message: 'ERROR: Contraseña incorrecta' });
        }

        // ÉXITO
        console.log("🎉 Login exitoso. Rol:", user.rol);
        
        connection.query('UPDATE Usuario SET activo = 0 WHERE id_usuario = ?', [user.id_usuario]);

        res.json({ 
            id_usuario: user.id_usuario, 
            usuario: user.usuario, 
            rol: user.rol 
        });
    });
});

// --- LOGOUT ---
app.post('/logout', (req, res) => {
    const { id_usuario } = req.body;
    if (!id_usuario) return res.status(400).json({ message: 'ID de usuario requerido' });

    connection.query('UPDATE Usuario SET activo = 1 WHERE id_usuario = ?', [id_usuario], (err) => {
        if (err) return res.status(500).json({ message: err.message });

        if (userSocketMap[id_usuario]) {
            const socketId = userSocketMap[id_usuario];
            delete userSocketMap[id_usuario];
            delete socketUserMap[socketId];
            io.emit('online users', Object.keys(userSocketMap));
        }

        res.json({ message: 'Sesión cerrada' });
    });
});


// --- PERFIL ---
app.get('/profile/:id', (req, res) => {
    const userId = req.params.id;
    const sql = "SELECT nombres, apellidos, usuario, correo, fechaNacimiento, foto, puntos, diamantes FROM Usuario WHERE id_usuario = ?";

    connection.query(sql, [userId], (err, results) => {
        if (err) return res.status(500).json({ message: err.message });
        if (results.length === 0) return res.status(404).json({ message: 'Usuario no encontrado' });

        const user = results[0];
        let fotoBase64 = null;
        if (user.foto) {
            fotoBase64 = `data:image/jpeg;base64,${Buffer.from(user.foto).toString('base64')}`;
        }

        res.json({
            nombres: user.nombres,
            apellidos: user.apellidos,
            usuario: user.usuario,
            correo: user.correo,
            fechaNacimiento: user.fechaNacimiento,
            foto: fotoBase64
        });
    });
});

// --- LISTAR USUARIOS PARA CHAT PRIVADO ---
app.get('/usuarios/:id', (req, res) => {
    const { id } = req.params;
    const sql = 'SELECT id_usuario, usuario FROM Usuario WHERE id_usuario != ?';
    connection.query(sql, [id], (err, results) => {
        if (err) return res.status(500).json({ message: err.message });
        res.json(results);
    });
});

// --- OBTENER MENSAJES DEL CHAT GENERAL (ID_CHAT_GENERAL = 1) ---
app.get('/mensajes/general', (req, res) => {
    const sql = `
        SELECT m.id_mensaje, m.contenido, m.fecha_envio AS fecha, u.usuario, u.id_usuario, m.encriptado
        FROM Mensaje m 
        JOIN Usuario u ON m.id_usuario = u.id_usuario
        WHERE m.id_chat = ?
        ORDER BY m.fecha_envio ASC
    `;
    connection.query(sql, [ID_CHAT_GENERAL], (err, results) => {
        if (err) return res.status(500).json({ message: err.message });

        const mensajesDesencriptados = results.map(m => ({
            id_mensaje: m.id_mensaje,
            mensaje: m.encriptado ? decrypt(m.contenido) : m.contenido,
            fecha: m.fecha,
            usuario: m.usuario,
            id_usuario: m.id_usuario
        }));

        res.json(mensajesDesencriptados);
    });
});

// --- OBTENER MENSAJES DE UN CHAT ESPECÍFICO (Privado o Grupo) ---
app.get('/mensajes/chat/:id_chat', (req, res) => {
    const { id_chat } = req.params;
    const sql = `
        SELECT m.id_mensaje, m.contenido, m.fecha_envio AS fecha, u.usuario, u.id_usuario, m.encriptado
        FROM Mensaje m 
        JOIN Usuario u ON m.id_usuario = u.id_usuario
        WHERE m.id_chat = ?
        ORDER BY m.fecha_envio ASC
    `;
    connection.query(sql, [id_chat], (err, results) => {
        if (err) return res.status(500).json({ message: err.message });

        const mensajesDesencriptados = results.map(m => ({
            id_mensaje: m.id_mensaje,
            mensaje: m.encriptado ? decrypt(m.contenido) : m.contenido,
            fecha: m.fecha,
            usuario: m.usuario,
            id_usuario: m.id_usuario
        }));

        res.json(mensajesDesencriptados);
    });
});

// --- CREAR/OBTENER CHAT PRIVADO ---
app.post('/chat/private', (req, res) => {
    const { id_usuario_1, id_usuario_2 } = req.body;

    const checkSql = `
        SELECT c.id_chat 
        FROM Chat c
        JOIN ChatUsuario cu1 ON c.id_chat = cu1.id_chat
        JOIN ChatUsuario cu2 ON c.id_chat = cu2.id_chat
        WHERE c.id_tipo_chat = ?
          AND cu1.id_usuario = ? AND cu2.id_usuario = ?
          AND cu1.id_usuario != cu2.id_usuario
        LIMIT 1;
    `;

    const checkParams = [ID_TIPO_CHAT_PRIVADO, id_usuario_1, id_usuario_2];

    connection.query(checkSql, checkParams, (err, results) => {
        if (err) return res.status(500).json({ message: err.message });

        if (results.length > 0) {
            return res.json({ id_chat: results[0].id_chat });
        }

        connection.beginTransaction((err) => {
            if (err) return res.status(500).json({ message: err.message });

            const createChatSql = 'INSERT INTO Chat (id_tipo_chat, creado_por) VALUES (?, ?)';
            connection.query(createChatSql, [ID_TIPO_CHAT_PRIVADO, id_usuario_1], (err, resultChat) => {
                if (err) {
                    return connection.rollback(() => res.status(500).json({ message: 'Error al crear chat: ' + err.message }));
                }

                const newChatId = resultChat.insertId;

                const users = [[newChatId, id_usuario_1], [newChatId, id_usuario_2]];
                const createUsersSql = 'INSERT INTO ChatUsuario (id_chat, id_usuario) VALUES ?';

                connection.query(createUsersSql, [users], (err) => {
                    if (err) {
                        return connection.rollback(() => res.status(500).json({ message: 'Error al añadir usuarios: ' + err.message }));
                    }

                    connection.commit((err) => {
                        if (err) {
                            return connection.rollback(() => res.status(500).json({ message: 'Error al hacer commit: ' + err.message }));
                        }
                        res.status(201).json({ id_chat: newChatId });
                    });
                });
            });
        });
    });
});

// --- HERRAMIENTA PARA RESETEAR CONTRASEÑA ---
// Pégalo antes de server.listen
app.get('/reset/:correo/:nuevaPassword', async (req, res) => {
    const { correo, nuevaPassword } = req.params;
    
    // 1. Encriptamos la nueva contraseña con la MISMA librería que usa el login
    const hash = await bcrypt.hash(nuevaPassword, 10);
    
    // 2. Actualizamos y forzamos el Rol a 1 (Administrador)
    const sql = 'UPDATE Usuario SET contrasena = ?, rol = 1 WHERE correo = ?';
    
    connection.query(sql, [hash, correo], (err, result) => {
        if (err) return res.send("Error SQL: " + err.message);
        
        if (result.affectedRows === 0) {
            return res.send(`❌ No encontré ningún usuario con el correo: <b>${correo}</b>`);
        }
        
        res.send(`
            <h1 style="color:green">¡ÉXITO! ✅</h1>
            <p>El usuario <b>${correo}</b> ha sido actualizado.</p>
            <p>Nueva contraseña: <b>${nuevaPassword}</b></p>
            <p>Rol: <b>Administrador (1)</b></p>
            <br>
            <a href="/"> <button style="padding:10px; cursor:pointer;">➡️ IR AL LOGIN</button> </a>
        `);
    });
});

// ================================================================
// ⬇️⬇️⬇️ RUTAS DE ADMINISTRACIÓN (NUEVAS) ⬇️⬇️⬇️
// ================================================================

// --- 1. GESTIÓN DE PARTIDOS (MUNDIAL) ---

// Obtener todos los partidos
app.get('/admin/matches', (req, res) => {
    const sql = "SELECT * FROM Partido ORDER BY fecha_partido ASC, id_partido ASC";
    connection.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// Agregar nuevo partido
app.post('/admin/matches', (req, res) => {
    const { equipo1, equipo2, fase } = req.body;
    const sql = "INSERT INTO Partido (equipo1, equipo2, fase, estatus) VALUES (?, ?, ?, 'pendiente')";
    connection.query(sql, [equipo1, equipo2, fase], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Partido agregado", id: result.insertId });
    });
});

// Eliminar partido
app.delete('/admin/matches/:id', (req, res) => {
    const { id } = req.params;
    const sql = "DELETE FROM Partido WHERE id_partido = ?";
    connection.query(sql, [id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Partido eliminado" });
    });
});

// Marcar partido como completado (y opcionalmente guardar marcador)
app.put('/admin/matches/:id/complete', (req, res) => {
    const { id } = req.params;
    // Por ahora solo cambiamos el estatus, luego podrías recibir goles también
    const sql = "UPDATE Partido SET estatus = 'finalizado' WHERE id_partido = ?";
    connection.query(sql, [id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Partido finalizado" });
    });
});


// --- 2. GESTIÓN DE TAREAS ---

// Obtener tareas
app.get('/admin/tasks', (req, res) => {
    // Obtenemos solo las tareas globales (id_grupo IS NULL)
    const sql = "SELECT * FROM Tarea WHERE id_grupo IS NULL ORDER BY id_tarea DESC";
    connection.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// Agregar tarea (CON DIAMANTES 💎) -> ¡ESTA ES LA PARTE QUE CAMBIÓ!
app.post('/admin/tasks', (req, res) => {
    const { titulo, descripcion, diamantes } = req.body; // Ahora recibimos también los diamantes
    
    // Insertamos guardando el valor en 'recompensa_diamantes'
    // Si no se especifica cantidad, usamos 5 por defecto (diamantes || 5)
    const sql = "INSERT INTO Tarea (titulo, descripcion, recompensa_diamantes, completada) VALUES (?, ?, ?, 0)";
    
    connection.query(sql, [titulo, descripcion, diamantes || 5], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Tarea creada", id: result.insertId });
    });
});

// Eliminar tarea
app.delete('/admin/tasks/:id', (req, res) => {
    const { id } = req.params;
    const sql = "DELETE FROM Tarea WHERE id_tarea = ?";
    connection.query(sql, [id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Tarea eliminada" });
    });
});


// --- 3. GESTIÓN DE INSIGNIAS (RECOMPENSAS) ---

// Obtener insignias
app.get('/admin/badges', (req, res) => {
    const sql = "SELECT * FROM Insignia ORDER BY id_insignia DESC";
    connection.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// Eliminar insignia
app.delete('/admin/badges/:id', (req, res) => {
    const { id } = req.params;
    const sql = "DELETE FROM Insignia WHERE id_insignia = ?";
    connection.query(sql, [id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Insignia eliminada" });
    });
});

// ================================================================
// ⬆️⬆️⬆️ FIN RUTAS DE ADMINISTRACIÓN ⬆️⬆️⬆️
// ================================================================

// ================================================================
// ⬇️⬇️⬇️ SECCIÓN MAESTRA DE QUINIELAS Y PRONÓSTICOS ⬇️⬇️⬇️
// ================================================================

// --- 1. ADMIN: Crear una Jornada completa (Varios partidos a la vez) ---
app.post('/admin/quiniela/batch', (req, res) => {
    const { nombreJornada, partidos } = req.body; 
    if (!partidos || partidos.length === 0) return res.status(400).json({message: "No hay partidos"});

    // Preparamos los valores para una inserción masiva
    const values = partidos.map(p => [p.eq1, p.eq2, nombreJornada, 'pendiente']);
    const sql = "INSERT INTO Partido (equipo1, equipo2, fase, estatus) VALUES ?";
    
    connection.query(sql, [values], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: `Jornada '${nombreJornada}' creada con ${result.affectedRows} partidos.` });
    });
});

// --- 2. ADMIN: Obtener lista de jornadas para el visualizador ---
app.get('/admin/quiniela/list', (req, res) => {
    const sql = "SELECT fase, COUNT(*) as total, estatus FROM Partido GROUP BY fase ORDER BY fase";
    connection.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// --- 3. ADMIN: Eliminar una Jornada completa ---
app.delete('/admin/quiniela/:nombreJornada', (req, res) => {
    const { nombreJornada } = req.params;
    const sql = "DELETE FROM Partido WHERE fase = ?";
    connection.query(sql, [nombreJornada], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: `Jornada eliminada` });
    });
});

// --- 4. ADMIN: Renombrar una Jornada ---
app.put('/admin/quiniela/:nombreJornada', (req, res) => {
    const { nombreJornada } = req.params;
    const { nuevoNombre } = req.body;
    const sql = "UPDATE Partido SET fase = ? WHERE fase = ?";
    connection.query(sql, [nuevoNombre, nombreJornada], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: `Jornada actualizada` });
    });
});

// --- 5. ADMIN: Registrar resultado de un partido y calcular puntos ---
app.put('/admin/matches/:id/result', (req, res) => {
    const { id } = req.params;
    const { goles1, goles2 } = req.body;

    // A. Actualizar el partido con el resultado final
    const sqlPartido = "UPDATE Partido SET goles_equipo1 = ?, goles_equipo2 = ?, estatus = 'finalizado' WHERE id_partido = ?";
    
    connection.query(sqlPartido, [goles1, goles2, id], (err, result) => {
        if (err) return res.status(500).json({ error: "Error al actualizar partido: " + err.message });

        // B. Calcular puntos para los pronósticos de este partido
        const sqlPuntos = `
            UPDATE Pronostico p
            JOIN Partido m ON p.id_partido = m.id_partido
            SET p.puntos_ganados = CASE
                -- Acierto Exacto (3 Puntos)
                WHEN p.prediccion_eq1 = m.goles_equipo1 AND p.prediccion_eq2 = m.goles_equipo2 THEN 3
                -- Acierto Ganador o Empate (1 Punto)
                WHEN (p.prediccion_eq1 > p.prediccion_eq2 AND m.goles_equipo1 > m.goles_equipo2) OR 
                     (p.prediccion_eq1 < p.prediccion_eq2 AND m.goles_equipo1 < m.goles_equipo2) OR 
                     (p.prediccion_eq1 = p.prediccion_eq2 AND m.goles_equipo1 = m.goles_equipo2)
                THEN 1
                ELSE 0
            END
            WHERE p.id_partido = ?;
        `;

        connection.query(sqlPuntos, [id], (err2, result2) => {
            if (err2) return res.status(500).json({ error: "Error calculando puntos: " + err2.message });

            // C. Actualizar el puntaje total en la tabla de Usuarios
            const sqlTotal = `
                UPDATE Usuario u
                SET u.puntos = (SELECT COALESCE(SUM(p.puntos_ganados), 0) FROM Pronostico p WHERE p.id_usuario = u.id_usuario);
            `;

            connection.query(sqlTotal, (err3, result3) => {
                if (err3) return res.status(500).json({ error: "Error actualizando totales: " + err3.message });
                res.json({ message: "Resultado guardado y puntos calculados exitosamente." });
            });
        });
    });
});

// --- 6. ADMIN/USUARIO: Obtener Tabla de Líderes (Ranking) ---
app.get('/admin/leaderboard', (req, res) => {
    const sql = "SELECT id_usuario, usuario, puntos FROM Usuario WHERE rol = 0 ORDER BY puntos DESC";
    connection.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// --- 7. USUARIO: Obtener todas las jornadas disponibles ---
app.get('/api/quiniela/jornadas', (req, res) => {
    const sql = "SELECT DISTINCT fase FROM Partido WHERE estatus = 'pendiente' ORDER BY fase";
    connection.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results.map(r => r.fase));
    });
});

// --- 8. USUARIO: Obtener partidos de una jornada específica ---
app.get('/api/quiniela/partidos/:jornada', (req, res) => {
    const { jornada } = req.params;
    const sql = "SELECT * FROM Partido WHERE fase = ? AND estatus = 'pendiente'";
    connection.query(sql, [jornada], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// --- 9. USUARIO: Guardar Pronósticos ---
app.post('/api/pronosticos', (req, res) => {
    const { id_usuario, predicciones } = req.body; 
    if (!predicciones || predicciones.length === 0) return res.status(400).json({message: "Sin datos"});

    const queries = predicciones.map(p => {
        return new Promise((resolve, reject) => {
            const sql = `
                INSERT INTO Pronostico (id_usuario, id_partido, prediccion_eq1, prediccion_eq2)
                VALUES (?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE prediccion_eq1 = ?, prediccion_eq2 = ?
            `;
            connection.query(sql, [id_usuario, p.id_partido, p.g1, p.g2, p.g1, p.g2], (err, result) => {
                if (err) reject(err); else resolve(result);
            });
        });
    });

    Promise.all(queries)
        .then(() => res.json({ message: "Pronósticos guardados correctamente" }))
        .catch(err => res.status(500).json({ error: err.message }));
});

// --- 10. USUARIO: Obtener Historial (SOLO FINALIZADAS) ---
app.get('/api/pronosticos/historial/:id_usuario', (req, res) => {
    const { id_usuario } = req.params;
    const sql = `
        SELECT 
            p.equipo1, p.equipo2, p.fase, p.estatus,
            p.goles_equipo1 AS real1, p.goles_equipo2 AS real2,
            pr.prediccion_eq1 AS pred1, pr.prediccion_eq2 AS pred2,
            pr.puntos_ganados
        FROM Pronostico pr
        JOIN Partido p ON pr.id_partido = p.id_partido
        WHERE pr.id_usuario = ? AND p.estatus = 'finalizado'
        ORDER BY p.id_partido DESC
    `;
    connection.query(sql, [id_usuario], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// ================================================================
// ⬆️⬆️⬆️ FIN ZONA COMPLETA ⬆️⬆️⬆️
// ================================================================

// ================================================================
// ⬇️⬇️⬇️ RUTAS DE RECOMPENSAS Y TAREAS (USUARIO) ⬇️⬇️⬇️
// ================================================================

// --- 1. Obtener Tareas (Globales) y verificar si el usuario ya las hizo ---
app.get('/api/tasks/user/:id_usuario', (req, res) => {
    const { id_usuario } = req.params;
    // Traemos todas las tareas globales (id_grupo NULL)
    // Y usamos LEFT JOIN para ver si este usuario ya la tiene en la tabla UsuarioTarea
    const sql = `
        SELECT t.*, 
               CASE WHEN ut.id_usuario IS NOT NULL THEN 1 ELSE 0 END as completada_por_usuario
        FROM Tarea t
        LEFT JOIN UsuarioTarea ut ON t.id_tarea = ut.id_tarea AND ut.id_usuario = ?
        WHERE t.id_grupo IS NULL
        ORDER BY t.id_tarea DESC
    `;
    connection.query(sql, [id_usuario], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// --- 2. Marcar Tarea como Completada y dar sus DIAMANTES específicos 💎 (SIN LÍMITE) ---
app.post('/api/tasks/complete', (req, res) => {
    const { id_usuario, id_tarea } = req.body;

    // 1. Primero verificamos si ya la hizo para no regalar diamantes dobles
    const sqlCheck = "SELECT * FROM UsuarioTarea WHERE id_usuario = ? AND id_tarea = ?";
    connection.query(sqlCheck, [id_usuario, id_tarea], (errCheck, resultsCheck) => {
        if (errCheck) return res.status(500).json({ error: errCheck.message });
        if (resultsCheck.length > 0) return res.json({ message: "Tarea ya estaba completada." });

        // 2. Si no la ha hecho, consultamos CUÁNTOS diamantes vale esa tarea
        const sqlTarea = "SELECT recompensa_diamantes FROM Tarea WHERE id_tarea = ?";
        connection.query(sqlTarea, [id_tarea], (errTask, resultsTask) => {
            if (errTask) return res.status(500).json({ error: errTask.message });
            if (resultsTask.length === 0) return res.status(404).json({ message: "Tarea no encontrada" });

            // Obtenemos el valor real de la tarea (o 5 por defecto si es null)
            const diamantesGanar = resultsTask[0].recompensa_diamantes || 5;

            // 3. Registramos la tarea como hecha en la tabla intermedia
            const sqlInsert = "INSERT INTO UsuarioTarea (id_usuario, id_tarea) VALUES (?, ?)";
            connection.query(sqlInsert, [id_usuario, id_tarea], (errInsert) => {
                if (errInsert) return res.status(500).json({ error: errInsert.message });

                // 4. Entregamos los diamantes correspondientes al usuario (SUMA DIRECTA SIN LÍMITE)
                const sqlUpdate = "UPDATE Usuario SET diamantes = diamantes + ? WHERE id_usuario = ?";
                connection.query(sqlUpdate, [diamantesGanar, id_usuario], (errUpdate) => {
                    if (errUpdate) console.error("Error entregando diamantes:", errUpdate);
                    
                    res.json({ 
                        message: "Tarea completada exitosamente", 
                        diamantesGanados: diamantesGanar 
                    });
                });
            });
        });
    });
});

// --- 3. GESTIÓN DE INSIGNIAS (RECOMPENSAS) ---

// Obtener insignias
app.get('/admin/badges', (req, res) => {
    const sql = "SELECT * FROM Insignia ORDER BY precio_puntos ASC";
    connection.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// Agregar insignia (ESTA ES LA PARTE IMPORTANTE QUE TE FALTA ACTUALIZAR)
app.post('/admin/badges', (req, res) => {
    const { nombre, descripcion, imagen_url, precio_puntos } = req.body;
    
    // Aquí está la clave: agregamos precio_puntos al INSERT
    const sql = "INSERT INTO Insignia (nombre, descripcion, imagen_url, precio_puntos) VALUES (?, ?, ?, ?)";
    
    connection.query(sql, [nombre, descripcion, imagen_url, precio_puntos], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Insignia creada", id: result.insertId });
    });
});

// Eliminar insignia
app.delete('/admin/badges/:id', (req, res) => {
    const { id } = req.params;
    const sql = "DELETE FROM Insignia WHERE id_insignia = ?";
    connection.query(sql, [id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Insignia eliminada" });
    });
});

// ================================================================
// ⬇️⬇️⬇️ RUTAS DE RECOMPENSAS PARA EL USUARIO (FALTANTES) ⬇️⬇️⬇️
// ================================================================

// --- 1. Obtener Tareas y saber si ya las completé ---
app.get('/api/tasks/user/:id_usuario', (req, res) => {
    const { id_usuario } = req.params;
    const sql = `
        SELECT t.*, 
               CASE WHEN ut.id_usuario IS NOT NULL THEN 1 ELSE 0 END as completada_por_usuario
        FROM Tarea t
        LEFT JOIN UsuarioTarea ut ON t.id_tarea = ut.id_tarea AND ut.id_usuario = ?
        WHERE t.id_grupo IS NULL
        ORDER BY t.id_tarea DESC
    `;
    connection.query(sql, [id_usuario], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// --- 2. Marcar Tarea como Completada ---
app.post('/api/tasks/complete', (req, res) => {
    const { id_usuario, id_tarea } = req.body;
    const sql = "INSERT INTO UsuarioTarea (id_usuario, id_tarea) VALUES (?, ?)";
    
    connection.query(sql, [id_usuario, id_tarea], (err, result) => {
        if (err) {
            if (err.code === 'ER_DUP_ENTRY') return res.json({ message: "Tarea ya estaba completada." });
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: "Tarea completada exitosamente" });
    });
});

// --- 3. Obtener Insignias y calcular si ya las gané por puntos ---
app.get('/api/badges/user/:id_usuario', (req, res) => {
    const { id_usuario } = req.params;
    
    // Modificamos la consulta para comparar los puntos del usuario con el precio de la insignia
    // Usamos CROSS JOIN para traer los datos del usuario y compararlos con cada insignia
    const sql = `
        SELECT i.*, 
               CASE 
                 -- Si los puntos del usuario son mayores o iguales al precio, la tiene (1)
                 WHEN u.puntos >= i.precio_puntos THEN 1 
                 -- Si ya se le otorgó manualmente (por si acaso), la tiene (1)
                 WHEN ui.id_usuario IS NOT NULL THEN 1 
                 -- Si no cumple nada, no la tiene (0)
                 ELSE 0 
               END as obtenida
        FROM Insignia i
        CROSS JOIN Usuario u 
        LEFT JOIN UsuarioInsignia ui ON i.id_insignia = ui.id_insignia AND ui.id_usuario = u.id_usuario
        WHERE u.id_usuario = ?
        ORDER BY i.precio_puntos ASC
    `;
    
    connection.query(sql, [id_usuario], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});
// ================================================================

// ---------------- INICIO DEL SERVIDOR ----------------
server.listen(port, "0.0.0.0", () => {
    console.log("🚀 Servidor corriendo en:");
    console.log(`👉 PC:      http://localhost:${port}`);
    console.log(`👉 Celular: http://172.20.10.2:${port}`);
});