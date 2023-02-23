const Libp2p = require('libp2p');
const WebrtcStar = require('libp2p-webrtc-star');
const Websockets = require('libp2p-websockets');
const Mplex = require('libp2p-mplex');
const Secio = require('libp2p-secio');
const KadDHT = require('libp2p-kad-dht');
const crypto = require('crypto');
const OrbitDB = require('orbit-db');
const nacl = require('libsodium-wrappers');


// Set up Libp2p node with the desired options
Libp2p.create({
    addresses: {
        listen: ['/dns4/wrtc-star1.par.dwebops.pub/tcp/443/wss/p2p-webrtc-star'],
    },
    modules: {
        transport: [WebrtcStar, Websockets],
        streamMuxer: [Mplex],
        connEncryption: [Secio],
        dht: KadDHT,
    },
}).then((node) => {
    // Set up OrbitDB with the desired options
    OrbitDB.createInstance(node, { directory: './orbitdb' }).then((orbitdb) => {
        // Your code that uses node and orbitdb goes here
    });
}).catch((err) => {
    console.error(err);
});

// Set up OrbitDB with the desired options
const orbitdb = await OrbitDB.createInstance(node, { directory: './orbitdb' });

// Define the Room class
class Room {
    constructor(name, password) {
        this.name = name;
        this.password = crypto.createHash('sha256').update(password).digest('base64');
        this.users = [];
        this.chat = orbitdb.kvstore(name);
        this.chat.load();
    }

    async join(username, password) {
        const hashedPassword = crypto.createHash('sha256').update(password).digest('base64');
        if (hashedPassword !== this.password) {
            throw new Error('Incorrect password');
        }
        if (this.users.includes(username)) {
            throw new Error('Username already taken');
        }
        this.users.push(username);
        await this.chat.put(username, '');
    }

    async leave(username) {
        const index = this.users.indexOf(username);
        if (index !== -1) {
            this.users.splice(index, 1);
            await this.chat.del(username);
        }
    }

    async broadcast(username, message) {
        const value = `${username}: ${message}`;
        await this.chat.put(username, value);
        for (const user of this.users) {
            if (user !== username) {
                await this.chat.del(user);
                await this.chat.put(user, value);
            }
        }
    }

    async getMessages() {
        const messages = {};
        for (const user of this.users) {
            const value = await this.chat.get(user);
            if (value) {
                messages[user] = value;
            }
        }
        return messages;
    }

}

class User {
    constructor(username, password, publicKey, privateKey) {
        this.username = username;
        this.password = password;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    async encryptData(data) {
        await nacl.ready;
        const nonce = nacl.randombytes_buf(nacl.crypto_secretbox_NONCEBYTES);
        const message = nacl.crypto_secretbox_easy(data, nonce, this.privateKey);
        const encrypted = new Uint8Array(nonce.length + message.length);
        encrypted.set(nonce);
        encrypted.set(message, nonce.length);
        return encrypted;
    }

    async decryptData(encryptedData) {
        await nacl.ready;
        const nonce = encryptedData.slice(0, nacl.crypto_secretbox_NONCEBYTES);
        const ciphertext = encryptedData.slice(nacl.crypto_secretbox_NONCEBYTES);
        const decrypted = nacl.crypto_secretbox_open_easy(ciphertext, nonce, this.publicKey);
        return decrypted;
    }
}

const userManager = {
    users: [],
    currentUser: null,

    async initialize() {
        await nacl.ready;
    },

    getCurrentUser() {
        return this.currentUser;
    },

    setCurrentUser(user) {
        this.currentUser = user;
    },

    async createUser(username, password) {
        await nacl.ready;
        const keyPair = nacl.crypto_box_keypair();
        const publicKey = keyPair.publicKey;
        const privateKey = keyPair.privateKey;
        const user = new User(username, password, publicKey, privateKey);
        this.users.push(user);
        return user;
    },

    getUserByUsername(username) {
        const user = this.users.find(user => user.username === username);
        return user;
    }
};