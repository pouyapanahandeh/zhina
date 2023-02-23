const Libp2p = require('libp2p');
const WebrtcStar = require('libp2p-webrtc-star');
const Websockets = require('libp2p-websockets');
const Mplex = require('libp2p-mplex');
const Secio = require('libp2p-secio');
const KadDHT = require('libp2p-kad-dht');
const crypto = require('crypto');
const OrbitDB = require('orbit-db');

// Set up Libp2p node with the desired options
const node = await Libp2p.create({
    addresses: {
        listen: ['/dns4/wrtc-star1.par.dwebops.pub/tcp/443/wss/p2p-webrtc-star'],
    },
    modules: {
        transport: [WebrtcStar, Websockets],
        streamMuxer: [Mplex],
        connEncryption: [Secio],
        dht: KadDHT,
    },
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
    constructor(username, password, keyPair) {
        this.username = username;
        this.password = password;
        this.keyPair = keyPair;
    }

    encryptData(data) {
        const encrypted = encrypt(data, this.keyPair.publicKey);
        return encrypted;
    }

    decryptData(encryptedData) {
        const decrypted = decrypt(encryptedData, this.keyPair.privateKey);
        return decrypted;
    }
}

const userManager = {
    users: [],
    currentUser: null,

    getCurrentUser() {
        return this.currentUser;
    },

    setCurrentUser(user) {
        this.currentUser = user;
    },

    createUser(username, password) {
        const keyPair = generateKeyPair();
        const user = new User(username, password, keyPair);
        this.users.push(user);
        return user;
    },

    getUserByUsername(username) {
        const user = this.users.find(user => user.username === username);
        return user;
    }
};
