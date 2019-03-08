var helpers = require('./helpers');
var forge = require('node-forge');
var pki = forge.pki;
var rsa = pki.rsa;

const AES_STANDARD = 'AES-CBC';

class Crypt {

    constructor(options) {
        options = options || {};

        // Add some entropy if available
        if (options.entropy) {
            this._entropy(options.entropy);
        }
    }

    fingerprint(publicKey) {
        return pki.getPublicKeyFingerprint(publicKey, {
            encoding: 'hex',
            delimiter: ':'
        });
    }

    signature(privateKey, message) {
        // Create SHA-1 checksum
        var csum = forge.md.sha1.create();
        csum.update(message, 'utf8');

        // Sign checksum with private key
        if (typeof privateKey === 'string') privateKey = pki.privateKeyFromPem(privateKey);
        var signature = privateKey.sign(csum);

        // Return base64 encoded signature
        return forge.util.encode64(signature);
    }

    verify(publicKey, signature, decrypted) {
        // Return false if ne signature is defined
        if (!signature) return false;

        // Create SHA-1 checksum
        var csum = forge.md.sha1.create();
        csum.update(decrypted, 'utf8');

        // Base64 decode signature
        signature = forge.util.decode64(signature);

        // Sign checksum with private key
        if (typeof publicKey === 'string') publicKey = pki.publicKeyFromPem(publicKey);
        
        // Verify signature
        var verified = publicKey.verify(csum.digest().getBytes(), signature);
        return verified
    }

    encrypt(publicKeys, message, signature) {
        var self = this;

        var payload = {};

        // Generate flat array of keys
        publicKeys = helpers.toArray(publicKeys);
        
        // Map PEM keys to forge public key objects
        publicKeys = publicKeys.map(function(key) {
            if (typeof key === 'string')
                return pki.publicKeyFromPem(key)
            return key;
        });

        // Generate random keys
        var iv = forge.random.getBytesSync(32);
        var key = forge.random.getBytesSync(32);

        // Encrypt random key with all of the public keys
        var encryptedKeys = {};
        publicKeys.forEach(function(publicKey) {
            var encryptedKey = publicKey.encrypt(key, 'RSA-OAEP');
            var fingerprint = self.fingerprint(publicKey);
            encryptedKeys[fingerprint] = forge.util.encode64(encryptedKey);
        });

        // Create buffer and cipher
        var buffer = forge.util.createBuffer(message, 'utf8');
        var cipher = forge.cipher.createCipher(AES_STANDARD, key);

        // Actual encryption
        cipher.start({iv: iv});
        cipher.update(buffer);
        cipher.finish();
        
        // Attach encrypted message int payload
        payload.v = helpers.version();
        payload.iv = forge.util.encode64(iv);
        payload.keys = encryptedKeys;
        payload.cipher = forge.util.encode64(cipher.output.data);
        payload.signature = signature;

        // Return encrypted message
        var output = JSON.stringify(payload);
        return output;
    }
	
	encryptMagic(publicKeys, message) {
        var self = this;
        publicKeys = helpers.toArray(publicKeys);
        publicKeys = publicKeys.map(function(key) {
            if (typeof key === 'string')
                return pki.publicKeyFromPem(key)
            return key;
        });
        var encryptedKeys = {};
		var result='';
        publicKeys.forEach(function(publicKey) {
            var encryptedMessage = publicKey.encrypt(message, 'RSA-OAEP');
            var fingerprint = self.fingerprint(publicKey);
            encryptedKeys[fingerprint] = forge.util.encode64(encryptedMessage);
			result = encryptedKeys[fingerprint];
        });
        return result;
    }
	
	decryptMagic(privateKey, encrypted) {
		
        if (typeof privateKey === 'string') privateKey = pki.privateKeyFromPem(privateKey);
        var keyBytes = forge.util.decode64(encrypted);
        var output = privateKey.decrypt(keyBytes, 'RSA-OAEP');
        return output
    }
	
	decrypt(cipher, key, iv){
		// Create buffer and decipher
		cipher = forge.util.decode64(cipher);
        var buffer = forge.util.createBuffer(cipher);
        var decipher = forge.cipher.createDecipher(AES_STANDARD, key);

        // Actual decryption
        decipher.start({iv: iv});
        decipher.update(buffer);
        decipher.finish();

        // Return utf-8 encoded bytes
        var bytes = decipher.output.getBytes();
        var decrypted = forge.util.decodeUtf8(bytes);
		return decrypted;
	}

    _validate(encrypted) {
        try {
            // Try to parse encrypted message
            var p = JSON.parse(encrypted);

            return (
                // Check required properties
                p.hasOwnProperty('v') &&
                p.hasOwnProperty('iv') &&
                p.hasOwnProperty('keys') &&
                p.hasOwnProperty('cipher'))

        } catch (e) {
            // Invalid message
            // Log the error and then return false
            console.warn(e);
            return false
        }
    }

    _entropy(input) {
        bytes = forge.util.encodeUtf8(String(input));
        forge.random.collect(bytes);
    }
}

module.exports = Crypt;
