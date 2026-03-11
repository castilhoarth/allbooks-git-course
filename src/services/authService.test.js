const { createToken, verifyToken } = require('./authService');
const jwt = require('jsonwebtoken');

describe('AuthService', () => {
    describe('createToken', () => {
        it('should create a valid JWT token with default expiration', () => {
            const payload = { email: 'test@test.com', id: 1 };
            const token = createToken(payload);

            expect(token).toBeDefined();
            expect(typeof token).toBe('string');
            expect(token.split('.').length).toBe(3); // JWT has 3 parts
        });

        it('should create a token with custom expiration time', () => {
            const payload = { email: 'admin@test.com', id: 2 };
            const token = createToken(payload, '1h');

            expect(token).toBeDefined();
            expect(typeof token).toBe('string');
        });

        it('should encode the payload correctly in the token', () => {
            const payload = { email: 'user@test.com', id: 123, role: 'admin' };
            const token = createToken(payload);

            const decoded = jwt.decode(token);
            expect(decoded.email).toBe(payload.email);
            expect(decoded.id).toBe(payload.id);
            expect(decoded.role).toBe(payload.role);
        });

        it('should create different tokens for different payloads', () => {
            const payload1 = { email: 'user1@test.com', id: 1 };
            const payload2 = { email: 'user2@test.com', id: 2 };

            const token1 = createToken(payload1);
            const token2 = createToken(payload2);

            expect(token1).not.toBe(token2);
        });
    });

    describe('verifyToken', () => {
        it('should verify a valid token successfully', () => {
            const payload = { email: 'verify@test.com', id: 99 };
            const token = createToken(payload);

            const result = verifyToken(token);

            expect(result).toBeDefined();
            expect(result.email).toBe(payload.email);
            expect(result.id).toBe(payload.id);
        });

        it('should return error for invalid token signature', () => {
            const payload = { email: 'fake@test.com', id: 1 };
            const fakeToken = jwt.sign(payload, 'wrong-secret-key');

            const result = verifyToken(fakeToken);

            expect(result).toBeDefined();
            expect(result.name).toBe('JsonWebTokenError');
        });

        it('should return error for malformed token', () => {
            const malformedToken = 'this.is.not.a.valid.token';

            const result = verifyToken(malformedToken);

            expect(result).toBeDefined();
            expect(result.name).toBe('JsonWebTokenError');
        });

        it('should return error for empty token', () => {
            const result = verifyToken('');

            expect(result).toBeDefined();
            expect(result.name).toBe('JsonWebTokenError');
        });

        it('should preserve all custom fields from the payload', () => {
            const payload = {
                email: 'custom@test.com',
                id: 555,
                role: 'user',
                permissions: ['read', 'write']
            };
            const token = createToken(payload);

            const result = verifyToken(token);

            expect(result.email).toBe(payload.email);
            expect(result.id).toBe(payload.id);
            expect(result.role).toBe(payload.role);
            expect(result.permissions).toEqual(payload.permissions);
        });
    });
});
