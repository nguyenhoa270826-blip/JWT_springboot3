package vn.iotstar.services;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    private RSAKey rsaJwk;

    @PostConstruct
    public void initRsaKey() {
        try {
            this.rsaJwk = new RSAKeyGenerator(2048)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID("key1")
                    .generate();
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot initialize RSA JWK", e);
        }
    }

    public String extractUsername(String token) {
        return extractClaim(token, JWTClaimsSet::getSubject);
    }

    public <T> T extractClaim(String token, Function<JWTClaimsSet, T> claimsResolver) {
        final JWTClaimsSet claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public long getExpirationTime() {
        return jwtExpiration;
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        try {
            Date now = new Date(System.currentTimeMillis());
            Date exp = new Date(System.currentTimeMillis() + expiration);

            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .subject(userDetails.getUsername())
                    .issuer("vn.iotstar")
                    .issueTime(now)
                    .expirationTime(exp)
                    .jwtID(UUID.randomUUID().toString());

            for (Map.Entry<String, Object> entry : extraClaims.entrySet()) {
                claimsBuilder.claim(entry.getKey(), entry.getValue());
            }

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                    .type(JOSEObjectType.JWT)
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claimsBuilder.build());
            JWSSigner signer = new MACSigner(getSignInKey());
            signedJWT.sign(signer);

            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Error generating JWT with Nimbus", e);
        }
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, JWTClaimsSet::getExpirationTime);
    }

    private JWTClaimsSet extractAllClaims(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new MACVerifier(getSignInKey());

            if (!signedJWT.verify(verifier)) {
                throw new SecurityException("The JWT signature is invalid");
            }

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            if (claims.getExpirationTime() != null && claims.getExpirationTime().before(new Date())) {
                throw new IllegalStateException("The JWT token has expired");
            }
            return claims;
        } catch (ParseException | JOSEException e) {
            throw new SecurityException("The JWT signature is invalid", e);
        }
    }

    private byte[] getSignInKey() {
        try {
            byte[] decoded = Base64.getDecoder().decode(secretKey);
            if (decoded.length >= 32) {
                return decoded;
            }
        } catch (IllegalArgumentException ignored) {
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(secretKey.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return secretKey.getBytes(StandardCharsets.UTF_8);
        }
    }

    public String generateRsaToken(UserDetails userDetails, String role) {
        try {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(userDetails.getUsername())
                    .claim("name", userDetails.getUsername())
                    .claim("role", role)
                    .issuer("vn.iotstar")
                    .issueTime(new Date())
                    .expirationTime(new Date(System.currentTimeMillis() + jwtExpiration))
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(JOSEObjectType.JWT)
                    .keyID(rsaJwk.getKeyID())
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claims);
            signedJWT.sign(new RSASSASigner(rsaJwk));
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Cannot sign RSA JWT", e);
        }
    }

    public Map<String, Object> verifyRsaToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new RSASSAVerifier(rsaJwk.toRSAPublicKey());
            if (!signedJWT.verify(verifier)) {
                throw new SecurityException("The RSA JWT signature is invalid");
            }
            return signedJWT.getJWTClaimsSet().getClaims();
        } catch (ParseException | JOSEException e) {
            throw new SecurityException("Cannot verify RSA JWT", e);
        }
    }

    public Map<String, Object> getPublicJwkSet() {
        return new JWKSet(rsaJwk.toPublicJWK()).toJSONObject();
    }

    public String generateEncryptedJweToken(String subject, Map<String, Object> payloadData) {
        try {
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issuer("vn.iotstar")
                    .issueTime(new Date())
                    .expirationTime(new Date(System.currentTimeMillis() + jwtExpiration));

            if (payloadData != null) {
                payloadData.forEach(builder::claim);
            }

            JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
            EncryptedJWT encryptedJWT = new EncryptedJWT(header, builder.build());
            encryptedJWT.encrypt(new DirectEncrypter(getSignInKey()));
            return encryptedJWT.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Cannot encrypt JWE token", e);
        }
    }

    public Map<String, Object> decryptJweToken(String jweString) {
        try {
            EncryptedJWT encryptedJWT = EncryptedJWT.parse(jweString);
            encryptedJWT.decrypt(new DirectDecrypter(getSignInKey()));
            return encryptedJWT.getJWTClaimsSet().getClaims();
        } catch (ParseException | JOSEException e) {
            throw new SecurityException("Cannot decrypt JWE token", e);
        }
    }
}