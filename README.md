# spring-security-3-JWT

We implemented Spring Security in the repo `spring-security-3` here let's start implementing JWT along the spring security.

To authenticate an user we need username and password. So, let's gp ahead and create a method in controller to accept userName and password.

```java
@PostMapping("/authenticate")
  public String authenticateAndGetTken(@RequestBody AuthenticationRequestDetails details) {
    return "";
  }

  @Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationRequestDetails {
    private String username;
    private String password;
}
```

As soon as we get the userName we have to create the token based on the userName, To do that we need a service class.

```java
@Autowired
  private JwtTokenGeneratingService jwtService;

@PostMapping("/authenticate")
  public String authenticateAndGetTken(@RequestBody AuthenticationRequestDetails details) {
    return jwtService.generateToken(details.getUsername());
  }
```

The service class looks like

```java
@Service
public class JwtTokenGeneratingService {

    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, username);
    }

    private String createToken(Map<String, Object> claims, String username) {

    }
}
```

To implement the unImplemented `createToken()` method we need few dependencies from JWT.

We know that the JWT token comes with `Header`, `Payload` and `Signature`. let's provide those.

`Subject and Expiration` time are part of `Payload`, that contains `userName and expiration time`.

`Header` and `signature` are being set at the same place `signWith()`

```java
private String createToken(Map<String, Object> claims, String username) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }
```

An important step that could not be ignored is, allowing the `/products/authenticate` without any security issues. Take a look at the `SecurityConfig's securityFilterChain()`

With the implementation we have, we will be able to generate the token to anyOne though he's not an user at all because we are not validating the user details to the details in DB.

// Creating the token in API tool.

```java
http://localhost:8080/products/authenticate

{
  "username":"sai",
  "password":"sai"
}
```
